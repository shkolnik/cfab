//! The member's telemetry: one instant of fabric state rendered as OpenMetrics text.
//!
//! `render` is pure. A fresh `Registry` and one `Collector` are built per call, so no metric
//! object outlives the snapshot it describes and a family can disappear when the fact behind it
//! does — which is what a state that is `None` means.

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeGaugeValue, EncodeMetric};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::ConstCounter;
use prometheus_client::metrics::gauge::ConstGauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use crate::commands::status::model::{
    BondLeg, Class, Condition, HomeCarrier, Ingress, LegKind, State, StatusModel,
};
use crate::prober::ProbeRows;
use crate::supervisor::child::State as ChildState;
use crate::supervisor::report::ProbedLeg;

/// The port the endpoint listens on. Rule: a large, memorable port with the lowest collision
/// chance on a member; no registered Prometheus port exists to defer to.
pub(crate) const PORT: u16 = 23232;

/// One gather, everything a render needs and nothing it must read for itself.
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    pub model: StatusModel,
    pub probed: ProbeRows,
    /// Wall-clock seconds at which this snapshot was gathered.
    pub collected_at_unix: f64,
    /// How long the gather took.
    pub collect_seconds: f64,
    /// Gathers that failed since the supervisor started.
    pub collect_failures: u64,
}

/// One series' labels. Owned, because most label values are pulled out of the snapshot's
/// strings and the encoder borrows whatever it is handed for the length of one family.
type Labels = Vec<(&'static str, String)>;

type Res = Result<(), std::fmt::Error>;

fn lbl(pairs: &[(&'static str, &str)]) -> Labels {
    pairs.iter().map(|(k, v)| (*k, escape(v))).collect()
}

/// Escape a label value for the text format. VERIFIED against prometheus-client 0.25.1: its
/// `EncodeLabelValue for &str` writes the string through untouched, so a condition line
/// carrying a quote or a newline — a TOML parser error does both — would otherwise be an
/// unparseable scrape rather than a reason line.
fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// One unlabeled gauge.
fn scalar<N: EncodeGaugeValue>(
    enc: &mut DescriptorEncoder<'_>,
    name: &str,
    help: &str,
    v: N,
) -> Res {
    let fam = enc.encode_descriptor(name, help, None, MetricType::Gauge)?;
    ConstGauge::new(v).encode(fam)
}

/// One unlabeled counter. `name` carries no `_total`: the encoder appends it to the sample and
/// OpenMetrics wants the bare name in `# HELP` and `# TYPE`.
fn scalar_counter(enc: &mut DescriptorEncoder<'_>, name: &str, help: &str, v: u64) -> Res {
    let fam = enc.encode_descriptor(name, help, None, MetricType::Counter)?;
    ConstCounter::new(v).encode(fam)
}

/// A labeled gauge family. An empty family writes nothing at all: a fact this member cannot
/// state is an absent family, never a zero that reads as a measurement.
fn family<N: EncodeGaugeValue + Copy>(
    enc: &mut DescriptorEncoder<'_>,
    name: &str,
    help: &str,
    rows: &[(Labels, N)],
) -> Res {
    if rows.is_empty() {
        return Ok(());
    }
    let mut fam = enc.encode_descriptor(name, help, None, MetricType::Gauge)?;
    for (labels, v) in rows {
        let e = fam.encode_family(labels)?;
        ConstGauge::new(*v).encode(e)?;
    }
    Ok(())
}

/// A labeled counter family, same absence rule as `family`.
fn counter_family(
    enc: &mut DescriptorEncoder<'_>,
    name: &str,
    help: &str,
    rows: &[(Labels, u64)],
) -> Res {
    if rows.is_empty() {
        return Ok(());
    }
    let mut fam = enc.encode_descriptor(name, help, None, MetricType::Counter)?;
    for (labels, v) in rows {
        let e = fam.encode_family(labels)?;
        ConstCounter::new(*v).encode(e)?;
    }
    Ok(())
}

/// Every state a `cfab_fabric_state` scrape must be able to compare against, so an alert can
/// name a state this member is not in.
const FABRIC_STATES: [State; 4] = [State::Up, State::UpDegraded, State::Failed, State::Down];

/// The child states, in the enum's order.
const CHILD_STATES: [ChildState; 4] = [
    ChildState::Starting,
    ChildState::Running,
    ChildState::Restarting,
    ChildState::Stopped,
];

/// The FRR session states the engine reports, plus `absent` for a router the engine's list does
/// not carry (which is how `status` words it).
const BGP_STATES: [&str; 7] = [
    "Idle",
    "Connect",
    "Active",
    "OpenSent",
    "OpenConfirm",
    "Established",
    "absent",
];

/// The forwarding watchdog's own vocabulary.
const WATCHDOG_RESULTS: [&str; 5] = ["ok", "actuated", "failed-closed", "blocked", "error"];

/// The enumerated series of a one-of-N family: every known value, plus the observed one when it
/// is outside the set — the emitter's vocabulary wins over this list, and a value that has
/// drifted must still be visible rather than silently reported as none of the above.
fn one_of(known: &[&str], actual: &str) -> Vec<String> {
    let mut out: Vec<String> = known.iter().map(|s| (*s).to_string()).collect();
    if !known.contains(&actual) {
        out.push(actual.to_string());
    }
    out
}

/// The reason lines as `status` prints them: each distinct text once, in the order the gather
/// found it. `status` dedups the same way at render time; doing it here rather than reaching
/// into `status` keeps this module free of everything but the model.
fn once_each(conditions: &[Condition]) -> Vec<&Condition> {
    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for c in conditions {
        if !seen.contains(&c.text.as_str()) {
            seen.push(&c.text);
            out.push(c);
        }
    }
    out
}

fn class_word(c: Class) -> &'static str {
    match c {
        Class::Settling => "settling",
        Class::Standing => "standing",
    }
}

#[derive(Debug)]
struct FabricCollector {
    snap: Arc<Snapshot>,
}

impl FabricCollector {
    /// Every bond leg the model read, fallback legs first and then the migrating ingress legs —
    /// the two are the same netdev shape and answer the same questions.
    fn legs(&self) -> Vec<&BondLeg> {
        self.snap
            .model
            .fallbacks
            .iter()
            .chain(
                self.snap
                    .model
                    .ingress
                    .iter()
                    .filter_map(|i| i.bond.as_ref()),
            )
            .collect()
    }

    /// The wire a leg is carrying on, by the leg's netdev name. The prober's row names the
    /// active PORT and carries no port-to-wire map of its own, so the model's leg — which read
    /// `bonding/active_slave` and knows every port's wire — is the one place that can answer it.
    fn active_wire(&self, bond: &str) -> Option<String> {
        self.legs()
            .iter()
            .find(|l| l.ifname == bond)
            .and_then(|l| l.active_wire())
            .map(str::to_string)
    }

    fn identity(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        let m = &self.snap.model.member;
        let build = vec![(lbl(&[("version", m.version.as_str())]), 1i64)];
        family(
            enc,
            "cfab_build_info",
            "The cfab version this member runs.",
            &build,
        )?;
        let member = vec![(
            lbl(&[("member", m.name.as_str()), ("kind", m.kind_word())]),
            1i64,
        )];
        family(
            enc,
            "cfab_member_info",
            "This member's row in the declaration.",
            &member,
        )
    }

    fn headline(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        let state = self.snap.model.state;
        let rows: Vec<(Labels, i64)> = FABRIC_STATES
            .iter()
            .map(|s| (lbl(&[("state", s.word())]), i64::from(*s == state)))
            .collect();
        family(
            enc,
            "cfab_fabric_state",
            "The member's verdict; exactly one series is 1.",
            &rows,
        )?;

        let Some(h) = &self.snap.model.headline else {
            return Ok(());
        };
        scalar(
            enc,
            "cfab_peers_up",
            "Peers with at least one adjacency up.",
            h.peers_up as i64,
        )?;
        scalar(
            enc,
            "cfab_peers_expected",
            "Peers the declaration expects.",
            h.peers as i64,
        )?;
        scalar(
            enc,
            "cfab_links_up",
            "BFD sessions up on declared segments.",
            h.links_up as i64,
        )?;
        scalar(
            enc,
            "cfab_links_expected",
            "BFD sessions the declaration expects, one per peer, zone and segment.",
            h.links as i64,
        )?;
        scalar(
            enc,
            "cfab_fallbacks_up",
            "Fallback OSPF neighbors at least 2-Way.",
            h.fallbacks_up as i64,
        )?;
        scalar(
            enc,
            "cfab_fallbacks_expected",
            "Fallback OSPF neighbors the declaration expects.",
            h.fallbacks as i64,
        )
    }

    fn adjacencies(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        let mut bfd: Vec<(Labels, i64)> = Vec::new();
        let mut fallback: Vec<(Labels, i64)> = Vec::new();
        for a in &self.snap.model.adjacencies {
            match a.seg {
                Some(seg) => bfd.push((
                    lbl(&[
                        ("zone", a.zone.as_str()),
                        ("segment", &seg.to_string()),
                        ("peer", a.peer_name.as_str()),
                    ]),
                    i64::from(a.up),
                )),
                None => fallback.push((
                    lbl(&[("zone", a.zone.as_str()), ("peer", a.peer_name.as_str())]),
                    i64::from(a.up),
                )),
            }
        }
        family(
            enc,
            "cfab_bfd_session_up",
            "1 when the BFD session on this declared segment leg is up.",
            &bfd,
        )?;
        family(
            enc,
            "cfab_fallback_neighbor_up",
            "1 when this fallback OSPF neighbor is at least 2-Way.",
            &fallback,
        )
    }

    fn legs_state(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        let mut home: Vec<(Labels, i64)> = Vec::new();
        let mut carrier: Vec<(Labels, i64)> = Vec::new();
        let mut present: std::collections::BTreeMap<String, bool> = Default::default();
        for l in self.legs() {
            for p in &l.ports {
                let e = present.entry(p.wire.clone()).or_insert(false);
                *e |= !p.absent;
            }
            if l.bonding.is_none() {
                continue;
            }
            // The name says fallback and the research table bounds it at one per zone: an
            // ingress leg's position is `cfab_ingress_active`, not a series in here.
            if l.kind == LegKind::Fallback {
                home.push((
                    lbl(&[("zone", l.zone.as_str()), ("bond", l.ifname.as_str())]),
                    i64::from(l.on_home()),
                ));
            }
            if let Some(HomeCarrier::Value(v)) = l.bonding.as_ref().map(|b| &b.home_carrier) {
                carrier.push((
                    lbl(&[("zone", l.zone.as_str()), ("bond", l.ifname.as_str())]),
                    i64::from(v == "1"),
                ));
            }
        }
        family(
            enc,
            "cfab_fallback_bond_active_home",
            "1 when the leg's active port is on the wire it belongs on.",
            &home,
        )?;
        family(
            enc,
            "cfab_bond_home_carrier",
            "The home wire's carrier, read only while the leg is off home.",
            &carrier,
        )?;
        let wires: Vec<(Labels, i64)> = present
            .iter()
            .map(|(w, p)| (lbl(&[("wire", w.as_str())]), i64::from(*p)))
            .collect();
        family(
            enc,
            "cfab_wire_present",
            "1 when this declared wire exists in the kernel.",
            &wires,
        )
    }

    /// The prober's per-leg families, for one family of legs.
    fn probed(
        &self,
        enc: &mut DescriptorEncoder<'_>,
        rows: &[ProbedLeg],
        active_name: &str,
        active_help: &str,
    ) -> Res {
        let mut active: Vec<(Labels, i64)> = Vec::new();
        for leg in rows {
            let on = self.active_wire(&leg.bond);
            let Some(on) = on else { continue };
            for p in &leg.ports {
                active.push((
                    lbl(&[
                        ("zone", leg.zone.as_str()),
                        ("island", p.island.as_str()),
                        ("wire", p.wire.as_str()),
                    ]),
                    i64::from(p.wire == on),
                ));
            }
        }
        family(enc, active_name, active_help, &active)
    }

    fn probe_ports(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        let mut usable: Vec<(Labels, i64)> = Vec::new();
        let mut suspect: Vec<(Labels, i64)> = Vec::new();
        let mut last: Vec<(Labels, f64)> = Vec::new();
        let mut moves: Vec<(Labels, u64)> = Vec::new();
        let legs = self
            .snap
            .probed
            .fallback
            .iter()
            .chain(self.snap.probed.ingress.iter());
        for leg in legs {
            moves.push((
                lbl(&[("zone", leg.zone.as_str()), ("bond", leg.bond.as_str())]),
                leg.moves,
            ));
            for p in &leg.ports {
                let labels = || {
                    lbl(&[
                        ("zone", leg.zone.as_str()),
                        ("bond", leg.bond.as_str()),
                        ("wire", p.wire.as_str()),
                        ("island", p.island.as_str()),
                    ])
                };
                usable.push((labels(), i64::from(p.reachable)));
                suspect.push((labels(), i64::from(p.suspect)));
                if let Some(ms) = p.last_reply_ms {
                    last.push((labels(), ms as f64 / 1000.0));
                }
            }
        }
        family(
            enc,
            "cfab_probe_port_usable",
            "1 when the prober can reach the far end over this wire.",
            &usable,
        )?;
        family(
            enc,
            "cfab_probe_port_suspect",
            "1 when this wire is silent past its window and is being asked directly.",
            &suspect,
        )?;
        family(
            enc,
            "cfab_probe_port_last_reply_seconds",
            "Seconds since this wire last showed life; absent when it never has.",
            &last,
        )?;
        counter_family(
            enc,
            "cfab_probe_moves",
            "Moves the prober has actuated on this leg since the supervisor started.",
            &moves,
        )
    }

    fn conditions(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        let lines = once_each(&self.snap.model.conditions);
        let counts: Vec<(Labels, i64)> = [Class::Settling, Class::Standing]
            .iter()
            .map(|c| {
                (
                    lbl(&[("class", class_word(*c))]),
                    lines.iter().filter(|l| l.class == *c).count() as i64,
                )
            })
            .collect();
        family(
            enc,
            "cfab_conditions",
            "Reason lines this member reports, counted by what they mean for a wait.",
            &counts,
        )?;
        let info: Vec<(Labels, i64)> = lines
            .iter()
            .map(|c| {
                (
                    lbl(&[("class", class_word(c.class)), ("text", c.text.as_str())]),
                    1i64,
                )
            })
            .collect();
        family(
            enc,
            "cfab_condition_info",
            "One series per reason line, worded exactly as status prints it.",
            &info,
        )
    }

    fn ingress(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        let mut reachable: Vec<(Labels, i64)> = Vec::new();
        let mut bgp: Vec<(Labels, i64)> = Vec::new();
        let mut pfx: Vec<(Labels, i64)> = Vec::new();
        for i in &self.snap.model.ingress {
            reach_row(i, &mut reachable);
            let state = i.bgp_state.clone().unwrap_or_else(|| "absent".to_string());
            for s in one_of(&BGP_STATES, &state) {
                bgp.push((
                    lbl(&[
                        ("zone", i.zone.as_str()),
                        ("neighbor", i.router.as_str()),
                        ("state", s.as_str()),
                    ]),
                    i64::from(s == state),
                ));
            }
            if let Some(n) = i.bgp_pfx_snt {
                pfx.push((
                    lbl(&[("zone", i.zone.as_str()), ("neighbor", i.router.as_str())]),
                    n as i64,
                ));
            }
        }
        family(
            enc,
            "cfab_ingress_reachable",
            "1 when the prober reaches the gateway router over some wire of the ingress leg.",
            &reachable,
        )?;
        family(
            enc,
            "cfab_bgp_neighbor_state",
            "The session state toward this zone's gateway router; exactly one series is 1.",
            &bgp,
        )?;
        family(
            enc,
            "cfab_bgp_neighbor_prefixes_sent",
            "Prefixes this member has sent the gateway router.",
            &pfx,
        )
    }

    fn components(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        let Some(c) = &self.snap.model.components else {
            return Ok(());
        };
        let mut state: Vec<(Labels, i64)> = Vec::new();
        let mut expected: Vec<(Labels, i64)> = Vec::new();
        let mut restarts: Vec<(Labels, u64)> = Vec::new();
        let mut uptime: Vec<(Labels, i64)> = Vec::new();
        let mut last_exit: Vec<(Labels, i64)> = Vec::new();
        for k in &c.components {
            for s in CHILD_STATES {
                state.push((
                    lbl(&[("component", k.name.as_str()), ("state", s.as_str())]),
                    i64::from(s == k.state),
                ));
            }
            expected.push((
                lbl(&[("component", k.name.as_str())]),
                i64::from(k.why.is_none()),
            ));
            restarts.push((lbl(&[("component", k.name.as_str())]), k.restarts));
            if let Some(u) = k.uptime_s {
                uptime.push((lbl(&[("component", k.name.as_str())]), u as i64));
            }
            if let Some(e) = &k.last_exit {
                last_exit.push((
                    lbl(&[("component", k.name.as_str()), ("cause", e.cause.as_str())]),
                    e.s_ago as i64,
                ));
            }
        }
        family(
            enc,
            "cfab_component_state",
            "The supervisor's state for this child; exactly one series is 1.",
            &state,
        )?;
        family(
            enc,
            "cfab_component_expected",
            "0 when this member is not meant to run the child, which is why it is stopped.",
            &expected,
        )?;
        counter_family(
            enc,
            "cfab_component_restarts",
            "Restarts of this child since the supervisor started.",
            &restarts,
        )?;
        family(
            enc,
            "cfab_component_uptime_seconds",
            "Seconds this child has been running; absent when it is not.",
            &uptime,
        )?;
        family(
            enc,
            "cfab_component_last_exit_age_seconds",
            "Seconds since this child last exited, by the cause it exited with.",
            &last_exit,
        )?;

        if let Some(n) = c.watchdog.last_tick_s_ago {
            scalar(
                enc,
                "cfab_watchdog_last_tick_age_seconds",
                "Seconds since the forwarding watchdog last ticked.",
                n as i64,
            )?;
        }
        let result: Vec<(Labels, i64)> = one_of(&WATCHDOG_RESULTS, &c.watchdog.result)
            .into_iter()
            .map(|s| {
                let v = i64::from(s == c.watchdog.result);
                (lbl(&[("result", s.as_str())]), v)
            })
            .collect();
        family(
            enc,
            "cfab_watchdog_result",
            "What the forwarding watchdog's last tick did; exactly one series is 1.",
            &result,
        )?;

        scalar(
            enc,
            "cfab_supervisor_uptime_seconds",
            "Seconds this supervisor has been running.",
            c.supervisor.uptime_s as i64,
        )?;
        scalar_counter(
            enc,
            "cfab_supervisor_applies",
            "Fabric applies this supervisor has completed.",
            c.supervisor.applies,
        )?;
        scalar(
            enc,
            "cfab_supervisor_applying",
            "1 while an apply is in progress.",
            i64::from(c.supervisor.applying),
        )?;
        scalar(
            enc,
            "cfab_supervisor_last_apply_failed",
            "1 when the last apply left an error; the message stays in status and the journal.",
            i64::from(c.supervisor.last_apply_error.is_some()),
        )
    }

    fn telemetry(&self, enc: &mut DescriptorEncoder<'_>) -> Res {
        scalar(
            enc,
            "cfab_telemetry_last_refresh_seconds",
            "Unix time at which this snapshot was gathered.",
            self.snap.collected_at_unix,
        )?;
        scalar(
            enc,
            "cfab_telemetry_collect_seconds",
            "Wall time of the last gather and render.",
            self.snap.collect_seconds,
        )?;
        scalar_counter(
            enc,
            "cfab_telemetry_collect_failures",
            "Gathers that failed since the supervisor started.",
            self.snap.collect_failures,
        )
    }
}

/// `cfab_ingress_reachable` for one zone, when the leg migrates and the prober has an opinion.
/// `status` treats exactly `AllDark` and `Quiet` as "nothing reaches the far end" (the line it
/// prints), so those are the zeros; `Unknown` is not a verdict and emits nothing.
fn reach_row(i: &Ingress, out: &mut Vec<(Labels, i64)>) {
    use crate::commands::status::model::Reach;
    match i.reach() {
        None | Some(Reach::Unknown) => {}
        Some(r) => out.push((
            lbl(&[("zone", i.zone.as_str())]),
            i64::from(!matches!(r, Reach::AllDark | Reach::Quiet)),
        )),
    }
}

impl Collector for FabricCollector {
    fn encode(&self, mut enc: DescriptorEncoder) -> Res {
        self.identity(&mut enc)?;
        self.headline(&mut enc)?;
        self.adjacencies(&mut enc)?;
        self.legs_state(&mut enc)?;
        self.probed(
            &mut enc,
            &self.snap.probed.fallback,
            "cfab_fallback_active",
            "1 on the wire the zone's fallback leg is carrying on.",
        )?;
        self.probed(
            &mut enc,
            &self.snap.probed.ingress,
            "cfab_ingress_active",
            "1 on the wire the zone's ingress leg is carrying on.",
        )?;
        self.probe_ports(&mut enc)?;
        self.conditions(&mut enc)?;
        self.ingress(&mut enc)?;
        self.components(&mut enc)?;
        self.telemetry(&mut enc)
    }
}

/// The largest request line the endpoint reads. Rule (spec §3.1): a scrape's request line is a
/// method, a short path and a version; anything larger is not a scraper and is dropped unread.
const MAX_REQUEST: usize = 1024;

/// What the endpoint answers a connection with. `head` means the request was `HEAD`: the same
/// headers, no body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Response {
    Metrics { head: bool },
    Landing { head: bool },
    NotFound,
    Close,
}

/// The page served at `/`: one link, so a browser pointed at the port finds the metrics.
const LANDING_BODY: &str = "<html><body><a href=\"/metrics\">/metrics</a></body></html>\n";

const NOT_FOUND_BODY: &str = "not found\n";

/// Classify one request by its request line alone. Headers are not read: the endpoint speaks
/// exactly enough HTTP for a scraper, and everything it does not recognize gets the connection
/// closed rather than an error page.
pub(crate) fn respond(request: &[u8]) -> Response {
    let capped = &request[..request.len().min(MAX_REQUEST)];
    let Some(end) = capped.iter().position(|&b| b == b'\n') else {
        return Response::Close;
    };
    let line = &capped[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Ok(line) = std::str::from_utf8(line) else {
        return Response::Close;
    };
    let mut tok = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (tok.next(), tok.next(), tok.next(), tok.next())
    else {
        return Response::Close;
    };
    if !version.starts_with("HTTP/1.") {
        return Response::Close;
    }
    let head = match method {
        "GET" => false,
        "HEAD" => true,
        _ => return Response::NotFound,
    };
    match target {
        "/metrics" => Response::Metrics { head },
        "/" => Response::Landing { head },
        _ => Response::NotFound,
    }
}

/// The full HTTP/1.1 bytes for a classified request. `body` is the metrics text; the landing and
/// not-found bodies are fixed. `Close` writes nothing.
pub(crate) fn write_response(r: &Response, body: &str) -> Vec<u8> {
    let (status, content_type, body, head) = match r {
        Response::Metrics { head } => (
            "200 OK",
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
            body,
            *head,
        ),
        Response::Landing { head } => ("200 OK", "text/html; charset=utf-8", LANDING_BODY, *head),
        Response::NotFound => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            NOT_FOUND_BODY,
            false,
        ),
        Response::Close => return Vec::new(),
    };
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if !head {
        out.push_str(body);
    }
    out.into_bytes()
}

/// The member's state as OpenMetrics text, ready to serve.
pub(crate) fn render(s: &Arc<Snapshot>) -> String {
    let mut reg = Registry::default();
    reg.register_collector(Box::new(FabricCollector {
        snap: Arc::clone(s),
    }));
    let mut out = String::new();
    prometheus_client::encoding::text::encode(&mut out, &reg)
        .expect("fmt::Write on a String cannot fail");
    out
}

/// How long a connection has to deliver its whole request line. Rule (spec §3.1): a scraper
/// writes its request at once, so a peer that has not finished in two seconds is not scraping
/// and must not hold a slot.
const READ_DEADLINE: Duration = Duration::from_secs(2);

/// Connections served at once. Rule (spec §3.1): bounded with no queue — a scrape costs one
/// `Arc` clone, so this is far past any real set of scrapers and still refuses a socket flood.
const MAX_INFLIGHT: usize = 16;

/// How often the snapshot behind the endpoint is re-gathered. Rule (spec §3.2): Prometheus's
/// own default scrape interval, so a scrape is never more than one gather stale.
pub(crate) const REFRESH: Duration = Duration::from_secs(15);

/// How often a failed bind is retried. Rule (spec §3.1): a bind failure is never fatal, and a
/// minute is soon enough to take the port over once whatever held it goes away.
pub(crate) const BIND_RETRY: Duration = Duration::from_secs(60);

/// The listening socket, on every address. Bound blocking and handed to tokio, so a failure is
/// an `io::Error` the caller can report rather than a panic inside a task.
pub(crate) fn bind(port: u16) -> std::io::Result<TcpListener> {
    let l = std::net::TcpListener::bind(("0.0.0.0", port))?;
    l.set_nonblocking(true)?;
    TcpListener::from_std(l)
}

/// Serve `/metrics` until the listener dies. Every connection is answered from `latest`, the
/// snapshot the supervisor's refresh arm publishes: the accept path performs no gather, holds
/// no lock, and touches no host.
pub(crate) async fn serve(listener: TcpListener, latest: watch::Receiver<Arc<str>>) {
    let slots = Arc::new(Semaphore::new(MAX_INFLIGHT));
    loop {
        let sock = match listener.accept().await {
            Ok((sock, _)) => sock,
            Err(e) => {
                // Per-accept errors (EMFILE and friends) are transient; back off rather than
                // spin, and never take the endpoint down for one of them.
                tracing::warn!(%e, "metrics: accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // No queue: past `MAX_INFLIGHT` the socket is dropped at once, which is a closed
        // connection to the peer and no work at all here.
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            drop(sock);
            continue;
        };
        let latest = latest.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_one(sock, latest).await;
        });
    }
}

/// One connection: read a request line under one deadline, answer, close. No keep-alive.
async fn serve_one(mut sock: TcpStream, latest: watch::Receiver<Arc<str>>) {
    // One deadline for the whole read, not per read: a peer dribbling a byte at a time must
    // still be gone within `READ_DEADLINE`.
    let deadline = tokio::time::Instant::now() + READ_DEADLINE;
    let mut buf = vec![0u8; MAX_REQUEST];
    let mut n = 0;
    let r = loop {
        if n == buf.len() {
            break Response::Close;
        }
        match tokio::time::timeout_at(deadline, sock.read(&mut buf[n..])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break Response::Close,
            Ok(Ok(k)) => {
                n += k;
                if buf[..n].contains(&b'\n') {
                    break respond(&buf[..n]);
                }
            }
        }
    };
    let body: Arc<str> = match r {
        Response::Metrics { .. } => latest.borrow().clone(),
        Response::Landing { .. } | Response::NotFound | Response::Close => Arc::from(""),
    };
    let bytes = write_response(&r, &body);
    if !bytes.is_empty() {
        let _ = sock.write_all(&bytes).await;
    }
    let _ = sock.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixtures build a `Snapshot` by value; the collector holds one behind an `Arc`, which
    /// is what the supervisor hands it. One clone here, none per refresh.
    fn render(s: &Snapshot) -> String {
        super::render(&Arc::new(s.clone()))
    }

    use crate::commands::status::model::{
        Adjacency, Bonding, Headline, LegPort, MemberInfo, Reach,
    };
    use crate::model::MemberKind;
    use crate::supervisor::child::{ExitCause, State as ChildState};
    use crate::supervisor::report::{
        Component, Components, ProbedPort, SupervisorInfo, WatchdogInfo,
    };

    fn component(
        name: &str,
        state: ChildState,
        uptime_s: Option<u64>,
        why: Option<&str>,
        last_exit: Option<ExitCause>,
    ) -> Component {
        Component {
            name: name.to_string(),
            state,
            pid: Some(1234),
            uptime_s,
            restarts: 0,
            last_exit,
            why: why.map(str::to_string),
        }
    }

    fn components() -> Components {
        Components {
            supervisor: SupervisorInfo {
                pid: 1000,
                uptime_s: 3600,
                applying: false,
                applies: 1,
                last_apply_error: None,
            },
            components: vec![
                component("engine", ChildState::Running, Some(60), None, None),
                component(
                    "shape-daemon",
                    ChildState::Running,
                    Some(60),
                    None,
                    Some(ExitCause {
                        cause: "signal SIGTERM".to_string(),
                        s_ago: 300,
                    }),
                ),
                component(
                    "conf-sync",
                    ChildState::Stopped,
                    None,
                    Some("not clustered"),
                    None,
                ),
            ],
            watchdog: WatchdogInfo {
                last_tick_s_ago: Some(1),
                result: "ok".to_string(),
                detail: None,
            },
            ingress: Vec::new(),
            fallback: Vec::new(),
            metrics_error: None,
        }
    }

    fn port(ifname: &str, wire: &str) -> LegPort {
        LegPort {
            ifname: ifname.to_string(),
            wire: wire.to_string(),
            absent: false,
        }
    }

    /// The zone's universal segment, sitting on its home wire.
    fn fallback_leg() -> BondLeg {
        BondLeg {
            kind: LegKind::Fallback,
            zone: "storage".to_string(),
            ifname: "cfab-st-fb".to_string(),
            home: "eth9".to_string(),
            router: None,
            reach: Reach::Home,
            ports: vec![port("cfab-st-fb-a", "eth9"), port("cfab-st-fb-b", "eth1")],
            bonding: Some(Bonding {
                mii_status: "up".to_string(),
                active_slave: "cfab-st-fb-a".to_string(),
                home_carrier: HomeCarrier::NotRead,
                slaves: Ok(vec!["cfab-st-fb-a".to_string(), "cfab-st-fb-b".to_string()]),
            }),
        }
    }

    /// The ingress leg, moved off its home wire — the F27 shape, so the carrier and the
    /// off-home families are both exercised.
    fn ingress_leg() -> BondLeg {
        BondLeg {
            kind: LegKind::Ingress,
            zone: "mgmt".to_string(),
            ifname: "cfab-gw249".to_string(),
            home: "eth1".to_string(),
            router: Some("192.168.249.254".to_string()),
            reach: Reach::HomeDark,
            ports: vec![port("cfab-gw249-a", "eth1"), port("cfab-gw249-b", "eth9")],
            bonding: Some(Bonding {
                mii_status: "up".to_string(),
                active_slave: "cfab-gw249-b".to_string(),
                home_carrier: HomeCarrier::Value("0".to_string()),
                slaves: Ok(vec!["cfab-gw249-a".to_string(), "cfab-gw249-b".to_string()]),
            }),
        }
    }

    fn ingress_row() -> Ingress {
        Ingress {
            zone: "mgmt".to_string(),
            router: "192.168.249.254".to_string(),
            table: "249".to_string(),
            default_present: true,
            default_linkdown: false,
            ifname: Some("cfab-gw249".to_string()),
            cidr: "192.168.249.1/32".to_string(),
            cidr_present: Some(true),
            bond: Some(ingress_leg()),
            bgp_state: Some("Established".to_string()),
            bgp_pfx_snt: Some(3),
        }
    }

    fn probed_port(wire: &str, island: &str, reachable: bool, last: Option<u64>) -> ProbedPort {
        ProbedPort {
            wire: wire.to_string(),
            island: island.to_string(),
            reachable,
            suspect: !reachable,
            last_reply_ms: last,
        }
    }

    fn probe_rows() -> ProbeRows {
        ProbeRows {
            fallback: vec![ProbedLeg {
                zone: "storage".to_string(),
                bond: "cfab-st-fb".to_string(),
                active: Some("cfab-st-fb-a".to_string()),
                quiet: false,
                ports: vec![
                    probed_port("eth9", "b", true, Some(40)),
                    probed_port("eth1", "a", false, None),
                ],
                moves: 0,
            }],
            ingress: vec![ProbedLeg {
                zone: "mgmt".to_string(),
                bond: "cfab-gw249".to_string(),
                active: Some("cfab-gw249-b".to_string()),
                quiet: false,
                ports: vec![
                    probed_port("eth1", "a", false, None),
                    probed_port("eth9", "b", true, Some(120)),
                ],
                moves: 2,
            }],
        }
    }

    fn adjacency(zone: &str, seg: Option<u8>, node: u8, name: &str, up: bool) -> Adjacency {
        Adjacency {
            zone: zone.to_string(),
            seg,
            peer_node: node,
            peer_name: name.to_string(),
            peer_addr: seg.map(|s| format!("10.{s}.0.{node}")),
            up,
        }
    }

    fn model(state: State, headline: Option<Headline>, full: bool) -> StatusModel {
        StatusModel {
            member: MemberInfo {
                name: "pve1-tb".to_string(),
                kind: MemberKind::Host,
                version: "0.4.8".to_string(),
            },
            state,
            headline,
            adjacencies: if full {
                vec![
                    adjacency("storage", Some(1), 2, "pve2-tb", true),
                    adjacency("storage", Some(2), 3, "pve3-tb", true),
                    adjacency("mgmt", Some(1), 2, "pve2-tb", false),
                    adjacency("storage", None, 2, "pve2-tb", true),
                ]
            } else {
                Vec::new()
            },
            fallbacks: if full {
                vec![fallback_leg()]
            } else {
                Vec::new()
            },
            ingress: if full {
                vec![ingress_row()]
            } else {
                Vec::new()
            },
            conditions: if full {
                vec![
                    Condition {
                        class: Class::Settling,
                        text: "storage:1:.3 forming".to_string(),
                    },
                    Condition {
                        class: Class::Standing,
                        text: "wire eth9 absent (no such netdev)".to_string(),
                    },
                    Condition {
                        class: Class::Standing,
                        text: "wire eth9 absent (no such netdev)".to_string(),
                    },
                ]
            } else {
                Vec::new()
            },
            components: Some(components()),
            prefs: Vec::new(),
            run_dir: "/run/cfab".to_string(),
        }
    }

    fn snapshot(model: StatusModel, probed: ProbeRows) -> Snapshot {
        Snapshot {
            model,
            probed,
            collected_at_unix: 1_700_000_000.0,
            collect_seconds: 0.048,
            collect_failures: 0,
        }
    }

    pub(super) fn fixture_up() -> Snapshot {
        let h = Headline {
            peers_up: 2,
            peers: 2,
            links_up: 18,
            links: 18,
            fallbacks_up: 6,
            fallbacks: 6,
        };
        snapshot(model(State::Up, Some(h), true), probe_rows())
    }

    /// Nothing applied: no supervisor asked for a headline, no legs, no adjacencies.
    fn fixture_down() -> Snapshot {
        snapshot(model(State::Down, None, false), ProbeRows::default())
    }

    fn fixture_degraded() -> Snapshot {
        let h = Headline {
            peers_up: 2,
            peers: 2,
            links_up: 17,
            links: 18,
            fallbacks_up: 6,
            fallbacks: 6,
        };
        let mut m = model(State::UpDegraded, Some(h), true);
        m.adjacencies[1].up = false;
        snapshot(m, probe_rows())
    }

    /// `prometheus-parse` reads the Prometheus text format, which has no `# EOF` terminator.
    fn parse(text: &str) -> prometheus_parse::Scrape {
        let body: Vec<_> = text
            .lines()
            .filter(|l| *l != "# EOF")
            .map(|l| Ok(l.to_string()))
            .collect();
        prometheus_parse::Scrape::parse(body.into_iter()).expect("the oracle parses the body")
    }

    #[test]
    fn build_info_is_emitted_and_parses() {
        let text = render(&fixture_up());
        assert!(
            text.contains("cfab_build_info{version=\"0.4.8\"} 1"),
            "{text}"
        );
        let scrape = parse(&text);
        let s = scrape
            .samples
            .iter()
            .find(|s| s.metric == "cfab_build_info")
            .expect("family");
        assert_eq!(s.labels.get("version"), Some("0.4.8"));
    }

    #[test]
    fn output_ends_with_the_openmetrics_terminator() {
        assert!(render(&fixture_up()).ends_with("# EOF\n"));
    }

    #[test]
    fn golden_up() {
        assert_eq!(render(&fixture_up()), include_str!("metrics_golden_up.txt"));
    }

    #[test]
    fn golden_down() {
        assert_eq!(
            render(&fixture_down()),
            include_str!("metrics_golden_down.txt")
        );
    }

    #[test]
    fn golden_degraded() {
        assert_eq!(
            render(&fixture_degraded()),
            include_str!("metrics_golden_degraded.txt")
        );
    }

    #[test]
    fn every_family_parses_and_is_present_once() {
        let text = render(&fixture_up());
        let scrape = parse(&text);
        for name in [
            "cfab_build_info",
            "cfab_member_info",
            "cfab_fabric_state",
            "cfab_peers_up",
            "cfab_peers_expected",
            "cfab_links_up",
            "cfab_links_expected",
            "cfab_fallbacks_up",
            "cfab_fallbacks_expected",
            "cfab_bfd_session_up",
            "cfab_fallback_neighbor_up",
            "cfab_fallback_bond_active_home",
            "cfab_fallback_active",
            "cfab_ingress_active",
            "cfab_probe_port_usable",
            "cfab_probe_port_suspect",
            "cfab_probe_port_last_reply_seconds",
            "cfab_probe_moves_total",
            "cfab_conditions",
            "cfab_condition_info",
            "cfab_ingress_reachable",
            "cfab_bgp_neighbor_state",
            "cfab_bgp_neighbor_prefixes_sent",
            "cfab_wire_present",
            "cfab_bond_home_carrier",
            "cfab_component_state",
            "cfab_component_expected",
            "cfab_component_restarts_total",
            "cfab_component_uptime_seconds",
            "cfab_component_last_exit_age_seconds",
            "cfab_watchdog_last_tick_age_seconds",
            "cfab_watchdog_result",
            "cfab_supervisor_uptime_seconds",
            "cfab_supervisor_applies_total",
            "cfab_supervisor_applying",
            "cfab_supervisor_last_apply_failed",
            "cfab_telemetry_last_refresh_seconds",
            "cfab_telemetry_collect_seconds",
            "cfab_telemetry_collect_failures_total",
        ] {
            // A counter's `# HELP`/`# TYPE` carry the bare name and its samples carry `_total`;
            // the parser keeps whichever the line said, so both spellings are accepted here.
            let base = name.strip_suffix("_total").unwrap_or(name);
            assert!(
                scrape.docs.contains_key(name) || scrape.docs.contains_key(base),
                "missing HELP for {name}"
            );
            assert!(
                scrape
                    .samples
                    .iter()
                    .any(|s| s.metric == name || s.metric == base),
                "no sample for {name}"
            );
        }
        let ones: Vec<_> = scrape
            .samples
            .iter()
            .filter(|s| {
                s.metric == "cfab_fabric_state" && s.value == prometheus_parse::Value::Gauge(1.0)
            })
            .collect();
        assert_eq!(ones.len(), 1);
        assert_eq!(ones[0].labels.get("state"), Some("UP"));

        // The duplicated reason line is one series, and the counts agree with it.
        assert_eq!(
            scrape
                .samples
                .iter()
                .filter(|s| s.metric == "cfab_condition_info")
                .count(),
            2
        );
        let count = |class: &str| {
            scrape
                .samples
                .iter()
                .find(|s| s.metric == "cfab_conditions" && s.labels.get("class") == Some(class))
                .map(|s| s.value.clone())
        };
        assert_eq!(count("settling"), Some(prometheus_parse::Value::Gauge(1.0)));
        assert_eq!(count("standing"), Some(prometheus_parse::Value::Gauge(1.0)));

        // The ingress leg sits off its home wire, so exactly the wire it moved to reads 1.
        assert!(text.contains("cfab_ingress_active{zone=\"mgmt\",island=\"b\",wire=\"eth9\"} 1"));
        assert!(text.contains("cfab_ingress_active{zone=\"mgmt\",island=\"a\",wire=\"eth1\"} 0"));
        // The ingress leg is not a fallback bond, so it earns no series in that family.
        assert!(!text.contains("cfab_fallback_bond_active_home{zone=\"mgmt\""));
    }

    #[test]
    fn down_fixture_has_no_adjacency_families() {
        let text = render(&fixture_down());
        assert!(!text.contains("cfab_bfd_session_up{") && !text.contains("cfab_peers_up "));
        assert!(text.contains("cfab_fabric_state{state=\"DOWN\"} 1"));
        // The supervisor still answers, so its own families stay.
        assert!(text.contains("cfab_component_state{component=\"engine\",state=\"running\"} 1"));
    }

    #[test]
    fn a_silent_supervisor_drops_every_component_family() {
        let mut s = fixture_down();
        s.model.components = None;
        let text = render(&s);
        for name in [
            "cfab_component_state",
            "cfab_watchdog_result",
            "cfab_supervisor_uptime_seconds",
        ] {
            assert!(!text.contains(name), "{name} survived a silent supervisor");
        }
        assert!(text.contains("cfab_telemetry_collect_seconds"));
    }

    #[test]
    fn label_values_are_escaped() {
        let mut s = fixture_up();
        s.model.conditions = vec![Condition {
            class: Class::Standing,
            text: "shape drift on eth1: \"class 1:10\"\nrate 705Mbit".to_string(),
        }];
        let text = render(&s);
        assert!(text.contains("\\\"class 1:10\\\""), "{text}");
        assert!(text.contains("\\n"), "{text}");
        let scrape = parse(&text);
        let s = scrape
            .samples
            .iter()
            .find(|s| s.metric == "cfab_condition_info")
            .expect("family");
        // `prometheus-parse` 0.2.5 hands back the escaped bytes rather than unescaping them,
        // so this asserts what reached the wire: one line, no bare quote, no bare newline.
        assert_eq!(
            s.labels.get("text"),
            Some("shape drift on eth1: \\\"class 1:10\\\"\\nrate 705Mbit")
        );
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    #[test]
    fn get_metrics_10_and_11() {
        assert!(matches!(
            respond(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"),
            Response::Metrics { head: false }
        ));
        assert!(matches!(
            respond(b"GET /metrics HTTP/1.0\r\n\r\n"),
            Response::Metrics { head: false }
        ));
        assert!(matches!(
            respond(b"HEAD /metrics HTTP/1.1\r\n\r\n"),
            Response::Metrics { head: true }
        ));
    }

    #[test]
    fn landing_and_404() {
        assert!(matches!(
            respond(b"GET / HTTP/1.1\r\n\r\n"),
            Response::Landing { head: false }
        ));
        assert!(matches!(
            respond(b"HEAD / HTTP/1.1\r\n\r\n"),
            Response::Landing { head: true }
        ));
        // Query strings are not interpreted: the target is not the path.
        assert!(matches!(
            respond(b"GET /metrics?x=1 HTTP/1.1\r\n\r\n"),
            Response::NotFound
        ));
        assert!(matches!(
            respond(b"GET /other HTTP/1.1\r\n\r\n"),
            Response::NotFound
        ));
        assert!(matches!(
            respond(b"POST /metrics HTTP/1.1\r\n\r\n"),
            Response::NotFound
        ));
    }

    #[test]
    fn garbage_and_oversize_close() {
        assert!(matches!(respond(b"\x16\x03\x01\x00"), Response::Close)); // a TLS hello
        assert!(matches!(respond(b"GET /metrics"), Response::Close)); // no terminator yet
        assert!(matches!(respond(&vec![b'A'; 2048]), Response::Close));
        // A request line longer than the cap, terminator included, is still refused.
        let mut long = vec![b'A'; MAX_REQUEST + 8];
        long.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(respond(&long), Response::Close));
        // Bare LF is a terminator too.
        assert!(matches!(
            respond(b"GET /metrics HTTP/1.1\n\n"),
            Response::Metrics { head: false }
        ));
        // Not UTF-8.
        assert!(matches!(
            respond(b"GET /\xff\xfe HTTP/1.1\r\n\r\n"),
            Response::Close
        ));
        // Wrong protocol on a three-token line.
        assert!(matches!(
            respond(b"GET /metrics HTTP/2.0\r\n\r\n"),
            Response::Close
        ));
        // Wrong token count.
        assert!(matches!(respond(b"GET /metrics\r\n\r\n"), Response::Close));
    }

    #[test]
    fn response_bytes() {
        let b = write_response(&Response::Metrics { head: false }, "x 1\n");
        let s = String::from_utf8(b).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains(
            "Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\n"
        ));
        assert!(s.contains("Content-Length: 4\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("\r\n\r\nx 1\n"));

        // HEAD sends the headers the GET would have sent, and no body.
        let h =
            String::from_utf8(write_response(&Response::Metrics { head: true }, "x 1\n")).unwrap();
        assert!(h.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(h.contains("Content-Length: 4\r\n"));
        assert!(h.ends_with("\r\n\r\n"));

        let l = String::from_utf8(write_response(&Response::Landing { head: false }, "")).unwrap();
        assert!(l.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(l.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(l.contains(&format!("Content-Length: {}\r\n", LANDING_BODY.len())));
        assert!(l.ends_with(LANDING_BODY));
        let lh = String::from_utf8(write_response(&Response::Landing { head: true }, "")).unwrap();
        assert!(lh.contains(&format!("Content-Length: {}\r\n", LANDING_BODY.len())));
        assert!(lh.ends_with("\r\n\r\n"));

        assert!(
            String::from_utf8(write_response(&Response::NotFound, ""))
                .unwrap()
                .starts_with("HTTP/1.1 404 Not Found\r\n")
        );
        assert!(write_response(&Response::Close, "").is_empty());
    }

    // ---- the serve loop -----------------------------------------------------------------

    /// One scrape: connect, ask, read the whole answer to EOF (the endpoint closes).
    async fn scrape(addr: std::net::SocketAddr, request: &str) -> String {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(request.as_bytes()).await.unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).await.unwrap();
        out
    }

    /// The endpoint answers from the watch, sees a replacement without a restart, 404s an
    /// unknown path, and hangs up on a peer that never finishes its request line.
    #[tokio::test(flavor = "multi_thread")]
    async fn serve_answers_from_the_latest_snapshot_and_drops_a_stalled_peer() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = watch::channel(Arc::<str>::from("cfab_x 1\n"));
        let server = tokio::spawn(serve(l, rx));

        let r = scrape(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
        assert!(r.ends_with("\r\n\r\ncfab_x 1\n"), "{r}");

        assert!(
            scrape(addr, "GET /nope HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 404 Not Found\r\n")
        );

        // A peer that sends part of a request line and then nothing: the endpoint must close it
        // on its own, without an answer, inside the read deadline.
        let mut stalled = TcpStream::connect(addr).await.unwrap();
        stalled.write_all(b"GET").await.unwrap();
        let mut sink = Vec::new();
        let closed = tokio::time::timeout(
            READ_DEADLINE + Duration::from_secs(1),
            stalled.read_to_end(&mut sink),
        )
        .await;
        assert!(closed.is_ok(), "a stalled peer was not closed in time");
        assert!(sink.is_empty(), "a malformed request earns no answer");

        // The next scrape sees a snapshot published after the loop started: nothing is cached
        // per connection.
        tx.send_replace(Arc::from("cfab_y 2\n"));
        assert!(
            scrape(addr, "GET /metrics HTTP/1.0\r\n\r\n")
                .await
                .ends_with("cfab_y 2\n")
        );
        server.abort();
    }

    /// The in-flight bound: with `MAX_INFLIGHT` connections open and unanswered, one more is
    /// dropped immediately — closed with no bytes, not queued behind the others.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_connection_past_the_inflight_bound_is_dropped_at_once() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (_tx, rx) = watch::channel(Arc::<str>::from("cfab_x 1\n"));
        let server = tokio::spawn(serve(l, rx));

        // Each holder occupies a slot for the whole read deadline: connected, silent.
        let mut held = Vec::new();
        for _ in 0..MAX_INFLIGHT {
            let c = TcpStream::connect(addr).await.unwrap();
            c.writable().await.unwrap();
            held.push(c);
        }
        // Let the accept loop take every one of them before the extra arrives.
        tokio::task::yield_now().await;
        let mut extra = TcpStream::connect(addr).await.unwrap();
        let mut sink = Vec::new();
        let closed = tokio::time::timeout(
            READ_DEADLINE - Duration::from_millis(500),
            extra.read_to_end(&mut sink),
        )
        .await;
        assert!(
            closed.is_ok() && sink.is_empty(),
            "the 17th connection must be dropped while 16 are held, got {sink:?}"
        );
        drop(held);
        server.abort();
    }
}
