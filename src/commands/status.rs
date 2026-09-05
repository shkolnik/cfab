//! `cfab status` — what this member's fabric is doing right now, in four states.
//!
//! `UP` (0) every expected adjacency available · `UP-DEGRADED` (1) up, some down · `FAILED` (2)
//! no adjacency available while up is desired · `DOWN` (3) up is not desired. The headline
//! carries three fixed counts, `(<peers> | <links> | <fallbacks>)`.
//!
//! **Detectors actuate, status reports.** Nothing here writes: a condition that makes a link
//! unsafe is brought down by `cfab fwd-watchdog`, and the state then follows from the adjacency
//! counts. Everything else is a reason line that does not move the state — a false `FAILED`
//! costs an exit code, a false actuation costs packets.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Duration;

use serde_json::Value;

use crate::commands::common::{conf_interfaces, foreign_forward_remedy, unresolved_forward_drops};
use crate::commands::engine_ctl;
use crate::derive::{View, segments_of};
use crate::emit;
use crate::error::Result;
use crate::model::MemberKind;
use crate::sys::{Sys, run_optional};

/// The re-read cadence of `--wait`.
const POLL_SECS: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Up,
    /// Up, but some expected adjacency is down. One hyphenated token so it has one spelling and
    /// the word UP stays visible on a degraded member.
    UpDegraded,
    Failed,
    Down,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            State::Up => "UP",
            State::UpDegraded => "UP-DEGRADED",
            State::Failed => "FAILED",
            State::Down => "DOWN",
        }
    }

    /// Nagios-style: 0 ok, 1 warning, 2 critical, 3 unknown/not-desired.
    pub fn code(self) -> u8 {
        match self {
            State::Up => 0,
            State::UpDegraded => 1,
            State::Failed => 2,
            State::Down => 3,
        }
    }
}

pub struct StatusReport {
    pub state: State,
    /// The process exit code — `state.code()`, or 0 for UP/UP-DEGRADED under `--permissive`.
    pub code: u8,
    pub output: String,
}

/// The three fields of the headline, each `n/N`. All three are on the links axis; they are
/// separate because a lost BFD session shows sub-second and a lost fallback neighbor only after
/// the OSPF dead interval.
#[derive(Default, Debug, PartialEq, Eq)]
struct Counts {
    peers_up: usize,
    peers: usize,
    links_up: usize,
    links: usize,
    fallbacks_up: usize,
    fallbacks: usize,
}

impl Counts {
    fn state(&self) -> State {
        if self.links_up == 0 && self.fallbacks_up == 0 {
            State::Failed
        } else if self.links_up == self.links && self.fallbacks_up == self.fallbacks {
            State::Up
        } else {
            State::UpDegraded
        }
    }

    fn fields(&self) -> String {
        format!(
            "{}/{} | {}/{} | {}/{}",
            self.peers_up, self.peers, self.links_up, self.links, self.fallbacks_up, self.fallbacks
        )
    }
}

/// Reason lines. Not verdicts: a posture condition either actuates (the links go down and the
/// state follows) or lands here, where it never moves the state.
#[derive(Default)]
struct Ctx {
    reasons: Vec<String>,
}

impl Ctx {
    fn note(&mut self, msg: impl Into<String>) {
        self.reasons.push(msg.into());
    }
}

pub fn run(sys: &mut dyn Sys, view: &View, wait_s: u64, permissive: bool) -> Result<StatusReport> {
    let f = view.fabric;
    // Intent: `up` creates the run dir, `down` removes it whole. No run dir = up is not desired,
    // and there is nothing to wait for.
    if !sys.exists(&f.run_dir) {
        return Ok(finish(
            view,
            State::Down,
            "fabric not applied".to_string(),
            &Ctx::default(),
            permissive,
        ));
    }

    let expected = expected_links(view)?;
    let mut t = 0u64;
    let (mut counts, mut c);
    loop {
        c = Ctx::default();
        counts = read(sys, view, &expected, &mut c)?;
        // The wait exists for the post-`up` settle, not as a verdict: only UP ends it early.
        // A degraded or failed member waits the full deadline and then reports what it reached.
        if counts.state() == State::Up || t >= wait_s {
            break;
        }
        t += POLL_SECS;
        sys.sleep(Duration::from_secs(POLL_SECS));
    }
    Ok(finish(
        view,
        counts.state(),
        counts.fields(),
        &c,
        permissive,
    ))
}

fn finish(view: &View, state: State, fields: String, c: &Ctx, permissive: bool) -> StatusReport {
    let kind_s = match view.kind() {
        MemberKind::Host => "host",
        MemberKind::Leaf => "leaf",
    };
    let mut out = format!(
        "{} ({fields}) on {} ({kind_s})\n",
        state.word(),
        view.member.name
    );
    for r in once_each(&c.reasons) {
        let _ = writeln!(out, "  {r}");
    }
    let code = if permissive && matches!(state, State::Up | State::UpDegraded) {
        0
    } else {
        state.code()
    };
    StatusReport {
        state,
        code,
        output: out,
    }
}

/// One BFD session per (zone, segment) shared with each peer, keyed by the peer's segment
/// address — exact for a heterogeneous membership and per session, so a dark segment is named,
/// not just counted. The declaration is the denominator, and it is meant to ignore a cable pull.
fn expected_links(view: &View) -> Result<Vec<(u8, String, u8, String)>> {
    let f = view.fabric;
    let host = &view.member.name;
    let mut expected: Vec<(u8, String, u8, String)> = Vec::new();
    let ours = segments_of(f, view.member);
    for m in &f.members {
        if m.name == *host {
            continue;
        }
        let theirs = segments_of(f, m);
        for shared in ours.intersection(&theirs) {
            let (z, seg) = shared.split_once(':').expect("zone:seg");
            let zone = f.zone(z)?;
            let seg: u8 = seg.parse().expect("seg number");
            expected.push((
                m.node,
                z.to_string(),
                seg,
                format!("{}.{seg}.{}", zone.block(), m.node),
            ));
        }
    }
    Ok(expected)
}

/// One instant read of everything: the doctor, the posture passes, then the adjacency counts.
fn read(
    sys: &mut dyn Sys,
    view: &View,
    expected: &[(u8, String, u8, String)],
    c: &mut Ctx,
) -> Result<Counts> {
    let f = view.fabric;
    // First: the engine may be gone because another BFD daemon took our port, and every count
    // below needs the engine. Diagnose that before reporting its symptoms.
    let port_taken = bfd_port(sys, view, c)?;
    let doc = engine_ctl::state(sys, f).ok();
    if doc.is_none() && !port_taken {
        c.note("engine not running: cfab-engine.service is not answering — re-run cfab up");
    }
    posture(sys, view, doc.as_ref(), c)?;
    return_path_and_ingress(sys, view, doc.as_ref(), c)?;
    mark_drift(sys, view, c)?;
    shape_posture(sys, view, c)?;
    link_speeds(sys, view, c)?;

    let mut counts = Counts::default();
    let mut peers: BTreeSet<u8> = BTreeSet::new();
    let mut peers_up: BTreeSet<u8> = BTreeSet::new();

    // ---- links: one BFD session per (peer, zone, segment) --------------------------
    let up_addrs: BTreeSet<String> = doc
        .as_ref()
        .map(|d| {
            d["bfd"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|s| s["state"] == "up")
                .filter_map(|s| s["peer"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // The BFD-up legs are the runtime half of the expectation rule below: which segment can
    // actually carry this peer's traffic right now, as opposed to which one we declared.
    let mut up_legs: BTreeSet<(u8, String, u8)> = BTreeSet::new();
    for (p, z, seg, addr) in expected {
        peers.insert(*p);
        counts.links += 1;
        if up_addrs.contains(addr) {
            counts.links_up += 1;
            peers_up.insert(*p);
            up_legs.insert((*p, z.clone(), *seg));
        } else {
            c.note(format!("down {z}:{seg}:.{p}"));
        }
    }

    // ---- fallbacks: one expected OSPF neighbor per peer carrying the zone's row ----
    let two_way = fallback(
        sys,
        view,
        doc.as_ref(),
        c,
        &mut counts,
        &mut peers,
        &mut peers_up,
    )?;

    counts.peers = peers.len();
    counts.peers_up = peers_up.len();

    reachability(sys, view, c, &up_legs, &two_way)?;
    Ok(counts)
}

/// BFD port custody, and the one diagnosis that must run before anything else: the engine binds
/// udp/BFD_PORT exclusively (no SO_REUSEADDR), so a daemon holding the port makes the engine exit
/// at the first session instead of stealing our packets. Returns true when that is why there is
/// no engine to talk to. A second BFD daemon that is merely present is a reason line: it takes
/// the port at our next restart. Measured 2026-09-05: with SO_REUSEADDR on both sides FRR's bfdd
/// and holo both bound 0.0.0.0:3784 and the last binder silently took every packet, either order.
fn bfd_port(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<bool> {
    let f = view.fabric;
    let port = f.bfd_port;
    let mut found: Vec<String> = Vec::new();
    for unit in ["frr", "bfdd"] {
        let unit = format!("{unit}.service");
        if let Some(out) = run_optional(sys, &["systemctl", "is-enabled", &unit])
            && out.stdout.trim() == "enabled"
        {
            found.push(format!("{unit} enabled"));
        }
    }
    for pid in sys.list_dir("/proc").unwrap_or_default() {
        if !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        // A reaped-but-not-waited bfdd keeps its /proc entry and its name (seen in the
        // container fixture, whose init reaps nothing): a zombie holds no socket.
        if let Ok(comm) = sys.read(&format!("/proc/{pid}/comm"))
            && comm.trim() == "bfdd"
            && !sys
                .read(&format!("/proc/{pid}/status"))
                .unwrap_or_default()
                .contains("State:\tZ")
        {
            found.push(format!("bfdd running (pid {pid})"));
        }
    }
    if !found.is_empty() {
        c.note(format!(
            "bfd udp/{port}: another BFD daemon is on this host ({}) — it takes the port at our \
             next engine restart; stop it (systemctl disable --now frr), or declare a free \
             BFD_PORT on EVERY member",
            found.join(", ")
        ));
    }
    // A bind failure in the log is only news while the engine is gone: the engine that answers
    // holds the port (nothing else can), and a line from a start it has since survived is history.
    if engine_ctl::state(sys, f).is_ok() {
        return Ok(false);
    }
    let systemd = sys.exists("/run/systemd/system");
    let log = engine_ctl::engine_log(sys, f, systemd);
    let Some(line) = engine_ctl::bfd_bind_error_line(&log, port) else {
        return Ok(false);
    };
    c.note(format!(
        "bfd udp/{port}: the engine is not running and could not bind it — {line}"
    ));
    c.note(format!(
        "remedy: {}",
        engine_ctl::bfd_bind_remedy(line, port)
    ));
    Ok(true)
}

fn posture(sys: &mut dyn Sys, view: &View, doc: Option<&Value>, c: &mut Ctx) -> Result<()> {
    let f = view.fabric;
    // The fallback bond is a segment here: it carries L3 and takes the same loose rp_filter.
    // Its slaves never appear — they are L2 only.
    let l3: Vec<String> = view
        .class_rows()
        .into_iter()
        .map(|r| r.ifname)
        .chain(view.fallback_rows().into_iter().map(|r| r.ifname))
        .collect();
    for ifname in &l3 {
        let got = sys
            .read(&format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "missing".to_string());
        if got != "2" {
            c.note(format!("rp_filter {ifname}={got} (want 2 = loose)"));
        }
    }

    match view.kind() {
        MemberKind::Leaf => {
            let mut ifs: Vec<String> = l3.clone();
            for z in &f.zones {
                let id = View::identity_if(z);
                ifs.push(id.clone());
                ifs.push(format!("{id}-peer"));
            }
            for ifn in ifs {
                let v = sys
                    .read(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if v != "0" {
                    c.note(format!("{ifn} forwarding!=0 (a leaf never transits)"));
                }
            }
            for z in &f.zones {
                let blk = format!("{}.0.0/16", z.block());
                let r1000 = sys.run(&["ip", "rule", "show", "pref", "1000"])?.stdout;
                if !r1000.contains(&format!("to {blk} iif lo lookup main")) {
                    c.note(format!(
                        "leak guard missing: pref 1000 to {blk} iif lo lookup main"
                    ));
                }
                let r1001 = sys.run(&["ip", "rule", "show", "pref", "1001"])?.stdout;
                if !r1001.contains(&format!("to {blk} unreachable")) {
                    c.note(format!(
                        "leak guard missing: pref 1001 to {blk} unreachable"
                    ));
                }
            }
            // never-a-transit: every transit link in our self-originated router LSA carries
            // the offset — exactly cost + offset for a link from one of our segment
            // addresses, at least the offset for any other
            let Some(doc) = doc else { return Ok(()) };
            for z in &f.zones {
                // Segments AND the fallback bond as `(seg, cost)`: the bond addresses and
                // advertises exactly like a segment (`10.<id>.<seg>.<node>`), so a
                // class-rows-only list leaves its transit link owned by nobody and the
                // check silently weakens to "at least the offset" for it.
                let rows: Vec<(u8, u32)> = view
                    .class_rows()
                    .into_iter()
                    .filter(|r| r.zone == z.name)
                    .map(|r| (r.seg, r.ospf_cost))
                    .chain(
                        view.fallback_rows()
                            .into_iter()
                            .filter(|r| r.zone == z.name)
                            .map(|r| (r.seg, r.ospf_cost)),
                    )
                    .collect();
                let mut below = false;
                for link in doc["ospf"][&z.name]["self_lsa_links"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|l| engine_ctl::is_transit(&l["type"]))
                {
                    let metric = link["metric"].as_u64().unwrap_or(0);
                    let addr = link["if"].as_str().unwrap_or("");
                    let want = rows
                        .iter()
                        .find(|(seg, _)| view.segment_addr(z, *seg) == addr)
                        .map(|(_, cost)| u64::from(cost + f.leaf_cost_offset));
                    if metric < u64::from(f.leaf_cost_offset) || want.is_some_and(|w| metric != w) {
                        below = true;
                    }
                }
                if below {
                    c.note(format!(
                        "ospf {}: a transit link in our router LSA is advertised below \
                         LEAF_COST_OFFSET={} (we could be chosen as a transit) — re-run cfab up",
                        z.id, f.leaf_cost_offset
                    ));
                }
            }
        }
        MemberKind::Host if f.host_forward => {
            let want_policy = emit::policy::generate(view)?;
            let loaded = sys
                .read(&format!("{}/policy.nft", f.run_dir))
                .unwrap_or_default();
            if want_policy != loaded {
                c.note("policy drift — re-run cfab up");
            }
            let live = sys.run(&["nft", "-s", "list", "table", "inet", "cfab-fwd"])?;
            let applied = sys
                .read(&format!("{}/policy.applied", f.run_dir))
                .unwrap_or_default();
            if !live.ok() || live.stdout != applied {
                c.note("ruleset drift — re-run cfab up");
            }
            let chain = sys
                .run(&["nft", "list", "chain", "inet", "cfab-fwd", "forward"])?
                .stdout;
            if !chain.contains("policy drop;") {
                c.note(
                    "transit disabled: table inet cfab-fwd / chain forward with policy drop is \
                     not loaded — re-run cfab up",
                );
            }
            // Our accept is not the last word: every base chain at the forward hook runs and
            // one drop verdict ends the packet. Without this check `status` would report a
            // healthy posture with transit 100 % dead (Docker, measured on pve1 2026-09-04).
            let blocked = unresolved_forward_drops(sys)?;
            if !blocked.is_empty() {
                let ifs: Vec<String> = view
                    .owned_forwarding()
                    .into_iter()
                    .filter(|(_, fwd)| *fwd)
                    .map(|(ifn, _)| ifn)
                    .collect();
                for b in &blocked {
                    c.note(format!(
                        "transit blocked by a foreign forward-hook chain: {b}"
                    ));
                }
                c.note(foreign_forward_remedy(&ifs));
            }
            if let Some(admin) = view.admin_if() {
                for counter in ["admin-in", "admin-out"] {
                    match counter_packets(&chain, counter) {
                        Some(0) => {}
                        Some(n) => c.note(format!(
                            "{counter} counter = {n} (something tried to transit {admin})"
                        )),
                        None => c.note(format!(
                            "{counter} counter = absent (something tried to transit {admin})"
                        )),
                    }
                }
                let v = sys.read(&format!("/proc/sys/net/ipv4/conf/{admin}/forwarding"))?;
                if v.trim() != "0" {
                    c.note(format!("{admin} forwarding=1"));
                }
            }
            let present = conf_interfaces(sys)?;
            for (ifn, fwd) in view.owned_forwarding() {
                if !present.contains(&ifn) {
                    continue;
                }
                let v = sys.read(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"))?;
                let v = v.trim();
                if fwd && v != "1" {
                    c.note(format!(
                        "{ifn} forwarding=0 (class-table interface should forward)"
                    ));
                } else if !fwd && v != "0" {
                    c.note(format!(
                        "{ifn} forwarding=1 (cfab interface that must not transit)"
                    ));
                }
            }
            if !sys
                .run(&["systemctl", "is-active", "-q", "cfab-fwd-watchdog.timer"])?
                .ok()
            {
                c.note("cfab-fwd-watchdog.timer not active (the actuator is down)");
            }
        }
        MemberKind::Host => {
            if sys.run(&["nft", "list", "table", "inet", "cfab-fwd"])?.ok() {
                c.note("HOST_FORWARD=0 but table inet cfab-fwd is loaded");
            }
            for ifn in conf_interfaces(sys)? {
                if !view.owns_if(&ifn) {
                    continue;
                }
                let path = format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding");
                if sys.read(&path)?.trim() != "0" {
                    c.note(format!("{path} = 1 with HOST_FORWARD=0"));
                }
            }
        }
    }
    Ok(())
}

/// ietf-ospf `nbr-state-type`, in its enum order. The fallback bar is 2-Way: on a broadcast LAN
/// two DROthers never go past it, so Full would be a bar a healthy fallback LAN cannot clear.
const NBR_STATES: [&str; 8] = [
    "down", "attempt", "init", "2-way", "exstart", "exchange", "loading", "full",
];

fn at_least_two_way(state: &str) -> bool {
    NBR_STATES
        .iter()
        .position(|s| *s == state)
        .is_some_and(|i| i >= 3)
}

/// The fallback segment: which wire each zone's bond is actually on, and whether every peer that
/// carries the row is adjacent on it. Fallback legs carry no BFD, so an OSPF neighbor at ≥ 2-Way
/// is the availability signal — and it counts toward the state, in its own field.
///
fn fallback(
    sys: &mut dyn Sys,
    view: &View,
    doc: Option<&Value>,
    c: &mut Ctx,
    counts: &mut Counts,
    peers: &mut BTreeSet<u8>,
    peers_up: &mut BTreeSet<u8>,
) -> Result<BTreeSet<(u8, String)>> {
    let f = view.fabric;
    let mut two_way: BTreeSet<(u8, String)> = BTreeSet::new();
    let rows = view.fallback_rows();
    if rows.is_empty() {
        return Ok(two_way);
    }
    for r in &rows {
        let z = f.zone(&r.zone)?;
        let zone = &r.zone;

        // ---- the leg: bonding/{mii_status,active_slave} ------------------------------
        let mii = sys.read(&format!("/sys/class/net/{}/bonding/mii_status", r.ifname));
        let active = sys.read(&format!("/sys/class/net/{}/bonding/active_slave", r.ifname));
        match (mii, active) {
            (Err(_), _) | (_, Err(_)) => {
                c.note(format!(
                    "fallback {zone}: {} is not a bond (/sys/class/net/{}/bonding unreadable) — \
                     re-run cfab up",
                    r.ifname, r.ifname
                ));
            }
            (Ok(mii), Ok(active)) if mii.trim() != "up" => {
                // A dark bond whose active slave is a stranger is not the same fault as a dark
                // bond, and "no carrier" would send an operator to the wrong end of the cable.
                // The line says what was READ, not what the watchdog did with it: `status`
                // cannot know whether an eviction was attempted (on a leaf the watchdog is not
                // even scheduled), and a confident wrong diagnosis is worse than a plain one.
                let active = active.trim().to_string();
                if !active.is_empty() && !r.slaves.iter().any(|s| s.ifname == active) {
                    c.note(format!(
                        "fallback {zone} down with foreign slave {active} active"
                    ));
                } else {
                    c.note(format!("fallback {zone} no carrier"));
                }
            }
            (Ok(_), Ok(active)) => {
                let active = active.trim();
                match r
                    .slaves
                    .iter()
                    .find(|s| s.ifname == active)
                    .map(|s| s.wire.clone())
                {
                    None => c.note(format!(
                        "fallback {zone}: {} is up with no slave of ours active \
                         (active_slave={active:?})",
                        r.ifname
                    )),
                    Some(wire) if wire == r.home => {}
                    Some(wire) => {
                        // Off the home wire is only a fault while the home wire still has
                        // carrier: that is a stuck reselect. A dark home is the bond doing its
                        // job. An unreadable carrier is neither and is never assumed healthy —
                        // the file returns EINVAL on a down interface, so this is a field state.
                        match sys.read(&format!("/sys/class/net/{}/carrier", r.home)) {
                            Ok(s) if s.trim() == "1" => c.note(format!(
                                "fallback {zone} via {wire} (home {} has carrier)",
                                r.home
                            )),
                            Ok(_) => c.note(format!("fallback {zone} via {wire}")),
                            Err(_) => c.note(format!(
                                "fallback {zone} via {wire} (home {} carrier unreadable)",
                                r.home
                            )),
                        }
                    }
                }
            }
        }

        // ---- adjacency: every peer carrying this zone's fallback row, at least 2-Way ----
        let peer_members: Vec<&crate::model::Member> = f
            .members
            .iter()
            .filter(|m| m.name != view.member.name)
            .filter(|m| {
                crate::derive::fallback_rows_of(f, m)
                    .iter()
                    .any(|p| p.zone == *zone)
            })
            .collect();
        for m in &peer_members {
            peers.insert(m.node);
            counts.fallbacks += 1;
        }
        // An interface the engine does not carry indexes to Null here, and Null reads as an
        // empty neighbor list — every declared peer would be reported absent, which names the
        // wrong fault. The missing interface IS the fault; say that instead.
        let nbrs = doc
            .and_then(|d| d["ospf"][zone]["interfaces"].get(r.ifname.as_str()))
            .map(|i| &i["neighbors"]);
        let Some(nbrs) = nbrs else {
            if doc.is_some() {
                c.note(format!(
                    "fallback {zone}: {} is missing from the engine's ospf state (its neighbors \
                     cannot be read) — re-run cfab up",
                    r.ifname
                ));
            }
            for m in &peer_members {
                c.note(format!("down {zone}:fallback:.{}", m.node));
            }
            continue;
        };
        for m in &peer_members {
            let rid = format!("{}.0.{}", z.block(), m.node);
            let state = nbrs
                .as_array()
                .into_iter()
                .flatten()
                .find(|n| n["router_id"] == rid.as_str())
                .and_then(|n| n["state"].as_str())
                .map(|s| s.rsplit(':').next().unwrap_or(s))
                .unwrap_or("absent");
            if at_least_two_way(state) {
                counts.fallbacks_up += 1;
                peers_up.insert(m.node);
                two_way.insert((m.node, zone.clone()));
            } else {
                c.note(format!("down {zone}:fallback:.{}", m.node));
            }
        }
    }
    Ok(two_way)
}

/// Each peer's identity, in each zone, must be reached over the interface we expect and with a
/// pinned source address — and the expectation is read from RUNTIME state, never the declaration:
/// `expected_dev` = the cheapest of (the segment legs whose BFD to this peer is up) together with
/// (the zone's fallback bond, if this peer is at least 2-Way on it).
///
/// This is the D3 class. Both former sites keyed on `segments_of()`, so a cable pull never made
/// two members disjoint in the model, and the fabric's own safety net read as a fault while it
/// was doing its job. The declaration still sources the DENOMINATOR (`expected_links`) — that
/// number is meant to ignore a cable pull — but no expectation comes from it any more.
///
/// A peer with nothing up in a zone gets no expectation at all: those adjacencies are already
/// counted down, and "no BFD-up segment to a peer" is not a second, louder verdict.
fn reachability(
    sys: &mut dyn Sys,
    view: &View,
    c: &mut Ctx,
    up_legs: &BTreeSet<(u8, String, u8)>,
    two_way: &BTreeSet<(u8, String)>,
) -> Result<()> {
    let f = view.fabric;
    let host = &view.member.name;
    for m in &f.members {
        if m.name == *host {
            continue;
        }
        let p = m.node;
        for z in &f.zones {
            // (cost, ifname, is_fallback). The fallback row's cost is validated to sit above
            // every host path in its zone, so the bond sorts last and is chosen only when no
            // segment leg to this peer is up.
            let mut candidates: Vec<(u32, String, bool)> = view
                .class_rows()
                .into_iter()
                .filter(|r| r.zone == z.name && up_legs.contains(&(p, z.name.clone(), r.seg)))
                .map(|r| (r.ospf_cost, r.ifname, false))
                .collect();
            if two_way.contains(&(p, z.name.clone())) {
                candidates.extend(
                    view.fallback_rows()
                        .into_iter()
                        .filter(|r| r.zone == z.name)
                        .map(|r| (r.ospf_cost, r.ifname, true)),
                );
            }
            candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            let Some((_, expect, is_fallback)) = candidates.first() else {
                continue;
            };
            let target = format!("{}.0.{p}", z.block());
            let (dev, route_line) = route_dev(sys, &target)?;
            if dev != *expect {
                c.note(format!(
                    "{} to {} via {dev}, expected {expect}",
                    z.name, m.name
                ));
            } else if *is_fallback {
                // Health, whichever branch supplied the expectation — but worth a line: this
                // peer is reachable, and not over a declared segment.
                c.note(format!("{} to {} via fallback", z.name, m.name));
            }
            if !route_line.contains(&format!("src {}.0.{}", z.block(), view.node())) {
                c.note(format!(
                    "{} to {} src not pinned: [{route_line}]",
                    z.name, m.name
                ));
            }
        }
    }
    Ok(())
}

/// Return-path rules per zone; a gw zone's table must hold the engine's default, its leg must carry
/// the address, and the router must be peering.
fn return_path_and_ingress(
    sys: &mut dyn Sys,
    view: &View,
    doc: Option<&Value>,
    c: &mut Ctx,
) -> Result<()> {
    let f = view.fabric;
    let n = view.node();
    for z in &f.zones {
        let blk = format!("{}.0.0/16", z.block());
        let id = z.id.to_string();
        let r2000 = sys.run(&["ip", "rule", "show", "pref", "2000"])?.stdout;
        if !r2000.contains(&format!(
            "from {blk} to {blk} lookup main suppress_prefixlength 0"
        )) {
            c.note(format!(
                "return path missing: pref 2000 from {blk} to {blk} lookup main \
                 suppress_prefixlength 0"
            ));
        }
        let r2001 = sys.run(&["ip", "rule", "show", "pref", "2001"])?.stdout;
        if !r2001
            .lines()
            .any(|l| l.trim_end().ends_with(&format!("from {blk} lookup {id}")))
        {
            c.note(format!(
                "return path missing: pref 2001 from {blk} lookup {id}"
            ));
        }
        let r2002 = sys.run(&["ip", "rule", "show", "pref", "2002"])?.stdout;
        if !r2002.contains(&format!("from {blk} unreachable")) {
            c.note(format!(
                "return path missing: pref 2002 from {blk} unreachable"
            ));
        }
        let Some(gw) = &z.gw else { continue };
        let table = sys.run(&["ip", "route", "show", "table", &id])?.stdout;
        if !table.lines().any(|l| l.starts_with("default ")) {
            c.note(format!(
                "{} gw {} unreachable (table {id} has no default)",
                z.name, gw.router
            ));
        }
        // ingress leg + session (members carrying the leg): the router must be peering, else
        // the outside cannot reach this zone's identities
        let Some(leg) = view.gw_rows().into_iter().find(|r| r.zone == z.name) else {
            continue;
        };
        let cidr = gw.leg_cidr(n);
        let addr = sys
            .run(&["ip", "-4", "-br", "addr", "show", "dev", &leg.ifname])?
            .stdout;
        if !addr.contains(&format!(" {cidr}")) {
            c.note(format!(
                "{} ingress leg {} missing or not {cidr}",
                z.name, leg.ifname
            ));
        }
        let Some(doc) = doc else { continue };
        let state = doc["bgp"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|n| n["peer"] == gw.router.as_str())
            .and_then(|n| n["state"].as_str())
            .unwrap_or("absent")
            .to_string();
        if state != "Established" {
            c.note(format!("{} ingress: bgp {} {state}", z.name, gw.router));
        }
    }
    Ok(())
}

fn mark_drift(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    // Host only: a leaf marks nothing. The DSCP plane is a queueing switch's actual isolation
    // mechanism, so drift is worth a line.
    if view.kind() != MemberKind::Host {
        return Ok(());
    }
    let f = view.fabric;
    let want = emit::mark::generate(view)?;
    let loaded = sys
        .read(&format!("{}/mark.nft", f.run_dir))
        .unwrap_or_default();
    if want != loaded {
        c.note("mark drift — re-run cfab up");
    }
    let live = sys.run(&["nft", "-s", "list", "table", "inet", "cfab"])?;
    let applied = sys
        .read(&format!("{}/mark.applied", f.run_dir))
        .unwrap_or_default();
    if !live.ok() || live.stdout != applied {
        c.note("mark drift — re-run cfab up");
    }
    Ok(())
}

/// The daemon must be alive, and every wire with carrier must carry exactly the tree the shape
/// derivation gives for the current up-set. A wire without carrier may hold a stale tree
/// (left alone).
fn shape_posture(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    if view.kind() != MemberKind::Host {
        return Ok(());
    }
    if !sys
        .run(&["systemctl", "is-active", "-q", "cfab-shape.service"])?
        .ok()
    {
        c.note("shaping down: cfab-shape.service not active");
    }
    let wires = view.wires();
    let carrier_up: Vec<bool> = wires
        .iter()
        .map(|w| {
            sys.read(&format!("/sys/class/net/{w}/carrier"))
                .map(|s| s.trim() == "1")
                .unwrap_or(false)
        })
        .collect();
    for (dev, up_now) in wires.iter().zip(&carrier_up) {
        if !up_now {
            continue;
        }
        let measured = read_cap(sys, view, dev);
        let carrier = |w: &str| {
            sys.read(&format!("/sys/class/net/{w}/carrier"))
                .map(|s| s.trim() == "1")
                .unwrap_or(true)
        };
        let derivation = match emit::shape::derive(view, dev, measured, &carrier) {
            Ok(d) => d,
            Err(e) => {
                c.note(format!("shape derivation for {dev} failed: {e}"));
                continue;
            }
        };
        let live = sys.run(&["tc", "class", "show", "dev", dev])?.stdout;
        for b in &derivation.bands {
            let want = if b.eff >= 1000 && b.eff % 1000 == 0 {
                format!("rate {}Gbit", b.eff / 1000)
            } else if b.eff >= 1 {
                format!("rate {}Mbit", b.eff)
            } else {
                "rate 1Kbit".to_string()
            };
            let cid = format!("1:{}", b.minor);
            let hit = live.lines().any(|l| {
                l.contains(&format!("class htb {cid} ")) && l.contains(&format!(" {want} "))
            });
            if !hit {
                c.note(format!("shape drift on {dev}: class {cid} want {want}"));
            }
        }
    }
    Ok(())
}

fn link_speeds(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    for wire in view.wires() {
        let decl = view.link_speed(&wire)?.to_string();
        let obs = sys
            .read(&format!("/sys/class/net/{wire}/speed"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "-1".to_string());
        let carrier = sys
            .read(&format!("/sys/class/net/{wire}/carrier"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if carrier && obs != decl {
            let drv = sys.run(&["ethtool", "-i", &wire])?.stdout;
            let driver = drv
                .lines()
                .find_map(|l| l.strip_prefix("driver:"))
                .map(str::trim)
                .unwrap_or("?");
            c.note(format!(
                "{wire}: link speed {obs} != declared {decl} (driver {driver})"
            ));
        }
    }
    Ok(())
}

/// `ip route get <target>` → (the `dev` it leaves by, the whole first line). The line is
/// carried back with the device because every caller quotes it in the reason it reports.
fn route_dev(sys: &mut dyn Sys, target: &str) -> Result<(String, String)> {
    let route = sys.run(&["ip", "route", "get", target])?.stdout;
    let route_line = route.lines().next().unwrap_or("").trim().to_string();
    let words: Vec<&str> = route_line.split_whitespace().collect();
    let dev = words
        .iter()
        .position(|w| *w == "dev")
        .and_then(|i| words.get(i + 1))
        .map(|s| s.to_string())
        .unwrap_or_default();
    Ok((dev, route_line))
}

/// Each condition is named once and the lines are sorted: a zone with two down peers pushes its
/// line per peer, and this output is read by humans, scripts and agents alike.
fn once_each(reasons: &[String]) -> Vec<String> {
    let mut sorted: Vec<String> = reasons.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
}

/// `counter packets N bytes M … comment "<name>"` → N.
fn counter_packets(chain: &str, comment: &str) -> Option<u64> {
    let line = chain
        .lines()
        .find(|l| l.contains(&format!("comment \"{comment}\"")))?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let i = words.iter().position(|w| *w == "packets")?;
    words.get(i + 1)?.parse().ok()
}

/// The cap the shape derivation prefers over the declared link speed: the shared chain (local
/// cap file → cluster-published cap, cached back locally → declared).
fn read_cap(sys: &mut dyn Sys, view: &View, dev: &str) -> Option<u64> {
    crate::caps::read_cap(
        sys,
        &crate::cluster::Pmxcfs::new(),
        &view.member.name,
        &view.fabric.run_dir,
        dev,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// The engine's state document as `engine::state::document` shapes it: every instance
    /// healthy with transit links at the leaf offset, one BFD session per (peer, state), and
    /// every peer that carries the zone's fallback row adjacent on the fallback bond.
    fn engine_value(view: &View, bfd: &[(String, &str)]) -> serde_json::Value {
        let f = view.fabric;
        let mut doc = engine_ctl::tests::healthy_doc(view);
        doc["bfd"] = bfd
            .iter()
            .map(|(peer, state)| {
                serde_json::json!({
                    "local": null, "peer": peer, "if": "cfab-x", "state": state,
                    "rx_us": 300000, "tx_us": 300000, "mult": 3
                })
            })
            .collect();
        for r in view.fallback_rows() {
            let z = f.zone(&r.zone).unwrap();
            let nbrs: Vec<serde_json::Value> = f
                .members
                .iter()
                .filter(|m| m.name != view.member.name)
                .filter(|m| {
                    crate::derive::fallback_rows_of(f, m)
                        .iter()
                        .any(|p| p.zone == r.zone)
                })
                .map(|m| {
                    serde_json::json!({
                        "router_id": format!("{}.0.{}", z.block(), m.node),
                        "addr": format!("{}.{}.{}", z.block(), r.seg, m.node),
                        "state": "full",
                    })
                })
                .collect();
            doc["ospf"][&r.zone]["interfaces"][&r.ifname]["neighbors"] =
                serde_json::Value::Array(nbrs);
        }
        doc
    }

    fn engine_doc(view: &View, bfd: &[(String, &str)]) -> String {
        engine_value(view, bfd).to_string()
    }

    /// The `bonding/` sysfs a live active-backup bond exposes, captured from the spike
    /// container (`cat /sys/class/net/cfab-st-fb/bonding/{mii_status,active_slave}` →
    /// `up` / `cfab-st-fb-st`), plus the L3 posture `up` sets on the bond itself.
    fn fallback_sysfs(mut sys: MockSys, view: &View, forwarding: &str) -> MockSys {
        for r in view.fallback_rows() {
            let home = r
                .slaves
                .iter()
                .find(|s| s.wire == r.home)
                .expect("the home wire is one of the slaves");
            sys = sys
                .file(
                    &format!("/sys/class/net/{}/bonding/mii_status", r.ifname),
                    "up\n",
                )
                .file(
                    &format!("/sys/class/net/{}/bonding/active_slave", r.ifname),
                    &format!("{}\n", home.ifname),
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", r.ifname),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                    forwarding,
                );
        }
        sys
    }

    /// A leaf's healthy environment: the run dir (the intent marker `up` creates), posture
    /// sysctls on every segment, the fallback bonds and the identity veths, the leak-guard and
    /// return-path rules, and the gw zone's learned default. Each test adds the engine state
    /// and the routes it wants to prove.
    fn leaf_env(view: &View) -> MockSys {
        let f = view.fabric;
        let mut sys = MockSys::default().file(&f.run_dir, "");
        for r in view.class_rows() {
            sys = sys
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", r.ifname),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                    "0\n",
                );
        }
        for z in &f.zones {
            let id = View::identity_if(z);
            sys = sys
                .file(&format!("/proc/sys/net/ipv4/conf/{id}/forwarding"), "0\n")
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{id}-peer/forwarding"),
                    "0\n",
                );
        }
        sys = fallback_sysfs(sys, view, "0\n");
        sys
            .on_stdout(&["ip", "rule", "show", "pref", "1000"],
                "1000: from all to 10.99.0.0/16 iif lo lookup main\n1000: from all to 10.199.0.0/16 iif lo lookup main\n1000: from all to 10.249.0.0/16 iif lo lookup main\n")
            .on_stdout(&["ip", "rule", "show", "pref", "1001"],
                "1001: from all to 10.99.0.0/16 unreachable\n1001: from all to 10.199.0.0/16 unreachable\n1001: from all to 10.249.0.0/16 unreachable\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2000"],
                "2000: from 10.99.0.0/16 to 10.99.0.0/16 lookup main suppress_prefixlength 0\n2000: from 10.199.0.0/16 to 10.199.0.0/16 lookup main suppress_prefixlength 0\n2000: from 10.249.0.0/16 to 10.249.0.0/16 lookup main suppress_prefixlength 0\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2001"],
                "2001: from 10.99.0.0/16 lookup 99\n2001: from 10.199.0.0/16 lookup 199\n2001: from 10.249.0.0/16 lookup 249\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2002"],
                "2002: from 10.99.0.0/16 unreachable\n2002: from 10.199.0.0/16 unreachable\n2002: from 10.249.0.0/16 unreachable\n")
            // gw zone (mgmt): the leaf learns the ingress default via OSPF from the hosts
            .on_stdout(&["ip", "route", "show", "table", "249"],
                "default via 10.249.3.1 dev cfab-mg proto ospf metric 20\n")
    }

    /// Every expected BFD session, up.
    fn all_bfd_up(f: &Fabric) -> Vec<(String, &'static str)> {
        let mut bfd = Vec::new();
        for p in [1u8, 2u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    bfd.push((format!("{}.{seg}.{p}", z.block()), "up"));
                }
            }
        }
        bfd
    }

    /// Each peer identity reached over the zone's primary segment with a pinned src.
    fn primary_routes(mut sys: MockSys, view: &View) -> MockSys {
        for p in [1u8, 2u8] {
            for z in &view.fabric.zones {
                let prim = view
                    .class_rows()
                    .into_iter()
                    .filter(|r| r.zone == z.name)
                    .min_by_key(|r| r.ospf_cost)
                    .unwrap()
                    .ifname;
                sys = sys.on_stdout(
                    &["ip", "route", "get", &format!("{}.0.{p}", z.block())],
                    &format!(
                        "{}.0.{p} via {}.1.{p} dev {prim} src {}.0.3 uid 0\n",
                        z.block(),
                        z.block(),
                        z.block()
                    ),
                );
            }
        }
        sys
    }

    /// The healthy leaf, ready to run: every posture file, every route, every session up.
    fn healthy_leaf(view: &View) -> MockSys {
        let f = view.fabric;
        primary_routes(leaf_env(view), view)
            .socket("/run/cfab/engine.sock", &engine_doc(view, &all_bfd_up(f)))
    }

    /// A forwarding host's healthy environment. The host arm of `posture` is the widest
    /// surface `status` touches — policy and mark drift, nft counters, shaping, link speeds —
    /// so the never-writes invariant is only worth something if it runs over this too.
    fn host_env(view: &View) -> MockSys {
        let f = view.fabric;
        let mut sys = MockSys::default().file(&f.run_dir, "");
        for r in view.class_rows() {
            sys = sys
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", r.ifname),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                    "1\n",
                );
        }
        for r in view.fallback_rows() {
            let home = r
                .slaves
                .iter()
                .find(|s| s.wire == r.home)
                .expect("the home wire is one of the slaves");
            sys = sys
                .file(
                    &format!("/sys/class/net/{}/bonding/mii_status", r.ifname),
                    "up\n",
                )
                .file(
                    &format!("/sys/class/net/{}/bonding/active_slave", r.ifname),
                    &format!("{}\n", home.ifname),
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", r.ifname),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                    "1\n",
                );
        }
        for r in view.gw_rows() {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                "1\n",
            );
        }
        for s in view.fallback_rows().into_iter().flat_map(|r| r.slaves) {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", s.ifname),
                "0\n",
            );
        }
        for w in view.wires() {
            sys = sys
                .file(&format!("/sys/class/net/{w}/carrier"), "1\n")
                .file(
                    &format!("/sys/class/net/{w}/speed"),
                    &format!("{}\n", view.link_speed(&w).unwrap()),
                );
        }
        sys = sys
            .file("/proc/sys/net/ipv4/conf/eth0/forwarding", "0\n")
            .file(
                &format!("{}/policy.nft", f.run_dir),
                &crate::emit::policy::generate(view).unwrap(),
            )
            .file(
                &format!("{}/policy.applied", f.run_dir),
                "table inet cfab-fwd\n",
            )
            .file(
                &format!("{}/mark.nft", f.run_dir),
                &crate::emit::mark::generate(view).unwrap(),
            )
            .file(&format!("{}/mark.applied", f.run_dir), "table inet cfab\n");
        sys.on_stdout(
            &["nft", "-s", "list", "table", "inet", "cfab-fwd"],
            "table inet cfab-fwd\n",
        )
        .on_stdout(&["nft", "-s", "list", "table", "inet", "cfab"], "table inet cfab\n")
        .on_stdout(
            &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
            "chain forward {\n  type filter hook forward priority filter; policy drop;\n               iifname @admin counter packets 0 bytes 0 drop comment \"admin-in\"\n               oifname @admin counter packets 0 bytes 0 drop comment \"admin-out\"\n               counter packets 0 bytes 0 comment \"default-deny\"\n}",
        )
        .on_stdout(
            &["nft", "-j", "list", "chains"],
            r#"{"nftables":[{"chain":{"family":"inet","table":"cfab-fwd","name":"forward","hook":"forward","prio":0,"policy":"drop"}}]}"#,
        )
        .on_stdout(&["ip", "rule", "show", "pref", "2000"],
            "2000: from 10.99.0.0/16 to 10.99.0.0/16 lookup main suppress_prefixlength 0\n2000: from 10.199.0.0/16 to 10.199.0.0/16 lookup main suppress_prefixlength 0\n2000: from 10.249.0.0/16 to 10.249.0.0/16 lookup main suppress_prefixlength 0\n")
        .on_stdout(&["ip", "rule", "show", "pref", "2001"],
            "2001: from 10.99.0.0/16 lookup 99\n2001: from 10.199.0.0/16 lookup 199\n2001: from 10.249.0.0/16 lookup 249\n")
        .on_stdout(&["ip", "rule", "show", "pref", "2002"],
            "2002: from 10.99.0.0/16 unreachable\n2002: from 10.199.0.0/16 unreachable\n2002: from 10.249.0.0/16 unreachable\n")
        .on_stdout(&["ip", "route", "show", "table", "249"],
            "default via 10.249.3.1 dev cfab-mg proto ospf metric 20\n")
    }

    fn headline(report: &StatusReport) -> &str {
        report.output.lines().next().unwrap_or("")
    }

    /// Every argv `status` is allowed to run, and the one socket request. This list is the
    /// invariant's teeth: `MockSys` records writes, mkdirs, removes, renames and spawns in
    /// `calls` too, so anything that is not on it fails the test by name.
    fn is_read_only(call: &str) -> bool {
        const ALLOWED: &[&str] = &[
            "ip route get ",
            "ip route show table ",
            "ip rule show pref ",
            "ip -4 -br addr show dev ",
            "nft list ",
            "nft -s list ",
            "nft -j list ",
            "systemctl is-active ",
            "systemctl is-enabled ",
            "tc class show dev ",
            "ethtool -i ",
        ];
        (call.starts_with("unix_request ") && call.trim_end().ends_with(" state"))
            || ALLOWED.iter().any(|p| call.starts_with(p))
    }

    /// One `status` run over one fixture: nothing in `MockSys.files` may change, and every
    /// call must be on the read-only allowlist.
    fn assert_never_writes(label: &str, sys: &mut MockSys, view: &View, wait: u64) {
        let before = sys.files.clone();
        let report = run(sys, view, wait, false).unwrap();
        let changed: BTreeSet<&String> = before
            .keys()
            .chain(sys.files.keys())
            .filter(|k| before.get(*k) != sys.files.get(*k))
            .collect();
        assert!(
            changed.is_empty(),
            "{label}: status changed {changed:?}\n{}",
            report.output
        );
        for call in &sys.calls {
            assert!(
                is_read_only(call),
                "{label}: status is not read-only: `{call}`"
            );
        }
    }

    /// **Detectors actuate, status reports.** This is the test that gives the split its teeth:
    /// if `status` ever repairs something itself, the two halves start disagreeing about what
    /// the fabric is, and a member can report a posture it only has because reading it created
    /// it. Run over every fixture in this module, healthy and broken, host and leaf.
    #[test]
    fn status_never_writes() {
        let f = fabric();
        let leaf = View::new(&f, "pve3-tb").unwrap();
        let host = View::new(&f, "pve1-tb").unwrap();

        assert_never_writes("healthy leaf", &mut healthy_leaf(&leaf), &leaf, 0);
        assert_never_writes("engine absent (FAILED)", &mut leaf_env(&leaf), &leaf, 0);
        assert_never_writes("no run dir (DOWN)", &mut MockSys::default(), &leaf, 0);
        assert_never_writes(
            "bfd port taken (FAILED)",
            &mut leaf_env(&leaf).file(
                "/run/cfab/engine.log",
                "ERROR bfd: cannot bind udp 0.0.0.0:3784: address in use\n",
            ),
            &leaf,
            0,
        );

        let mut bfd = all_bfd_up(&f);
        bfd[0].1 = "down";
        assert_never_writes(
            "a down BFD session (UP-DEGRADED)",
            &mut primary_routes(leaf_env(&leaf), &leaf)
                .socket("/run/cfab/engine.sock", &engine_doc(&leaf, &bfd)),
            &leaf,
            0,
        );
        // With a deadline: the wait loop must not write on any pass either.
        assert_never_writes(
            "a down BFD session, --wait 6",
            &mut primary_routes(leaf_env(&leaf), &leaf)
                .socket("/run/cfab/engine.sock", &engine_doc(&leaf, &bfd)),
            &leaf,
            6,
        );

        // Every posture condition rows 4/5/6/19 detect: status must REPORT each one and repair
        // none of them — the watchdog owns the repair.
        assert_never_writes(
            "rp_filter drift (row 4)",
            &mut healthy_leaf(&leaf).file("/proc/sys/net/ipv4/conf/cfab-mg-fb/rp_filter", "1\n"),
            &leaf,
            0,
        );
        assert_never_writes(
            "leak guard missing (row 5)",
            &mut healthy_leaf(&leaf).on_stdout(&["ip", "rule", "show", "pref", "1001"], ""),
            &leaf,
            0,
        );
        assert_never_writes(
            "return path missing (row 6)",
            &mut healthy_leaf(&leaf).on_stdout(&["ip", "rule", "show", "pref", "2002"], ""),
            &leaf,
            0,
        );
        assert_never_writes(
            "foreign active slave (row 19)",
            &mut healthy_leaf(&leaf).file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "someone-elses0\n",
            ),
            &leaf,
            0,
        );
        assert_never_writes(
            "bond downed over a foreign slave (row 19, actuated)",
            &mut healthy_leaf(&leaf)
                .file("/sys/class/net/cfab-st-fb/bonding/mii_status", "down\n")
                .file(
                    "/sys/class/net/cfab-st-fb/bonding/active_slave",
                    "someone-elses0\n",
                ),
            &leaf,
            0,
        );
        assert_never_writes(
            "rows 5/6 actuated: the fabric legs are down and the rules are still missing",
            &mut leaf_env(&leaf)
                .on_stdout(&["ip", "rule", "show", "pref", "1001"], "")
                .on_stdout(&["ip", "rule", "show", "pref", "2002"], "")
                .file("/sys/class/net/eth9/carrier", "0\n")
                .file("/sys/class/net/eth1/carrier", "0\n")
                .file("/sys/class/net/eth0/carrier", "0\n"),
            &leaf,
            0,
        );
        assert_never_writes(
            "stuck reselect",
            &mut healthy_leaf(&leaf)
                .file(
                    "/sys/class/net/cfab-st-fb/bonding/active_slave",
                    "cfab-st-fb-mg\n",
                )
                .file("/sys/class/net/eth9/carrier", "1\n"),
            &leaf,
            0,
        );
        assert_never_writes(
            "dark bond",
            &mut healthy_leaf(&leaf)
                .file("/sys/class/net/cfab-cl-fb/bonding/mii_status", "down\n")
                .file("/sys/class/net/cfab-cl-fb/bonding/active_slave", "\n"),
            &leaf,
            0,
        );
        assert_never_writes(
            "a leaf transit link below the offset",
            &mut {
                let mut doc = engine_value(&leaf, &all_bfd_up(&f));
                doc["ospf"]["storage"]["self_lsa_links"][0]["metric"] = serde_json::json!(1);
                primary_routes(leaf_env(&leaf), &leaf)
                    .socket("/run/cfab/engine.sock", &doc.to_string())
            },
            &leaf,
            0,
        );

        // The host arm: policy and mark drift, nft counters, shaping, link speeds, ingress.
        let mut host_sys = host_env(&host);
        for p in [2u8, 3u8] {
            for z in &f.zones {
                host_sys = host_sys.on_stdout(
                    &["ip", "route", "get", &format!("{}.0.{p}", z.block())],
                    &format!(
                        "{}.0.{p} dev cfab-st src {}.0.1 uid 0\n",
                        z.block(),
                        z.block()
                    ),
                );
            }
        }
        assert_never_writes(
            "a forwarding host with drift everywhere",
            &mut host_sys.socket("/run/cfab/engine.sock", &engine_doc(&host, &[])),
            &host,
            0,
        );

        // The runtime-disjoint shape, over the fabric that has no fallback rows at all.
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace("cfab-st-fb  any storage 9 300 fallback 5000\n", "")
                .replace("cfab-cl-fb  any cluster 9 301 fallback 5000\n", "")
                .replace("cfab-mg-fb  any mgmt    9 302 fallback 5000\n", "");
        let nofb = Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap();
        let nofb_view = View::new(&nofb, "pve3-tb").unwrap();
        assert_never_writes(
            "a member declaring no fallback rows",
            &mut healthy_leaf(&nofb_view),
            &nofb_view,
            0,
        );
    }

    #[test]
    fn counter_parse() {
        let chain = "    iifname @admin counter packets 0 bytes 0 drop comment \"admin-in\"\n\
                     counter packets 42 bytes 999 comment \"default-deny\"";
        assert_eq!(counter_packets(chain, "admin-in"), Some(0));
        assert_eq!(counter_packets(chain, "default-deny"), Some(42));
        assert_eq!(counter_packets(chain, "nope"), None);
    }

    #[test]
    fn two_way_is_the_adjacency_bar() {
        for s in ["2-way", "exstart", "exchange", "loading", "full"] {
            assert!(at_least_two_way(s), "{s}");
        }
        for s in ["down", "attempt", "init", "absent", ""] {
            assert!(!at_least_two_way(s), "{s}");
        }
    }

    #[test]
    fn reasons_are_sorted_and_named_once() {
        let r = vec![
            "b".to_string(),
            "a".to_string(),
            "b".to_string(),
            "a".to_string(),
        ];
        assert_eq!(once_each(&r), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn a_healthy_forwarding_host_is_up() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = host_env(&view);
        for p in [2u8, 3u8] {
            for z in &f.zones {
                let prim = view
                    .class_rows()
                    .into_iter()
                    .filter(|r| r.zone == z.name)
                    .min_by_key(|r| r.ospf_cost)
                    .unwrap()
                    .ifname;
                sys = sys.on_stdout(
                    &["ip", "route", "get", &format!("{}.0.{p}", z.block())],
                    &format!(
                        "{}.0.{p} dev {prim} src {}.0.1 uid 0\n",
                        z.block(),
                        z.block()
                    ),
                );
            }
        }
        let mut bfd = Vec::new();
        for p in [2u8, 3u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    bfd.push((format!("{}.{seg}.{p}", z.block()), "up"));
                }
            }
        }
        let mut sys = sys.socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(
            headline(&report),
            "UP (2/2 | 18/18 | 6/6) on pve1-tb (host)"
        );
    }

    /// UP: every link and every fallback available, three fields, exit 0, and — the whole
    /// point of the split — no reason lines at all.
    #[test]
    fn a_healthy_leaf_is_up_with_three_fields() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view);
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(report.code, 0);
        assert_eq!(
            report.output, "UP (2/2 | 18/18 | 6/6) on pve3-tb (leaf)\n",
            "{}",
            report.output
        );
        assert!(sys.slept.is_empty(), "--wait 0 is one instant read");
    }

    /// A BFD-capable daemon on the host is a reason line, never a state: it takes the port at
    /// our next engine restart, but nothing is down yet.
    #[test]
    fn a_second_bfd_daemon_is_a_reason_line_while_we_are_up() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .on_stdout(&["systemctl", "is-enabled", "frr.service"], "enabled\n")
            .file("/proc/812/comm", "bfdd\n")
            .file("/proc/812/status", "Name:\tbfdd\nState:\tS (sleeping)\n")
            // A zombie of the same name holds nothing and must not be reported.
            .file("/proc/813/comm", "bfdd\n")
            .file("/proc/813/status", "Name:\tbfdd\nState:\tZ (zombie)\n");
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "a reason line moves no state");
        assert_eq!(report.code, 0);
        assert!(
            report.output.contains(
                "  bfd udp/3784: another BFD daemon is on this host (frr.service enabled, \
                 bfdd running (pid 812)) — it takes the port at our next engine restart; stop it \
                 (systemctl disable --now frr), or declare a free BFD_PORT on EVERY member\n"
            ),
            "{}",
            report.output
        );
    }

    /// The engine is gone because the port is taken: zero adjacencies is FAILED, and the
    /// doctor's diagnosis rides along as the reason so a dead-because-stolen-port engine is
    /// explained rather than reported as a bare FAILED.
    #[test]
    fn a_lost_bfd_port_is_failed_with_the_diagnosis() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = leaf_env(&view).file(
            "/run/cfab/engine.log",
            "ERROR bfd: cannot bind udp 0.0.0.0:3784: address in use (held by bfdd pid 812)\n",
        );
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Failed, "output:\n{}", report.output);
        assert_eq!(report.code, 2);
        assert_eq!(
            headline(&report),
            "FAILED (0/2 | 0/18 | 0/6) on pve3-tb (leaf)"
        );
        assert!(
            report.output.contains(
                "  bfd udp/3784: the engine is not running and could not bind it — bfd: \
                 cannot bind udp 0.0.0.0:3784: address in use (held by bfdd pid 812)\n"
            ),
            "{}",
            report.output
        );
        assert!(
            report.output.contains(
                "  remedy: stop FRR, which owns bfdd: systemctl disable --now frr; or declare a \
                 free BFD_PORT (now 3784) in fabric.conf on EVERY member — every peer of a \
                 session must use the same port\n"
            ),
            "{}",
            report.output
        );
        // The generic "engine not running" line must NOT also appear: one spelling per
        // condition, and the doctor's is the one that names the cause.
        assert!(
            !report.output.contains("engine not running:"),
            "{}",
            report.output
        );
    }

    /// The engine is simply absent (no port thief): still zero adjacencies, still FAILED, and
    /// the reason names the engine rather than eighteen symptoms of it.
    #[test]
    fn an_absent_engine_is_failed() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = leaf_env(&view);
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Failed, "output:\n{}", report.output);
        assert_eq!(report.code, 2);
        assert_eq!(
            headline(&report),
            "FAILED (0/2 | 0/18 | 0/6) on pve3-tb (leaf)"
        );
        assert!(
            report.output.contains(
                "  engine not running: cfab-engine.service is not answering — re-run cfab up\n"
            ),
            "{}",
            report.output
        );
    }

    /// Pull one segment (dark) → UP-DEGRADED, exit 1, the session named in the one spelling.
    #[test]
    fn a_down_bfd_session_is_up_degraded() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut bfd = Vec::new();
        for p in [1u8, 2u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    let dark = p == 1 && z.name == "storage" && seg == 1;
                    bfd.push((
                        format!("{}.{seg}.{p}", z.block()),
                        if dark { "down" } else { "up" },
                    ));
                }
            }
        }
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(
            report.state,
            State::UpDegraded,
            "output:\n{}",
            report.output
        );
        assert_eq!(report.code, 1);
        assert_eq!(
            headline(&report),
            "UP-DEGRADED (2/2 | 17/18 | 6/6) on pve3-tb (leaf)"
        );
        assert!(
            report.output.contains("  down storage:1:.1\n"),
            "{}",
            report.output
        );
    }

    /// A fallback neighbor below the bar is the same grade on the third field: the island-
    /// disjoint safety net is gone for that peer even though every BFD session is up.
    #[test]
    fn a_down_fallback_neighbor_is_up_degraded() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_value(&view, &all_bfd_up(&f));
        doc["ospf"]["storage"]["interfaces"]["cfab-st-fb"]["neighbors"] = serde_json::json!([
            { "router_id": "10.99.0.2", "addr": "10.99.9.2", "state": "2-way" },
            { "router_id": "10.99.0.1", "addr": "10.99.9.1", "state": "ietf-ospf:init" }
        ]);
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(
            report.state,
            State::UpDegraded,
            "output:\n{}",
            report.output
        );
        assert_eq!(report.code, 1);
        assert_eq!(
            headline(&report),
            "UP-DEGRADED (2/2 | 18/18 | 5/6) on pve3-tb (leaf)"
        );
        assert!(
            report.output.contains("  down storage:fallback:.1\n"),
            "{}",
            report.output
        );
        // 2-Way itself clears the bar.
        assert!(
            !report.output.contains("down storage:fallback:.2"),
            "{}",
            report.output
        );
    }

    /// Intent: no run dir = `down` was run (or `up` never was). DOWN, exit 3, and nothing is
    /// read from the host at all — there is no fabric to describe.
    #[test]
    fn no_run_dir_is_down() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = MockSys::default();
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Down);
        assert_eq!(report.code, 3);
        assert_eq!(
            report.output,
            "DOWN (fabric not applied) on pve3-tb (leaf)\n"
        );
        assert!(sys.calls.is_empty(), "{:?}", sys.calls);
    }

    /// `--permissive` maps UP and UP-DEGRADED to 0 and leaves FAILED and DOWN exactly where
    /// they are: it hides a degradation, never an outage.
    #[test]
    fn permissive_spares_degraded_and_never_failed_or_down() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();

        let mut sys = healthy_leaf(&view);
        assert_eq!(run(&mut sys, &view, 0, true).unwrap().code, 0);

        let mut bfd = all_bfd_up(&f);
        bfd[0].1 = "down";
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        let r = run(&mut sys, &view, 0, true).unwrap();
        assert_eq!(r.state, State::UpDegraded, "{}", r.output);
        assert_eq!(r.code, 0, "--permissive: UP-DEGRADED exits 0");

        let mut sys = leaf_env(&view);
        let r = run(&mut sys, &view, 0, true).unwrap();
        assert_eq!(r.state, State::Failed);
        assert_eq!(r.code, 2, "--permissive never masks FAILED");

        let mut sys = MockSys::default();
        let r = run(&mut sys, &view, 0, true).unwrap();
        assert_eq!(r.state, State::Down);
        assert_eq!(r.code, 3, "--permissive never masks DOWN");
    }

    /// A member that declares no fallback rows still prints all three fields — `0/0`, so the
    /// line has one shape everywhere and a reader never has to count separators.
    #[test]
    fn a_member_with_no_fallback_rows_prints_zero_of_zero() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace("cfab-st-fb  any storage 9 300 fallback 5000\n", "")
                .replace("cfab-cl-fb  any cluster 9 301 fallback 5000\n", "")
                .replace("cfab-mg-fb  any mgmt    9 302 fallback 5000\n", "");
        let f = Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap();
        let view = View::new(&f, "pve3-tb").unwrap();
        assert!(view.fallback_rows().is_empty());
        let mut sys = healthy_leaf(&view);
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(
            headline(&report),
            "UP (2/2 | 18/18 | 0/0) on pve3-tb (leaf)"
        );
    }

    /// `--wait <s>` re-reads every 2 s until UP, then reports — no "not converged" verdict.
    #[test]
    fn wait_re_reads_every_two_seconds_until_up() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut bfd = all_bfd_up(&f);
        bfd[0].1 = "down";
        let degraded = engine_doc(&view, &bfd);
        let up = engine_doc(&view, &all_bfd_up(&f));
        // The doctor and the count each read the socket once per pass, so a pass consumes two
        // replies; the last reply repeats forever.
        let mut sys = primary_routes(leaf_env(&view), &view).socket_seq(
            "/run/cfab/engine.sock",
            &[degraded.clone(), degraded, up.clone(), up],
        );
        let report = run(&mut sys, &view, 30, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(
            sys.slept,
            vec![Duration::from_secs(2)],
            "one 2 s sleep between the two passes"
        );
    }

    /// FAILED does not end the wait either: a fabric coming up passes through it, so ending
    /// early there would report the state of a fabric that had not finished starting.
    #[test]
    fn wait_does_not_short_circuit_on_failed() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = leaf_env(&view);
        let report = run(&mut sys, &view, 6, false).unwrap();
        assert_eq!(report.state, State::Failed, "{}", report.output);
        assert_eq!(sys.slept.len(), 3, "6 s in 2 s steps: FAILED waited it out");
    }

    /// DOWN does short-circuit: there is no intent, so there is nothing to wait for.
    #[test]
    fn wait_short_circuits_on_down() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = MockSys::default();
        let report = run(&mut sys, &view, 600, false).unwrap();
        assert_eq!(report.state, State::Down);
        assert!(sys.slept.is_empty(), "DOWN never waits");
    }

    /// The wait is for the post-`up` settle, not a verdict: a member that stays degraded waits
    /// the whole deadline and then reports the state it reached.
    #[test]
    fn wait_runs_to_the_deadline_on_a_degraded_member() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut bfd = all_bfd_up(&f);
        bfd[0].1 = "down";
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        let report = run(&mut sys, &view, 6, false).unwrap();
        assert_eq!(report.state, State::UpDegraded, "{}", report.output);
        assert_eq!(sys.slept.len(), 3, "6 s in 2 s steps");
    }

    /// The bond is active on a wire that is not the home while the home still has carrier — a
    /// stuck reselect. Ruled a warn: it is a reason line, and the state does not move.
    #[test]
    fn a_stuck_reselect_is_a_reason_line_not_a_state() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            // storage homes on eth9 (cfab-st, cost 10); the bond sits on the mg slave
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "cfab-st-fb-mg\n",
            )
            .file("/sys/class/net/eth9/carrier", "1\n");
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  fallback storage via eth0 (home eth9 has carrier)\n"),
            "{}",
            report.output
        );
    }

    /// The same reselect with the home wire dark: the bond did exactly its job, so the line is
    /// the plain spelling.
    #[test]
    fn a_backup_wire_with_a_dark_home_gets_the_plain_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "cfab-st-fb-mg\n",
            )
            .file("/sys/class/net/eth9/carrier", "0\n");
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report.output.contains("  fallback storage via eth0\n"),
            "{}",
            report.output
        );
    }

    /// The same reselect with the home wire's carrier unreadable (the file returns EINVAL on a
    /// down interface). Unreadable is never quietly healthy: its own spelling.
    #[test]
    fn an_unreadable_home_carrier_gets_its_own_spelling() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        // no /sys/class/net/eth9/carrier at all — the read fails
        let mut sys = healthy_leaf(&view).file(
            "/sys/class/net/cfab-st-fb/bonding/active_slave",
            "cfab-st-fb-mg\n",
        );
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert!(
            report
                .output
                .contains("  fallback storage via eth0 (home eth9 carrier unreadable)\n"),
            "{}",
            report.output
        );
    }

    /// Every slave dark: one spelling, `fallback <zone> no carrier`.
    #[test]
    fn a_dark_fallback_bond_says_no_carrier() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file("/sys/class/net/cfab-cl-fb/bonding/mii_status", "down\n")
            .file("/sys/class/net/cfab-cl-fb/bonding/active_slave", "\n");
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert!(
            report.output.contains("  fallback cluster no carrier\n"),
            "{}",
            report.output
        );
    }

    /// Row 19's actuated end: a bond cfab owns is down with a stranger still enslaved in it.
    /// That reads exactly like a dark bond, and "no carrier" would send an operator to the
    /// wrong end of the cable. The line reports what was READ — `status` cannot know whether
    /// the watchdog ever tried to evict the intruder, and on a leaf it is not even scheduled.
    #[test]
    fn a_bond_downed_over_a_foreign_slave_says_so_not_no_carrier() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file("/sys/class/net/cfab-st-fb/bonding/mii_status", "down\n")
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "someone-elses0\n",
            );
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert!(
            report
                .output
                .contains("  fallback storage down with foreign slave someone-elses0 active\n"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("fallback storage no carrier"),
            "{}",
            report.output
        );
    }

    /// An interface the engine does not carry yields `Null` where its neighbors should be, and
    /// `Null` reads as an empty list — every declared peer would be reported absent, naming the
    /// wrong fault. Name the real one, and still count those legs unavailable.
    #[test]
    fn a_fallback_interface_absent_from_the_engine_state_is_named() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_value(&view, &all_bfd_up(&f));
        doc["ospf"]["storage"]["interfaces"]
            .as_object_mut()
            .unwrap()
            .remove("cfab-st-fb");
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(
            headline(&report),
            "UP-DEGRADED (2/2 | 18/18 | 4/6) on pve3-tb (leaf)"
        );
        assert!(
            report.output.contains(
                "  fallback storage: cfab-st-fb is missing from the engine's ospf state \
                 (its neighbors cannot be read) — re-run cfab up\n"
            ),
            "{}",
            report.output
        );
    }

    /// Two peers gone from the same fallback LAN: one line each, named by node, and the third
    /// field carries the count.
    #[test]
    fn two_gone_fallback_peers_get_a_line_each() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_value(&view, &all_bfd_up(&f));
        doc["ospf"]["storage"]["interfaces"]["cfab-st-fb"]["neighbors"] = serde_json::json!([]);
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(
            headline(&report),
            "UP-DEGRADED (2/2 | 18/18 | 4/6) on pve3-tb (leaf)"
        );
        for n in [1, 2] {
            assert!(
                report
                    .output
                    .contains(&format!("  down storage:fallback:.{n}\n")),
                "{}",
                report.output
            );
        }
    }

    /// The never-a-transit check must hold the fallback bond to the EXACT offset too: the bond
    /// advertises from `10.<id>.9.<node>`, which no class row owns, so a fallback-blind check
    /// silently falls back to the weaker "at least the offset" arm and lets a wrong metric
    /// through. 5000 + 30000 = 35000 is the only acceptable value. A wrong cost cannot be
    /// repaired by amputation, so it is a reason line and the state stays UP.
    #[test]
    fn a_leafs_fallback_transit_link_is_held_to_the_exact_offset() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_value(&view, &all_bfd_up(&f));
        let fallback_addr = view.segment_addr(f.zone("storage").unwrap(), 9);
        let links = doc["ospf"]["storage"]["self_lsa_links"]
            .as_array_mut()
            .unwrap();
        let link = links
            .iter_mut()
            .find(|l| l["if"] == fallback_addr.as_str())
            .expect("the fallback bond advertises a transit link");
        // Above LEAF_COST_OFFSET, so the weak arm accepts it; not cost + offset, so the
        // exact arm must not.
        link["metric"] = serde_json::json!(31000);
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "a wrong cost never amputates");
        assert!(
            report.output.contains(
                "  ospf 99: a transit link in our router LSA is advertised below \
                 LEAF_COST_OFFSET=30000"
            ),
            "{}",
            report.output
        );
    }

    /// The bond carries L3 and must have the loose rp_filter every cfab interface has. The
    /// watchdog writes it back (row 4); `status` reports it while it is wrong.
    #[test]
    fn a_wrong_rp_filter_is_a_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys =
            healthy_leaf(&view).file("/proc/sys/net/ipv4/conf/cfab-mg-fb/rp_filter", "1\n");
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  rp_filter cfab-mg-fb=1 (want 2 = loose)\n"),
            "{}",
            report.output
        );
    }

    /// A leaf never transits — on the bond either.
    #[test]
    fn a_leaf_bond_that_forwards_is_a_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys =
            healthy_leaf(&view).file("/proc/sys/net/ipv4/conf/cfab-st-fb/forwarding", "1\n");
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert!(
            report
                .output
                .contains("  cfab-st-fb forwarding!=0 (a leaf never transits)\n"),
            "{}",
            report.output
        );
    }

    /// A missing leak-guard rule is the watchdog's to restore (row 5); `status` names it in the
    /// one spelling and does not move the state.
    #[test]
    fn a_missing_leak_guard_is_a_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).on_stdout(&["ip", "rule", "show", "pref", "1001"], "");
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  leak guard missing: pref 1001 to 10.99.0.0/16 unreachable\n"),
            "{}",
            report.output
        );
    }

    /// A missing return-path rule, same shape.
    #[test]
    fn a_missing_return_path_rule_is_a_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).on_stdout(&["ip", "rule", "show", "pref", "2002"], "");
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  return path missing: pref 2002 from 10.99.0.0/16 unreachable\n"),
            "{}",
            report.output
        );
    }

    /// Two members with no island in common: pve1-tb has only its st wire, pve2-tb only its cl
    /// wire, so they share no segment in any zone. The fallback bond is the only path between
    /// them — and reaching them over it is health.
    fn disjoint_fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace(
                    "pve1-tb 1 host eth9:5000 eth1:1000 eth0:1000",
                    "pve1-tb 1 host eth9:5000 - -",
                )
                .replace(
                    "pve2-tb 2 host eth9:5000 eth1:1000 eth0:1000",
                    "pve2-tb 2 host - eth1:1000 -",
                )
                .replace("USB_NICS=\"pve1-tb:eth9 pve2-tb:eth9\"", "USB_NICS=\"\"");
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// Every declared BFD leg up, as the runtime half of the expectation rule.
    fn all_legs_up(view: &View) -> BTreeSet<(u8, String, u8)> {
        expected_links(view)
            .unwrap()
            .into_iter()
            .map(|(p, z, seg, _)| (p, z, seg))
            .collect()
    }

    /// Every peer adjacent on every zone's fallback bond.
    fn all_two_way(view: &View) -> BTreeSet<(u8, String)> {
        let f = view.fabric;
        f.members
            .iter()
            .filter(|m| m.name != view.member.name)
            .flat_map(|m| f.zones.iter().map(move |z| (m.node, z.name.clone())))
            .collect()
    }

    fn disjoint_routes(devs: [&str; 6]) -> MockSys {
        let mut sys = MockSys::default();
        for (target, dev) in [
            "10.99.0.2",
            "10.199.0.2",
            "10.249.0.2",
            "10.99.0.3",
            "10.199.0.3",
            "10.249.0.3",
        ]
        .iter()
        .zip(devs)
        {
            sys = sys.on_stdout(
                &["ip", "route", "get", target],
                &format!(
                    "{target} dev {dev} src {}.0.1 uid 0\n",
                    &target[..target.len() - 4]
                ),
            );
        }
        sys
    }

    #[test]
    fn an_island_disjoint_peer_is_expected_over_the_fallback_bond() {
        let f = disjoint_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert!(
            segments_of(&f, f.member("pve1-tb").unwrap())
                .intersection(&segments_of(&f, f.member("pve2-tb").unwrap()))
                .next()
                .is_none()
        );
        let mut sys = disjoint_routes([
            // the island-disjoint peer: over the storage/cluster/mgmt fallback bonds
            "cfab-st-fb",
            "cfab-cl-fb",
            "cfab-mg-fb",
            // the peer we do share segments with: over the cheapest shared segment
            "cfab-st",
            "cfab-cl-bk",
            "cfab-mg-b2",
        ]);
        let mut c = Ctx::default();
        reachability(
            &mut sys,
            &view,
            &mut c,
            &all_legs_up(&view),
            &all_two_way(&view),
        )
        .unwrap();
        assert_eq!(
            once_each(&c.reasons),
            vec![
                "cluster to pve2-tb via fallback".to_string(),
                "mgmt to pve2-tb via fallback".to_string(),
                "storage to pve2-tb via fallback".to_string(),
            ]
        );
    }

    #[test]
    fn an_island_disjoint_peer_off_the_fallback_bond_is_named() {
        let f = disjoint_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = disjoint_routes([
            // storage to the disjoint peer leaves over a class segment, not the bond
            "cfab-st",
            "cfab-cl-fb",
            "cfab-mg-fb",
            "cfab-st",
            "cfab-cl-bk",
            "cfab-mg-b2",
        ]);
        let mut c = Ctx::default();
        reachability(
            &mut sys,
            &view,
            &mut c,
            &all_legs_up(&view),
            &all_two_way(&view),
        )
        .unwrap();
        assert!(
            c.reasons
                .contains(&"storage to pve2-tb via cfab-st, expected cfab-st-fb".to_string()),
            "{:?}",
            c.reasons
        );
    }

    /// pve1-tb and pve3-tb sit on the st and mg islands, pve2-tb only on cl: pve2-tb shares no
    /// segment with pve3-tb in any zone, while pve1-tb shares two per zone (so one of them can
    /// go dark without the zone losing its only session).
    fn half_disjoint_fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace(
                    "pve1-tb 1 host eth9:5000 eth1:1000 eth0:1000",
                    "pve1-tb 1 host eth9:5000 - eth0:1000",
                )
                .replace(
                    "pve2-tb 2 host eth9:5000 eth1:1000 eth0:1000",
                    "pve2-tb 2 host - eth1:1000 -",
                )
                .replace(
                    "pve3-tb 3 leaf eth9:10000 eth1:1000 eth0:1000",
                    "pve3-tb 3 leaf eth9:10000 - eth0:1000",
                )
                .replace("USB_NICS=\"pve1-tb:eth9 pve2-tb:eth9\"", "USB_NICS=\"\"");
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// D3, closed. A cable pull makes two members disjoint at RUNTIME while the declaration
    /// still says they share two storage segments. The old rule keyed the expectation on
    /// `segments_of()`, so it expected a segment that no longer carries anything and graded the
    /// fabric's own safety net as a fault. The runtime rule expects the bond, because the bond
    /// is what is up.
    #[test]
    fn a_runtime_disjoint_peer_is_expected_over_the_bond_not_the_declared_segment() {
        let f = half_disjoint_fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        // The declaration still says pve3-tb shares two storage segments with pve1-tb.
        assert_eq!(
            expected_links(&view)
                .unwrap()
                .iter()
                .filter(|(p, z, _, _)| *p == 1 && z == "storage")
                .count(),
            2
        );
        // At runtime both are dark; every other session is up.
        let bfd: Vec<(String, &str)> = [
            ("10.99.1.1", "down"),
            ("10.99.3.1", "down"),
            ("10.199.2.1", "up"),
            ("10.199.3.1", "up"),
            ("10.249.1.1", "up"),
            ("10.249.3.1", "up"),
        ]
        .iter()
        .map(|(a, s)| (a.to_string(), *s))
        .collect();
        let mut sys = leaf_env(&view).socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        for (target, dev) in [
            // storage to pve1-tb now rides the fallback bond; the rest are unchanged
            ("10.99.0.1", "cfab-st-fb"),
            ("10.199.0.1", "cfab-cl-bk"),
            ("10.249.0.1", "cfab-mg"),
            ("10.99.0.2", "cfab-st-fb"),
            ("10.199.0.2", "cfab-cl-fb"),
            ("10.249.0.2", "cfab-mg-fb"),
        ] {
            sys = sys.on_stdout(
                &["ip", "route", "get", target],
                &format!(
                    "{target} dev {dev} src {}.0.3 uid 0\n",
                    &target[..target.len() - 4]
                ),
            );
        }
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(
            report.state,
            State::UpDegraded,
            "output:\n{}",
            report.output
        );
        assert_eq!(report.code, 1);
        assert_eq!(
            headline(&report),
            "UP-DEGRADED (2/2 | 4/6 | 6/6) on pve3-tb (leaf)"
        );
        assert!(
            report
                .output
                .contains("  storage to pve1-tb via fallback\n"),
            "{}",
            report.output
        );
        // The companion assertion: the declaration-keyed rule would have expected a storage
        // segment here and called the working fallback path a fault. Nothing may say that.
        assert!(
            !report
                .output
                .contains("storage to pve1-tb via cfab-st-fb, expected"),
            "the declaration-keyed expectation is back: {}",
            report.output
        );
    }

    /// A leaf that is island-disjoint from one peer: the bond is that peer's expected path in
    /// every zone, and being on it is health — the reason line only appears where it is not.
    #[test]
    fn an_island_disjoint_peer_off_the_bond_is_named_while_a_segment_is_down() {
        let f = half_disjoint_fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        assert!(
            segments_of(&f, view.member)
                .intersection(&segments_of(&f, f.member("pve2-tb").unwrap()))
                .next()
                .is_none(),
            "pve2-tb must be island-disjoint from pve3-tb in every zone"
        );
        // pve1-tb shares two segments per zone; storage seg 1 is dark, the rest up.
        let bfd: Vec<(String, &str)> = [
            ("10.99.1.1", "down"),
            ("10.99.3.1", "up"),
            ("10.199.2.1", "up"),
            ("10.199.3.1", "up"),
            ("10.249.1.1", "up"),
            ("10.249.3.1", "up"),
        ]
        .iter()
        .map(|(a, s)| (a.to_string(), *s))
        .collect();
        let mut sys = leaf_env(&view).socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        for (target, dev) in [
            // the peer we share segments with
            ("10.99.0.1", "cfab-st"),
            ("10.199.0.1", "cfab-cl-bk"),
            ("10.249.0.1", "cfab-mg"),
            // the island-disjoint peer: cluster and mgmt over the bond, storage NOT
            ("10.99.0.2", "cfab-st-b2"),
            ("10.199.0.2", "cfab-cl-fb"),
            ("10.249.0.2", "cfab-mg-fb"),
        ] {
            sys = sys.on_stdout(
                &["ip", "route", "get", target],
                &format!(
                    "{target} dev {dev} src {}.0.3 uid 0\n",
                    &target[..target.len() - 4]
                ),
            );
        }
        let report = run(&mut sys, &view, 0, false).unwrap();
        assert_eq!(
            report.state,
            State::UpDegraded,
            "output:\n{}",
            report.output
        );
        assert_eq!(
            headline(&report),
            "UP-DEGRADED (2/2 | 5/6 | 6/6) on pve3-tb (leaf)"
        );
        assert!(
            report
                .output
                .contains("  storage to pve2-tb via cfab-st-b2, expected cfab-st-fb\n"),
            "{}",
            report.output
        );
        // the other direction, over the same live run
        assert!(
            report
                .output
                .contains("  cluster to pve2-tb via fallback\n"),
            "{}",
            report.output
        );
    }
}
