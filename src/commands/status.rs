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
use crate::derive::{Port, View, segments_of};
use crate::emit;
use crate::emit::ceiling_ipt::Backend as MarkBackend;
use crate::error::Result;
use crate::model::{Fabric, MemberKind};
use crate::supervisor::child::State as CompState;
use crate::supervisor::report::{Component, Components, ProbedLeg, render_line};
use crate::sys::{Output, Sys, run_optional};

/// The re-read cadence of `--wait`.
const POLL_SECS: u64 = 2;

/// The forwarding watchdog ticks every 3 s (spec §5). `status` treats it as not ticking once
/// the last tick is older than this — comfortably past three missed ticks, so a scheduling
/// hiccup on a busy single-vCPU host does not raise a false alarm. This is a reason line, never
/// actuation, so a generous bar is right: a false positive costs an operator a look, a packet
/// never. Chosen, not derived — the tick cadence is a supervisor constant, not a declaration.
const WATCHDOG_STALE_SECS: u64 = 10;

pub mod model;

pub use model::{
    Adjacency, BondLeg, Bonding, Class, Condition, Headline, HomeCarrier, Ingress, LegKind,
    LegPort, MemberInfo, Reach, State, StatusModel,
};

pub struct StatusReport {
    pub state: State,
    /// The process exit code — `state.code()`, or 0 for UP/UP-DEGRADED under `--permissive`.
    pub code: u8,
    pub output: String,
}

/// Reason lines. Not verdicts: a posture condition either actuates (the links go down and the
/// state follows) or lands here, where it never moves the state.
#[derive(Default, Clone)]
struct Ctx {
    reasons: Vec<(Class, String)>,
    /// Every expected adjacency, up or down. The `down <zone>:<seg>:.<node>` lines are rendered
    /// from these rows, never pushed as text.
    adjacencies: Vec<Adjacency>,
    /// One row per zone carrying a fallback bond.
    fallbacks: Vec<BondLeg>,
    /// One row per gw zone on a host.
    ingress: Vec<Ingress>,
}

impl Ctx {
    /// A line the fabric is expected to clear by itself (see `Class::Settling`).
    fn settling(&mut self, msg: impl Into<String>) {
        self.reasons.push((Class::Settling, msg.into()));
    }

    /// A line no amount of waiting changes (see `Class::Standing`).
    fn standing(&mut self, msg: impl Into<String>) {
        self.reasons.push((Class::Standing, msg.into()));
    }

    /// One expected adjacency, with the line a down one earns pushed where the gather found
    /// it. Rendered from the row, so the `down …` spelling has one source.
    fn adjacency(&mut self, a: Adjacency) {
        if !a.up {
            // Settling: an adjacency that is still forming is the state `--wait` exists for.
            self.settling(format!("down {}", a.label()));
        }
        self.adjacencies.push(a);
    }

    /// One zone's fallback leg, with the lines it earns.
    fn fallback_leg(&mut self, leg: BondLeg) {
        self.reasons.extend(leg_reasons(&leg));
        self.fallbacks.push(leg);
    }

    /// The reasons so far, as the model carries them.
    fn conditions(&self) -> Vec<Condition> {
        self.reasons
            .iter()
            .map(|(class, text)| Condition {
                class: *class,
                text: text.clone(),
            })
            .collect()
    }

    /// One gw zone's ingress, with the lines it earns.
    fn ingress(&mut self, row: Ingress) {
        self.reasons.extend(ingress_reasons(&row));
        self.ingress.push(row);
    }
}

impl StatusModel {
    /// Is this fabric still settling? One settling condition is enough: `--wait` exists for
    /// exactly the window in which they are still there.
    pub fn settling(&self) -> bool {
        self.conditions.iter().any(|c| c.class == Class::Settling)
    }
}

/// `declared` is the on-disk declaration to compare the running fabric against — `Some` only
/// when `view.fabric` came from the applied copy in the run dir (finding F9). When status is
/// reading the file itself there is nothing to compare, and this is `None`.
pub fn run(
    sys: &mut dyn Sys,
    view: &View,
    wait_s: u64,
    permissive: bool,
    declared: Option<&std::path::Path>,
) -> Result<StatusReport> {
    // Read once, before the `--wait` loop: the file on disk is not what the loop is waiting for.
    let mut base = Ctx::default();
    if let Some(cfg) = declared
        && let Some(note) = declaration_note(&*sys, view, cfg)
    {
        // Standing: only an operator's edit or a reload changes what this file says.
        base.standing(note);
    }
    let expected = expected_links(view)?;
    let mut t = 0u64;
    loop {
        let m = gather(sys, view, &expected, &base)?;
        // The wait exists for the post-`up` settle, not as a verdict: only a settled UP ends it
        // early. Every other state — degraded, failed, not applied — and every UP that still
        // carries a settling reason line waits the full deadline and then reports what it
        // reached. The headline alone is not enough: it counts sessions, and a member's routes,
        // addresses and source pins arrive after the sessions do (F22).
        if (m.state == State::Up && !m.settling()) || t >= wait_s {
            // No fabric applied: there is nothing to describe and no supervisor to ask, so
            // the always-printed components line is suppressed then alone.
            let with_components = m.headline.is_some();
            return Ok(render_text(&m, permissive, with_components));
        }
        t += POLL_SECS;
        sys.sleep(Duration::from_secs(POLL_SECS));
    }
}

/// One instant read of this member's fabric into the model both renderers consume. `base`
/// carries the reasons that were read once, before the `--wait` loop.
fn gather(
    sys: &mut dyn Sys,
    view: &View,
    expected: &[ExpectedLink],
    base: &Ctx,
) -> Result<StatusModel> {
    let f = view.fabric;
    // Intent: `up` creates the run dir, `down` removes it whole. No run dir = up is not
    // desired *right now* — which a restarting supervisor passes through, so this is
    // re-read on every poll like every other input to the verdict.
    let applied = sys.exists(&f.run_dir);
    let components = applied.then(|| read_components(sys, f)).flatten();
    gather_with(sys, view, expected, base, applied, components)
}

/// One gather without the `--wait` loop and without the `cfab.sock` round trip, for the
/// supervisor: it already holds its own `components` document, and asking itself over its own
/// socket from its own main thread is a deadlock waiting to be written.
// The supervisor's metrics refresh is its only caller and it is not wired yet.
#[allow(dead_code)]
pub(crate) fn snapshot_model(
    sys: &mut dyn Sys,
    view: &View,
    comps: Option<Components>,
) -> Result<StatusModel> {
    let expected = expected_links(view)?;
    let applied = sys.exists(&view.fabric.run_dir);
    gather_with(sys, view, &expected, &Ctx::default(), applied, comps)
}

/// The gather itself, once the `components` document is in hand — from the socket for `status`,
/// from memory for the supervisor. One body, so the two can never describe a member differently.
fn gather_with(
    sys: &mut dyn Sys,
    view: &View,
    expected: &[ExpectedLink],
    base: &Ctx,
    applied: bool,
    components: Option<Components>,
) -> Result<StatusModel> {
    let f = view.fabric;
    let mut c = base.clone();
    let headline = if applied {
        Some(read(sys, view, expected, &mut c, components.as_ref())?)
    } else {
        None
    };
    let conditions = c.conditions();
    Ok(StatusModel {
        member: MemberInfo {
            name: view.member.name.clone(),
            kind: view.kind(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        state: headline.as_ref().map_or(State::Down, Headline::state),
        headline,
        adjacencies: c.adjacencies,
        fallbacks: c.fallbacks,
        ingress: c.ingress,
        conditions,
        components,
        prefs: view.prefs(),
        run_dir: f.run_dir.clone(),
    })
}

/// The fabric the supervisor applied, if it is still on disk: `<run_dir>/fabric.toml.applied`,
/// written by `cfab run` before its initial apply and removed with the run dir by `cfab down`.
/// `None` means nothing is running (or the copy is unreadable), and status falls back to the
/// declared file exactly as it always did.
///
/// `run_dir` lives *inside* the declaration, so finding the copy means knowing the run dir
/// before parsing anything: read `config` for it, and fall back to the packaged default
/// `/run/cfab` when that file is the very thing that will not parse. Both are tried, since a
/// declaration whose `run_dir` was edited since the apply points at the wrong directory. The
/// one case this cannot cover is a member that both moved `run_dir` off the default AND has an
/// unparseable file: nothing on disk can then say where the copy is, and status falls back to
/// today's exit 1. No packaged deployment moves it (only `scripts/engine-oracle.sh`, a test
/// harness, does).
pub fn applied_fabric(sys: &dyn Sys, config: &std::path::Path) -> Option<Fabric> {
    let declared_run_dir = sys
        .read(&config.to_string_lossy())
        .ok()
        .and_then(|t| crate::decl::Declaration::parse(&t).ok())
        .and_then(|d| Fabric::from_decl(&d).ok())
        .map(|f| f.run_dir);
    let mut dirs: Vec<String> = declared_run_dir.into_iter().collect();
    if !dirs.iter().any(|d| d == crate::decl::RUN_DIR) {
        dirs.push(crate::decl::RUN_DIR.to_string());
    }
    dirs.iter()
        .map(|d| crate::applied_decl_path(d))
        .filter_map(|p| sys.read(&p).ok())
        .find_map(|t| {
            crate::decl::Declaration::parse(&t)
                .ok()
                .and_then(|d| Fabric::from_decl(&d).ok())
        })
}

/// The one reason line the on-disk declaration can earn while status describes the applied copy.
/// A reason, never a state (see `Ctx`): the fabric on the wire is whatever it is regardless of
/// what the file now says.
fn declaration_note(sys: &dyn Sys, view: &View, config: &std::path::Path) -> Option<String> {
    let config = config.display().to_string();
    let stale = |why: String| {
        format!(
            "declaration {config}: {why} (status describes the running fabric; a reload of \
             this file will be refused)"
        )
    };
    let text = match sys.read(&config) {
        Ok(t) => t,
        Err(e) => return Some(stale(e.to_string())),
    };
    match crate::supervisor::parse_for_member(&view.member.name, &text) {
        // The `fabric.toml: ` prefix an `Error::Config` carries is redundant once the line has
        // already named the file: print the message the parser gave, line/column and all.
        Err(crate::Error::Config(msg)) => Some(stale(msg)),
        Err(e) => Some(stale(e.to_string())),
        Ok(next) if next == *view.fabric => None,
        Ok(_) => Some(format!(
            "declaration {config} changed since apply (systemctl reload cfab to apply; the \
             fabric will restart)"
        )),
    }
}

/// The `components` document over `<run_dir>/cfab.sock` (spec §9). A read, never a write; the
/// supervisor being absent, slow or unparseable is not a crash — it degrades to `None`, which
/// the engine row and the components line render as "no supervisor answering".
fn read_components(sys: &mut dyn Sys, f: &Fabric) -> Option<Components> {
    let reply = sys
        .unix_request(&format!("{}/cfab.sock", f.run_dir), "components\n")
        .ok()?;
    serde_json::from_str(&reply).ok()
}

/// The engine's socket is silent: say why, in the one spelling the condition earns. With a
/// supervisor answering, quote the child it reports; without one, name the socket and the
/// remedy. The engine is a supervised child now, never its own unit.
fn engine_down_reason(f: &Fabric, comps: Option<&Components>) -> String {
    match comps.and_then(|c| c.components.iter().find(|k| k.name == "engine")) {
        Some(e) => {
            let mut s = format!(
                "engine not running: the supervisor reports it {}, {} restart(s)",
                e.state.as_str(),
                e.restarts
            );
            if let Some(x) = &e.last_exit {
                s.push_str(&format!(", last exit {}", x.cause));
            }
            s
        }
        None => format!(
            "engine not running: no supervisor answering on {}/cfab.sock — start it \
             (systemctl start cfab)",
            f.run_dir
        ),
    }
}

/// The prose renderer: the model in the words `cfab status` has always used.
pub fn render_text(m: &StatusModel, permissive: bool, with_components: bool) -> StatusReport {
    let fields = match &m.headline {
        Some(h) => h.fields(),
        None => "fabric not applied".to_string(),
    };
    let mut out = format!(
        "{} ({fields}) on {} ({})\n",
        m.state.word(),
        m.member.name,
        m.member.kind_word()
    );
    for r in once_each(&m.conditions) {
        // A TOML parse error arrives as several lines (message, then the caret snippet); its
        // continuation lines are indented one step further so the block still reads as one
        // reason under the headline.
        for (i, line) in r.lines().enumerate() {
            let _ = writeln!(out, "{}{line}", if i == 0 { "  " } else { "    " });
        }
    }
    // This member's wire order per zone, with the derived/override marker: the one thing an
    // operator cannot infer from the interface names, and what every OSPF cost below comes
    // from. Same spelling as `cfab gen prefs`, minus the member column.
    for p in &m.prefs {
        let _ = writeln!(out, "  prefs {}", p.render());
    }
    // The one always-printed line (spec §9): last, so the reasons read as a block above it.
    if with_components {
        match &m.components {
            Some(cc) => {
                let _ = writeln!(out, "  {}", render_line(cc));
            }
            None => {
                let _ = writeln!(
                    out,
                    "  components: no supervisor answering on {}/cfab.sock",
                    m.run_dir
                );
            }
        }
    }
    let code = if permissive && matches!(m.state, State::Up | State::UpDegraded) {
        0
    } else {
        m.state.code()
    };
    StatusReport {
        state: m.state,
        code,
        output: out,
    }
}

/// One expected BFD session, as the declaration alone describes it.
struct ExpectedLink {
    node: u8,
    name: String,
    zone: String,
    seg: u8,
    addr: String,
}

/// One BFD session per (zone, segment) shared with each peer, keyed by the peer's segment
/// address — exact for a heterogeneous membership and per session, so a dark segment is named,
/// not just counted. The declaration is the denominator, and it is meant to ignore a cable pull.
fn expected_links(view: &View) -> Result<Vec<ExpectedLink>> {
    let f = view.fabric;
    let host = &view.member.name;
    let mut expected: Vec<ExpectedLink> = Vec::new();
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
            expected.push(ExpectedLink {
                node: m.node,
                name: m.name.clone(),
                zone: z.to_string(),
                seg,
                addr: format!("{}.{seg}.{}", zone.block(), m.node),
            });
        }
    }
    Ok(expected)
}

/// One instant read of everything: the doctor, the posture passes, then the adjacency counts.
fn read(
    sys: &mut dyn Sys,
    view: &View,
    expected: &[ExpectedLink],
    c: &mut Ctx,
    comps: Option<&Components>,
) -> Result<Headline> {
    let f = view.fabric;
    // First: the engine may be gone because another BFD daemon took our port, and every count
    // below needs the engine. Diagnose that before reporting its symptoms.
    bfd_port(sys, view, c, comps)?;
    let doc = engine_ctl::state(sys, f).ok();
    if doc.is_none() {
        // The engine's socket is silent. The supervisor (spec §9) is the authority on why:
        // if it answers, quote the child's state; if it does not, the fault is upstream of
        // the engine and the remedy is to start the service — one spelling each.
        c.settling(engine_down_reason(f, comps));
    }
    let absent = absent_ifs(&*sys, view);
    posture(sys, view, doc.as_ref(), comps, c, &absent)?;
    return_path_and_ingress(sys, view, doc.as_ref(), comps, c, &absent)?;
    mark_drift(sys, view, c)?;
    ceiling_counters(sys, view, c)?;
    shape_posture(sys, view, comps, c)?;
    link_speeds(sys, view, c, &absent)?;

    let mut counts = Headline::default();
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
    for e in expected {
        peers.insert(e.node);
        counts.links += 1;
        let up = up_addrs.contains(&e.addr);
        if up {
            counts.links_up += 1;
            peers_up.insert(e.node);
            up_legs.insert((e.node, e.zone.clone(), e.seg));
        }
        c.adjacency(Adjacency {
            zone: e.zone.clone(),
            seg: Some(e.seg),
            peer_node: e.node,
            peer_name: e.name.clone(),
            peer_addr: Some(e.addr.clone()),
            up,
        });
    }

    // ---- fallbacks: one expected OSPF neighbor per peer carrying the zone's row ----
    let two_way = fallback(
        sys,
        view,
        doc.as_ref(),
        comps,
        c,
        &absent,
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
/// udp/`[bfd] port` exclusively (no SO_REUSEADDR), so a daemon holding the port makes the engine
/// exit at the first session instead of stealing our packets. Measured 2026-09-05: with
/// SO_REUSEADDR on both sides FRR's bfdd and holo both bound 0.0.0.0:3784 and the last binder
/// silently took every packet, either order.
///
/// The question is custody of OUR port, never presence on the host: cfab is designed to run beside
/// FRR by declaring a different `[bfd] port`, and F13 (VERIFIED pve1-tb 2026-09-06, 0.4.1) was
/// this probe calling that supported layout a conflict. So the reason line fires only when a
/// socket is bound on our port and is provably not the engine's own.
fn bfd_port(sys: &mut dyn Sys, view: &View, c: &mut Ctx, comps: Option<&Components>) -> Result<()> {
    let f = view.fabric;
    let port = f.bfd_port;
    let engine = comps.and_then(|c| c.components.iter().find(|k| k.name == "engine"));
    if port_custody(sys, port, c, engine) {
        // One condition, one diagnosis: the live custody read is the more specific account of
        // exactly the fact the bind line reports, and it names a holder that is still there.
        return Ok(());
    }
    // A bind failure in the ring buffer is only news while the engine is gone, and only when the
    // holder has since let go — otherwise the custody probe above already said it. The supervisor
    // is the authority on "gone": no engine component (no supervisor answering — the custody
    // probe already ran and we cannot read the ring) means no scan, and a `running` engine holds
    // the port (nothing else can), so any bind line it left is history. Only an engine the
    // supervisor reports down earns the diagnosis, read from its child ring buffer over cfab.sock
    // (spec §3/§9) — best effort, a silent or unparseable socket just leaves the generic reason.
    let Some(engine) = engine else {
        return Ok(());
    };
    if engine.state == CompState::Running {
        return Ok(());
    }
    let reply = match sys.unix_request(&format!("{}/cfab.sock", f.run_dir), "log engine 200\n") {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    let Ok(doc) = serde_json::from_str::<LogReply>(&reply) else {
        return Ok(());
    };
    let joined = doc.lines.join("\n");
    if let Some(line) = engine_ctl::bfd_bind_error_line(&joined, port) {
        // Standing, both: a port somebody else holds is let go by that somebody, never by
        // waiting — and the second line is this one's remedy.
        c.standing(format!(
            "bfd udp/{port}: the engine is not running and could not bind it — {line}"
        ));
        c.standing(format!(
            "remedy: {}",
            engine_ctl::bfd_bind_remedy(line, port)
        ));
    }
    Ok(())
}

/// The `log <name> [n]` reply over `cfab.sock` (spec §9): the child ring buffer's tail. A parse
/// failure degrades the BFD diagnosis to silence — it is never load-bearing enough to crash.
#[derive(serde::Deserialize)]
struct LogReply {
    lines: Vec<String>,
}

/// Who holds udp/`port` right now, and the reason line if that is not us. Two notes or none —
/// what holds it, then the one spelling of the remedy (`engine_ctl::bfd_port_remedy`) — and
/// `true` when it said something, which stands the ring-buffer diagnosis down.
///
/// Ownership is decided by the least-assuming evidence available, in this order:
///   * a socket on the port whose inode is in a live bfdd's fd table — a named foreign holder,
///     whatever the engine is doing (we are up only until our next restart);
///   * otherwise a socket on the port while the supervisor reports the engine NOT running — the
///     engine cannot be holding a socket it does not have, so it is somebody's, unidentified;
///   * otherwise silence. A running engine binds the port itself, and an engine we cannot ask
///     about (no supervisor answering) leaves us unable to tell its socket from a stranger's —
///     a false conflict is worse than a missed one, because the supported layout produces it.
fn port_custody(sys: &mut dyn Sys, port: u16, c: &mut Ctx, engine: Option<&Component>) -> bool {
    let bound = udp_inodes_on(
        sys,
        port,
        engine.is_some_and(|e| e.state == CompState::Running),
    );
    if bound.is_empty() {
        return false;
    }
    let units = bfd_units(sys);
    let pids = bfdd_pids(sys);
    let holder = pids
        .iter()
        .find(|pid| socket_inodes(sys, pid).iter().any(|i| bound.contains(i)));
    let (what, remedy) = match holder {
        Some(pid) => {
            let mut bits = vec![format!("pid {pid}")];
            bits.extend(units.iter().map(|u| format!("{u}.service enabled")));
            // bfdd.service manages this process directly; frr.service is the coarser handle and
            // may not even own the bfdd we found.
            let handle = match units.iter().find(|u| *u == "bfdd").or(units.first()) {
                Some(u) => engine_ctl::BfdHolder::Unit(u.clone()),
                None => engine_ctl::BfdHolder::Pid(pid.clone()),
            };
            (format!("bfdd ({})", bits.join(", ")), handle)
        }
        // Not bfdd's, and only provably not ours while the engine is down.
        None if engine.is_some_and(|e| e.state != CompState::Running) => (
            "another process".to_string(),
            engine_ctl::BfdHolder::Unknown,
        ),
        None => return false,
    };
    // Standing, both: the holder is another daemon, and the second line is this one's remedy.
    c.standing(format!(
        "bfd udp/{port}: {what} holds this port, which the engine needs exclusively"
    ));
    c.standing(format!(
        "remedy: {}",
        engine_ctl::bfd_port_remedy(&remedy, port)
    ));
    true
}

/// The BFD-capable systemd units enabled here, by base name (`frr`, `bfdd`) — context for a
/// holder we identify, and the handle its remedy names.
fn bfd_units(sys: &mut dyn Sys) -> Vec<String> {
    ["frr", "bfdd"]
        .into_iter()
        .filter(|unit| {
            run_optional(
                sys,
                &["systemctl", "is-enabled", &format!("{unit}.service")],
            )
            .is_some_and(|out| out.stdout.trim() == "enabled")
        })
        .map(str::to_string)
        .collect()
}

/// Every live bfdd on this host. A reaped-but-not-waited bfdd keeps its /proc entry and its name
/// (seen in the container fixture, whose init reaps nothing): a zombie holds no socket.
fn bfdd_pids(sys: &mut dyn Sys) -> Vec<String> {
    sys.list_dir("/proc")
        .unwrap_or_default()
        .into_iter()
        .filter(|pid| pid.chars().all(|ch| ch.is_ascii_digit()))
        .filter(|pid| {
            sys.read(&format!("/proc/{pid}/comm"))
                .is_ok_and(|comm| comm.trim() == "bfdd")
                && !sys
                    .read(&format!("/proc/{pid}/status"))
                    .unwrap_or_default()
                    .contains("State:\tZ")
        })
        .collect()
}

/// The inodes of every UDP socket bound to `port` that could cost the engine the port.
///
/// The engine binds IPv4 only (`engine::bfd_socket_policy`, `ipv6: false`), so the two families
/// are not symmetric. A v6 socket can only ever hurt us by being dual-stack (not `V6ONLY`) and
/// bound BEFORE we are, blocking our IPv4 bind; once our v4 socket is bound it takes every
/// packet we care about and a `[::]` holder beside it is harmless. So the v6 table counts only
/// while the engine is not bound — `engine_bound` drops it once the supervisor says the engine
/// is running.
fn udp_inodes_on(sys: &dyn Sys, port: u16, engine_bound: bool) -> Vec<u64> {
    ["/proc/net/udp", "/proc/net/udp6"]
        .into_iter()
        .filter(|path| !engine_bound || !path.ends_with('6'))
        .filter_map(|path| sys.read(path).ok())
        .flat_map(|table| udp_table_inodes(&table, port))
        .collect()
}

/// Parse one `/proc/net/udp{,6}` table: the port half of the `local_address` column (hex, after
/// the `:`, whatever the address width) and the `inode` column. Anything that does not parse —
/// the header line, a short line — is skipped rather than guessed at.
fn udp_table_inodes(table: &str, port: u16) -> Vec<u64> {
    const INODE_COL: usize = 9;
    table
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let local = f.get(1)?.rsplit_once(':')?.1;
            (u16::from_str_radix(local, 16).ok()? == port)
                .then(|| f.get(INODE_COL)?.parse::<u64>().ok())?
        })
        .collect()
}

/// The socket inodes a process holds, from its fd table (`/proc/<pid>/fd/<n>` →
/// `socket:[<inode>]`). Unreadable (the process exited, or we are not root) is an empty list:
/// an unidentified holder, never a wrong accusation.
fn socket_inodes(sys: &dyn Sys, pid: &str) -> Vec<u64> {
    sys.list_dir(&format!("/proc/{pid}/fd"))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|fd| sys.read_link(&format!("/proc/{pid}/fd/{fd}")).ok())
        .filter_map(|target| {
            target
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}

/// Interfaces that cannot exist right now because the wire under them is gone. A wire can
/// vanish under a running fabric — a USB NIC unplugged, a driver removed — and the kernel takes
/// every path under it away at the same instant: `/sys/class/net/<wire>`,
/// `/proc/sys/net/ipv4/conf/<wire>` and every VLAN leg tagged on it. That is a graded state
/// (the peers still grade this member UP-DEGRADED), never a refusal. One set, so every
/// per-interface read degrades the same way and the wire earns exactly one reason line
/// (`link_speeds`).
///
/// A bond outlives its ports: only the port on a vanished wire goes, never the leg itself.
fn absent_ifs(sys: &dyn Sys, view: &View) -> BTreeSet<String> {
    let wires: BTreeSet<String> = view
        .wires()
        .into_iter()
        .filter(|w| !sys.exists(&format!("/sys/class/net/{w}")))
        .collect();
    let mut out = wires.clone();
    out.extend(
        view.class_rows()
            .into_iter()
            .filter(|r| wires.contains(&r.wire))
            .map(|r| r.ifname),
    );
    for r in view.gw_rows() {
        if r.migrates() {
            out.extend(
                r.ports
                    .into_iter()
                    .filter(|s| wires.contains(&s.wire))
                    .map(|s| s.ifname),
            );
        } else if wires.contains(&r.home) {
            out.insert(r.ifname);
        }
    }
    out.extend(
        view.fallback_rows()
            .into_iter()
            .flat_map(|r| r.ports)
            .filter(|s| wires.contains(&s.wire))
            .map(|s| s.ifname),
    );
    out
}

/// One per-interface sysfs/procfs read. `None` means there is nothing left to check and the
/// condition has already been reported: silently when the interface went with its wire (the
/// wire's own `absent` line is the account of it), otherwise in its own reason line. `status`
/// never fails on a file the kernel can take away underneath it.
fn if_file(
    sys: &dyn Sys,
    c: &mut Ctx,
    absent: &BTreeSet<String>,
    ifname: &str,
    path: &str,
) -> Option<String> {
    if absent.contains(ifname) {
        return None;
    }
    match sys.read(path) {
        Ok(v) => Some(v),
        Err(e) => {
            c.settling(format!("{path} unreadable ({e})"));
            None
        }
    }
}

fn posture(
    sys: &mut dyn Sys,
    view: &View,
    doc: Option<&Value>,
    comps: Option<&Components>,
    c: &mut Ctx,
    absent: &BTreeSet<String>,
) -> Result<()> {
    let f = view.fabric;
    // The fallback bond is a segment here: it carries L3 and takes the same loose rp_filter.
    // Its ports never appear — they are L2 only.
    let l3: Vec<String> = view
        .class_rows()
        .into_iter()
        .map(|r| r.ifname)
        .chain(view.fallback_rows().into_iter().map(|r| r.ifname))
        .collect();
    for ifname in &l3 {
        if absent.contains(ifname) {
            continue;
        }
        let got = sys
            .read(&format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "missing".to_string());
        if got != "2" {
            c.settling(format!("rp_filter {ifname}={got} (want 2 = loose)"));
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
                let Some(v) = if_file(
                    &*sys,
                    c,
                    absent,
                    &ifn,
                    &format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"),
                ) else {
                    continue;
                };
                let v = v.trim();
                if v != "0" {
                    c.settling(format!("{ifn} forwarding!=0 (a leaf never transits)"));
                }
            }
            for z in &f.zones {
                let blk = format!("{}.0.0/16", z.block());
                let r1000 = sys.run(&["ip", "rule", "show", "pref", "1000"])?.stdout;
                if !r1000.contains(&format!("to {blk} iif lo lookup main")) {
                    c.settling(format!(
                        "leak guard missing: pref 1000 to {blk} iif lo lookup main"
                    ));
                }
                let r1001 = sys.run(&["ip", "rule", "show", "pref", "1001"])?.stdout;
                if !r1001.contains(&format!("to {blk} unreachable")) {
                    c.settling(format!(
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
                    c.settling(format!(
                        "ospf {}: a transit link in our router LSA is advertised below \
                         `[cost] leaf_offset`={} (we could be chosen as a transit) — re-run cfab up",
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
                // Standing: a mismatch against generated state, repaired by `up` alone.
                c.standing("policy drift — re-run cfab up");
            }
            let live = sys.run(&["nft", "-s", "list", "table", "inet", "cfab-fwd"])?;
            let applied = sys
                .read(&format!("{}/policy.applied", f.run_dir))
                .unwrap_or_default();
            if !live.ok() || live.stdout != applied {
                c.standing("ruleset drift — re-run cfab up");
            }
            let chain = sys
                .run(&["nft", "list", "chain", "inet", "cfab-fwd", "forward"])?
                .stdout;
            if !chain.contains("policy drop;") {
                c.standing(
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
                // Standing, both: a foreign chain at the forward hook is another package's,
                // and the second line is this one's remedy.
                for b in &blocked {
                    c.standing(format!(
                        "transit blocked by a foreign forward-hook chain: {b}"
                    ));
                }
                c.standing(foreign_forward_remedy(&ifs));
            }
            if !view.admin_ifs().is_empty() {
                let admin = view.admin_ifs().join(" ");
                for counter in ["admin-in", "admin-out"] {
                    match counter_packets(&chain, counter) {
                        Some(0) => {}
                        // Standing: a counter is history, and history does not settle.
                        Some(n) => c.standing(format!(
                            "{counter} counter = {n} (something tried to transit {admin})"
                        )),
                        None => c.standing(format!(
                            "{counter} counter = absent (something tried to transit {admin})"
                        )),
                    }
                }
                for a in view.admin_ifs() {
                    let path = format!("/proc/sys/net/ipv4/conf/{a}/forwarding");
                    if if_file(&*sys, c, absent, a, &path).is_some_and(|v| v.trim() != "0") {
                        c.settling(format!("{a} forwarding=1"));
                    }
                }
            }
            let present = conf_interfaces(sys)?;
            for (ifn, fwd) in view.owned_forwarding() {
                if !present.contains(&ifn) {
                    continue;
                }
                let Some(v) = if_file(
                    &*sys,
                    c,
                    absent,
                    &ifn,
                    &format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"),
                ) else {
                    continue;
                };
                let v = v.trim();
                if fwd && v != "1" {
                    c.settling(format!(
                        "{ifn} forwarding=0 (class-table interface should forward)"
                    ));
                } else if !fwd && v != "0" {
                    c.settling(format!(
                        "{ifn} forwarding=1 (cfab interface that must not transit)"
                    ));
                }
            }
            // The watchdog is a task in the supervisor now (spec §5): read its last tick from
            // the components document instead of probing a systemd timer. No supervisor answering
            // is already said once on the components line, so this row stays silent then.
            if let Some(cc) = comps
                && let Some(ago) = cc.watchdog.last_tick_s_ago
                && ago > WATCHDOG_STALE_SECS
            {
                c.settling(format!(
                    "forwarding watchdog not ticking (last tick {ago}s ago) — the actuator is down"
                ));
            }
        }
        MemberKind::Host => {
            if sys.run(&["nft", "list", "table", "inet", "cfab-fwd"])?.ok() {
                // Standing: a table left behind by an earlier declaration; `down` removes it.
                c.standing("`[forward] enabled`=0 but table inet cfab-fwd is loaded");
            }
            for ifn in conf_interfaces(sys)? {
                if !view.owns_if(&ifn) {
                    continue;
                }
                let path = format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding");
                if if_file(&*sys, c, absent, &ifn, &path).is_some_and(|v| v.trim() != "0") {
                    c.settling(format!("{path} = 1 with `[forward] enabled`=0"));
                }
            }
        }
    }
    Ok(())
}

/// Where one leg is and what to call it: everything `read_bond_leg` needs that the sysfs reads
/// cannot supply.
struct LegSpec<'a> {
    kind: LegKind,
    zone: &'a str,
    ifname: &'a str,
    home: &'a str,
    /// The gw router this leg reaches; `Some` only on an ingress leg.
    router: Option<String>,
    ports: &'a [Port],
    reach: Reach,
}

/// What one leg's `bonding/` sysfs says, as a row. The two migrating legs cfab builds — a
/// zone's universal segment and an ingress leg on gw scope `any` — are the SAME netdev shape
/// built by the same builder, so they are read by the same code and every condition has one
/// spelling. Reads only: a leg that has migrated or lost a port is the watchdog's business to
/// actuate on; here it is named.
fn read_bond_leg(sys: &mut dyn Sys, absent: &BTreeSet<String>, spec: LegSpec<'_>) -> BondLeg {
    let LegSpec {
        kind,
        zone,
        ifname,
        home,
        router,
        ports,
        reach,
    } = spec;
    let ports: Vec<LegPort> = ports
        .iter()
        .map(|p| LegPort {
            ifname: p.ifname.clone(),
            wire: p.wire.clone(),
            absent: absent.contains(&p.ifname),
        })
        .collect();
    let mii = sys.read(&format!("/sys/class/net/{ifname}/bonding/mii_status"));
    let active = sys.read(&format!("/sys/class/net/{ifname}/bonding/active_slave"));
    let bonding = match (mii, active) {
        // Nothing under `bonding/` can be read, the port list included: the port checks below
        // would only repeat what that says.
        (Err(_), _) | (_, Err(_)) => None,
        (Ok(mii), Ok(active)) => {
            let mii = mii.trim().to_string();
            let active = active.trim().to_string();
            // Off the home wire is only a fault while the home wire still has carrier, so this
            // file is read in exactly the branch that turns on it — and nowhere else, because
            // it returns EINVAL on a down interface.
            let off_home = ports
                .iter()
                .find(|p| p.ifname == active)
                .is_some_and(|p| p.wire != home);
            let home_carrier =
                if mii == "up" && !matches!(reach, Reach::AllDark | Reach::Quiet) && off_home {
                    match sys.read(&format!("/sys/class/net/{home}/carrier")) {
                        Ok(v) => HomeCarrier::Value(v.trim().to_string()),
                        Err(_) => HomeCarrier::Unreadable,
                    }
                } else {
                    HomeCarrier::NotRead
                };
            let slaves = sys
                .read(&format!("/sys/class/net/{ifname}/bonding/slaves"))
                .map(|v| v.split_whitespace().map(str::to_string).collect())
                .map_err(|e| e.to_string());
            Some(Bonding {
                mii_status: mii,
                active_slave: active,
                home_carrier,
                slaves,
            })
        }
    };
    BondLeg {
        kind,
        zone: zone.to_string(),
        ifname: ifname.to_string(),
        home: home.to_string(),
        router,
        reach,
        ports,
        bonding,
    }
}

/// What one leg row says, in words. Only three things differ between the two families, and all
/// of them are here rather than in a branch: the `subject` each line opens with (`<zone>
/// fallback` / `<zone> ingress`), the `noun` for what is on the far end (`peers` / `router`),
/// and the `dark` line, because a leg with no live port means "the safety net is gone" on a
/// fallback and "the outside cannot reach this zone" on the ingress.
fn leg_reasons(leg: &BondLeg) -> Vec<(Class, String)> {
    let mut out: Vec<(Class, String)> = Vec::new();
    let ifname = &leg.ifname;
    let home = &leg.home;
    let zone = &leg.zone;
    let subject = match leg.kind {
        LegKind::Fallback => format!("{zone} fallback"),
        LegKind::Ingress => format!("{zone} ingress"),
    };
    let noun = match leg.kind {
        LegKind::Fallback => "peers",
        LegKind::Ingress => "router",
    };
    // A leg with no live port IS the ingress being unreachable, and that already has a grade in
    // `return_path_and_ingress`: keep its spelling, name the leg as the reason.
    let dark = match leg.kind {
        LegKind::Fallback => format!("{zone} fallback no carrier"),
        LegKind::Ingress => format!(
            "{zone} gw {} unreachable (ingress leg {ifname} has no live port)",
            leg.router.as_deref().unwrap_or_default()
        ),
    };
    let Some(b) = &leg.bonding else {
        out.push((
            Class::Settling,
            format!(
                "{subject}: {ifname} is not a bond (/sys/class/net/{ifname}/bonding unreadable) \
                 — re-run cfab up"
            ),
        ));
        return out;
    };
    let active = &b.active_slave;
    if b.mii_status != "up" {
        // A dark bond whose active port is a stranger is not the same fault as a dark bond, and
        // "no carrier" would send an operator to the wrong end of the cable. The line says what
        // was READ, not what the watchdog did with it: `status` cannot know whether an eviction
        // was attempted (on a leaf the watchdog is not even scheduled), and a confident wrong
        // diagnosis is worse than a plain one.
        if !active.is_empty() && !leg.ports.iter().any(|s| s.ifname == *active) {
            out.push((
                Class::Settling,
                format!("{subject} down with foreign port {active} active"),
            ));
        } else {
            out.push((Class::Settling, dark));
        }
    } else if leg.reach == Reach::AllDark {
        // The prober's verdict outranks where the bond sits: with no wire reaching the router,
        // the active port explains nothing an operator can act on, and the wire whose uplink to
        // fix is every one of them.
        out.push((
            Class::Settling,
            format!("{subject}: {noun} unreachable on every wire"),
        ));
    } else if leg.reach == Reach::Quiet {
        // Nobody is heard anywhere, so no wire is to blame and the bond was left where it is.
        // Settling: the fabric may simply be starting, and one line says it once.
        out.push((
            Class::Settling,
            format!("{subject}: no {noun} heard on any wire"),
        ));
    } else {
        match leg.active_wire() {
            None => out.push((
                Class::Settling,
                format!(
                    "{subject}: {ifname} is up with no port of ours active \
                     (active_slave={active:?})"
                ),
            )),
            Some(wire) if wire == home => {}
            Some(wire) => match &b.home_carrier {
                // Carrier and forwarding are not the same fact (finding F21). When the prober
                // knows the home wire cannot reach the router, THAT is the cause and the
                // carrier is a detail — the operator's next move is the uplink, not the bond.
                // Standing, all four: the leg is up and carrying on a backup wire. That is the
                // migration working, and it holds until the home wire's fault is fixed — a
                // member that lives on one of these (a dead island uplink, a stuck reselect)
                // would otherwise spend every deadline of every `status --wait` on it.
                HomeCarrier::Value(s) if s == "1" && leg.reach == Reach::HomeDark => out.push((
                    Class::Standing,
                    format!("{subject} via {wire} (home {home}: {noun} unreachable)"),
                )),
                // A suspicion, not a verdict: the home wire is silent and is being asked.
                // Settling, because the next tick or two answers it either way.
                HomeCarrier::Value(s) if s == "1" && leg.reach == Reach::HomeSuspect => out.push((
                    Class::Settling,
                    format!("{subject} via {wire} (home {home}: no {noun} heard)"),
                )),
                HomeCarrier::Value(s) if s == "1" => out.push((
                    Class::Standing,
                    format!("{subject} via {wire} (home {home} has carrier)"),
                )),
                HomeCarrier::Value(_) => {
                    out.push((Class::Standing, format!("{subject} via {wire}")))
                }
                // `NotRead` cannot reach this arm: the gather reads the file in exactly this
                // branch. An unreadable carrier is never assumed healthy.
                HomeCarrier::Unreadable | HomeCarrier::NotRead => out.push((
                    Class::Standing,
                    format!("{subject} via {wire} (home {home} carrier unreadable)"),
                )),
            },
        }
    }
    // Per port: is it still ATTACHED? `mii_status` reads `up` on a bond that has lost a port
    // entirely, so the leg-level grade above cannot see it — and losing one is not theoretical
    // (F5: a re-enumerated USB NIC comes back with a fresh ifindex and its leg is re-created
    // unattached). A port whose wire has vanished is skipped: the wire's own line accounts for
    // it, and its leg cannot exist at all.
    let listed = match &b.slaves {
        Ok(v) => v,
        // `if_file`'s spelling for an unreadable per-interface file, with this leg's subject:
        // the port list is the only thing that can say a port went missing, so losing it is a
        // named gap in the diagnosis, never silence.
        Err(e) => {
            out.push((
                Class::Settling,
                format!("{subject}: /sys/class/net/{ifname}/bonding/slaves unreadable ({e})"),
            ));
            return out;
        }
    };
    for s in leg.ports.iter().filter(|s| !s.absent) {
        if !listed.contains(&s.ifname) {
            // Settling despite the remedy it names: the watchdog re-attaches a leg the kernel
            // re-created under a fresh ifindex within a tick (F5, measured 3 s on pve3-tb).
            out.push((
                Class::Settling,
                format!(
                    "{subject}: port {} on {} is not a port of {ifname} — re-run cfab up",
                    s.ifname, s.wire
                ),
            ));
        }
    }
    for name in listed
        .iter()
        .filter(|n| !leg.ports.iter().any(|s| s.ifname == **n))
    {
        // Standing: nothing of ours added it, so nothing of ours takes it back.
        out.push((
            Class::Standing,
            format!("{subject}: {ifname} has a foreign port {name}"),
        ));
    }
    out
}

/// The prober's verdict for one zone's leg, from the `components` document.
fn reach(rows: Option<&[ProbedLeg]>, zone: &str, home: &str) -> Reach {
    let Some(row) = rows.and_then(|r| r.iter().find(|i| i.zone == zone)) else {
        return Reach::Unknown;
    };
    if row.ports.is_empty() {
        return Reach::Unknown;
    }
    if row.ports.iter().all(|s| !s.reachable) {
        return Reach::AllDark;
    }
    if row.quiet {
        return Reach::Quiet;
    }
    match row.ports.iter().find(|s| s.wire == home) {
        Some(s) if !s.reachable => Reach::HomeDark,
        Some(s) if s.suspect => Reach::HomeSuspect,
        // A home wire the prober does not list at all cannot be called dark.
        Some(_) | None => Reach::Home,
    }
}

/// The fallback segment: which wire each zone's bond is actually on, and whether every peer that
/// carries the row is adjacent on it. Fallback legs carry no BFD, so an OSPF neighbor at ≥ 2-Way
/// is the availability signal — and it counts toward the state, in its own field.
///
#[allow(clippy::too_many_arguments)]
fn fallback(
    sys: &mut dyn Sys,
    view: &View,
    doc: Option<&Value>,
    comps: Option<&Components>,
    c: &mut Ctx,
    absent: &BTreeSet<String>,
    counts: &mut Headline,
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

        // ---- the leg: bonding/{mii_status,active_slave,slaves} -----------------------
        let leg = read_bond_leg(
            sys,
            absent,
            LegSpec {
                kind: LegKind::Fallback,
                zone,
                ifname: &r.ifname,
                home: &r.home,
                router: None,
                ports: &r.ports,
                reach: reach(comps.map(|c| c.fallback.as_slice()), zone, &r.home),
            },
        );
        c.fallback_leg(leg);

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
        let nbrs = doc.and_then(|d| crate::engine::state::ospf_neighbors(d, zone, &r.ifname));
        let Some(nbrs) = nbrs else {
            if doc.is_some() {
                c.settling(format!(
                    "{zone} fallback: {} is missing from the engine's ospf state (its neighbors \
                     cannot be read) — re-run cfab up",
                    r.ifname
                ));
            }
            for m in &peer_members {
                c.adjacency(fallback_adjacency(m, zone, false));
            }
            continue;
        };
        for m in &peer_members {
            let rid = format!("{}.0.{}", z.block(), m.node);
            let state = crate::engine::state::neighbor_state(nbrs, &rid);
            let up = crate::engine::state::at_least_two_way(state);
            if up {
                counts.fallbacks_up += 1;
                peers_up.insert(m.node);
                two_way.insert((m.node, zone.clone()));
            }
            c.adjacency(fallback_adjacency(m, zone, up));
        }
    }
    Ok(two_way)
}

/// One peer's row on a zone's fallback bond.
fn fallback_adjacency(m: &crate::model::Member, zone: &str, up: bool) -> Adjacency {
    Adjacency {
        zone: zone.to_string(),
        seg: None,
        peer_node: m.node,
        peer_name: m.name.clone(),
        peer_addr: None,
        up,
    }
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
            // No route at all is one condition with one line: the src pin is a property of a
            // route, so quoting an empty route line under it would say the same thing twice in
            // a spelling (`src not pinned: []`) that names the wrong fault.
            let Some(dev) = dev else {
                c.settling(format!(
                    "{} to {}: no route yet, expected {expect}",
                    z.name, m.name
                ));
                continue;
            };
            if dev != *expect {
                c.settling(format!(
                    "{} to {} via {dev}, expected {expect}",
                    z.name, m.name
                ));
            } else if *is_fallback {
                // Health, whichever branch supplied the expectation — but worth a line: this
                // peer is reachable, and not over a declared segment. Standing: a member that
                // is domain-disjoint from this peer reaches it over the bond by design, and
                // no amount of waiting moves it back onto a segment it does not share.
                c.standing(format!("{} to {} via fallback", z.name, m.name));
            }
            if !route_line.contains(&format!("src {}.0.{}", z.block(), view.node())) {
                c.settling(format!(
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
#[allow(clippy::too_many_arguments)]
fn return_path_and_ingress(
    sys: &mut dyn Sys,
    view: &View,
    doc: Option<&Value>,
    comps: Option<&Components>,
    c: &mut Ctx,
    absent: &BTreeSet<String>,
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
            c.settling(format!(
                "return path missing: pref 2000 from {blk} to {blk} lookup main \
                 suppress_prefixlength 0"
            ));
        }
        let r2001 = sys.run(&["ip", "rule", "show", "pref", "2001"])?.stdout;
        if !r2001
            .lines()
            .any(|l| l.trim_end().ends_with(&format!("from {blk} lookup {id}")))
        {
            c.settling(format!(
                "return path missing: pref 2001 from {blk} lookup {id}"
            ));
        }
        let r2002 = sys.run(&["ip", "rule", "show", "pref", "2002"])?.stdout;
        if !r2002.contains(&format!("from {blk} unreachable")) {
            c.settling(format!(
                "return path missing: pref 2002 from {blk} unreachable"
            ));
        }
        let Some(gw) = &z.gw else { continue };
        // A leaf carries no ingress leg and no table-<id>: the outside reaches a leaf at the
        // leaf's own addresses, never at a fabric identity (unsupported by design, James
        // 2026-09-06), so there is no return path to check and nothing to report.
        if view.kind() == MemberKind::Leaf {
            continue;
        }
        // Bound before the table is read: a MIGRATING leg owns its own carrier diagnosis
        // below, and the `linkdown` clause must not say the same thing a second time.
        let leg = view.gw_rows().into_iter().find(|r| r.zone == z.name);
        let table = sys.run(&["ip", "route", "show", "table", &id])?.stdout;
        // Two distinct failures, each with its own wording (neither reachable for the other):
        // no default line at all, versus a default line the kernel has marked inactive. A
        // table can (transiently, or via a stale entry) hold more than one `default ` line, so
        // every one of them is checked: any single dead line makes the return path degraded,
        // even if another `default ` line in the same table reads healthy.
        let default_lines: Vec<&str> = table
            .lines()
            .filter(|l| l.starts_with("default "))
            .collect();
        let mut row = Ingress {
            zone: z.name.clone(),
            router: gw.router.to_string(),
            table: id.clone(),
            default_present: !default_lines.is_empty(),
            default_linkdown: leg.as_ref().is_none_or(|l| !l.migrates())
                && default_lines
                    .iter()
                    // INFERRED, not measured (task E2.2 — no CAP_NET_ADMIN on the build host; task E3
                    // settles it live): `up` sets ignore_routes_with_linkdown=1, which the reading says
                    // KEEPS a carrier-less leg's default line but flags it `linkdown` (or `dead`) and
                    // makes it inactive for lookups. Under FRR, zebra withdrew the route and `verify`
                    // degraded the zone; cfab must not read healthier than the FRR build did. If E3
                    // finds the kernel withdraws the line instead of flagging it, this branch is dropped.
                    .any(|l| l.contains("linkdown") || l.contains("dead")),
            ifname: None,
            cidr: gw.leg_cidr(n),
            cidr_present: None,
            bond: None,
            bgp_state: None,
            bgp_pfx_snt: None,
        };
        // ingress leg + session (members carrying the leg): the router must be peering, else
        // the outside cannot reach this zone's identities
        let Some(leg) = leg else {
            c.ingress(row);
            continue;
        };
        row.ifname = Some(leg.ifname.clone());
        // A leg on gw scope `any` is an active-backup bond: the same reader the universal
        // segments get, so the ONE leg the outside depends on is graded like every other
        // migrating leg — a dark bond, a stranger active on it, a migration to a backup wire,
        // a port that never re-attached. A leg on a single domain is a plain sub-interface
        // and has none of this state.
        if leg.migrates() {
            row.bond = Some(read_bond_leg(
                sys,
                absent,
                LegSpec {
                    kind: LegKind::Ingress,
                    zone: &z.name,
                    ifname: &leg.ifname,
                    home: &leg.home,
                    router: Some(gw.router.to_string()),
                    ports: &leg.ports,
                    reach: reach(comps.map(|c| c.ingress.as_slice()), &z.name, &leg.home),
                },
            ));
        }
        let addr = sys
            .run(&["ip", "-4", "-br", "addr", "show", "dev", &leg.ifname])?
            .stdout;
        row.cidr_present = Some(addr.contains(&format!(" {}", row.cidr)));
        let Some(doc) = doc else {
            c.ingress(row);
            continue;
        };
        let entry = doc["bgp"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|n| n["peer"] == gw.router.as_str());
        row.bgp_state = Some(
            entry
                .and_then(|n| n["state"].as_str())
                .unwrap_or("absent")
                .to_string(),
        );
        row.bgp_pfx_snt = Some(entry.and_then(|n| n["pfx_snt"].as_u64()).unwrap_or(0));
        c.ingress(row);
    }
    Ok(())
}

/// What one gw zone's ingress row says, in words.
fn ingress_reasons(i: &Ingress) -> Vec<(Class, String)> {
    let mut out: Vec<(Class, String)> = Vec::new();
    let (zone, router, table) = (&i.zone, &i.router, &i.table);
    if !i.default_present {
        // Settling: the default in this table is LEARNED from the router, so a table with none
        // is the ordinary state of the first seconds after the engine starts.
        out.push((
            Class::Settling,
            format!("{zone} gw {router} unreachable (table {table} has no default)"),
        ));
    } else if i.default_linkdown {
        out.push((
            Class::Settling,
            format!(
                "{zone} gw {router} unreachable (table {table} default is linkdown - the \
                 ingress leg has no carrier)"
            ),
        ));
    }
    if let Some(b) = &i.bond {
        out.extend(leg_reasons(b));
    }
    if let (Some(ifname), Some(false)) = (&i.ifname, i.cidr_present) {
        out.push((
            Class::Settling,
            format!("{zone} ingress leg {ifname} missing or not {}", i.cidr),
        ));
    }
    match (&i.bgp_state, i.bgp_pfx_snt) {
        (Some(state), _) if state != "Established" => {
            // Settling, and so is the `pfx_snt == 0` line below it: a BGP session takes seconds
            // to establish and another moment to send the zone's prefixes.
            out.push((
                Class::Settling,
                format!(
                    "{zone} ingress: bgp {router} {state} (not Established - the router is not \
                     learning this zone's identities)"
                ),
            ));
        }
        (Some(_), Some(0)) => {
            // Established but advertising nothing is the exact signature of a missing neighbor
            // afi-safi export policy: the session is healthy, the zone's identities never leave.
            out.push((
                Class::Settling,
                format!(
                    "{zone} ingress: bgp {router} Established but advertising nothing (0 sent \
                     prefixes - the neighbor afi-safi export policy is not attached)"
                ),
            ));
        }
        _ => {}
    }
    out
}

/// The backend `up` recorded, or nft when there is no record: nft is what every member ran
/// before the record existed, and it is the only backend a host ever has. Never a re-probe —
/// `status` reports, it does not ask the kernel to change anything.
fn mark_backend(sys: &mut dyn Sys, f: &Fabric) -> MarkBackend {
    emit::ceiling_ipt::recorded(sys, &f.run_dir).unwrap_or(MarkBackend::Nft)
}

fn mark_drift(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    // Every kind: `up` installs the mark state on every kind. The DSCP plane is a queueing
    // switch's actual isolation mechanism and the ceiling is the fallback segment's only
    // containment, so drift in either is worth a line. Which mechanism holds it is printed
    // unconditionally — on the ceiling-only backend the missing bulk clamp is a real, named
    // degradation an operator must not have to infer.
    let f = view.fabric;
    let backend = mark_backend(sys, f);
    // Standing: printed on every healthy member, every time — the one line that would make
    // `--wait` spend its whole deadline on every run if it were ever called settling.
    c.standing(backend.status_line());
    let (want, loaded_path, live) = match backend {
        MarkBackend::Nft => (
            emit::mark::generate(view)?,
            format!("{}/mark.nft", f.run_dir),
            sys.run(&["nft", "-s", "list", "table", "inet", "cfab"])?,
        ),
        MarkBackend::IptablesLegacy => {
            let save = sys.run(&["iptables-legacy-save", "-t", "mangle"])?;
            let live = Output {
                status: save.status,
                stdout: emit::ceiling_ipt::ours(&save.stdout),
                stderr: save.stderr,
            };
            (
                emit::ceiling_ipt::generate(view)?,
                format!("{}/mark.ipt", f.run_dir),
                live,
            )
        }
    };
    let loaded = sys.read(&loaded_path).unwrap_or_default();
    if want != loaded {
        c.standing("mark drift — re-run cfab up");
    }
    let applied = sys
        .read(&format!("{}/mark.applied", f.run_dir))
        .unwrap_or_default();
    if !live.ok() || live.stdout != applied {
        c.standing("mark drift — re-run cfab up");
    }
    Ok(())
}

/// The fallback control-egress ceiling's drop counters, on every kind — like the table that
/// holds them. A tripped ceiling is the containment working — it protects every switch port the
/// fallback broadcast domain reaches — so it is a reason line and never moves the state: the
/// links axis already reports what a lost fallback adjacency costs. A ceiling rule that is gone
/// while up is desired is mark drift, reported by `mark_drift` above; there is no second
/// detector here and nothing actuates on it (`cfab fwd-watchdog` restores sysctls, bond
/// membership and `ip rule`s — never an nft table).
fn ceiling_counters(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    let ceilings = emit::mark::ceilings(view);
    if ceilings.is_empty() {
        return Ok(());
    }
    // Stateful listing: `nft -s` (and `iptables-legacy-save` without `-c`) is what
    // `mark.applied` is compared against and deliberately omits the counters this reads.
    let backend = mark_backend(sys, view.fabric);
    let listing = match backend {
        MarkBackend::Nft => sys.run(&["nft", "list", "table", "inet", "cfab"])?,
        MarkBackend::IptablesLegacy => sys.run(&["iptables-legacy-save", "-c", "-t", "mangle"])?,
    };
    if !listing.ok() {
        return Ok(()); // mark_drift already said the mark state is not loaded
    }
    for ce in ceilings {
        // Either backend's number is the DROP's own counter, and both reset it on re-apply:
        // what a reader sees is the count since this member's last `up`, one spelling.
        let dropped = match backend {
            MarkBackend::Nft => counter_packets(&listing.stdout, &format!("ceiling-{}", ce.zone)),
            MarkBackend::IptablesLegacy => {
                emit::ceiling_ipt::drop_packets(&listing.stdout, &ce.zone)
            }
        };
        if let Some(n) = dropped
            && n > 0
        {
            // Standing: a drop counter since this member's last `up`.
            c.standing(format!(
                "{} fallback: control egress ceiling tripped ({n} drops, limit {}/s)",
                ce.zone, ce.rate_pps
            ));
        }
    }
    Ok(())
}

/// The daemon must be alive, and every wire it says it shaped must still carry exactly the tree
/// it recorded installing. Status does NOT derive the shape: it did once, from its own carrier
/// read, and reported drift on correctly shaped wires whenever its reading or its instant
/// differed from the daemon's across the debounce window (F19). The daemon's record
/// (`<run_dir>/shape.applied`) is the single expectation.
fn shape_posture(
    sys: &mut dyn Sys,
    view: &View,
    comps: Option<&Components>,
    c: &mut Ctx,
) -> Result<()> {
    if view.kind() != MemberKind::Host {
        return Ok(());
    }
    // shape-daemon is a supervised child now (spec §9): its liveness is the state the supervisor
    // reports, not a systemd unit. Anything other than `running` is shaping down; no supervisor
    // answering is already said once on the components line, so this row stays silent then.
    if let Some(cc) = comps
        && let Some(sd) = cc.components.iter().find(|k| k.name == "shape-daemon")
        && sd.state != CompState::Running
    {
        c.settling(format!(
            "shaping down: shape-daemon is {}, {} restart(s)",
            sd.state.as_str(),
            sd.restarts
        ));
        // No expectation to check, exactly as for an absent record: a daemon that is not
        // running maintains nothing, so after a crash its record can describe floors the
        // kernel no longer holds. Calling that standing drift would say waiting changes
        // nothing, when the daemon coming back is the whole remedy.
        return Ok(());
    }
    let path = crate::shape_applied_path(&view.fabric.run_dir);
    // Absent and unparseable are one condition — no expectation to compare against — and a
    // half-written record parses as neither, so both land here as "not applied yet".
    let record = match sys
        .read(&path)
        .ok()
        .and_then(|t| emit::shape::ShapeApplied::parse(&t).ok())
    {
        Some(r) => r,
        None => {
            c.settling(format!(
                "no shape record yet at {path} — shape-daemon has not applied"
            ));
            return Ok(());
        }
    };
    for dev in view.wires() {
        match record.wires.get(&dev) {
            // In the declaration but not in the record: the daemon has not reached this wire
            // yet. Settling — its next reconverge decides.
            None => c.settling(format!(
                "shape not applied on {dev} yet — shape-daemon has no record for it"
            )),
            // A wire the daemon deliberately left alone: whatever tc holds on it is stale by
            // design, and the wire being down is already graded on the links axis.
            Some(emit::shape::AppliedWire::NoCarrier) => {}
            Some(emit::shape::AppliedWire::Failed(e)) => {
                // Standing: the derivation is a pure function of the declaration.
                c.standing(format!("shape derivation for {dev} failed: {e}"));
            }
            Some(emit::shape::AppliedWire::Shaped(classes)) => {
                let live = sys.run(&["tc", "class", "show", "dev", &dev])?.stdout;
                for (cid, rate) in classes {
                    let hit = live.lines().any(|l| {
                        l.contains(&format!("class htb {cid} "))
                            && l.contains(&format!(" rate {rate} "))
                    });
                    if !hit {
                        // Standing: the kernel disagrees with what the daemon says it installed,
                        // and no amount of waiting re-applies it.
                        c.standing(format!(
                            "shape drift on {dev}: class {cid} want rate {rate}"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn link_speeds(
    sys: &mut dyn Sys,
    view: &View,
    c: &mut Ctx,
    absent: &BTreeSet<String>,
) -> Result<()> {
    for wire in view.wires() {
        // Task 5b (RULED, James 2026-09-05): an absent wire gets its own spelling, distinct
        // from a present-but-carrierless one — an operator must tell "unplugged" from "gone".
        // This is the one place it is said: every other per-interface read in `status` goes
        // silent for what the wire took with it (`absent_ifs`).
        if absent.contains(&wire) {
            // Standing: a netdev the kernel does not have is hardware or driver, not a
            // settle — and what it costs is already graded on the links axis.
            c.standing(format!(
                "wire {wire} absent (no such netdev) — its segments are not configured"
            ));
            continue;
        }
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
            // Standing: the wire negotiated what it negotiated; the declaration is what
            // disagrees with it.
            c.standing(format!(
                "{wire}: link speed {obs} != declared {decl} (driver {driver})"
            ));
        }
    }
    Ok(())
}

/// `ip route get <target>` → (the `dev` it leaves by, the whole first line). The line is
/// carried back with the device because every caller quotes it in the reason it reports.
///
/// `None` is "there is no route to this target": right after `up` the engine has not installed
/// one yet, and `ip route get` then fails with nothing on stdout. It is never an empty device
/// name — F22 printed one into a reason line (`via , expected cfab-cl`), which reads as a
/// device whose name is missing rather than as a route that is missing.
fn route_dev(sys: &mut dyn Sys, target: &str) -> Result<(Option<String>, String)> {
    let route = sys.run(&["ip", "route", "get", target])?.stdout;
    let route_line = route.lines().next().unwrap_or("").trim().to_string();
    let words: Vec<&str> = route_line.split_whitespace().collect();
    let dev = words
        .iter()
        .position(|w| *w == "dev")
        .and_then(|i| words.get(i + 1))
        .map(|s| s.to_string());
    Ok((dev, route_line))
}

/// Each condition is named once and the lines are sorted: a zone with two down peers pushes its
/// line per peer, and this output is read by humans, scripts and agents alike.
fn once_each(conditions: &[Condition]) -> Vec<String> {
    let mut sorted: Vec<String> = conditions.iter().map(|c| c.text.clone()).collect();
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
    // Anchored on `counter`, not on the first `packets`: a rule carrying `burst 160 packets`
    // (the ceiling) has that word before the counter's own.
    let i = words.iter().position(|w| *w == "counter")?;
    if words.get(i + 1) != Some(&"packets") {
        return None;
    }
    words.get(i + 2)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::{Declaration, fixtures};
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    /// The same fabric with `[bfd] port` declared away from FRR's default — the supported way
    /// to run cfab beside an FRR that owns udp/3784.
    fn fabric_on_bfd_port(port: u16) -> Fabric {
        let mut f = fabric();
        f.bfd_port = port;
        f
    }

    /// `/proc/net/udp` as the kernel prints it (captured shape, pve1-tb 2026-09-06): a header
    /// line, then one bound socket per line. The probe reads two columns out of it — the port
    /// half of `local_address` (4 uppercase hex digits) and `inode` — so the rows carry a
    /// wildcard address and the header stays verbatim.
    fn proc_net_udp(sockets: &[(u16, u64)]) -> String {
        let mut out = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when \
                       retrnsmt   uid  timeout inode ref pointer drops\n"
            .to_string();
        for (i, (port, inode)) in sockets.iter().enumerate() {
            out += &format!(
                "{:5}: 00000000:{port:04X} 00000000:0000 07 00000000:00000000 00:00000000 \
                 00000000     0        0 {inode} 2 0000000000000000 0\n",
                4600 + i
            );
        }
        out
    }

    /// `/proc/net/udp6`: the same columns with a 128-bit `local_address`.
    fn proc_net_udp6(sockets: &[(u16, u64)]) -> String {
        let mut out = "   sl  local_address                         remote_address              \
                       st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref \
                       pointer drops\n"
            .to_string();
        for (i, (port, inode)) in sockets.iter().enumerate() {
            out += &format!(
                "{:5}: {z}:{port:04X} {z}:0000 07 00000000:00000000 00:00000000 \
                 00000000     0        0 {inode} 2 0000000000000000 0\n",
                4700 + i,
                z = "0".repeat(32)
            );
        }
        out
    }

    /// A live FRR bfdd on this host: the unit enabled, the process running (plus a zombie of
    /// the same name, which holds no socket), and the fd table that ties it to `inodes`.
    fn frr_bfdd(sys: MockSys, inodes: &[u64]) -> MockSys {
        let mut sys = sys
            .on_stdout(&["systemctl", "is-enabled", "frr.service"], "enabled\n")
            .file("/proc/812/comm", "bfdd\n")
            .file("/proc/812/status", "Name:\tbfdd\nState:\tS (sleeping)\n")
            // A reaped-but-not-waited bfdd keeps its /proc entry and its name (the container
            // fixture, whose init reaps nothing): a zombie holds no socket.
            .file("/proc/813/comm", "bfdd\n")
            .file("/proc/813/status", "Name:\tbfdd\nState:\tZ (zombie)\n");
        // fd 0..2 are the standard streams (a non-socket target the scan must skip); the
        // sockets start at 3, as they do live.
        sys = sys.link("/proc/812/fd/0", "/dev/null");
        for (i, inode) in inodes.iter().enumerate() {
            sys = sys.link(
                &format!("/proc/812/fd/{}", i + 3),
                &format!("socket:[{inode}]"),
            );
        }
        sys
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
    /// `up` / `cfab-st-fb-a`), plus the L3 posture `up` sets on the bond itself.
    fn fallback_sysfs(mut sys: MockSys, view: &View, forwarding: &str) -> MockSys {
        for r in view.fallback_rows() {
            let home = r
                .ports
                .iter()
                .find(|s| s.wire == r.home)
                .expect("the home wire is one of the ports");
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
                    &format!("/sys/class/net/{}/bonding/slaves", r.ifname),
                    &format!("{}\n", port_list(&r.ports)),
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

    /// `bonding/slaves` as the kernel prints it: the port netdevs, space separated, in join
    /// order.
    fn port_list(ports: &[crate::derive::Port]) -> String {
        ports
            .iter()
            .map(|s| s.ifname.as_str())
            .collect::<Vec<_>>()
            .join(" ")
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
        for w in view.wires() {
            sys = sys.file(&format!("/sys/class/net/{w}"), "");
        }
        sys = mark_env(fallback_sysfs(sys, view, "0\n"), view);
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
            // gw zone (mgmt): a leaf has no table 249 at all (no ingress leg, no return
            // default) — reading it would fail, and status must never read it on a leaf
            .on_fail(&["ip", "route", "show", "table", "249"], 2,
                "Error: ipv4: FIB table does not exist.")
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

    /// The `components` document a healthy supervisor publishes for `view` (spec §9): the
    /// engine running, shape-daemon running on a host and stopped on a leaf, conf-sync stopped
    /// (this testbed is not clustered), and the forwarding watchdog ticking. Uptimes are 3600 s
    /// so the line renders `1h00m`.
    fn healthy_components(view: &View) -> String {
        let shape = if view.kind() == MemberKind::Host {
            serde_json::json!({"name": "shape-daemon", "state": "running", "pid": 1250,
                "uptime_s": 3600, "restarts": 0, "last_exit": null})
        } else {
            serde_json::json!({"name": "shape-daemon", "state": "stopped", "pid": null,
                "uptime_s": null, "restarts": 0, "last_exit": null, "why": "host only"})
        };
        serde_json::json!({
            "supervisor": {"pid": 1234, "uptime_s": 3601, "applying": false, "applies": 1,
                "last_apply_error": null},
            "components": [
                {"name": "engine", "state": "running", "pid": 1240, "uptime_s": 3600,
                 "restarts": 0, "last_exit": null},
                shape,
                {"name": "conf-sync", "state": "stopped", "pid": null, "uptime_s": null,
                 "restarts": 0, "last_exit": null, "why": "not clustered"}
            ],
            "watchdog": {"last_tick_s_ago": 2, "result": "ok", "detail": null}
        })
        .to_string()
    }

    /// The `components` document of a supervisor whose engine is down: it keeps failing to
    /// start, which is the state every "provably not our socket" rule turns on.
    fn engine_down_components() -> String {
        serde_json::json!({
            "supervisor": {"pid": 1234, "uptime_s": 60, "applying": false, "applies": 1,
                "last_apply_error": null},
            "components": [
                {"name": "engine", "state": "restarting", "pid": null, "uptime_s": null,
                 "restarts": 4, "last_exit": {"cause": "exit 1", "s_ago": 1}}
            ],
            "watchdog": {"last_tick_s_ago": 2, "result": "ok", "detail": null}
        })
        .to_string()
    }

    /// The healthy leaf, ready to run: every posture file, every route, every session up, and a
    /// supervisor answering the `components` query.
    fn healthy_leaf(view: &View) -> MockSys {
        let f = view.fabric;
        primary_routes(leaf_env(view), view)
            .socket("/run/cfab/engine.sock", &engine_doc(view, &all_bfd_up(f)))
            .socket("/run/cfab/cfab.sock", &healthy_components(view))
    }

    /// `table inet cfab` as `up` leaves it: the generated file, the `-s` readback it stores and
    /// the stateful listing `ceiling_counters` parses, with every ceiling at zero. Installed on
    /// every kind, so both `leaf_env` and `host_env` build on it.
    fn mark_env(sys: MockSys, view: &View) -> MockSys {
        let f = view.fabric;
        sys.file(
            &format!("{}/mark.nft", f.run_dir),
            &crate::emit::mark::generate(view).unwrap(),
        )
        .file(&format!("{}/mark.applied", f.run_dir), "table inet cfab\n")
        .on_stdout(
            &["nft", "-s", "list", "table", "inet", "cfab"],
            "table inet cfab\n",
        )
        .on_stdout(
            &["nft", "list", "table", "inet", "cfab"],
            &ceiling_listing(view, 0),
        )
    }

    /// `nft list table inet cfab` as nftables 1.1.3 prints the ceiling rules, with `drops`
    /// packets counted on every one of them. The `burst <n> packets` before the counter is the
    /// reason `counter_packets` anchors on the word `counter`.
    fn ceiling_listing(view: &View, drops: u64) -> String {
        let mut out = String::from(
            "table inet cfab {\n\tchain out {\n\t\ttype filter hook output priority mangle; policy accept;\n",
        );
        let emitted = crate::emit::mark::generate(view).unwrap();
        for c in crate::emit::mark::ceilings(view) {
            // The fixture is only honest while `up` actually installs the rule this parses.
            assert!(
                emitted.contains(&format!("comment \"ceiling-{}\"", c.zone)),
                "no ceiling rule is emitted for {}: the fixture would be inventing one",
                c.zone
            );
            out.push_str(&format!(
                "\t\toifname {{ \"{}\" }} ip protocol ospf limit rate over {}/second burst {} packets counter packets {drops} bytes {} drop comment \"ceiling-{}\"\n",
                c.ifname,
                c.rate_pps,
                c.burst_pkts,
                drops * 78,
                c.zone
            ));
        }
        out.push_str("\t}\n}\n");
        out
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
                .ports
                .iter()
                .find(|s| s.wire == r.home)
                .expect("the home wire is one of the ports");
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
                    &format!("/sys/class/net/{}/bonding/slaves", r.ifname),
                    &format!("{}\n", port_list(&r.ports)),
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
            // An ingress leg on gw scope `any` is the same bond a universal segment is, with
            // the same `bonding/` sysfs and the same L2-only ports.
            if r.migrates() {
                let home = r
                    .ports
                    .iter()
                    .find(|s| s.wire == r.home)
                    .expect("the home wire is one of the ports");
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
                        &format!("/sys/class/net/{}/bonding/slaves", r.ifname),
                        &format!("{}\n", port_list(&r.ports)),
                    );
                for s in &r.ports {
                    sys = sys.file(
                        &format!("/proc/sys/net/ipv4/conf/{}/forwarding", s.ifname),
                        "0\n",
                    );
                }
            }
        }
        for s in view.fallback_rows().into_iter().flat_map(|r| r.ports) {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", s.ifname),
                "0\n",
            );
        }
        for w in view.wires() {
            sys = sys
                .file(&format!("/sys/class/net/{w}"), "")
                .file(&format!("/sys/class/net/{w}/carrier"), "1\n")
                .file(
                    &format!("/sys/class/net/{w}/speed"),
                    &format!("{}\n", view.link_speed(&w).unwrap()),
                );
        }
        // Every wire is an admin wire on a host, and `status` reads the forwarding flag of
        // each one.
        for a in view.admin_ifs() {
            sys = sys.file(&format!("/proc/sys/net/ipv4/conf/{a}/forwarding"), "0\n");
        }
        sys = sys
            .file(
                &format!("{}/policy.nft", f.run_dir),
                &crate::emit::policy::generate(view).unwrap(),
            )
            .file(
                &format!("{}/policy.applied", f.run_dir),
                "table inet cfab-fwd\n",
            );
        let sys = mark_env(sys, view)
            .on_stdout(
                &["nft", "-s", "list", "table", "inet", "cfab-fwd"],
                "table inet cfab-fwd\n",
            )
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
            "default via 10.249.3.1 dev cfab-mg proto ospf metric 20\n");
        shaped(sys, view)
    }

    /// The shape-daemon's record plus the matching kernel state on every wire: a healthy host
    /// IS shaped, so the fixture says so rather than leaving `tc class show` silent.
    fn shaped(mut sys: MockSys, view: &View) -> MockSys {
        let mut wires = std::collections::BTreeMap::new();
        for w in view.wires() {
            let classes = emit::shape::derive(view, &w, None, &|_| true)
                .unwrap()
                .applied_classes();
            sys = sys.on_stdout(
                &["tc", "class", "show", "dev", &w],
                &tc_class_show(&classes),
            );
            wires.insert(w, emit::shape::AppliedWire::Shaped(classes));
        }
        let rec = emit::shape::ShapeApplied { tick: 1, wires };
        sys.file(
            &crate::shape_applied_path(&view.fabric.run_dir),
            &rec.render(),
        )
    }

    /// `tc class show` output for a set of classes, as the kernel prints it.
    fn tc_class_show(classes: &[(String, String)]) -> String {
        classes
            .iter()
            .map(|(cid, rate)| {
                format!(
                    "class htb {cid} parent 1:1 leaf 10: prio 0 rate {rate} ceil 5Gbit \
                     burst 64Kb cburst 64Kb\n"
                )
            })
            .collect()
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
        if let Some(rest) = call.strip_prefix("unix_request ") {
            // `<path> <verb> [args]`: the engine's `state`, and the supervisor's read-only
            // `components` / `log` (spec §9). Every other request would be a write.
            return matches!(
                rest.split_whitespace().nth(1),
                Some("state" | "components" | "log")
            );
        }
        ALLOWED.iter().any(|p| call.starts_with(p))
    }

    /// One `status` run over one fixture: nothing in `MockSys.files` may change, and every
    /// call must be on the read-only allowlist.
    fn assert_never_writes(label: &str, sys: &mut MockSys, view: &View, wait: u64) {
        let before = sys.files.clone();
        let report = run(sys, view, wait, false, None).unwrap();
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
        // A not-applied fabric now rides out the deadline too: no pass may write.
        assert_never_writes("no run dir, --wait 6", &mut MockSys::default(), &leaf, 6);

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
            "foreign active port (row 19)",
            &mut healthy_leaf(&leaf).file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "someone-elses0\n",
            ),
            &leaf,
            0,
        );
        assert_never_writes(
            "bond downed over a foreign port (row 19, actuated)",
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
                    "cfab-st-fb-c\n",
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
        assert_never_writes(
            "a tripped control-egress ceiling",
            &mut healthy_host(&f, &host).on_stdout(
                &["nft", "list", "table", "inet", "cfab"],
                &ceiling_listing(&host, 28),
            ),
            &host,
            0,
        );

        // The runtime-disjoint shape, over the fabric that has no fallback rows at all.
        let text = fixtures::without_universal_legs(&fixtures::example());
        let nofb = Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap();
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
            assert!(crate::engine::state::at_least_two_way(s), "{s}");
        }
        for s in ["down", "attempt", "init", "absent", ""] {
            assert!(!crate::engine::state::at_least_two_way(s), "{s}");
        }
    }

    #[test]
    fn reasons_are_sorted_and_named_once() {
        let mut c = Ctx::default();
        c.settling("b");
        c.standing("a");
        c.settling("b");
        c.standing("a");
        assert_eq!(
            once_each(&c.conditions()),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    /// A forwarding host with every leg up, every route on its primary and every BFD session
    /// established: the fixture the transit-posture tests vary one fact of.
    fn healthy_host(f: &Fabric, view: &View) -> MockSys {
        let mut sys = host_env(view);
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
        sys.socket("/run/cfab/engine.sock", &engine_doc(view, &bfd))
            .socket("/run/cfab/cfab.sock", &healthy_components(view))
    }

    /// The prose is rendered from the model and from nothing else, byte for byte. The literal
    /// is the whole report a healthy forwarding host prints, so any renderer change — a word,
    /// an indent, a line's position — fails here rather than in the field.
    #[test]
    fn the_prose_is_rendered_from_the_model_byte_for_byte() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        let expected = expected_links(&view).unwrap();
        let m = gather(&mut sys, &view, &expected, &Ctx::default()).unwrap();

        // The rows the headline counts, each one a fact and not a line.
        assert_eq!(m.member.name, "pve1-tb");
        assert_eq!(m.member.kind_word(), "host");
        assert_eq!(m.member.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(m.state, State::Up);
        let h = m.headline.clone().unwrap();
        assert_eq!((h.links_up, h.links), (18, 18));
        assert_eq!((h.fallbacks_up, h.fallbacks), (6, 6));
        assert_eq!(m.adjacencies.iter().filter(|a| a.seg.is_some()).count(), 18);
        assert_eq!(m.adjacencies.iter().filter(|a| a.seg.is_none()).count(), 6);
        assert!(m.adjacencies.iter().all(|a| a.up));
        assert_eq!(m.fallbacks.len(), f.zones.len());
        assert!(m.fallbacks.iter().all(|l| l.on_home()), "{:?}", m.fallbacks);
        let ing = m.ingress.iter().find(|i| i.zone == "mgmt").unwrap();
        assert_eq!(ing.router, "192.168.249.254");
        assert_eq!(ing.bgp_state.as_deref(), Some("Established"));
        assert_eq!(ing.bgp_pfx_snt, Some(0));
        assert_eq!(m.prefs.len(), f.zones.len());
        assert!(m.components.is_some());

        let report = render_text(&m, false, true);
        assert_eq!(report.code, 0);
        assert_eq!(
            report.output,
            "UP (2/2 | 18/18 | 6/6) on pve1-tb (host)\n  \
             mark: nft\n  \
             mgmt ingress leg cfab-gw249 missing or not 192.168.249.1/24\n  \
             mgmt ingress: bgp 192.168.249.254 Established but advertising nothing (0 sent \
             prefixes - the neighbor afi-safi export policy is not attached)\n  \
             prefs storage: eth9 eth1 eth0 (derived)\n  \
             prefs cluster: eth1 eth9 eth0 (derived)\n  \
             prefs mgmt: eth0 eth9 eth1 (derived)\n  \
             components: engine running 1h00m (0 restarts) | shape-daemon running 1h00m \
             (0 restarts) | conf-sync stopped (not clustered) | watchdog ok 2s ago\n"
        );

        // `run` is the two halves called in order and adds nothing of its own.
        let mut sys = healthy_host(&f, &view);
        assert_eq!(
            run(&mut sys, &view, 0, false, None).unwrap().output,
            report.output
        );
    }

    /// One member with every kind of adjacency trouble at once, so the report carries an
    /// ingress reason, a down BFD link, a migrated fallback leg and a dark one with a peer down
    /// on it in the same print: a down BFD session in storage, the storage fallback bond off
    /// its home wire, the cluster fallback bond dark and missing pve2-tb's neighbor, and a gw
    /// router that is not peering.
    fn tangled_host(f: &Fabric, view: &View) -> MockSys {
        let mut sys = healthy_host(f, view);
        let mut bfd = Vec::new();
        for p in [2u8, 3u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    let state = if z.name == "storage" && seg == 1 && p == 2 {
                        "down"
                    } else {
                        "up"
                    };
                    bfd.push((format!("{}.{seg}.{p}", z.block()), state));
                }
            }
        }
        let mut doc = engine_value(view, &bfd);
        for r in view.fallback_rows() {
            let z = f.zone(&r.zone).unwrap();
            if r.zone == "cluster" {
                doc["ospf"][&r.zone]["interfaces"][&r.ifname]["neighbors"] = serde_json::json!([{
                    "router_id": format!("{}.0.3", z.block()),
                    "addr": format!("{}.{}.3", z.block(), r.seg),
                    "state": "full",
                }]);
            }
        }
        for n in doc["bgp"].as_array_mut().into_iter().flatten() {
            n["state"] = serde_json::json!("Idle");
        }
        for r in view.fallback_rows() {
            if r.zone == "storage" {
                let off = r.ports.iter().find(|s| s.wire != r.home).unwrap();
                sys = sys.file(
                    &format!("/sys/class/net/{}/bonding/active_slave", r.ifname),
                    &format!("{}\n", off.ifname),
                );
            }
            if r.zone == "cluster" {
                sys = sys.file(
                    &format!("/sys/class/net/{}/bonding/mii_status", r.ifname),
                    "down\n",
                );
            }
        }
        sys.socket("/run/cfab/engine.sock", &doc.to_string())
    }

    /// The report a member carrying every kind of adjacency trouble at once prints, byte for
    /// byte. The expected text was captured from the pre-model `run` at e3b8623, not from this
    /// code: it has an ingress reason, a down BFD link, a migrated fallback leg and a dark one
    /// with a peer down on it, so a renderer that lost a line, reordered the block or dropped a
    /// row's derivation fails here.
    #[test]
    fn a_report_with_ingress_link_and_both_fallback_troubles_matches_the_pre_model_render() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tangled_host(&f, &view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.code, 1);
        assert_eq!(
            report.output,
            "UP-DEGRADED (2/2 | 17/18 | 5/6) on pve1-tb (host)\n  \
             cluster fallback no carrier\n  \
             down cluster:fallback:.2\n  \
             down storage:1:.2\n  \
             mark: nft\n  \
             mgmt ingress leg cfab-gw249 missing or not 192.168.249.1/24\n  \
             mgmt ingress: bgp 192.168.249.254 Idle (not Established - the router is not \
             learning this zone's identities)\n  \
             storage fallback via eth1 (home eth9 has carrier)\n  \
             storage to pve2-tb via cfab-st, expected cfab-st-bk\n  \
             prefs storage: eth9 eth1 eth0 (derived)\n  \
             prefs cluster: eth1 eth9 eth0 (derived)\n  \
             prefs mgmt: eth0 eth9 eth1 (derived)\n  \
             components: engine running 1h00m (0 restarts) | shape-daemon running 1h00m \
             (0 restarts) | conf-sync stopped (not clustered) | watchdog ok 2s ago\n"
        );

        // The rows carry the same four facts, structured, for the renderers that want numbers.
        let mut sys = tangled_host(&f, &view);
        let expected = expected_links(&view).unwrap();
        let m = gather(&mut sys, &view, &expected, &Ctx::default()).unwrap();
        assert_eq!(render_text(&m, false, true).output, report.output);
        let down: Vec<String> = m
            .adjacencies
            .iter()
            .filter(|a| !a.up)
            .map(Adjacency::label)
            .collect();
        assert_eq!(down, vec!["storage:1:.2", "cluster:fallback:.2"]);
        let st = m.fallbacks.iter().find(|l| l.zone == "storage").unwrap();
        assert!(!st.on_home());
        assert_eq!(st.active_wire(), Some("eth1"));
        let cl = m.fallbacks.iter().find(|l| l.zone == "cluster").unwrap();
        assert_eq!(cl.bonding.as_ref().unwrap().mii_status, "down");
        let ing = m.ingress.iter().find(|i| i.zone == "mgmt").unwrap();
        assert_eq!(ing.bgp_state.as_deref(), Some("Idle"));
    }

    #[test]
    fn a_healthy_forwarding_host_is_up() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(
            headline(&report),
            "UP (2/2 | 18/18 | 6/6) on pve1-tb (host)"
        );
        assert!(
            !report.output.contains("transit disabled"),
            "{}",
            report.output
        );
    }

    /// A healthy fabric never trips the ceiling, and a zero counter says nothing: the fixture's
    /// ceilings all read 0, so the whole report is silent about them.
    #[test]
    fn an_untripped_ceiling_is_silent() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up);
        assert!(!report.output.contains("ceiling"), "{}", report.output);
    }

    /// A tripped ceiling is the containment working: one reason line per zone naming the drops
    /// and the derived limit, the state still UP, the exit code still 0. It protects the switch
    /// and every port the fallback broadcast domain reaches; it does not make a link unsafe.
    #[test]
    fn a_tripped_ceiling_is_one_reason_line_and_the_state_stays_up() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view).on_stdout(
            &["nft", "list", "table", "inet", "cfab"],
            &ceiling_listing(&view, 28),
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(report.code, 0);
        assert_eq!(
            headline(&report),
            "UP (2/2 | 18/18 | 6/6) on pve1-tb (host)"
        );
        for zone in ["storage", "cluster", "mgmt"] {
            let want =
                format!("  {zone} fallback: control egress ceiling tripped (28 drops, limit 80/s)");
            assert!(
                report.output.lines().filter(|l| *l == want).count() == 1,
                "expected exactly one {want:?} in:\n{}",
                report.output
            );
        }
        // Nothing else moved: the mark table still matches what was applied.
        assert!(!report.output.contains("mark drift"), "{}", report.output);
    }

    /// The same on a leaf. `up` installs the table on every kind, so `status` reads the counter
    /// on every kind — a leaf that has stopped shouting must say so, or the containment is
    /// invisible on exactly the member (a NAS) where the CPU cost of a storm lands hardest.
    #[test]
    fn a_tripped_ceiling_on_a_leaf_is_the_same_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).on_stdout(
            &["nft", "list", "table", "inet", "cfab"],
            &ceiling_listing(&view, 28),
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(report.code, 0);
        assert_eq!(
            headline(&report),
            "UP (2/2 | 18/18 | 6/6) on pve3-tb (leaf)"
        );
        for zone in ["storage", "cluster", "mgmt"] {
            let want =
                format!("  {zone} fallback: control egress ceiling tripped (28 drops, limit 80/s)");
            assert!(
                report.output.lines().filter(|l| *l == want).count() == 1,
                "expected exactly one {want:?} in:\n{}",
                report.output
            );
        }
        assert!(!report.output.contains("mark drift"), "{}", report.output);
    }

    /// A leaf's mark table is watched for drift like a host's: the table `up` installed is the
    /// only thing keeping the ceiling on the wire, and nothing actuates on its absence.
    #[test]
    fn a_leaf_with_a_stale_mark_table_reports_drift() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).file("/run/cfab/mark.nft", "table inet cfab\n");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains("mark drift — re-run cfab up"),
            "{}",
            report.output
        );
    }

    /// A leaf on the iptables-legacy backend, as `up` left it: the recorded choice, the
    /// restore input, the readback, and a live dump whose ceiling chains have `drops` on
    /// their DROP rules.
    fn ipt_leaf(view: &View, drops: u64) -> MockSys {
        let f = view.fabric;
        let rendered = crate::emit::ceiling_ipt::generate(view).unwrap();
        // Our half taken verbatim from the render, so the fixture cannot drift from what `up`
        // loads; the built-ins and the foreign chain are what the live table has beside it.
        let mut save = String::from(
            "*mangle\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [9:600]\n\
             :DOCKER-USER - [0:0]\n",
        );
        for l in rendered.lines().filter(|l| l.starts_with(':')) {
            save.push_str(l);
            save.push('\n');
        }
        save.push_str("-A OUTPUT -j cfab-out\n");
        for l in rendered.lines().filter(|l| l.starts_with("-A ")) {
            save.push_str(l);
            save.push('\n');
        }
        save.push_str("COMMIT\n");
        // The `-c` dump is the same text with counters: only the DROP rules carry any.
        let counted: String = save
            .lines()
            .map(|l| {
                if l.starts_with("-A cfab-ceil-") && l.ends_with("-j DROP") {
                    format!("[{drops}:{}] {l}\n", drops * 52)
                } else if l.starts_with("-A ") {
                    format!("[0:0] {l}\n")
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        healthy_leaf(view)
            .file(&format!("{}/mark.backend", f.run_dir), "iptables-legacy\n")
            .file(
                &format!("{}/mark.ipt", f.run_dir),
                &crate::emit::ceiling_ipt::generate(view).unwrap(),
            )
            .file(
                &format!("{}/mark.applied", f.run_dir),
                &crate::emit::ceiling_ipt::ours(&save),
            )
            .on_stdout(&["iptables-legacy-save", "-t", "mangle"], &save)
            .on_stdout(&["iptables-legacy-save", "-c", "-t", "mangle"], &counted)
    }

    /// The backend is named on every kind, and the ceiling-only one says what it cannot do —
    /// the missing bulk DSCP clamp is a real degradation an operator must not have to infer.
    /// It is a reason line, not a state: the ceiling is on the wire either way.
    #[test]
    fn the_mark_backend_is_named_and_the_ceiling_only_one_says_what_it_lacks() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let report = run(&mut ipt_leaf(&view, 0), &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(report.code, 0);
        assert!(
            report.output.contains(
                "\n  mark: iptables-legacy (ceiling only; bulk DSCP clamp unavailable on this \
                 kernel)\n"
            ),
            "{}",
            report.output
        );
        assert!(!report.output.contains("mark drift"), "{}", report.output);
        // The nft table is never consulted on this member.
        assert!(!ipt_leaf(&view, 0).ran("nft"), "the ipt backend ran nft");
    }

    /// The tripped line is one spelling for both backends: same words, same numbers, read
    /// from the DROP rule's own counter.
    #[test]
    fn a_tripped_ceiling_on_the_iptables_backend_is_the_same_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let report = run(&mut ipt_leaf(&view, 28), &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(report.code, 0);
        for zone in ["storage", "cluster", "mgmt"] {
            let want =
                format!("  {zone} fallback: control egress ceiling tripped (28 drops, limit 80/s)");
            assert!(
                report.output.lines().filter(|l| *l == want).count() == 1,
                "expected exactly one {want:?} in:\n{}",
                report.output
            );
        }
    }

    /// The jump `-A OUTPUT -j cfab-out` is what puts the ceiling on the wire at all: without
    /// it the chains are resident and unreachable. On nft the hook lives inside the covered
    /// table, so this failure mode does not exist there; here it must be watched explicitly,
    /// or a member reads clean while policing nothing.
    #[test]
    fn a_readback_missing_the_output_jump_is_drift() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        // Same live table with the one jump deleted — everything else identical.
        let mut unhooked = ipt_leaf(&view, 0);
        let save = unhooked
            .cmd_rules
            .iter()
            .rev()
            .find(|(p, _)| p == &["iptables-legacy-save", "-t", "mangle"])
            .map(|(_, o)| o.stdout.clone())
            .unwrap();
        assert!(save.contains("-A OUTPUT -j cfab-out\n"), "{save}");
        let unhooked_save = save.replace("-A OUTPUT -j cfab-out\n", "");
        unhooked = unhooked.on_stdout(&["iptables-legacy-save", "-t", "mangle"], &unhooked_save);
        let report = run(&mut unhooked, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains("mark drift — re-run cfab up"),
            "an unhooked ceiling read clean:\n{}",
            report.output
        );
    }

    /// Drift on this backend has the same two halves as on nft: what `up` rendered against
    /// what it wrote, and the live ruleset against the readback it stored.
    #[test]
    fn the_iptables_backend_reports_declaration_and_live_drift() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut stale = ipt_leaf(&view, 0).file("/run/cfab/mark.ipt", "*mangle\nCOMMIT\n");
        assert!(
            run(&mut stale, &view, 0, false, None)
                .unwrap()
                .output
                .contains("mark drift — re-run cfab up")
        );
        // Live: the ceiling chains were flushed out from under us.
        let mut flushed = ipt_leaf(&view, 0).on_stdout(
            &["iptables-legacy-save", "-t", "mangle"],
            "*mangle\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n",
        );
        let report = run(&mut flushed, &view, 0, false, None).unwrap();
        assert_eq!(
            report
                .output
                .lines()
                .filter(|l| l.contains("mark drift"))
                .count(),
            1,
            "{}",
            report.output
        );
    }

    /// `burst 160 packets` sits before the counter on a ceiling rule, so a parse anchored on
    /// the first `packets` reads the burst size (or fails) instead of the drop count.
    #[test]
    fn counter_packets_reads_the_counter_not_the_burst() {
        let line = "oifname { \"cfab-st-fb\" } ip protocol ospf limit rate over 80/second \
                    burst 160 packets counter packets 28 bytes 2184 drop comment \"ceiling-storage\"";
        assert_eq!(counter_packets(line, "ceiling-storage"), Some(28));
        assert_eq!(counter_packets(line, "ceiling-cluster"), None);
        assert_eq!(
            counter_packets(
                "iifname @admin counter packets 0 bytes 0 drop comment \"admin-in\"",
                "admin-in"
            ),
            Some(0)
        );
    }

    /// Spec §12 (b), the reporting half. A host whose forward policy is gone has failed closed:
    /// the watchdog turned forwarding off and had the engine re-advertise at the leaf offset.
    /// This member is still reachable on every leg, so `status` stays UP — the transit loss is
    /// a reason line, not a state. The offset costs are invisible here by design: `status`
    /// counts adjacencies, and every one of them survives the re-advertisement.
    #[test]
    fn a_fail_closed_transit_host_is_up_with_the_transit_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view).on_stdout(
            &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
            "chain forward {\n  type filter hook forward priority filter; policy accept;\n}",
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(
            headline(&report),
            "UP (2/2 | 18/18 | 6/6) on pve1-tb (host)"
        );
        assert!(
            report.output.contains(
                "transit disabled: table inet cfab-fwd / chain forward with policy drop is not \
                 loaded — re-run cfab up"
            ),
            "{}",
            report.output
        );
    }

    /// UP: every link and every fallback available, three fields, exit 0, and — the whole
    /// point of the split — no reason lines at all.
    #[test]
    fn a_healthy_leaf_is_up_with_three_fields() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(report.code, 0);
        assert_eq!(
            report.output,
            "UP (2/2 | 18/18 | 6/6) on pve3-tb (leaf)\n  mark: nft\n\
             \x20 prefs storage: eth9 eth1 eth0 (derived)\n\
             \x20 prefs cluster: eth1 eth9 eth0 (derived)\n\
             \x20 prefs mgmt: eth0 eth9 eth1 (derived)\n  components: engine running 1h00m \
             (0 restarts) | shape-daemon stopped (host only) | conf-sync stopped (not clustered) \
             | watchdog ok 2s ago\n",
            "{}",
            report.output
        );
        assert!(sys.slept.is_empty(), "--wait 0 is one instant read");
    }

    /// The packaged example, as text — the same declaration `fabric()` types, so a status run
    /// pointed at it must read "identical" and say nothing.
    fn example_text() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
            .unwrap()
    }

    const CONFIG: &str = "/etc/cfab/fabric.toml";

    /// The declaration path this status run compares against.
    fn cfg() -> &'static std::path::Path {
        std::path::Path::new(CONFIG)
    }

    /// F9: the file on disk will not parse (an operator mid-edit), but the applied copy is in
    /// the run dir. `status` describes the RUNNING fabric — full counts, UP — and the broken
    /// file is a reason line naming the parse error, never a state and never exit 1.
    #[test]
    fn an_unparseable_declaration_is_a_reason_line_and_status_still_describes_the_fabric() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).file(CONFIG, "[[member]]\nname = \n");
        let report = run(&mut sys, &view, 0, false, Some(cfg())).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(
            report.code, 0,
            "a reason line moves no state and no exit code"
        );
        assert_eq!(
            headline(&report),
            "UP (2/2 | 18/18 | 6/6) on pve3-tb (leaf)",
            "the counts come from the running fabric, not the file"
        );
        assert!(
            report.output.contains(
                "declaration /etc/cfab/fabric.toml: TOML parse error at line 2, column 8"
            ),
            "the parser's own line/column must survive into the reason line: {}",
            report.output
        );
        assert!(
            report.output.contains(
                "(status describes the running fabric; a reload of this file will be refused)"
            ),
            "{}",
            report.output
        );
        // The parse error is several lines: every continuation line is indented past the first
        // so the reason still reads as one block under the headline.
        for line in report.output.lines().skip(1) {
            assert!(
                line.starts_with("  "),
                "an unindented continuation line breaks the block: {:?} in\n{}",
                line,
                report.output
            );
        }
    }

    /// A declaration that parses but no longer names this member is the same reason line: the
    /// reload would refuse it, so status says so rather than describing somebody else's fabric.
    #[test]
    fn a_declaration_that_drops_this_member_is_the_same_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let text = example_text().replace("pve3-tb", "pve4-tb");
        let mut sys = healthy_leaf(&view).file(CONFIG, &text);
        let report = run(&mut sys, &view, 0, false, Some(cfg())).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("declaration /etc/cfab/fabric.toml: ")
                && report
                    .output
                    .contains("a reload of this file will be refused"),
            "{}",
            report.output
        );
    }

    /// A valid file that differs from what is running: one line, in the reload's own vocabulary
    /// — the restart is the cost of applying it, and the operator should know that before typing.
    #[test]
    fn a_changed_declaration_is_the_changed_since_apply_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let text = example_text().replace("node = 3", "node = 7");
        assert_ne!(text, example_text(), "the fixture edit must land");
        let mut sys = healthy_leaf(&view).file(CONFIG, &text);
        let report = run(&mut sys, &view, 0, false, Some(cfg())).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report.output.contains(
                "declaration /etc/cfab/fabric.toml changed since apply (systemctl reload cfab \
                 to apply; the fabric will restart)"
            ),
            "{}",
            report.output
        );
    }

    /// The ordinary case: the file on disk is the fabric that is running. Not one extra line —
    /// the healthy leaf's output is byte-identical to the run that never looked at the file.
    #[test]
    fn a_declaration_identical_to_the_applied_one_says_nothing() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut quiet = healthy_leaf(&view);
        let expected = run(&mut quiet, &view, 0, false, None).unwrap().output;
        let mut sys = healthy_leaf(&view).file(CONFIG, &example_text());
        let report = run(&mut sys, &view, 0, false, Some(cfg())).unwrap();
        assert_eq!(report.output, expected);
    }

    /// Equality is SEMANTIC (the derived `Fabric`, as `classify_reload` decides it), so a
    /// comment or a whitespace edit is not "changed" — a reason line the operator cannot act on
    /// is noise.
    #[test]
    fn a_comment_only_edit_is_not_a_changed_declaration() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let text = format!("# an operator's note\n{}", example_text());
        let mut sys = healthy_leaf(&view).file(CONFIG, &text);
        let report = run(&mut sys, &view, 0, false, Some(cfg())).unwrap();
        assert!(!report.output.contains("declaration "), "{}", report.output);
    }

    /// A file that vanished under a running fabric reads as the same stale-file reason, not a
    /// crash: the fabric is still up and status still describes it.
    #[test]
    fn a_missing_declaration_under_a_running_fabric_is_a_reason_line() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view);
        let report = run(&mut sys, &view, 0, false, Some(cfg())).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("declaration /etc/cfab/fabric.toml: ")
                && report
                    .output
                    .contains("a reload of this file will be refused"),
            "{}",
            report.output
        );
    }

    /// `applied_fabric` finds the copy at the run dir the declaration names.
    #[test]
    fn the_applied_copy_is_found_at_the_declared_run_dir() {
        let text = example_text().replace("run_dir = \"/run/cfab\"", "run_dir = \"/run/other\"");
        assert_ne!(text, example_text(), "the example's run_dir line moved");
        let sys = MockSys::default()
            .file(CONFIG, &text)
            .file("/run/other/fabric.toml.applied", &example_text());
        let got = applied_fabric(&sys, cfg()).expect("the applied copy is the running fabric");
        assert_eq!(got.run_dir, "/run/cfab", "the copy is what was APPLIED");
    }

    /// The file that will not parse cannot name a run dir, so the packaged default is where the
    /// copy is looked for — the case the whole feature exists for.
    #[test]
    fn an_unparseable_declaration_falls_back_to_the_default_run_dir() {
        let sys = MockSys::default()
            .file(CONFIG, "nonsense = [")
            .file("/run/cfab/fabric.toml.applied", &example_text());
        assert!(applied_fabric(&sys, cfg()).is_some());
    }

    /// Nothing applied: `None`, and the caller keeps today's behavior (parse the file, and its
    /// error is exit 1 — there is no running fabric to describe).
    #[test]
    fn no_applied_copy_is_none() {
        let sys = MockSys::default().file(CONFIG, "nonsense = [");
        assert!(applied_fabric(&sys, cfg()).is_none());
    }

    /// A leaf carries no ingress leg: the gw-zone return-path check is skipped, so a leaf whose
    /// table-<id> does not exist (the real state — VERIFIED pve3-tb 2026-09-06) reads UP with no
    /// reason line. Reaching a leaf from outside at a fabric identity is unsupported by design,
    /// not a degraded return path.
    #[test]
    fn a_leaf_skips_the_gw_return_path_check() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            !report.output.contains("gw ") && !report.output.contains("table 249"),
            "a leaf must not report the gw return path: {}",
            report.output
        );
        assert!(
            !sys.ran("ip route show table 249"),
            "status must not read table 249 on a leaf"
        );
    }

    /// F13, VERIFIED live on pve1-tb 2026-09-06 with 0.4.1: FRR's bfdd holds udp/3784 while our
    /// declaration says 13784, and status still called it a conflict. Running beside FRR on a
    /// declared free port is the designed coexistence, not a fault: the probe must look at who
    /// holds OUR port, never at who is on the host.
    #[test]
    fn frr_on_another_port_is_not_a_conflict() {
        let f = fabric_on_bfd_port(13784);
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = frr_bfdd(healthy_leaf(&view), &[41231, 41232])
            .file("/proc/net/udp", &proc_net_udp(&[(3784, 41231)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[(3784, 41232)]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            !report.output.contains("bfd udp/"),
            "bfdd on 3784 is no news while we declared 13784:\n{}",
            report.output
        );
    }

    /// A daemon that really holds our port is a reason line, never a state: it keeps the port
    /// at our next engine restart, but nothing is down yet. The line names the holder.
    #[test]
    fn a_daemon_holding_our_bfd_port_is_a_reason_line_while_we_are_up() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = frr_bfdd(healthy_leaf(&view), &[41231])
            .file("/proc/net/udp", &proc_net_udp(&[(3784, 41231)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "a reason line moves no state");
        assert_eq!(report.code, 0);
        assert!(
            report.output.contains(
                "  bfd udp/3784: bfdd (pid 812, frr.service enabled) holds this port, which the \
                 engine needs exclusively\n"
            ),
            "{}",
            report.output
        );
        assert!(
            report.output.contains(
                "  remedy: stop FRR, which owns bfdd: systemctl disable --now frr; or declare a \
                 free [bfd] port (now 3784) in fabric.toml on EVERY member — every peer of a \
                 session must use the same port\n"
            ),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("BFD_PORT"),
            "the declaration key is `[bfd] port`, one spelling everywhere:\n{}",
            report.output
        );
    }

    /// The engine opens no IPv6 BFD socket (`bfd_socket_policy`, `ipv6: false`), so once its
    /// IPv4 socket is bound a `[::]` holder can take nothing from it: while the engine runs, a
    /// v6-only holder is not news.
    #[test]
    fn a_v6_only_holder_is_silent_while_the_engine_runs() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = frr_bfdd(healthy_leaf(&view), &[41232])
            .file("/proc/net/udp", &proc_net_udp(&[(9000, 41240)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[(3784, 41232)]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            !report.output.contains("bfd udp/"),
            "a v6-only holder takes nothing from a bound v4 socket:\n{}",
            report.output
        );
    }

    /// The other side of it: while the engine is NOT bound, a dual-stack holder on `[::]` is
    /// exactly what keeps its IPv4 bind from succeeding, so the v6 table counts.
    #[test]
    fn a_v6_only_holder_is_reported_while_the_engine_is_down() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = frr_bfdd(leaf_env(&view), &[41232])
            .socket_verb(
                "/run/cfab/cfab.sock",
                "components",
                &engine_down_components(),
            )
            .file("/proc/net/udp", &proc_net_udp(&[(9000, 41240)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[(3784, 41232)]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  bfd udp/3784: bfdd (pid 812, frr.service enabled) holds this port, which the \
                 engine needs exclusively\n"
            ),
            "{}",
            report.output
        );
    }

    /// With both units enabled the remedy names the one that manages the process: stopping
    /// bfdd.service is the narrower action, and frr.service may not even own this bfdd.
    #[test]
    fn the_remedy_prefers_the_bfdd_unit_when_both_are_enabled() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = frr_bfdd(healthy_leaf(&view), &[41231])
            .on_stdout(&["systemctl", "is-enabled", "bfdd.service"], "enabled\n")
            .file("/proc/net/udp", &proc_net_udp(&[(3784, 41231)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  remedy: stop bfdd: systemctl disable --now bfdd; or declare a free [bfd] port \
                 (now 3784) in fabric.toml on EVERY member — every peer of a session must use \
                 the same port\n"
            ),
            "{}",
            report.output
        );
    }

    /// One condition, one diagnosis. A holder we can see live AND a bind line the engine left in
    /// its ring buffer are the same fact; the live custody read is the more specific of the two,
    /// so the ring-buffer diagnosis stands down rather than saying it again in other words.
    #[test]
    fn a_live_holder_and_a_stale_bind_line_produce_one_diagnosis() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let log = serde_json::json!({
            "lines": [
                "ERROR bfd: cannot bind udp 0.0.0.0:3784: address in use (holder unknown)"
            ]
        })
        .to_string();
        let mut sys = frr_bfdd(leaf_env(&view), &[41231])
            .socket_verb(
                "/run/cfab/cfab.sock",
                "components",
                &engine_down_components(),
            )
            .socket_verb("/run/cfab/cfab.sock", "log", &log)
            .file("/proc/net/udp", &proc_net_udp(&[(3784, 41231)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(
            report.output.matches("bfd udp/3784:").count(),
            1,
            "one condition, one headline:\n{}",
            report.output
        );
        assert_eq!(
            report.output.matches("  remedy: ").count(),
            1,
            "one condition, one remedy:\n{}",
            report.output
        );
        assert!(
            report.output.contains(
                "  bfd udp/3784: bfdd (pid 812, frr.service enabled) holds this port, which the \
                 engine needs exclusively\n"
            ),
            "the live holder is the one that survives:\n{}",
            report.output
        );
    }

    /// Nobody on the port and no BFD daemon anywhere: silence.
    #[test]
    fn a_free_bfd_port_says_nothing() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file("/proc/net/udp", &proc_net_udp(&[(9000, 41240)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(!report.output.contains("bfd udp/"), "{}", report.output);
    }

    /// An unidentified holder: the engine is down (the supervisor says so), yet the port is
    /// bound — so the socket is provably not ours, and status says so without naming a daemon
    /// it could not resolve. The same socket while the engine RUNS is our own and is silent
    /// (`a_bound_port_is_our_own_engine_while_it_runs`).
    #[test]
    fn an_unidentified_holder_is_reported_while_the_engine_is_down() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let comps = serde_json::json!({
            "supervisor": {"pid": 1234, "uptime_s": 60, "applying": false, "applies": 1,
                "last_apply_error": null},
            "components": [
                {"name": "engine", "state": "restarting", "pid": null, "uptime_s": null,
                 "restarts": 4, "last_exit": {"cause": "exit 1", "s_ago": 1}}
            ],
            "watchdog": {"last_tick_s_ago": 2, "result": "ok", "detail": null}
        })
        .to_string();
        let mut sys = leaf_env(&view)
            .socket_verb("/run/cfab/cfab.sock", "components", &comps)
            .file("/proc/net/udp", &proc_net_udp(&[(3784, 41231)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  bfd udp/3784: another process holds this port, which the engine needs \
                 exclusively\n"
            ),
            "{}",
            report.output
        );
        assert!(
            report.output.contains(
                "  remedy: find the holder (ss -ulpn | grep ':3784') and stop it; or declare a \
                 free [bfd] port (now 3784) in fabric.toml on EVERY member — every peer of a \
                 session must use the same port\n"
            ),
            "{}",
            report.output
        );
    }

    /// The other half of the ownership rule: a down engine is not evidence of a thief. Nothing
    /// is bound on the port, so there is nobody to blame — an engine that is down for its own
    /// reasons must not be told a phantom holds the port.
    #[test]
    fn a_free_port_is_not_blamed_when_the_engine_is_down() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let comps = serde_json::json!({
            "supervisor": {"pid": 1234, "uptime_s": 60, "applying": false, "applies": 1,
                "last_apply_error": null},
            "components": [
                {"name": "engine", "state": "restarting", "pid": null, "uptime_s": null,
                 "restarts": 4, "last_exit": {"cause": "exit 1", "s_ago": 1}}
            ],
            "watchdog": {"last_tick_s_ago": 2, "result": "ok", "detail": null}
        })
        .to_string();
        let mut sys = leaf_env(&view)
            .socket_verb("/run/cfab/cfab.sock", "components", &comps)
            .file("/proc/net/udp", &proc_net_udp(&[(9000, 41240)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(!report.output.contains("bfd udp/"), "{}", report.output);
    }

    /// Teeth for the ownership rule: a socket on our port while the supervisor reports the
    /// engine running IS the engine's own — reporting it would flag every healthy host.
    #[test]
    fn a_bound_port_is_our_own_engine_while_it_runs() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file("/proc/net/udp", &proc_net_udp(&[(3784, 41231)]))
            .file("/proc/net/udp6", &proc_net_udp6(&[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(!report.output.contains("bfd udp/"), "{}", report.output);
    }

    /// The engine is simply absent (no port thief): still zero adjacencies, still FAILED, and
    /// the reason names the engine rather than eighteen symptoms of it.
    #[test]
    fn an_absent_engine_is_failed() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = leaf_env(&view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Failed, "output:\n{}", report.output);
        assert_eq!(report.code, 2);
        assert_eq!(
            headline(&report),
            "FAILED (0/2 | 0/18 | 0/6) on pve3-tb (leaf)"
        );
        // No supervisor answering on cfab.sock (leaf_env registers none): the fault is upstream
        // of the engine, and the row names the socket and the remedy — never the old unit.
        assert!(
            report.output.contains(
                "  engine not running: no supervisor answering on /run/cfab/cfab.sock — start it \
                 (systemctl start cfab)\n"
            ),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("cfab-engine.service"),
            "the old spelling must be gone: {}",
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
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

    /// A fallback neighbor below the bar is the same grade on the third field: the domain-
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
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

    /// A host peering with its zone's ingress router. The mgmt zone is the only one with a gw in
    /// the shipped fabric, so it is the only zone that can produce an ingress bgp reason line.
    fn ingress_host_sys(host: &View, bgp: serde_json::Value) -> MockSys {
        let mut doc = engine_value(host, &[]);
        doc["bgp"] = bgp;
        host_env(host).socket("/run/cfab/engine.sock", &doc.to_string())
    }

    /// A session that is not Established: the router is not learning the zone, named in the one
    /// spelling with its reason.
    #[test]
    fn ingress_bgp_not_established_is_a_reason() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let mut sys = ingress_host_sys(
            &host,
            serde_json::json!([
                { "peer": "192.168.249.254", "state": "Idle", "pfx_snt": 0 }
            ]),
        );
        let report = run(&mut sys, &host, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "mgmt ingress: bgp 192.168.249.254 Idle (not Established - the router is \
                 not learning this zone's identities)"
            ),
            "{}",
            report.output
        );
    }

    /// The failure a missing neighbor afi-safi export policy causes: the session is Established but
    /// zero prefixes are advertised, so the outside can reach nothing in the zone.
    #[test]
    fn ingress_bgp_established_advertising_nothing_is_a_reason() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let mut sys = ingress_host_sys(
            &host,
            serde_json::json!([
                { "peer": "192.168.249.254", "state": "Established", "pfx_snt": 0 }
            ]),
        );
        let report = run(&mut sys, &host, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "mgmt ingress: bgp 192.168.249.254 Established but advertising nothing \
                 (0 sent prefixes - the neighbor afi-safi export policy is not attached)"
            ),
            "{}",
            report.output
        );
    }

    /// Established and advertising: no ingress bgp reason at all.
    #[test]
    fn ingress_bgp_established_and_advertising_is_silent() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let mut sys = ingress_host_sys(
            &host,
            serde_json::json!([
                { "peer": "192.168.249.254", "state": "Established", "pfx_snt": 5 }
            ]),
        );
        let report = run(&mut sys, &host, 0, false, None).unwrap();
        assert!(!report.output.contains("ingress: bgp"), "{}", report.output);
    }

    // ---- the migrating ingress leg (gw scope `any`) -------------------------------------

    /// pve1-tb's ingress bond. mgmt's cheapest segment is on domain c, so the leg homes on
    /// eth0 and its home port is `cfab-gw249-c`.
    const GW_BOND: &str = "cfab-gw249";

    /// The same declaration with the ingress leg pinned to one domain — the example ships
    /// scope `any`, the migrating leg.
    fn fabric_with_a_domain_gw() -> Fabric {
        let text = crate::decl::fixtures::with_a_domain_gw(&example_text());
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    /// A migrating ingress leg sitting on its home wire with every port attached is health:
    /// not one bond line about it.
    #[test]
    fn a_healthy_migrating_ingress_leg_is_silent() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        for needle in [
            "mgmt ingress via ",
            "no live port",
            "is not a bond",
            "not a port",
            "with no port of ours active",
        ] {
            assert!(
                !report.output.contains(needle),
                "{needle}:\n{}",
                report.output
            );
        }
    }

    /// Every port dark: the bond is up with nothing under it, and that is the ingress the
    /// outside cannot use — the existing `gw <router> unreachable (...)` grade, naming the leg.
    #[test]
    fn a_dark_migrating_ingress_leg_is_the_gw_unreachable_grade() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        sys = sys
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/mii_status"),
                "down\n",
            )
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/active_slave"),
                "\n",
            );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  mgmt gw 192.168.249.254 unreachable (ingress leg cfab-gw249 has no live \
                 port)\n"
            ),
            "{}",
            report.output
        );
    }

    /// ONE event, ONE line. A leg with no live port also makes the kernel flag the zone's
    /// default `linkdown`, so the route check and the bond reader both saw the same darkness
    /// and an operator got two reason lines for one cable. The bond reader owns it on a
    /// migrating leg: it reads the CAUSE (no port of ours is live under the leg) rather than
    /// the kernel's consequence, it names the leg, and the `linkdown` clause is an INFERRED
    /// kernel behavior that may not fire at all. `table has no default` is a different
    /// condition and still reported.
    #[test]
    fn a_dark_migrating_ingress_leg_is_reported_once() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view)
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/mii_status"),
                "down\n",
            )
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/active_slave"),
                "\n",
            )
            .on_stdout(
                &["ip", "route", "show", "table", "249"],
                "default via 192.168.249.254 dev cfab-gw249 proto 205 linkdown\n",
            );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  mgmt gw 192.168.249.254 unreachable (ingress leg cfab-gw249 has no live \
                 port)\n"
            ),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("default is linkdown"),
            "one event, one line:\n{}",
            report.output
        );
    }

    /// The port list is the only thing that can say a port went missing, so a leg whose
    /// `bonding/slaves` cannot be read is a gap in the diagnosis, not silence — and the line
    /// carries the leg's subject like every other line this reader emits.
    #[test]
    fn an_unreadable_port_list_is_named_with_its_leg() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        sys.files
            .remove(&format!("/sys/class/net/{GW_BOND}/bonding/slaves"));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  mgmt ingress: /sys/class/net/cfab-gw249/bonding/slaves unreadable ("),
            "{}",
            report.output
        );
    }

    /// Migrated to a backup wire while the home wire still has carrier: a stuck reselect, named
    /// with the wire it moved to — the same sentence a migrated fallback bond earns.
    #[test]
    fn a_migrated_ingress_leg_names_the_wire_it_moved_to() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view).file(
            &format!("/sys/class/net/{GW_BOND}/bonding/active_slave"),
            "cfab-gw249-b\n",
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  mgmt ingress via eth1 (home eth0 has carrier)\n"),
            "{}",
            report.output
        );
    }

    /// The same migration with a DARK home wire is the bond doing its job: the line still names
    /// the wire (an operator must know the ingress moved), without the stuck-reselect clause.
    #[test]
    fn a_migrated_ingress_leg_off_a_dark_home_drops_the_carrier_clause() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view)
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/active_slave"),
                "cfab-gw249-b\n",
            )
            .file("/sys/class/net/eth0/carrier", "0\n");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains("  mgmt ingress via eth1\n"),
            "{}",
            report.output
        );
    }

    /// The `components` document with the ingress prober's rows for the mgmt leg: `dark` names
    /// the wires the router does NOT answer over.
    fn components_with_ingress(view: &View, dark: &[&str]) -> String {
        let mut doc: serde_json::Value =
            serde_json::from_str(&healthy_components(view)).expect("the healthy fixture");
        let ports: Vec<serde_json::Value> = [("eth9", "a"), ("eth1", "b"), ("eth0", "c")]
            .iter()
            .map(|(wire, island)| {
                serde_json::json!({
                    "wire": wire, "island": island,
                    "reachable": !dark.contains(wire),
                    "last_reply_ms": if dark.contains(wire) { serde_json::Value::Null }
                                     else { serde_json::json!(2) },
                })
            })
            .collect();
        doc["ingress"] = serde_json::json!([{
            "zone": "mgmt", "bond": GW_BOND, "active": "cfab-gw249-c", "ports": ports,
        }]);
        doc.to_string()
    }

    /// F21: the home wire has carrier and the bond has moved off it, but the reason is not a
    /// stuck reselect — the router cannot be reached over it. Same sentence, different cause,
    /// and the cause is the half an operator can act on.
    #[test]
    fn a_migration_off_a_router_dead_home_names_the_router_not_the_carrier() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view)
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/active_slave"),
                "cfab-gw249-a\n",
            )
            .socket(
                "/run/cfab/cfab.sock",
                &components_with_ingress(&view, &["eth0"]),
            );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  mgmt ingress via eth9 (home eth0: router unreachable)\n"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("home eth0 has carrier"),
            "one spelling per condition: {}",
            report.output
        );
    }

    /// F23: the ingress prober reports a port with no carrier as router-unreachable, because a
    /// wire with no carrier reaches nothing and the kernel will not put ingress on it either.
    /// The reason an operator reads must still be the carrier, never the router: the home wire
    /// being dark is the bond doing its job, and it keeps the plain spelling it has always had.
    #[test]
    fn a_migration_off_a_carrier_less_home_never_blames_the_router() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view)
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/active_slave"),
                "cfab-gw249-a\n",
            )
            .file("/sys/class/net/eth0/carrier", "0\n")
            .socket(
                "/run/cfab/cfab.sock",
                &components_with_ingress(&view, &["eth0"]),
            );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains("  mgmt ingress via eth9\n"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("router unreachable"),
            "no carrier is not the router's fault: {}",
            report.output
        );
    }

    /// The same migration while the router DOES answer over the home wire is the old fault (a
    /// stuck reselect), and must keep the old sentence.
    #[test]
    fn a_migration_off_a_reachable_home_keeps_the_carrier_sentence() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view)
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/active_slave"),
                "cfab-gw249-a\n",
            )
            .socket("/run/cfab/cfab.sock", &components_with_ingress(&view, &[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  mgmt ingress via eth9 (home eth0 has carrier)\n"),
            "{}",
            report.output
        );
    }

    /// No wire reaches the router: where the bond sits explains nothing, so that is the only
    /// thing the line says.
    #[test]
    fn an_ingress_leg_no_wire_can_reach_the_router_over_says_exactly_that() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view).socket(
            "/run/cfab/cfab.sock",
            &components_with_ingress(&view, &["eth9", "eth1", "eth0"]),
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  mgmt ingress: router unreachable on every wire\n"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("mgmt ingress via "),
            "the active port explains nothing here: {}",
            report.output
        );
    }

    /// The prober reporting every wire reachable adds nothing to a healthy status.
    #[test]
    fn a_healthy_leg_with_the_prober_reporting_stays_silent() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view)
            .socket("/run/cfab/cfab.sock", &components_with_ingress(&view, &[]));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        for needle in ["router unreachable", "mgmt ingress via "] {
            assert!(
                !report.output.contains(needle),
                "{needle}:\n{}",
                report.output
            );
        }
    }

    /// A dark bond whose active port is a stranger is not the same fault as a dark bond, and
    /// the ingress leg says so in the fallback leg's words.
    #[test]
    fn an_ingress_bond_with_a_foreign_port_active_is_named() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view)
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/mii_status"),
                "down\n",
            )
            .file(
                &format!("/sys/class/net/{GW_BOND}/bonding/active_slave"),
                "bond0\n",
            );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  mgmt ingress down with foreign port bond0 active\n"),
            "{}",
            report.output
        );
    }

    /// A leg carrying the bond's name that is not a bond at all: named, with the remedy, in the
    /// one spelling the fallback leg already uses.
    #[test]
    fn an_ingress_leg_that_is_not_a_bond_says_re_run_cfab_up() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        sys.files
            .remove(&format!("/sys/class/net/{GW_BOND}/bonding/mii_status"));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  mgmt ingress: cfab-gw249 is not a bond \
                 (/sys/class/net/cfab-gw249/bonding unreadable) — re-run cfab up\n"
            ),
            "{}",
            report.output
        );
    }

    /// The F5 class, on the ingress leg: the bond is up on its home wire but one port never
    /// came back (a re-enumerated USB NIC leaves the leg unattached until something rebuilds
    /// it). The bond's own `mii_status` reads healthy, so only the port list can say it.
    #[test]
    fn an_ingress_port_that_is_not_attached_is_named() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view).file(
            &format!("/sys/class/net/{GW_BOND}/bonding/slaves"),
            "cfab-gw249-a cfab-gw249-c\n",
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  mgmt ingress: port cfab-gw249-b on eth1 is not a port of cfab-gw249 — \
                 re-run cfab up\n"
            ),
            "{}",
            report.output
        );
    }

    /// The same check on a universal segment: one reader, one spelling, both legs.
    #[test]
    fn a_fallback_port_that_is_not_attached_is_named() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view).file(
            "/sys/class/net/cfab-st-fb/bonding/slaves",
            "cfab-st-fb-a cfab-st-fb-c\n",
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  storage fallback: port cfab-st-fb-b on eth1 is not a port of cfab-st-fb \
                 — re-run cfab up\n"
            ),
            "{}",
            report.output
        );
    }

    /// A wire that vanished under a running fabric takes its ingress PORT and nothing else:
    /// the bond outlives it (that is the whole point of the migrating leg), so the leg's own
    /// reads must keep happening. F15's set, on the shape F15 never saw.
    #[test]
    fn a_vanished_wire_takes_the_ingress_port_and_not_the_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        sys.files.remove("/sys/class/net/eth1");
        let absent = absent_ifs(&sys, &view);
        assert!(absent.contains("cfab-gw249-b"), "{absent:?}");
        assert!(!absent.contains("cfab-gw249"), "{absent:?}");
        // and the port on a vanished wire is not then reported as missing: the wire's own
        // line is the account of it.
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            !report.output.contains("cfab-gw249-b is not a port"),
            "{}",
            report.output
        );
    }

    /// A default line the kernel has flagged `linkdown` is a DISTINCT failure from no default
    /// at all, with its own wording (ignore_routes_with_linkdown=1 keeps the line but makes it
    /// inactive for lookups). INFERRED (task E2.2): the exact flag string is settled live in E3.
    /// On a leg PINNED to one domain this flag is the only carrier signal there is, so it is
    /// the shape these two tests use; a migrating leg's bond speaks for itself
    /// (`a_dark_migrating_ingress_leg_is_reported_once`).
    #[test]
    fn a_linkdown_default_is_a_distinct_reason() {
        let f = fabric_with_a_domain_gw();
        let host = View::new(&f, "pve1-tb").unwrap();
        let mut sys = ingress_host_sys(
            &host,
            serde_json::json!([
                { "peer": "192.168.249.254", "state": "Established", "pfx_snt": 5 }
            ]),
        )
        .on_stdout(
            &["ip", "route", "show", "table", "249"],
            "default via 10.249.3.1 dev cfab-mg proto ospf metric 20 linkdown\n",
        );
        let report = run(&mut sys, &host, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "mgmt gw 192.168.249.254 unreachable (table 249 default is linkdown - the \
                 ingress leg has no carrier)"
            ),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("has no default"),
            "the linkdown wording must not spill into the no-default condition: {}",
            report.output
        );
    }

    /// A table can hold more than one `default ` line (transient ECMP, a stale entry before a
    /// `replace` lands). The FIRST one here is healthy; the SECOND is `linkdown`. Every
    /// `default ` line must be checked, not just the first — an old `.find()`-first check would
    /// stop at the healthy first line and never notice the dead second, silently masking a
    /// degraded return path.
    #[test]
    fn a_second_default_line_flagged_linkdown_still_degrades() {
        let f = fabric_with_a_domain_gw();
        let host = View::new(&f, "pve1-tb").unwrap();
        let mut sys = ingress_host_sys(
            &host,
            serde_json::json!([
                { "peer": "192.168.249.254", "state": "Established", "pfx_snt": 5 }
            ]),
        )
        .on_stdout(
            &["ip", "route", "show", "table", "249"],
            "default via 10.249.3.1 dev cfab-mg proto ospf metric 20\n\
             default via 10.249.3.2 dev cfab-mg proto ospf metric 30 linkdown\n",
        );
        let report = run(&mut sys, &host, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "mgmt gw 192.168.249.254 unreachable (table 249 default is linkdown - the \
                 ingress leg has no carrier)"
            ),
            "a dead second `default ` line must degrade the return path even though the first \
             `default ` line is healthy: {}",
            report.output
        );
    }

    /// No default line at all keeps today's wording — a different condition, a different string.
    #[test]
    fn no_default_at_all_keeps_its_own_wording() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let mut sys = ingress_host_sys(
            &host,
            serde_json::json!([
                { "peer": "192.168.249.254", "state": "Established", "pfx_snt": 5 }
            ]),
        )
        .on_stdout(&["ip", "route", "show", "table", "249"], "");
        let report = run(&mut sys, &host, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("mgmt gw 192.168.249.254 unreachable (table 249 has no default)"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("is linkdown"),
            "the no-default wording must not spill into the linkdown condition: {}",
            report.output
        );
    }

    /// A healthy default (present, no linkdown/dead flag) notes nothing about the return path.
    #[test]
    fn a_healthy_default_notes_nothing() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let mut sys = ingress_host_sys(
            &host,
            serde_json::json!([
                { "peer": "192.168.249.254", "state": "Established", "pfx_snt": 5 }
            ]),
        );
        let report = run(&mut sys, &host, 0, false, None).unwrap();
        assert!(
            !report.output.contains("has no default") && !report.output.contains("is linkdown"),
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Down);
        assert_eq!(report.code, 3);
        assert_eq!(
            report.output,
            "DOWN (fabric not applied) on pve3-tb (leaf)\n\
             \x20 prefs storage: eth9 eth1 eth0 (derived)\n\
             \x20 prefs cluster: eth1 eth9 eth0 (derived)\n\
             \x20 prefs mgmt: eth0 eth9 eth1 (derived)\n"
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
        assert_eq!(run(&mut sys, &view, 0, true, None).unwrap().code, 0);

        let mut bfd = all_bfd_up(&f);
        bfd[0].1 = "down";
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        let r = run(&mut sys, &view, 0, true, None).unwrap();
        assert_eq!(r.state, State::UpDegraded, "{}", r.output);
        assert_eq!(r.code, 0, "--permissive: UP-DEGRADED exits 0");

        let mut sys = leaf_env(&view);
        let r = run(&mut sys, &view, 0, true, None).unwrap();
        assert_eq!(r.state, State::Failed);
        assert_eq!(r.code, 2, "--permissive never masks FAILED");

        let mut sys = MockSys::default();
        let r = run(&mut sys, &view, 0, true, None).unwrap();
        assert_eq!(r.state, State::Down);
        assert_eq!(r.code, 3, "--permissive never masks DOWN");
    }

    /// A member that declares no fallback rows still prints all three fields — `0/0`, so the
    /// line has one shape everywhere and a reader never has to count separators.
    #[test]
    fn a_member_with_no_fallback_rows_prints_zero_of_zero() {
        let text = fixtures::without_universal_legs(&fixtures::example());
        let f = Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap();
        let view = View::new(&f, "pve3-tb").unwrap();
        assert!(view.fallback_rows().is_empty());
        let mut sys = healthy_leaf(&view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
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
        // The count reads the engine socket once per pass; the last reply repeats forever.
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket_seq("/run/cfab/engine.sock", &[degraded, up]);
        let report = run(&mut sys, &view, 30, false, None).unwrap();
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
        let report = run(&mut sys, &view, 6, false, None).unwrap();
        assert_eq!(report.state, State::Failed, "{}", report.output);
        assert_eq!(sys.slept.len(), 3, "6 s in 2 s steps: FAILED waited it out");
    }

    /// F18: "not applied" is a state a fabric passes THROUGH, not only one it never left. The
    /// ruled SIGHUP-changed path tears the fabric down, exits 6 and lets systemd restart the
    /// unit, so the run dir is gone for a couple of seconds — exactly what an operator's
    /// `--wait` is for. The wait must ride it out and report the fabric that came back.
    #[test]
    fn wait_rides_out_a_fabric_that_is_not_applied_yet() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).appears_after(1, &f.run_dir, "");
        sys.files.remove(&f.run_dir);
        let report = run(&mut sys, &view, 6, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(report.code, 0);
        assert_eq!(
            headline(&report),
            "UP (2/2 | 18/18 | 6/6) on pve3-tb (leaf)"
        );
        assert_eq!(
            sys.slept,
            vec![Duration::from_secs(2)],
            "one 2 s sleep, then the run dir was back"
        );
    }

    /// A fabric that never comes up waits the deadline out like FAILED and DEGRADED do, then
    /// reports the same verdict it reports today.
    #[test]
    fn wait_runs_to_the_deadline_on_a_fabric_that_is_never_applied() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = MockSys::default();
        let report = run(&mut sys, &view, 6, false, None).unwrap();
        assert_eq!(report.state, State::Down);
        assert_eq!(report.code, 3);
        assert_eq!(
            headline(&report),
            "DOWN (fabric not applied) on pve3-tb (leaf)"
        );
        assert_eq!(sys.slept.len(), 3, "6 s in 2 s steps");
    }

    /// `--wait 0` stays one instant read on a fabric that is not applied: the poll loop is
    /// entered, the deadline is already spent, nothing sleeps.
    #[test]
    fn wait_zero_on_a_fabric_that_is_not_applied_is_one_instant_read() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = MockSys::default();
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Down);
        assert_eq!(
            headline(&report),
            "DOWN (fabric not applied) on pve3-tb (leaf)"
        );
        assert!(sys.slept.is_empty(), "--wait 0 is one instant read");
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
        let report = run(&mut sys, &view, 6, false, None).unwrap();
        assert_eq!(report.state, State::UpDegraded, "{}", report.output);
        assert_eq!(sys.slept.len(), 3, "6 s in 2 s steps");
    }

    /// F22 (VERIFIED on the rack 2026-09-07): the headline goes UP as soon as the sessions are
    /// up, seconds before the engine has installed the routes the identities answer on — and
    /// `--wait` returned on the headline alone, so the role's deployment gate passed ~3 s before
    /// the fabric could carry anything. A settling reason line holds the wait.
    #[test]
    fn wait_holds_while_a_settle_line_is_present() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        // The cluster route to pve1-tb is not installed yet: `ip route get` answers nothing.
        let mut sys = healthy_leaf(&view).on_stdout(&["ip", "route", "get", "10.199.0.1"], "");
        let report = run(&mut sys, &view, 6, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert_eq!(
            sys.slept.len(),
            3,
            "the wait must ride out the settle, not return on the headline:\n{}",
            report.output
        );
    }

    /// The other half: the wait ends the moment the settle lines are gone, not at the deadline.
    /// The rp_filter one stands in for every line the fabric installs after `up` — it is the one
    /// a `MockSys` can make arrive while the loop is sleeping.
    #[test]
    fn wait_ends_as_soon_as_the_settle_lines_clear() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let path = "/proc/sys/net/ipv4/conf/cfab-mg-fb/rp_filter";
        let mut sys = healthy_leaf(&view)
            .file(path, "1\n")
            .appears_after(1, path, "2\n");
        let report = run(&mut sys, &view, 30, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            !report.output.contains("rp_filter"),
            "the settled fabric is what gets reported:\n{}",
            report.output
        );
        assert_eq!(
            sys.slept,
            vec![Duration::from_secs(2)],
            "one 2 s sleep, then the settle line was gone"
        );
    }

    /// Standing lines are what a healthy fabric prints by design (the mark backend on every
    /// member, an operator's edited file here). They must never hold the gate: a member with one
    /// would wait the whole deadline out on every single `status --wait`.
    #[test]
    fn wait_ends_at_once_when_only_standing_lines_are_present() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let text = example_text().replace("node = 3", "node = 7");
        let mut sys = healthy_leaf(&view).file(CONFIG, &text);
        let report = run(&mut sys, &view, 30, false, Some(cfg())).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report.output.contains("changed since apply") && report.output.contains("mark: nft"),
            "the standing lines must still be reported:\n{}",
            report.output
        );
        assert!(
            sys.slept.is_empty(),
            "a standing line is not something to wait for:\n{}",
            report.output
        );
    }

    /// F22, the second half: with no route at all `ip route get` names no device, and the line
    /// read `cluster to pve1-tb via , expected cfab-cl` — an empty name where a device belongs.
    /// One spelling per condition: no route is its own line, and it stands in for the src-pin
    /// line too (there is no route to pin a source on).
    #[test]
    fn a_peer_with_no_route_says_so_instead_of_an_empty_device() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).on_stdout(&["ip", "route", "get", "10.199.0.1"], "");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("cluster to pve1-tb: no route yet, expected cfab-cl"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("via ,"),
            "an empty device name is not a spelling:\n{}",
            report.output
        );
        assert!(
            !report.output.contains("src not pinned"),
            "no route is one condition, not two:\n{}",
            report.output
        );
    }

    /// The bond is active on a wire that is not the home while the home still has carrier — a
    /// stuck reselect. Ruled a warn: it is a reason line, and the state does not move.
    #[test]
    fn a_stuck_reselect_is_a_reason_line_not_a_state() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            // storage homes on eth9 (cfab-st, cost 10); the bond sits on the mg port
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "cfab-st-fb-c\n",
            )
            .file("/sys/class/net/eth9/carrier", "1\n");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  storage fallback via eth0 (home eth9 has carrier)\n"),
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
                "cfab-st-fb-c\n",
            )
            .file("/sys/class/net/eth9/carrier", "0\n");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report.output.contains("  storage fallback via eth0\n"),
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
            "cfab-st-fb-c\n",
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  storage fallback via eth0 (home eth9 carrier unreadable)\n"),
            "{}",
            report.output
        );
    }

    /// Every port dark: one spelling, `fallback <zone> no carrier`.
    #[test]
    fn a_dark_fallback_bond_says_no_carrier() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file("/sys/class/net/cfab-cl-fb/bonding/mii_status", "down\n")
            .file("/sys/class/net/cfab-cl-fb/bonding/active_slave", "\n");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains("  cluster fallback no carrier\n"),
            "{}",
            report.output
        );
    }

    /// The `components` document with the fallback prober's rows for storage's leg on a leaf.
    /// `dark` names wires the peers are confirmed unreachable over, `suspect` wires that are
    /// silent and being asked, and `quiet` says no wire heard anything at all.
    fn components_with_fallback(
        view: &View,
        active: &str,
        dark: &[&str],
        suspect: &[&str],
        quiet: bool,
    ) -> String {
        let mut doc: serde_json::Value =
            serde_json::from_str(&healthy_components(view)).expect("the healthy fixture");
        let ports: Vec<serde_json::Value> = [("eth9", "a"), ("eth1", "b"), ("eth0", "c")]
            .iter()
            .map(|(wire, island)| {
                serde_json::json!({
                    "wire": wire, "island": island,
                    "reachable": !dark.contains(wire),
                    "suspect": suspect.contains(wire),
                    "last_reply_ms": if dark.contains(wire) { serde_json::Value::Null }
                                     else { serde_json::json!(400) },
                })
            })
            .collect();
        doc["fallback"] = serde_json::json!([{
            "zone": "storage", "bond": "cfab-st-fb", "active": active,
            "quiet": quiet, "ports": ports,
        }]);
        doc.to_string()
    }

    /// The migration this whole mechanism exists to make: the home wire keeps carrier, its
    /// island's uplink is dead, and the leg has moved. The cause is named, and it STANDS —
    /// it holds until somebody fixes the uplink.
    #[test]
    fn a_fallback_leg_moved_off_a_peer_dead_home_names_the_peers() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "cfab-st-fb-c\n",
            )
            .file("/sys/class/net/eth9/carrier", "1\n")
            .socket(
                "/run/cfab/cfab.sock",
                &components_with_fallback(&view, "cfab-st-fb-c", &["eth9"], &[], false),
            );
        let report = run(&mut sys, &view, 6, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  storage fallback via eth0 (home eth9: peers unreachable)\n"),
            "{}",
            report.output
        );
        // STANDING (F22): a member living on a dead island uplink would otherwise spend every
        // deadline of every `status --wait` on a line that is not going to change by itself.
        assert!(
            sys.slept.is_empty(),
            "a verdict must not hold the wait:\n{}",
            report.output
        );
    }

    /// A suspicion is not a verdict: the home wire is silent and being asked, and the line says
    /// so in the settling voice, so `status --wait` rides it out instead of declaring it.
    #[test]
    fn a_silent_home_wire_is_settling_not_a_verdict() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "cfab-st-fb-c\n",
            )
            .file("/sys/class/net/eth9/carrier", "1\n")
            .socket(
                "/run/cfab/cfab.sock",
                &components_with_fallback(&view, "cfab-st-fb-c", &[], &["eth9"], false),
            );
        let report = run(&mut sys, &view, 6, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  storage fallback via eth0 (home eth9: no peers heard)\n"),
            "{}",
            report.output
        );
        // Settling (F22): `--wait` rides it out rather than returning on the UP headline. The
        // next tick or two turns it into either silence or a standing verdict.
        assert_eq!(
            sys.slept.len(),
            3,
            "a suspicion must hold the wait:\n{}",
            report.output
        );
    }

    /// Nobody is heard on any wire. The fault is not per-wire, so the line does not name one —
    /// and nothing was moved.
    #[test]
    fn a_fallback_leg_that_hears_nobody_anywhere_says_so_once() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).socket(
            "/run/cfab/cfab.sock",
            &components_with_fallback(&view, "cfab-st-fb-a", &[], &["eth9", "eth1", "eth0"], true),
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  storage fallback: no peers heard on any wire\n"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("storage fallback via "),
            "where the bond sits explains nothing here: {}",
            report.output
        );
    }

    /// Every wire confirmed dead: the same shape as the ingress leg's, with the noun swapped.
    #[test]
    fn a_fallback_leg_no_wire_reaches_its_peers_over_says_exactly_that() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).socket(
            "/run/cfab/cfab.sock",
            &components_with_fallback(&view, "cfab-st-fb-a", &["eth9", "eth1", "eth0"], &[], false),
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  storage fallback: peers unreachable on every wire\n"),
            "{}",
            report.output
        );
    }

    /// A prober reporting every wire live adds nothing: a healthy fallback leg is silent.
    #[test]
    fn a_healthy_fallback_leg_with_the_prober_reporting_stays_silent() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view).socket(
            "/run/cfab/cfab.sock",
            &components_with_fallback(&view, "cfab-st-fb-a", &[], &[], false),
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "{}", report.output);
        assert!(
            !report.output.contains("storage fallback"),
            "{}",
            report.output
        );
    }

    /// A supervisor from before the fallback prober publishes no rows at all, and every line
    /// then reads exactly as it did before it existed — the carrier wording, not a verdict
    /// about peers nobody asked about.
    #[test]
    fn an_older_supervisor_falls_back_to_the_carrier_wording() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "cfab-st-fb-c\n",
            )
            .file("/sys/class/net/eth9/carrier", "1\n");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  storage fallback via eth0 (home eth9 has carrier)\n"),
            "{}",
            report.output
        );
    }

    /// Row 19's actuated end: a bond cfab owns is down with a stranger still attached to it.
    /// That reads exactly like a dark bond, and "no carrier" would send an operator to the
    /// wrong end of the cable. The line reports what was READ — `status` cannot know whether
    /// the watchdog ever tried to evict the intruder, and on a leaf it is not even scheduled.
    #[test]
    fn a_bond_downed_over_a_foreign_port_says_so_not_no_carrier() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf(&view)
            .file("/sys/class/net/cfab-st-fb/bonding/mii_status", "down\n")
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "someone-elses0\n",
            );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  storage fallback down with foreign port someone-elses0 active\n"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("storage fallback no carrier"),
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(
            headline(&report),
            "UP-DEGRADED (2/2 | 18/18 | 4/6) on pve3-tb (leaf)"
        );
        assert!(
            report.output.contains(
                "  storage fallback: cfab-st-fb is missing from the engine's ospf state \
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
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
        // Above `[cost] leaf_offset`, so the weak arm accepts it; not cost + offset, so the
        // exact arm must not.
        link["metric"] = serde_json::json!(31000);
        let mut sys = primary_routes(leaf_env(&view), &view)
            .socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "a wrong cost never amputates");
        assert!(
            report.output.contains(
                "  ospf 99: a transit link in our router LSA is advertised below \
                 `[cost] leaf_offset`=30000"
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  rp_filter cfab-mg-fb=1 (want 2 = loose)\n"),
            "{}",
            report.output
        );
    }

    /// Task 5b (RULED, James 2026-09-05): a declared wire with no netdev gets its own reason
    /// line — distinct from the existing "no carrier" wording — and grades UP-DEGRADED by
    /// adjacency exactly as a carrier-less wire does, never a refusal.
    #[test]
    fn status_names_an_absent_wire_in_its_own_words() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        // eth9 carries storage seg1 (primary), cluster seg2 (backup) and mgmt seg3 (backup):
        // an absent eth9 kills adjacency on exactly those three (zone, seg) pairs, for both
        // peers.
        let mut bfd = Vec::new();
        for p in [2u8, 3u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    let dark = (z.name == "storage" && seg == 1)
                        || (z.name == "cluster" && seg == 2)
                        || (z.name == "mgmt" && seg == 3);
                    bfd.push((
                        format!("{}.{seg}.{p}", z.block()),
                        if dark { "down" } else { "up" },
                    ));
                }
            }
        }
        let mut sys = host_env(&view);
        // Review finding 7 (2026-09-05): a real absent netdev has no children either — drop
        // every "/sys/class/net/eth9"-prefixed entry, not just the bare directory marker, so
        // this test would fail (not pass by ordering alone) if any later check started
        // reading a file under an absent wire.
        sys.files
            .retain(|k, _| !k.starts_with("/sys/class/net/eth9"));
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
        let mut sys = sys.socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  wire eth9 absent (no such netdev) — its segments are not configured\n"
            ),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("no carrier"),
            "not the carrier row: {}",
            report.output
        );
        assert_eq!(
            report.code, 1,
            "UP-DEGRADED: graded by adjacency, as today: {}",
            report.output
        );
    }

    /// A forwarding host whose eth9 has vanished the way a USB NIC does: the netdev, its
    /// procfs directory and every VLAN leg on it are gone together. The fallback bonds stay —
    /// a bond survives losing a port — and so do the peers, which still grade this member.
    fn host_without_eth9(f: &Fabric, view: &View) -> MockSys {
        let mut bfd = Vec::new();
        for p in [2u8, 3u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    let dark = (z.name == "storage" && seg == 1)
                        || (z.name == "cluster" && seg == 2)
                        || (z.name == "mgmt" && seg == 3);
                    bfd.push((
                        format!("{}.{seg}.{p}", z.block()),
                        if dark { "down" } else { "up" },
                    ));
                }
            }
        }
        let mut sys = healthy_host(f, view);
        let mut gone: BTreeSet<String> = BTreeSet::new();
        gone.insert("eth9".to_string());
        for r in view.class_rows().into_iter().filter(|r| r.wire == "eth9") {
            gone.insert(r.ifname);
        }
        for s in view
            .fallback_rows()
            .into_iter()
            .flat_map(|r| r.ports)
            .chain(view.gw_rows().into_iter().flat_map(|r| r.ports))
            .filter(|s| s.wire == "eth9")
        {
            gone.insert(s.ifname);
        }
        sys.files.retain(|k, _| {
            !gone.iter().any(|g| {
                *k == format!("/sys/class/net/{g}")
                    || k.starts_with(&format!("/sys/class/net/{g}/"))
                    || k.starts_with(&format!("/proc/sys/net/ipv4/conf/{g}/"))
            })
        });
        sys.socket("/run/cfab/engine.sock", &engine_doc(view, &bfd))
    }

    /// Every interface a vanished wire carried is gone with it — a real USB unplug takes
    /// `/sys/class/net/eth9` AND `/proc/sys/net/ipv4/conf/eth9`, plus every VLAN leg on it.
    /// F15 (observed on hardware 2026-09-07, 0.4.4): `status` then exited 1 printing only
    /// `No such file or directory (os error 2)`. Status grades a vanished wire; it never fails
    /// on a read the kernel can take away underneath it.
    #[test]
    fn an_absent_wire_takes_its_procfs_with_it_and_status_still_grades() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = host_without_eth9(&f, &view);
        let report = match run(&mut sys, &view, 0, false, None) {
            Ok(r) => r,
            Err(e) => panic!("F15: status must grade a vanished wire, not fail with [{e}]"),
        };
        assert!(
            report.output.contains(
                "  wire eth9 absent (no such netdev) — its segments are not configured\n"
            ),
            "{}",
            report.output
        );
        assert_eq!(
            headline(&report),
            "UP-DEGRADED (2/2 | 12/18 | 6/6) on pve1-tb (host)",
            "{}",
            report.output
        );
        assert_eq!(report.code, 1, "{}", report.output);
        // No read the wire took with it may reach the output as a raw io error, and the
        // interfaces that went with the wire are covered by its one line, not named again.
        assert!(
            !report.output.contains("os error") && !report.output.contains("unreadable"),
            "{}",
            report.output
        );
        for gone in ["cfab-st", "cfab-cl-bk", "cfab-mg-b2"] {
            assert!(
                !report.output.contains(&format!("rp_filter {gone}=")),
                "{gone} went with eth9: {}",
                report.output
            );
        }
    }

    /// The absent set is exactly the vanished wire's interfaces: a sibling wire's own drift
    /// is still read and still named while eth9 is gone.
    #[test]
    fn a_sibling_wire_is_still_checked_while_eth9_is_absent() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let sibling = view
            .class_rows()
            .into_iter()
            .find(|r| r.wire == "eth1")
            .map(|r| r.ifname)
            .expect("a class row on eth1");
        let mut sys = host_without_eth9(&f, &view).file(
            &format!("/proc/sys/net/ipv4/conf/{sibling}/rp_filter"),
            "1\n",
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report
                .output
                .contains(&format!("rp_filter {sibling}=1 (want 2 = loose)")),
            "{}",
            report.output
        );
        assert!(
            report.output.contains("wire eth9 absent (no such netdev)"),
            "{}",
            report.output
        );
    }

    /// The other half of the class: a file `status` expected to read and could not, on an
    /// interface whose wire is still there. That is not the vanished-wire case and gets no
    /// silence — it is named in its own reason line, and it is still not a bare io error.
    #[test]
    fn an_unreadable_interface_file_is_a_reason_line_not_a_failure() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        sys.files
            .remove("/proc/sys/net/ipv4/conf/cfab-st/forwarding");
        let report = match run(&mut sys, &view, 0, false, None) {
            Ok(r) => r,
            Err(e) => panic!("status must report an unreadable file, not fail with [{e}]"),
        };
        assert!(
            report.output.contains(
                "  /proc/sys/net/ipv4/conf/cfab-st/forwarding unreadable (FATAL: mock: no file \
                 /proc/sys/net/ipv4/conf/cfab-st/forwarding)\n"
            ),
            "{}",
            report.output
        );
        assert_eq!(report.state, State::Up, "{}", report.output);
    }

    /// `--wait` over a vanished wire behaves like any other degraded member: it polls to the
    /// deadline and reports the state it reached, never a bare io error.
    #[test]
    fn wait_over_an_absent_wire_runs_to_the_deadline() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = host_without_eth9(&f, &view);
        let report = match run(&mut sys, &view, 4, false, None) {
            Ok(r) => r,
            Err(e) => panic!("F15: --wait must grade a vanished wire, not fail with [{e}]"),
        };
        assert_eq!(report.state, State::UpDegraded, "{}", report.output);
        assert_eq!(sys.slept.len(), 2, "4 s in 2 s steps");
        assert!(
            report.output.contains(
                "  wire eth9 absent (no such netdev) — its segments are not configured\n"
            ),
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  return path missing: pref 2002 from 10.99.0.0/16 unreachable\n"),
            "{}",
            report.output
        );
    }

    /// Two members with no domain in common: pve1-tb has only its st wire, pve2-tb only its cl
    /// wire, so they share no segment in any zone. The fallback bond is the only path between
    /// them — and reaching them over it is health.
    fn disjoint_fabric() -> Fabric {
        let text = fixtures::with_wires(
            &fixtures::with_wires(&fixtures::example(), "pve1-tb", "eth9@a:5000"),
            "pve2-tb",
            "eth1@b:1000",
        );
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    /// Every declared BFD leg up, as the runtime half of the expectation rule.
    fn all_legs_up(view: &View) -> BTreeSet<(u8, String, u8)> {
        expected_links(view)
            .unwrap()
            .into_iter()
            .map(|e| (e.node, e.zone, e.seg))
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
    fn a_domain_disjoint_peer_is_expected_over_the_fallback_bond() {
        let f = disjoint_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert!(
            segments_of(&f, f.member("pve1-tb").unwrap())
                .intersection(&segments_of(&f, f.member("pve2-tb").unwrap()))
                .next()
                .is_none()
        );
        let mut sys = disjoint_routes([
            // the domain-disjoint peer: over the storage/cluster/mgmt fallback bonds
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
            once_each(&c.conditions()),
            vec![
                "cluster to pve2-tb via fallback".to_string(),
                "mgmt to pve2-tb via fallback".to_string(),
                "storage to pve2-tb via fallback".to_string(),
            ]
        );
    }

    #[test]
    fn a_domain_disjoint_peer_off_the_fallback_bond_is_named() {
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
            once_each(&c.conditions())
                .contains(&"storage to pve2-tb via cfab-st, expected cfab-st-fb".to_string()),
            "{:?}",
            c.reasons
        );
    }

    /// pve1-tb and pve3-tb sit on the st and mg domains, pve2-tb only on cl: pve2-tb shares no
    /// segment with pve3-tb in any zone, while pve1-tb shares two per zone (so one of them can
    /// go dark without the zone losing its only session).
    fn half_disjoint_fabric() -> Fabric {
        let text = fixtures::with_wires(
            &fixtures::with_wires(
                &fixtures::with_wires(&fixtures::example(), "pve1-tb", "eth9@a:5000 eth0@c:1000"),
                "pve2-tb",
                "eth1@b:1000",
            ),
            "pve3-tb",
            "eth9@a:10000 eth0@c:1000",
        );
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
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
                .filter(|e| e.node == 1 && e.zone == "storage")
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
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

    /// A leaf that is domain-disjoint from one peer: the bond is that peer's expected path in
    /// every zone, and being on it is health — the reason line only appears where it is not.
    #[test]
    fn a_domain_disjoint_peer_off_the_bond_is_named_while_a_segment_is_down() {
        let f = half_disjoint_fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        assert!(
            segments_of(&f, view.member)
                .intersection(&segments_of(&f, f.member("pve2-tb").unwrap()))
                .next()
                .is_none(),
            "pve2-tb must be domain-disjoint from pve3-tb in every zone"
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
            // the domain-disjoint peer: cluster and mgmt over the bond, storage NOT
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
        let report = run(&mut sys, &view, 0, false, None).unwrap();
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

    // ---- Task 11: the components block and the reworded rows (spec §9) ------------------

    /// A `components:` line is always printed, and last — after every reason line.
    #[test]
    fn the_components_line_is_always_printed_last() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        let last = report.output.lines().last().unwrap();
        assert_eq!(
            last,
            "  components: engine running 1h00m (0 restarts) | shape-daemon running 1h00m \
             (0 restarts) | conf-sync stopped (not clustered) | watchdog ok 2s ago"
        );
    }

    /// No supervisor answering: stated once on the components line and once in the engine row,
    /// both naming the run-dir socket, and the old `cfab-engine.service` spelling gone.
    #[test]
    fn no_supervisor_is_stated_once_on_the_components_line_and_in_the_engine_row() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        // The fabric is applied (leaf_env creates the run dir) but no cfab.sock answers, and the
        // engine's own socket is silent too.
        let mut sys = leaf_env(&view);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  engine not running: no supervisor answering on /run/cfab/cfab.sock — start it \
                 (systemctl start cfab)\n"
            ),
            "{}",
            report.output
        );
        assert!(
            report
                .output
                .contains("  components: no supervisor answering on /run/cfab/cfab.sock\n"),
            "{}",
            report.output
        );
        assert!(
            !report.output.contains("cfab-engine.service"),
            "the old spelling must be gone: {}",
            report.output
        );
    }

    /// The watchdog and shaping rows are read from the components document, not a local probe:
    /// a stale tick is "not ticking", a shape-daemon that is not `running` is "shaping down".
    #[test]
    fn the_watchdog_and_shaping_rows_read_the_components_document() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let comps = serde_json::json!({
            "supervisor": {"pid": 1234, "uptime_s": 3601, "applying": false, "applies": 1,
                "last_apply_error": null},
            "components": [
                {"name": "engine", "state": "running", "pid": 1240, "uptime_s": 3600,
                 "restarts": 0, "last_exit": null},
                {"name": "shape-daemon", "state": "restarting", "pid": null, "uptime_s": null,
                 "restarts": 3, "last_exit": {"cause": "signal SIGKILL", "s_ago": 1}},
                {"name": "conf-sync", "state": "stopped", "pid": null, "uptime_s": null,
                 "restarts": 0, "last_exit": null, "why": "not clustered"}
            ],
            "watchdog": {"last_tick_s_ago": 47, "result": "error", "detail": "no tick"}
        })
        .to_string();
        let mut sys = healthy_host(&f, &view).socket("/run/cfab/cfab.sock", &comps);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        let out = &report.output;
        assert!(
            out.contains(
                "  forwarding watchdog not ticking (last tick 47s ago) — the actuator is down\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("  shaping down: shape-daemon is restarting, 3 restart(s)\n"),
            "{out}"
        );
    }

    /// A BFD bind failure the engine could not recover from, diagnosed from the child ring
    /// buffer over cfab.sock — the exact gap this change closes: no frr enabled and no bfdd
    /// process (the host probe above finds nothing), yet the engine is down because *something*
    /// holds udp/3784, and the ring buffer carries holo's line. The supervisor reports the engine
    /// down; status reads `log engine` and turns the line into the named remedy.
    #[test]
    fn a_bind_failure_in_the_ring_buffer_is_diagnosed_when_the_engine_is_down() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let comps = serde_json::json!({
            "supervisor": {"pid": 1234, "uptime_s": 60, "applying": false, "applies": 1,
                "last_apply_error": null},
            "components": [
                {"name": "engine", "state": "restarting", "pid": null, "uptime_s": null,
                 "restarts": 4, "last_exit": {"cause": "exit 1", "s_ago": 1}}
            ],
            "watchdog": {"last_tick_s_ago": 2, "result": "ok", "detail": null}
        })
        .to_string();
        let log = serde_json::json!({
            "lines": [
                "engine starting",
                "ERROR bfd: cannot bind udp 0.0.0.0:3784: address in use (holder unknown)"
            ]
        })
        .to_string();
        // No engine.sock: `state` fails, the engine is down. cfab.sock answers both verbs.
        let mut sys = leaf_env(&view)
            .socket_verb("/run/cfab/cfab.sock", "components", &comps)
            .socket_verb("/run/cfab/cfab.sock", "log", &log);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  bfd udp/3784: the engine is not running and could not bind it — bfd: cannot \
                 bind udp 0.0.0.0:3784: address in use (holder unknown)\n"
            ),
            "{}",
            report.output
        );
        assert!(
            report.output.contains(
                "  remedy: find the holder (ss -ulpn | grep ':3784') and stop it; or declare a \
                 free [bfd] port (now 3784) in fabric.toml on EVERY member — every peer of a \
                 session must use the same port\n"
            ),
            "{}",
            report.output
        );
    }

    /// Teeth for the running-engine gate: the engine that answers holds the port, so a bind line
    /// still sitting in its ring buffer is stale history and must be suppressed. Invariant: the
    /// diagnosis fires only for an engine the supervisor reports NOT running. Regressing the gate
    /// (deleting the `CompState::Running` early return in `bfd_port`) makes this test fail —
    /// verified during development, then the gate was restored.
    #[test]
    fn a_stale_bind_line_is_suppressed_while_the_engine_runs() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let log = serde_json::json!({
            "lines": [
                "ERROR bfd: cannot bind udp 0.0.0.0:3784: address in use (holder unknown)"
            ]
        })
        .to_string();
        // Healthy host: the engine is up and the supervisor reports it `running`; the ring buffer
        // still carries a bind line from an earlier start it has since survived.
        let mut sys = healthy_host(&f, &view)
            .socket_verb(
                "/run/cfab/cfab.sock",
                "components",
                &healthy_components(&view),
            )
            .socket_verb("/run/cfab/cfab.sock", "log", &log);
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert_eq!(report.state, State::Up, "output:\n{}", report.output);
        assert!(
            !report
                .output
                .contains("the engine is not running and could not bind it"),
            "a stale bind line must not be diagnosed while the engine runs:\n{}",
            report.output
        );
    }

    /// `status` still never writes with the new socket reads: the same snapshot-and-allowlist
    /// test, whose read-only allowlist now covers `unix_request <run_dir>/cfab.sock components`.
    /// A healthy supervisor answering cfab.sock is exercised through every fixture in
    /// `status_never_writes`; this asserts the allowlist accepts the new verb and rejects a
    /// hypothetical write on the same socket.
    #[test]
    fn status_still_never_writes_with_the_new_socket_reads() {
        assert!(is_read_only("unix_request /run/cfab/cfab.sock components"));
        assert!(is_read_only(
            "unix_request /run/cfab/cfab.sock log engine 2"
        ));
        assert!(is_read_only("unix_request /run/cfab/engine.sock state"));
        assert!(!is_read_only("unix_request /run/cfab/cfab.sock reapply"));
        assert!(!is_read_only("write /run/cfab/cfab.sock"));
    }

    /// Just the shape row's reason lines, with the classification `--wait` reads.
    fn shape_reasons(sys: &mut MockSys, view: &View) -> Vec<(Class, String)> {
        let mut c = Ctx::default();
        shape_posture(sys, view, None, &mut c).unwrap();
        c.reasons
    }

    /// F19's teeth. The daemon applied eth1's tree while eth9 was DOWN (storage promoted to its
    /// full floor there), then eth9 came back and the daemon has not reconverged yet. Status
    /// must report the fabric it is looking at — the kernel matches what the daemon recorded —
    /// and NOT re-derive from its own carrier read, which with eth9 up wants storage demoted to
    /// its token on eth1 and called every correctly shaped fallback wire "drift" on the rack.
    #[test]
    fn no_drift_when_the_kernel_matches_the_record_but_a_fresh_derivation_would_not() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        // The up-set at apply time: eth9 down. Every wire's tree comes from THAT derivation.
        let at_apply = |w: &str| w != "eth9";
        let mut wires = std::collections::BTreeMap::new();
        let mut sys = healthy_host(&f, &view);
        for w in view.wires() {
            let classes = emit::shape::derive(&view, &w, None, &at_apply)
                .unwrap()
                .applied_classes();
            sys = sys.on_stdout(
                &["tc", "class", "show", "dev", &w],
                &tc_class_show(&classes),
            );
            wires.insert(w, emit::shape::AppliedWire::Shaped(classes));
        }
        // A fresh derivation with eth9 back up wants a different rate on eth1 — the disagreement
        // this test is about. If it ever stops differing, the test has lost its teeth.
        let now = emit::shape::derive(&view, "eth1", None, &|_| true)
            .unwrap()
            .applied_classes();
        assert_ne!(
            now,
            emit::shape::derive(&view, "eth1", None, &at_apply)
                .unwrap()
                .applied_classes(),
            "fixture no longer distinguishes the two derivations"
        );
        sys = sys.file(
            &crate::shape_applied_path(&f.run_dir),
            &emit::shape::ShapeApplied { tick: 7, wires }.render(),
        );
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            !report.output.contains("shape drift"),
            "the kernel is exactly what the daemon recorded:\n{}",
            report.output
        );
        assert_eq!(report.state, State::Up, "{}", report.output);
    }

    /// No record: the daemon has not applied yet. One settling line — `--wait` is for exactly
    /// this window — and never a drift line about a shape nobody has installed.
    #[test]
    fn an_absent_shape_record_is_settling_not_drift() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view);
        sys.files.remove(&crate::shape_applied_path(&f.run_dir));
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  no shape record yet at /run/cfab/shape.applied — shape-daemon has not applied\n"
            ),
            "{}",
            report.output
        );
        assert!(!report.output.contains("shape drift"), "{}", report.output);
        // Settling, so `--wait` holds for it instead of returning on the UP headline.
        assert_eq!(
            shape_reasons(&mut sys, &view),
            vec![(
                Class::Settling,
                "no shape record yet at /run/cfab/shape.applied — shape-daemon has not applied"
                    .to_string()
            )]
        );
    }

    /// A half-written record parses as nothing, and "nothing" is the same condition as absent:
    /// status never invents an expectation out of a truncated file.
    #[test]
    fn an_unparseable_shape_record_reads_as_no_record() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys =
            healthy_host(&f, &view).file(&crate::shape_applied_path(&f.run_dir), "cfab-shape-a");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(
            report.output.contains(
                "  no shape record yet at /run/cfab/shape.applied — shape-daemon has not applied\n"
            ),
            "{}",
            report.output
        );
    }

    /// The kernel really does disagree with what the daemon recorded installing: that is drift,
    /// and it is STANDING — no reconverge is coming to fix a tree the daemon believes it wrote,
    /// so `--wait` must not spend its deadline on it.
    #[test]
    fn a_kernel_that_disagrees_with_the_record_is_standing_drift() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view).on_stdout(
            &["tc", "class", "show", "dev", "eth9"],
            "class htb 1:40 parent 1:1 leaf 40: prio 2 rate 3Mbit ceil 5Gbit burst 64Kb\n",
        );
        let report = run(&mut sys, &view, 6, false, None).unwrap();
        assert!(
            report
                .output
                .contains("  shape drift on eth9: class 1:40 want rate 2Gbit\n"),
            "{}",
            report.output
        );
        assert_eq!(
            shape_reasons(&mut sys, &view),
            vec![
                (
                    Class::Standing,
                    "shape drift on eth9: class 1:10 want rate 200Mbit".to_string()
                ),
                (
                    Class::Standing,
                    "shape drift on eth9: class 1:20 want rate 100Mbit".to_string()
                ),
                (
                    Class::Standing,
                    "shape drift on eth9: class 1:30 want rate 100Mbit".to_string()
                ),
                (
                    Class::Standing,
                    "shape drift on eth9: class 1:40 want rate 2Gbit".to_string()
                ),
            ],
            "standing: waiting re-applies nothing"
        );
    }

    /// A wire the daemon recorded skipping (no carrier) holds a stale tree by design, and the
    /// wire being down is graded on the links axis — status says nothing about its shape.
    #[test]
    fn a_wire_the_daemon_skipped_is_never_called_drift() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut rec = emit::shape::ShapeApplied::parse(
            &healthy_host(&f, &view)
                .read(&crate::shape_applied_path(&f.run_dir))
                .unwrap(),
        )
        .unwrap();
        rec.wires
            .insert("eth1".to_string(), emit::shape::AppliedWire::NoCarrier);
        let mut sys = healthy_host(&f, &view)
            .file(&crate::shape_applied_path(&f.run_dir), &rec.render())
            .on_stdout(&["tc", "class", "show", "dev", "eth1"], "");
        let report = run(&mut sys, &view, 0, false, None).unwrap();
        assert!(!report.output.contains("eth1: class"), "{}", report.output);
        assert!(!report.output.contains("shape drift"), "{}", report.output);
    }

    /// A shape-daemon that is not running leaves a record no one is maintaining: after a crash
    /// it describes floors the kernel may no longer hold. That is not standing drift — the
    /// daemon coming back IS the remedy — so the shaping-down line is the whole story and the
    /// record is not diffed at all.
    #[test]
    fn a_shape_daemon_that_is_down_earns_one_line_and_no_drift() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_host(&f, &view).on_stdout(
            &["tc", "class", "show", "dev", "eth9"],
            "class htb 1:40 parent 1:1 leaf 40: prio 2 rate 3Mbit ceil 5Gbit burst 64Kb\n",
        );
        let comps: Components = serde_json::from_str(&healthy_components(&view)).unwrap();
        let mut cc = comps;
        for k in &mut cc.components {
            if k.name == "shape-daemon" {
                k.state = CompState::Restarting;
                k.restarts = 2;
            }
        }
        let mut c = Ctx::default();
        shape_posture(&mut sys, &view, Some(&cc), &mut c).unwrap();
        assert_eq!(
            c.reasons,
            vec![(
                Class::Settling,
                "shaping down: shape-daemon is restarting, 2 restart(s)".to_string()
            )],
            "the record of a daemon that is not running is not an expectation"
        );
    }
}
