//! Per-VM host routes on a workload leg (spec §5.2, ruling 6).
//!
//! One derivation of "which addresses on this leg are VMs living on THIS host" (`local_vms`),
//! one hold-down that damps a withdrawal (`Holddown`), and one level-triggered reconcile
//! (`HostRoutes::tick`) that pushes that set at the two actuators it drives: the engine's
//! static routes (originated as OSPF type-5 into every allowed zone, so a peer's reply to a VM
//! takes the fabric instead of the admin switch) and the nft set the forward chain's
//! stray-forward drop reads.
//!
//! The set is derived ONCE and used by both `status`'s `vms_seen` and the routes, so the number
//! an operator reads and the routes this member originates can never disagree (conflict 12).
//!
//! Gate B (spec §5.2, §5.3): a VM whose membership drops out of the WANTED set (the same moment
//! its /32 withdraws) gets its neighbor entry deleted (`ip neigh del`), so a later packet ARPs
//! afresh instead of riding a dead MAC, and each join/leave gets one journal line. G0 1b measured
//! a real decay path a stale neighbor entry does not save it from: an idle VM's bridge FDB entry
//! ages out at the bridge's own `ageing_time` (300 s default) while the neighbor entry survives
//! STALE — so the reconcile also runs an idle-VM probe, a unicast ARP request per currently-live
//! VM at an interval derived from that same `ageing_time`, which is the only kind of frame that
//! draws a reply and therefore refreshes the FDB entry the beacon alone cannot touch.
//!
//! Level triggered on purpose: every tick sends the WHOLE wanted set to the engine and diffs
//! the nft set against what nft actually holds, so an `apply` that re-rendered `inet cfab-fwd`
//! (which re-declares the set empty and zeroes the drop counter) repairs itself on the next
//! tick without anything having to notice the apply happened. The cost of that choice is a
//! window of at most one tick after an `apply` in which the set is empty and the drop rule
//! therefore drops every fabric packet for a VM; `apply` is already a disruptive moment, and
//! the alternative — a cache of what we believe nft holds — is the failure mode this shape
//! exists to rule out.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::commands::engine_ctl;
use crate::derive::View;
use crate::model::Workload;
use crate::sys::Sys;
use crate::workload::announce::{AnnounceIo, PERIOD, unicast_probe};
use crate::workload::{deferred_names, uplink};

/// The nft table the forward policy and its sets live in (`emit::policy`).
const FWD_TABLE: (&str, &str) = ("inet", "cfab-fwd");

/// How long a VM's /32 outlives the neighbor entry that justified it (ruling 3): one announce
/// period. Flap damping only — a VM that goes quiet for a moment must not cost the fabric a
/// type-5 flush and a re-origination, each under the engine's own 5 s minimum interval.
///
/// The reconcile is level-triggered on the workload tick, so the withdrawal lands on the first
/// tick at or after the deadline: 5 s plus at most one tick, never less than 5 s.
pub const HOLDDOWN: Duration = PERIOD;

/// The neighbor states that mean "this address resolved to a MAC" (gate M1 review I1, research
/// `0e9bced`: a static neighbor is a resolved host too). NOARP, FAILED and INCOMPLETE carry no
/// usable lladdr and are not a VM being here.
const RESOLVED: &[&str] = &["REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"];

/// The addresses on `wl`'s leg that are VMs living on THIS host.
///
/// The join spec §5.2 asks for, in one place: an `ip -j neigh show dev <leg>` entry counts when
/// it is inside the row's prefix, resolved, not an address the fabric itself owns (any member's
/// declared address on this row, `gw`, `router`), AND its MAC appears in `bridge -j fdb show br
/// <uplink>` on a port that is not one of the bridge's uplink ports. That last clause is the
/// whole point: without it every VM in the VLAN — including the ones on peer hosts, learned
/// through the uplink — would look local, and this host would originate a /32 for a VM it
/// cannot reach except by sending the packet straight back out the admin switch.
///
/// A MAC with no FDB entry at all is NOT local: the bridge has no record of it being here, and
/// the conservative reading (do not claim it) is the one ruling 6 narrows toward.
///
/// `None` when either document does not parse as a JSON array, or is a non-empty array none of
/// whose entries carry the keys we read (an iproute2 that spells them otherwise) — a failed read
/// is never a fact about VMs, and every caller treats it as "unchanged", never as "they are all
/// gone". An EMPTY array is a real answer in both documents.
pub fn local_vms(
    neigh_json: &str,
    fdb_json: &str,
    view: &View,
    wl: &Workload,
    uplink_ports: &[String],
) -> Option<BTreeSet<Ipv4Addr>> {
    Some(
        local_vm_macs(neigh_json, fdb_json, view, wl, uplink_ports)?
            .into_keys()
            .collect(),
    )
}

/// The same join `local_vms` does, keeping each VM's MAC — the idle-VM probe's (gate B) unicast
/// target. `local_vms` is this function's addresses alone; every doc comment above it applies
/// here unchanged. A `lladdr` that does not parse as six hex octets (an iproute2 spelling we do
/// not understand — never seen in practice) drops that one VM rather than guessing at its MAC.
fn local_vm_macs(
    neigh_json: &str,
    fdb_json: &str,
    view: &View,
    wl: &Workload,
    uplink_ports: &[String],
) -> Option<BTreeMap<Ipv4Addr, [u8; 6]>> {
    let neigh: Value = serde_json::from_str(neigh_json).ok()?;
    let fdb: Value = serde_json::from_str(fdb_json).ok()?;
    let (neigh, fdb) = (neigh.as_array()?, fdb.as_array()?);

    // MAC -> the bridge ports it has been seen on. A MAC on both a VM port and the uplink (a
    // migration in flight) is local: the tap is the newer, more specific fact.
    let mut local_macs: BTreeSet<String> = BTreeSet::new();
    let mut understood = 0usize;
    for e in fdb {
        let (Some(mac), Some(port)) = (e["mac"].as_str(), e["ifname"].as_str()) else {
            continue;
        };
        understood += 1;
        if uplink_ports.iter().any(|p| p == port) {
            continue;
        }
        local_macs.insert(mac.to_ascii_lowercase());
    }
    // A non-empty document none of whose entries carried the two fields we read is an
    // iproute2 that spells them differently, not a bridge with no MACs on it. Refusing to
    // answer is the difference between a loud journal line and a member that silently reports
    // "0 vms seen" and withdraws every /32 it holds (fail loud, never degrade).
    if understood == 0 && !fdb.is_empty() {
        return None;
    }

    let exclude = fabric_addresses(view, wl);
    let mut out: BTreeMap<Ipv4Addr, [u8; 6]> = BTreeMap::new();
    let mut understood = 0usize;
    for e in neigh {
        // The shape test, and why it is `dst` + `state` and not the address parsing: an entry
        // for an IPv6 neighbor (every leg has fe80::) carries both keys and is simply not ours
        // to route, and an entry with no `lladdr` is a real unresolved neighbor. Only an
        // iproute2 that spells these two otherwise leaves us with nothing to read.
        let (Some(dst), Some(state)) = (e["dst"].as_str(), e["state"].as_array()) else {
            continue;
        };
        understood += 1;
        let Some(dst) = dst.parse::<Ipv4Addr>().ok() else {
            continue;
        };
        if !wl.prefix.contains(dst) || exclude.contains(&dst) {
            continue;
        }
        if !state
            .iter()
            .filter_map(|s| s.as_str())
            .any(|s| RESOLVED.contains(&s))
        {
            continue;
        }
        let Some(mac) = e["lladdr"].as_str() else {
            continue;
        };
        if local_macs.contains(&mac.to_ascii_lowercase())
            && let Some(bytes) = parse_mac(mac)
        {
            out.insert(dst, bytes);
        }
    }
    // Same reading as the FDB above: a non-empty document none of whose entries we could read
    // is a refusal, never "this leg has no neighbors" — the latter withdraws every /32.
    if understood == 0 && !neigh.is_empty() {
        return None;
    }
    Some(out)
}

/// `"02:cf:ab:00:00:01"` -> its six bytes. `None` for anything else.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in out.iter_mut() {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Every address on this workload the fabric itself owns: each declared member's address on the
/// row (fabric-wide, not just this member — `View::workload_rows` is this-member-only) and the
/// anycast `gw`. Without it a peer's own resolution of the gateway
/// would read as a VM, and this member would originate a /32 for an address every member holds.
fn fabric_addresses(view: &View, wl: &Workload) -> BTreeSet<Ipv4Addr> {
    let mut out: BTreeSet<Ipv4Addr> = view
        .fabric
        .members
        .iter()
        .flat_map(|m| m.workloads.iter())
        .filter(|mw| mw.name == wl.name)
        .map(|mw| mw.address)
        .collect();
    out.insert(wl.gw);
    out
}

/// The withdrawal damper (ruling 3). An address that appears is wanted at once; an address that
/// leaves stays wanted for `HOLDDOWN` and is dropped on the first observation after that, and a
/// return inside the window cancels the withdrawal outright.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Holddown {
    /// address -> when its withdrawal falls due; `None` while it is still live.
    entries: BTreeMap<Ipv4Addr, Option<Instant>>,
}

impl Holddown {
    /// The wanted set after observing `live`.
    pub fn observe(&mut self, live: &BTreeSet<Ipv4Addr>, now: Instant) -> BTreeSet<Ipv4Addr> {
        for a in live {
            // Both the addition and the cancellation: re-inserting `None` clears a deadline a
            // previous observation set, so a VM that answers again inside the window never
            // loses its route.
            self.entries.insert(*a, None);
        }
        let mut wanted = BTreeSet::new();
        self.entries.retain(|addr, due| {
            if live.contains(addr) {
                wanted.insert(*addr);
                return true;
            }
            let deadline = *due.get_or_insert(now + HOLDDOWN);
            if now < deadline {
                wanted.insert(*addr);
                true
            } else {
                false
            }
        });
        wanted
    }
}

/// The repeating conditions the reconcile deduplicates its journal on. Independent: an engine
/// that will not take a request says nothing about whether nft can be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Cond {
    /// The neighbor / FDB / uplink read the wanted set is derived from.
    Read,
    /// The engine would not take the route request.
    Engine,
    /// The nft set could not be read or updated.
    Nft,
    /// The idle-VM probe (gate B) could not send: the leg's MAC could not be read, or the send
    /// itself failed.
    Probe,
    /// The bridge's `ageing_time` could not be read: the probe still runs, at the fallback
    /// interval `DEFAULT_AGEING` assumes.
    AgeingTime,
}

impl Cond {
    /// What the recovery line calls this condition. One spelling, one sentence shape.
    fn as_str(self) -> &'static str {
        match self {
            Cond::Read => "VM read",
            Cond::Engine => "engine route request",
            Cond::Nft => "local set update",
            Cond::Probe => "idle-VM probe",
            Cond::AgeingTime => "bridge ageing_time read",
        }
    }
}

/// One `[[workload]]` row's reconcile state.
#[derive(Debug, Default)]
struct Row {
    holddown: Holddown,
    /// The line standing for each repeating condition, so a fault that lasts costs one line
    /// and not one every tick.
    standing: BTreeMap<Cond, String>,
    /// The wanted set as of the LAST tick's reconcile (gate B): diffed against this tick's to
    /// find who joined and who left, and departed exactly once each — never re-derived from a
    /// broad scan, which is what makes the `neigh del` below provably ours.
    last_wanted: BTreeSet<Ipv4Addr>,
    /// Whether this row has ever completed a membership reconcile. The FIRST one is a baseline
    /// (whatever is already there when cfab starts watching), never a set of changes: without
    /// this, every VM already on the wire at startup would log a "joined" line for a join that
    /// never happened. This does NOT reset when a row is deferred and later reinstalled — only
    /// `last_wanted` does (below) — so a row returning from deferral is NOT read as a fresh
    /// baseline: every VM already on the wire when it reinstalls logs a "joined" line, which is
    /// the desired behavior (the row was genuinely absent from the fabric while deferred).
    seen_before: bool,
    /// When the idle-VM probe (spec §5.2 (a)) is next due. `None` until this row's first
    /// installed tick.
    next_probe: Option<Instant>,
}

impl Row {
    fn say_once(&mut self, cond: Cond, line: String, out: &mut Vec<String>) {
        if self.standing.get(&cond).map(String::as_str) == Some(line.as_str()) {
            return;
        }
        self.standing.insert(cond, line.clone());
        out.push(line);
    }

    /// `cond` is over: say so once, and only if it was standing. Clearing it is the
    /// load-bearing half — a standing line never cleared swallows the SECOND occurrence of the
    /// same fault for the life of the process.
    fn recovered(&mut self, cond: Cond, name: &str, out: &mut Vec<String>) {
        if self.standing.remove(&cond).is_some() {
            out.push(format!(
                "cfab: workload {name}: {} recovered",
                cond.as_str()
            ));
        }
    }
}

/// The two reads and the join for one row, with no reporting: the live local VMs, or `None`
/// when a read could not be made or a document could not be read. `HostRoutes::observe` does
/// the same reads with a spelling per failure, which is what a supervisor tick owes the
/// journal; the callers here (`apply`'s seed, `status`'s count) have their own reporting.
pub fn read_local_vms(sys: &mut dyn Sys, view: &View, wl: &Workload) -> Option<BTreeSet<Ipv4Addr>> {
    let ports = uplink::identify_declared(&*sys, &wl.uplink, wl.vid)
        .ok()?
        .ports;
    let neigh = sys
        .run(&["ip", "-j", "neigh", "show", "dev", &wl.leg_ifname()])
        .ok()?;
    let fdb = sys
        .run(&["bridge", "-j", "fdb", "show", "br", &wl.uplink])
        .ok()?;
    if !neigh.ok() || !fdb.ok() {
        return None;
    }
    local_vms(&neigh.stdout, &fdb.stdout, view, wl, &ports)
}

/// What `apply` seeds `emit::policy::generate_seeded` from: set name -> the VMs on that leg.
///
/// Every declared row gets an entry, empty when the row is deferred (no leg to read) or when a
/// read failed — `apply` seeding empty is exactly what it did before this existed, and the
/// reconcile fills it on the next tick either way. Best effort by design: a seed that cannot
/// be read must never stop `up` from loading the policy.
pub fn seed_locals(sys: &mut dyn Sys, view: &View) -> BTreeMap<String, BTreeSet<Ipv4Addr>> {
    let rows = view.workload_rows();
    if rows.is_empty() {
        return BTreeMap::new();
    }
    let deferred = deferred_names(sys, view);
    rows.into_iter()
        .map(|row| {
            let vms = if deferred.contains(&row.wl.name) {
                BTreeSet::new()
            } else {
                read_local_vms(sys, view, row.wl).unwrap_or_default()
            };
            (row.wl.local_set(), vms)
        })
        .collect()
}

/// Every workload row's host-route reconcile, driven from the supervisor's workload tick.
#[derive(Debug, Default)]
pub struct HostRoutes {
    rows: BTreeMap<String, Row>,
}

impl HostRoutes {
    pub fn new() -> Self {
        Self::default()
    }

    /// One reconcile pass over every declared row. Returns the journal lines to say, in order;
    /// the caller owns stderr and the test trace. `io` is the same `AnnounceIo` the announcers
    /// send their beacon on (gate B): the idle-VM probe is one more frame type on the same
    /// socket, never a new one.
    pub fn tick(
        &mut self,
        sys: &mut dyn Sys,
        view: &View,
        io: &mut dyn AnnounceIo,
        now: Instant,
    ) -> Vec<String> {
        let mut out = Vec::new();
        let rows = view.workload_rows();
        if rows.is_empty() {
            return out; // a member with no `[[workload]]` row reads nothing at all
        }
        let deferred = deferred_names(sys, view);
        for row in rows {
            let wl = row.wl;
            self.rows.entry(wl.name.clone()).or_default();
            let installed = !deferred.contains(&wl.name);
            let live = if installed {
                self.observe(sys, view, wl, &mut out)
            } else {
                // A row with no leg has no local VMs to damp: forget the hold-down rather
                // than hold routes for a leg that is not there, and forget the membership
                // diff too — the leg is gone, and with it every neighbor entry that could
                // have been "left" (a deleted netdev takes its neighbor table with it).
                let r = self.rows.entry(wl.name.clone()).or_default();
                r.holddown = Holddown::default();
                r.last_wanted = BTreeSet::new();
                Some(BTreeMap::new())
            };
            // A read that failed costs one tick and nothing else — never a withdrawal.
            let Some(live) = live else { continue };
            let live_addrs: BTreeSet<Ipv4Addr> = live.keys().copied().collect();
            let ifindex = leg_ifindex(sys, &wl.leg_ifname()).unwrap_or(0);
            let wanted = {
                let r = self.rows.entry(wl.name.clone()).or_default();
                r.holddown.observe(&live_addrs, now)
            };
            if installed {
                self.reconcile_membership(sys, wl, &wanted, &mut out);
            }
            // The engine's set is the VMs PLUS this member's own leg address as a /32 (spec
            // fact 5): a relayed DHCP reply is unicast to `giaddr` = the leg address, and with
            // the workload /24 originated by nobody, nothing routes to it unless the host that
            // owns it says so. It rides the same request, so it is redistributed into the
            // allowed zones' OSPF as a type-5 (which is the only origination a leaf can hear)
            // and originated into BGP beside the VM /32s. It goes no further: the nft
            // `<leg>-local` set below is VM addresses, and a host proxy-ARPing for its own
            // address or claiming it as a VM is exactly what `fabric_addresses` excludes.
            // A deferred row has no leg to reach it by, so it withdraws with the leg.
            let mut engine_set = wanted.clone();
            if installed {
                engine_set.insert(row.addr);
            }
            self.ask_engine(sys, view, wl, ifindex, &engine_set, &mut out);
            self.sync_set(sys, wl, &wanted, &mut out);
            if installed {
                self.maybe_probe(sys, io, wl, &live, now, &mut out);
            }
        }
        out
    }

    /// The live local-VM set for one row, keyed by MAC, or `None` when a read this tick could
    /// not be made. The MAC is gate B's addition — the idle-VM probe's unicast target.
    fn observe(
        &mut self,
        sys: &mut dyn Sys,
        view: &View,
        wl: &Workload,
        out: &mut Vec<String>,
    ) -> Option<BTreeMap<Ipv4Addr, [u8; 6]>> {
        let leg = wl.leg_ifname();
        let name = wl.name.clone();
        // An uplink that cannot be identified is skipped in silence, deliberately: the
        // forwarding watchdog and `status` each already report that exact condition in their
        // own words, and a third reporter would turn one fault into three lines a tick. The
        // cost of the skip is one tick's routes, unchanged — never withdrawn.
        let Ok(up) = uplink::identify_declared(&*sys, &wl.uplink, wl.vid) else {
            return None;
        };
        let ports = up.ports;
        let neigh = sys.run(&["ip", "-j", "neigh", "show", "dev", &leg]).ok()?;
        if !neigh.ok() {
            self.fail(
                &name,
                Cond::Read,
                format!("cannot read the neighbors of {leg}"),
                out,
            );
            return None;
        }
        let fdb = sys
            .run(&["bridge", "-j", "fdb", "show", "br", &wl.uplink])
            .ok()?;
        if !fdb.ok() {
            self.fail(
                &name,
                Cond::Read,
                format!("cannot read the FDB of bridge {}", wl.uplink),
                out,
            );
            return None;
        }
        match local_vm_macs(&neigh.stdout, &fdb.stdout, view, wl, &ports) {
            Some(live) => {
                self.rows
                    .entry(name.clone())
                    .or_default()
                    .recovered(Cond::Read, &name, out);
                Some(live)
            }
            None => {
                self.fail(
                    &name,
                    Cond::Read,
                    format!(
                        "cannot parse the neighbors of {leg} or the FDB of {}",
                        wl.uplink
                    ),
                    out,
                );
                None
            }
        }
    }

    /// Journal one line per address whose WANTED membership changed since the last tick, and
    /// delete the neighbor entry of one that left (gate B, spec §5.3).
    ///
    /// Scoped to `wanted` — the SAME post-hold-down moment the engine's /32 and the nft set
    /// already drop the address — never earlier: a VM that returns within the hold-down window
    /// cancels the departure (`Holddown::observe`) before this ever sees it leave, so a flapping
    /// VM never pays a forced re-ARP, and a `Cmd::DhcpAck` neighbor write that lands inside the
    /// window is never raced by a delete (the very next fresh read puts the address straight
    /// back into `live`, which cancels the hold-down outright). The deletion itself is provably
    /// ours: one address this row's own reconcile watched leave `wanted`, on the row's own leg —
    /// never a broad flush, never by pattern.
    fn reconcile_membership(
        &mut self,
        sys: &mut dyn Sys,
        wl: &Workload,
        wanted: &BTreeSet<Ipv4Addr>,
        out: &mut Vec<String>,
    ) {
        let name = wl.name.clone();
        let leg = wl.leg_ifname();
        let r = self.rows.entry(name.clone()).or_default();
        let first = !r.seen_before;
        r.seen_before = true;
        let prev = std::mem::replace(&mut r.last_wanted, wanted.clone());
        if first {
            // Whatever is already live the first time this row is ever reconciled is a
            // baseline, not a set of changes: nothing here "just joined".
            return;
        }
        for addr in wanted.difference(&prev) {
            out.push(format!("cfab: workload {name}: vm {addr} joined"));
        }
        for addr in prev.difference(wanted) {
            let deleted = sys
                .run(&["ip", "neigh", "del", &addr.to_string(), "dev", &leg])
                .is_ok_and(|o| o.ok());
            if deleted {
                out.push(format!(
                    "cfab: workload {name}: vm {addr} left (no longer seen as a local VM)"
                ));
            } else {
                out.push(format!(
                    "cfab: workload {name}: vm {addr} left (no longer seen as a local VM); \
                     cannot delete its neighbor entry on {leg}"
                ));
            }
        }
    }

    /// The idle-VM probe (spec §5.2 (a), gate B). Fires at most once every `probe_interval` (a
    /// third of the bridge's own `ageing_time`, floored at the announcer's `PERIOD`) and, when
    /// it does, sends one unicast ARP request to every CURRENTLY live VM on this row — never a
    /// broadcast, never a VM this tick's own fresh read did not just confirm. The point is the
    /// reply: a frame this host sends is never learned from, so only the VM answering refreshes
    /// the bridge FDB entry that the beacon alone cannot touch (G0 1b).
    fn maybe_probe(
        &mut self,
        sys: &mut dyn Sys,
        io: &mut dyn AnnounceIo,
        wl: &Workload,
        live: &BTreeMap<Ipv4Addr, [u8; 6]>,
        now: Instant,
        out: &mut Vec<String>,
    ) {
        let name = wl.name.clone();
        let due = *self
            .rows
            .entry(name.clone())
            .or_default()
            .next_probe
            .get_or_insert(now);
        if now < due {
            return;
        }
        let (interval, ageing_fault) = probe_interval(sys, &wl.uplink);
        self.rows.entry(name.clone()).or_default().next_probe = Some(now + interval);
        match ageing_fault {
            Some(why) => self.fail_costing(
                &name,
                Cond::AgeingTime,
                why,
                &format!(
                    "probing at the default {}s ageing_time assumption",
                    DEFAULT_AGEING.as_secs()
                ),
                out,
            ),
            None => {
                self.rows
                    .entry(name.clone())
                    .or_default()
                    .recovered(Cond::AgeingTime, &name, out)
            }
        }
        if live.is_empty() {
            return; // nothing to refresh; the next due cycle checks again
        }
        let leg = wl.leg_ifname();
        let src_mac = match io.mac(&leg) {
            Ok(mac) => mac,
            Err(e) => {
                self.fail_costing(
                    &name,
                    Cond::Probe,
                    format!("cannot read the MAC of {leg} for the idle-VM probe: {e}"),
                    "no probe sent this cycle",
                    out,
                );
                return;
            }
        };
        // One aggregate condition for the whole cycle, never one per address: the fault is per
        // INTERFACE (every send here targets the same leg), so N failing VMs must cost one
        // line, not N distinct strings `say_once` cannot dedup and that all reprint every
        // cycle. `recovered` fires only when EVERY send this cycle succeeded — a mix of one
        // failure and one success is still a standing fault, never a same-tick "recovered"
        // contradicting the failure line it was meant to clear.
        let total = live.len();
        let mut failed = 0usize;
        let mut last_err = None;
        for (&addr, &mac) in live {
            let frame = unicast_probe(src_mac, mac, wl.gw, addr);
            if let Err(e) = io.send(&leg, &frame) {
                failed += 1;
                last_err = Some(format!("{addr}: {e}"));
            }
        }
        if failed > 0 {
            self.fail_costing(
                &name,
                Cond::Probe,
                format!(
                    "{failed} of {total} idle-VM probes on {leg} failed: {}",
                    last_err.unwrap_or_default()
                ),
                "retried next cycle",
                out,
            );
        } else {
            self.rows
                .entry(name.clone())
                .or_default()
                .recovered(Cond::Probe, &name, out);
        }
    }

    /// Hand the engine the WHOLE wanted set for this leg, every tick. `Northbound::commit`
    /// diffs against running, so re-asking for what is in force is free, and an engine that
    /// restarted (and so committed the base tree with no host routes) is repaired by the very
    /// next tick rather than by anything having to notice it restarted.
    fn ask_engine(
        &mut self,
        sys: &mut dyn Sys,
        view: &View,
        wl: &Workload,
        ifindex: u32,
        wanted: &BTreeSet<Ipv4Addr>,
        out: &mut Vec<String>,
    ) {
        let sock = engine_ctl::sock_path(view.fabric);
        let mut line = format!("workload-routes {} {ifindex}", wl.leg_ifname());
        for a in wanted {
            line.push_str(&format!(" {a}/32"));
        }
        line.push('\n');
        let name = wl.name.clone();
        let fault = match sys.unix_request(&sock, &line) {
            Ok(reply) => match refusal(&reply) {
                None => None,
                // The withdraw of an ifindex move landed and the install did not: the routes
                // are GONE, not unchanged, and the next tick re-asks for exactly this set.
                Some(Refusal::Withdrew(e)) => Some((
                    format!(
                        "engine withdrew the routes of {} and refused the reinstall: {e}",
                        wl.leg_ifname()
                    ),
                    "retried next tick",
                )),
                Some(Refusal::Plain) => Some((
                    format!("engine refused {}: {}", line.trim(), reply.trim()),
                    ENGINE_COST,
                )),
            },
            Err(e) => Some((
                format!("engine would not take {}: {e}", line.trim()),
                ENGINE_COST,
            )),
        };
        match fault {
            Some((why, cost)) => self.fail_costing(&name, Cond::Engine, why, cost, out),
            None => self
                .rows
                .entry(name.clone())
                .or_default()
                .recovered(Cond::Engine, &name, out),
        }
    }

    /// Diff the nft set against what nft actually holds and move only the difference.
    fn sync_set(
        &mut self,
        sys: &mut dyn Sys,
        wl: &Workload,
        wanted: &BTreeSet<Ipv4Addr>,
        out: &mut Vec<String>,
    ) {
        let set = wl.local_set();
        let name = wl.name.clone();
        let (family, table) = FWD_TABLE;
        let listing = sys.run(&["nft", "-j", "list", "set", family, table, &set]);
        let held = match listing {
            Ok(o) if o.ok() => parse_set_elements(&o.stdout),
            _ => None,
        };
        let Some(held) = held else {
            self.fail(
                &name,
                Cond::Nft,
                format!("cannot read the nft set {family} {table} {set}"),
                out,
            );
            return;
        };
        let add: Vec<String> = wanted.difference(&held).map(ToString::to_string).collect();
        let del: Vec<String> = held.difference(wanted).map(ToString::to_string).collect();
        for (verb, elems) in [("add", &add), ("delete", &del)] {
            if elems.is_empty() {
                continue;
            }
            let braced = format!("{{ {} }}", elems.join(", "));
            let ok = sys
                .run(&["nft", verb, "element", family, table, &set, &braced])
                .is_ok_and(|o| o.ok());
            if !ok {
                self.fail(
                    &name,
                    Cond::Nft,
                    format!("cannot {verb} {braced} in the nft set {family} {table} {set}"),
                    out,
                );
                return;
            }
        }
        self.rows
            .entry(name.clone())
            .or_default()
            .recovered(Cond::Nft, &name, out);
    }

    /// One spelling for every fault of one condition: what went wrong, then what it costs.
    ///
    /// Only `Cond::Read` and `Cond::Nft` are ever handed to this function — every other
    /// condition's cost text depends on which of several call sites raised it (an engine
    /// refusal vs. an engine withdraw, a MAC read vs. a send), so it is computed at the call
    /// site and passed straight to `fail_costing` instead. The other three arms are
    /// `unreachable!()`, not prose, so a spelling that can never print never gets invented —
    /// and a future call site that DOES route one of them through `fail()` panics under test
    /// immediately, rather than silently adopting whatever guess is sitting here unused.
    fn fail(&mut self, name: &str, cond: Cond, why: String, out: &mut Vec<String>) {
        let cost = match cond {
            Cond::Read => ENGINE_COST,
            Cond::Nft => "the local set is unchanged",
            Cond::Engine => unreachable!("Cond::Engine's cost is per-refusal; see ask_engine"),
            Cond::Probe => unreachable!("Cond::Probe's cost is per-fault; see maybe_probe"),
            Cond::AgeingTime => {
                unreachable!(
                    "Cond::AgeingTime's cost is fixed at its one call site; see maybe_probe"
                )
            }
        };
        self.fail_costing(name, cond, why, cost, out);
    }

    /// The same, for the one fault whose cost is not its condition's usual one.
    fn fail_costing(
        &mut self,
        name: &str,
        cond: Cond,
        why: String,
        cost: &str,
        out: &mut Vec<String>,
    ) {
        self.rows.entry(name.to_string()).or_default().say_once(
            cond,
            format!("cfab: workload {name}: {why}; {cost}"),
            out,
        );
    }
}

/// What every read fault and every ordinary engine refusal costs: nothing this tick.
const ENGINE_COST: &str = "host routes unchanged";

/// What an engine reply to `workload-routes` means.
enum Refusal {
    /// The two-step ifindex move whose withdraw landed and whose install did not: holo holds no
    /// routes for the leg, so this refusal cost the VMs their reach until the next tick.
    Withdrew(String),
    /// Every other refusal — the routes holo held before it are the routes it holds after.
    Plain,
}

/// `None` when the engine took the request. A reply we cannot parse but that carries the word
/// is a refusal we do not understand, which is still a refusal: never taken as success.
fn refusal(reply: &str) -> Option<Refusal> {
    let Ok(v) = serde_json::from_str::<Value>(reply) else {
        return reply.contains("\"error\"").then_some(Refusal::Plain);
    };
    let err = v.get("error")?;
    if v["withdrew"] == Value::Bool(true) {
        Some(Refusal::Withdrew(
            err.as_str().unwrap_or_default().to_string(),
        ))
    } else {
        Some(Refusal::Plain)
    }
}

/// The Linux bridge default `ageing_time` (300 s, G0 1b measured this exact value on the
/// testbed): the fallback the idle-VM probe uses only when the sysfs read itself fails, never a
/// substitute for reading it.
const DEFAULT_AGEING: Duration = Duration::from_secs(300);

/// How often the idle-VM probe fires for one row: a third of the bridge's own `ageing_time`, so
/// a single missed cycle (a busy tick, a transient read failure) still leaves a full cycle of
/// margin before a genuinely idle VM's FDB entry could age out. Floored at the announcer's own
/// `PERIOD`: an operator's bridge `ageing_time` is not a cfab knob, and a pathologically low one
/// must not turn the probe into a beacon.
///
/// `/sys/class/net/<bridge>/bridge/ageing_time` reports centiseconds (`USER_HZ`, the historic
/// unit every bridge sysfs timer uses) — 30000 is the kernel default 300 s, which is exactly
/// what G0 1b measured. A read that fails or does not parse falls back to `DEFAULT_AGEING`,
/// named once in the returned fault text; the probe keeps running either way (availability
/// first) rather than stopping because one fact about the host could not be confirmed.
fn probe_interval(sys: &dyn Sys, bridge: &str) -> (Duration, Option<String>) {
    let path = format!("/sys/class/net/{bridge}/bridge/ageing_time");
    match sys
        .read(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        Some(centisecs) => (
            (Duration::from_millis(centisecs.saturating_mul(10)) / 3).max(PERIOD),
            None,
        ),
        None => (
            (DEFAULT_AGEING / 3).max(PERIOD),
            Some(format!("cannot read {path}")),
        ),
    }
}

/// `/sys/class/net/<leg>/ifindex`. `None` when the leg is not there — the engine is then told
/// ifindex 0, which is never a real netdev, so a leg that comes back always reads as a move and
/// gets its routes re-resolved (holo resolves a static route's interface once, at commit).
fn leg_ifindex(sys: &dyn Sys, leg: &str) -> Option<u32> {
    sys.read(&format!("/sys/class/net/{leg}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The elements of one set from `nft -j list set …`. `None` when the document is not a set
/// listing at all (nft absent, the table gone, a refusal) — an empty set is `Some(empty)`, and
/// the two must never be confused: one means "nft holds nothing", the other "we do not know".
fn parse_set_elements(json: &str) -> Option<BTreeSet<Ipv4Addr>> {
    let doc: Value = serde_json::from_str(json).ok()?;
    let items = doc["nftables"].as_array()?;
    let set = items.iter().find_map(|i| i.get("set"))?;
    let mut out = BTreeSet::new();
    // A set with no elements has no `elem` key at all, which is an empty set, not a failure.
    for e in set["elem"].as_array().into_iter().flatten() {
        // A plain `ipv4_addr` element is a bare string; nft wraps an element carrying
        // attributes (a timeout, a comment) in an object instead. Neither is ours to reject.
        let text = e.as_str().or_else(|| e["val"].as_str());
        if let Some(a) = text.and_then(|s| s.parse::<Ipv4Addr>().ok()) {
            out.insert(a);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::{Declaration, fixtures};
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;
    use crate::workload::announce::mock::RecordingIo;

    /// A fresh recording `AnnounceIo` for a test that does not care about the idle-VM probe's
    /// frames — every `tick` needs one now that the probe rides the same socket.
    fn io() -> RecordingIo {
        RecordingIo::default()
    }

    fn wl_fabric() -> Fabric {
        Fabric::from_decl(
            &Declaration::parse(&fixtures::with_workload(&fixtures::example())).unwrap(),
        )
        .unwrap()
    }

    /// The fixture the plan names: one VM on a tap, this member and its peer, one out-of-prefix
    /// neighbor, and two VLAN-3 addresses whose MACs live on the uplink (VMs on another host).
    /// Only the first is local. (.1 is an ordinary address here: with `router` retired the VLAN
    /// has no gateway but cfab's own `gw`, so nothing about .1 is special any more.)
    const NEIGH: &str = r#"[
      {"dst":"192.168.20.103","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:01","state":["REACHABLE"]},
      {"dst":"192.168.20.2","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:02","state":["PERMANENT"]},
      {"dst":"192.168.20.3","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:03","state":["STALE"]},
      {"dst":"192.168.20.1","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:04","state":["REACHABLE"]},
      {"dst":"10.99.0.4","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:05","state":["REACHABLE"]},
      {"dst":"192.168.20.104","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:06","state":["REACHABLE"]}
    ]"#;

    const FDB: &str = r#"[
      {"mac":"02:cf:ab:00:00:01","ifname":"tap100i0","vlan":3,"master":"primary","state":""},
      {"mac":"02:cf:ab:00:00:02","ifname":"tap100i0","vlan":3,"master":"primary","state":"permanent"},
      {"mac":"02:cf:ab:00:00:03","ifname":"eth0","vlan":3,"master":"primary","state":""},
      {"mac":"02:cf:ab:00:00:04","ifname":"eth0","vlan":3,"master":"primary","state":""},
      {"mac":"02:cf:ab:00:00:06","ifname":"eth0","vlan":3,"master":"primary","state":""}
    ]"#;

    fn addr(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn set(addrs: &[&str]) -> BTreeSet<Ipv4Addr> {
        addrs.iter().map(|a| addr(a)).collect()
    }

    #[test]
    fn local_vms_counts_a_vm_on_a_tap_and_nothing_else() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let wl = &f.workloads[0];
        assert_eq!(
            local_vms(NEIGH, FDB, &v, wl, &["eth0".to_string()]).unwrap(),
            set(&["192.168.20.103"]),
            "the peers' addresses, the out-of-prefix entry and the VMs whose MACs are on the \
             uplink are all excluded"
        );
        // The teeth: with the uplink not named, the VMs on the OTHER host stop being excluded
        // and this member would originate /32s for VMs it cannot reach.
        assert_eq!(
            local_vms(NEIGH, FDB, &v, wl, &[]).unwrap(),
            set(&["192.168.20.1", "192.168.20.103", "192.168.20.104"])
        );
    }

    /// `parse_mac`: valid hex in, six bytes out; anything else is `None` — a malformed lladdr
    /// costs one VM, never a panic.
    #[test]
    fn parse_mac_reads_six_hex_octets_and_rejects_anything_else() {
        assert_eq!(
            parse_mac("02:cf:ab:00:00:01"),
            Some([0x02, 0xcf, 0xab, 0x00, 0x00, 0x01])
        );
        assert_eq!(parse_mac("02:cf:ab:00:00"), None, "too few groups");
        assert_eq!(parse_mac("02:cf:ab:00:00:01:02"), None, "too many groups");
        assert_eq!(parse_mac("gg:cf:ab:00:00:01"), None, "not hex");
        assert_eq!(parse_mac(""), None);
    }

    /// The idle-VM probe's own read (gate B): the same join `local_vms` counts, keyed by each
    /// VM's real MAC, which is exactly the MAC the neighbor table already carries for it (never
    /// invented, never the uplink's).
    #[test]
    fn local_vm_macs_keeps_the_real_mac_of_the_one_local_vm() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let wl = &f.workloads[0];
        let macs = local_vm_macs(NEIGH, FDB, &v, wl, &["eth0".to_string()]).unwrap();
        assert_eq!(
            macs,
            [(addr("192.168.20.103"), [0x02, 0xcf, 0xab, 0x00, 0x00, 0x01])]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        );
        // Same failure/empty semantics as `local_vms`, since `local_vms` is defined in terms of
        // this function: a bad document is `None`, never "no VMs".
        assert_eq!(local_vm_macs("not json", FDB, &v, wl, &[]), None);
    }

    /// The gateway is a fabric address on every member, and a MAC the bridge has no record of
    /// is not this host's VM. Neither may become a /32.
    #[test]
    fn the_gw_and_a_mac_with_no_fdb_entry_are_never_local() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let wl = &f.workloads[0];
        let neigh = r#"[
          {"dst":"192.168.20.254","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:07","state":["REACHABLE"]},
          {"dst":"192.168.20.105","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:08","state":["REACHABLE"]}
        ]"#;
        let fdb = r#"[{"mac":"02:cf:ab:00:00:07","ifname":"tap100i0","master":"primary"}]"#;
        assert!(
            local_vms(neigh, fdb, &v, wl, &["eth0".to_string()])
                .unwrap()
                .is_empty()
        );
        // The teeth for both halves at once: give .105 the FDB entry .254 has, and move .254 to
        // an address the fabric does not own — the one that is now local is the one that has
        // both a tap entry and no claim on it.
        let fdb = r#"[{"mac":"02:cf:ab:00:00:08","ifname":"tap100i0","master":"primary"}]"#;
        assert_eq!(
            local_vms(neigh, fdb, &v, wl, &["eth0".to_string()]).unwrap(),
            set(&["192.168.20.105"])
        );
    }

    /// The restart case: the leg now outlives a `systemctl restart cfab`, so its neighbor
    /// entries do too — and an entry nothing has touched for 30 s is STALE, not REACHABLE. An
    /// idle VM must still be a VM on the first tick after the restart, with no new traffic from
    /// it. `read_local_vms` re-reads the whole table every tick (there is no event-only path to
    /// miss it), so this pins the one thing that could silence it: the state list.
    #[test]
    fn a_stale_neighbor_entry_is_a_vm_so_an_idle_one_survives_a_restart() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let wl = &f.workloads[0];
        let fdb = r#"[{"mac":"02:cf:ab:00:00:0a","ifname":"tap100i0","master":"primary"}]"#;
        for state in ["REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"] {
            let neigh = format!(
                r#"[{{"dst":"192.168.20.107","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:0a","state":["{state}"]}}]"#
            );
            assert_eq!(
                local_vms(&neigh, fdb, &v, wl, &["eth0".to_string()]).unwrap(),
                set(&["192.168.20.107"]),
                "{state} is a resolved VM"
            );
        }
    }

    /// An unresolved neighbor is not a VM, and a document that does not parse is not an empty
    /// set: `None` is what stops a failed read from withdrawing every route.
    #[test]
    fn unresolved_states_do_not_count_and_a_bad_document_is_none() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let wl = &f.workloads[0];
        let fdb = r#"[{"mac":"02:cf:ab:00:00:09","ifname":"tap100i0","master":"primary"}]"#;
        for state in ["FAILED", "INCOMPLETE", "NOARP"] {
            let neigh = format!(
                r#"[{{"dst":"192.168.20.106","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:09","state":["{state}"]}}]"#
            );
            assert!(
                local_vms(&neigh, fdb, &v, wl, &["eth0".to_string()])
                    .unwrap()
                    .is_empty(),
                "{state} must not count"
            );
        }
        assert_eq!(local_vms("not json", fdb, &v, wl, &[]), None);
        assert_eq!(local_vms(NEIGH, "", &v, wl, &[]), None);
        assert_eq!(local_vms("{}", "{}", &v, wl, &[]), None);
        // An FDB document whose entries carry neither field we read (an iproute2 that spells
        // them differently) must refuse, not report "no MACs on the bridge" — the latter would
        // quietly withdraw every /32 this member holds.
        assert_eq!(
            local_vms(
                NEIGH,
                r#"[{"lladdr":"02:cf:ab:00:00:01","dev":"tap100i0"}]"#,
                &v,
                wl,
                &[]
            ),
            None
        );
        // An EMPTY document is a real answer: a bridge that has learned nothing yet.
        assert!(local_vms(NEIGH, "[]", &v, wl, &[]).unwrap().is_empty());
        // And the same on the neighbor side: an iproute2 that spells `dst`/`state` otherwise
        // must refuse, not read as "this leg has no neighbors" and withdraw every /32.
        assert_eq!(
            local_vms(
                r#"[{"address":"192.168.20.103","lladdr":"02:cf:ab:00:00:01","nud":["REACHABLE"]}]"#,
                fdb,
                &v,
                wl,
                &[]
            ),
            None
        );
        // An empty neighbor table is a real answer, and so is one holding only IPv6 (which we
        // do not route here): both are "no VMs", neither is a refusal.
        assert!(local_vms("[]", fdb, &v, wl, &[]).unwrap().is_empty());
        assert!(
            local_vms(
                r#"[{"dst":"fe80::1","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:09","state":["REACHABLE"]}]"#,
                fdb,
                &v,
                wl,
                &[]
            )
            .unwrap()
            .is_empty()
        );
    }

    /// The exclusion set is fabric-wide, not this member's own row: a peer's address on the
    /// workload must never read as a VM here (a 3-host testbed would otherwise count peers).
    #[test]
    fn the_exclusion_set_covers_every_member_and_the_gw() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            fabric_addresses(&v, &f.workloads[0]),
            set(&["192.168.20.2", "192.168.20.3", "192.168.20.254"]),
            "pve1-tb and pve2-tb carry the row; .254 is the anycast gw"
        );
    }

    #[test]
    fn a_vm_is_wanted_at_once_and_a_departure_is_held_for_one_announce_period() {
        let mut h = Holddown::default();
        let t0 = Instant::now();
        assert_eq!(
            h.observe(&set(&["192.168.20.103"]), t0),
            set(&["192.168.20.103"]),
            "an addition is never damped"
        );
        // The hold-down runs from the observation that first missed it, not from the last one
        // that saw it: the reconcile is level-triggered and a tick is the finest it can know.
        assert_eq!(
            h.observe(&BTreeSet::new(), t0 + Duration::from_secs(1)),
            set(&["192.168.20.103"]),
            "gone, and held"
        );
        assert_eq!(
            h.observe(
                &BTreeSet::new(),
                t0 + Duration::from_secs(1) + HOLDDOWN - Duration::from_millis(1)
            ),
            set(&["192.168.20.103"]),
            "still inside the window"
        );
        assert!(
            h.observe(&BTreeSet::new(), t0 + Duration::from_secs(1) + HOLDDOWN)
                .is_empty(),
            "withdrawn at the deadline"
        );
        assert_eq!(
            HOLDDOWN,
            Duration::from_secs(5),
            "ruling 3: one announce period"
        );
    }

    #[test]
    fn a_return_inside_the_window_cancels_the_withdrawal() {
        let mut h = Holddown::default();
        let t0 = Instant::now();
        let vm = set(&["192.168.20.103"]);
        h.observe(&vm, t0);
        h.observe(&BTreeSet::new(), t0 + Duration::from_secs(1));
        assert_eq!(
            h.observe(&vm, t0 + Duration::from_secs(2)),
            vm,
            "it came back"
        );
        // The cancelled deadline must not fire later: the clock restarts from the departure.
        assert_eq!(h.observe(&vm, t0 + Duration::from_secs(30)), vm);
        h.observe(&BTreeSet::new(), t0 + Duration::from_secs(31));
        assert_eq!(
            h.observe(&BTreeSet::new(), t0 + Duration::from_secs(33)),
            vm,
            "the hold-down runs from the SECOND departure, not the first"
        );
        assert!(
            h.observe(&BTreeSet::new(), t0 + Duration::from_secs(37))
                .is_empty()
        );
    }

    /// pve1-tb with the leg up, one VM on a tap, and an empty nft set: the tick must originate
    /// the /32 at the engine and add the element.
    fn tick_sys(elements: &str) -> MockSys {
        MockSys::default()
            .file("/sys/class/net/primary/bridge/stp_state", "0\n")
            .file("/sys/class/net/primary/bridge/ageing_time", "30000\n")
            .file("/sys/class/net/primary/brif/eth0/state", "3\n")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .link("/sys/class/net/eth0/device", "../../../0000:01:00.0")
            .file("/sys/class/net/cfab-work-vms/ifindex", "42\n")
            .on_stdout(&["ip", "-j", "neigh", "show", "dev", "cfab-work-vms"], NEIGH)
            .on_stdout(&["bridge", "-j", "fdb", "show", "br", "primary"], FDB)
            .on_stdout(
                &["nft", "-j", "list", "set", "inet", "cfab-fwd"],
                &format!(
                    r#"{{"nftables":[{{"set":{{"family":"inet","name":"cfab-work-vms-local","table":"cfab-fwd","type":"ipv4_addr"{elements}}}}}]}}"#
                ),
            )
            .socket("/run/cfab/engine.sock", "{\"workload_routes\":{\"routes\":1}}\n")
    }

    #[test]
    fn the_tick_originates_the_leg_ifindex_and_the_wanted_set_and_adds_the_element() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        let said = HostRoutes::new().tick(&mut sys, &v, &mut io(), Instant::now());
        assert!(said.is_empty(), "a healthy tick says nothing: {said:?}");
        assert!(
            sys.ran(
                "unix_request /run/cfab/engine.sock workload-routes cfab-work-vms 42 \
                 192.168.20.2/32 192.168.20.103/32"
            ),
            "{:?}",
            sys.calls
        );
        assert!(
            sys.ran("nft add element inet cfab-fwd cfab-work-vms-local { 192.168.20.103 }"),
            "{:?}",
            sys.calls
        );
        assert!(
            !sys.calls.iter().any(|c| c.contains("nft delete element")),
            "nothing to delete: {:?}",
            sys.calls
        );
    }

    /// Spec fact 5 and its one hazard, in one place: this member's own leg address is a /32 in
    /// the set handed to the ENGINE (so a relayed DHCP reply addressed to `giaddr` has a route
    /// home, over OSPF for a leaf and over BGP for the router) and is NOT in the nft
    /// `<leg>-local` set, which is VM addresses and decides what the host answers for. The two
    /// sets are built one line apart and it would cost nothing to conflate them.
    #[test]
    fn the_leg_slash_32_is_originated_and_never_joins_the_local_vm_set() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        HostRoutes::new().tick(&mut sys, &v, &mut io(), Instant::now());
        assert!(
            sys.ran(
                "unix_request /run/cfab/engine.sock workload-routes cfab-work-vms 42 \
                 192.168.20.2/32 192.168.20.103/32"
            ),
            "{:?}",
            sys.calls
        );
        assert!(
            !sys.calls
                .iter()
                .any(|c| c.contains("element") && c.contains("192.168.20.2")),
            "the leg address must not reach the local set: {:?}",
            sys.calls
        );
    }

    /// Level-triggered both ways: an element nft holds that we no longer want is deleted, and
    /// an element already in place is not re-added (the diff is the whole point).
    #[test]
    fn the_tick_deletes_what_nft_holds_and_we_no_longer_want() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys(r#","elem":["192.168.20.103","192.168.20.199"]"#);
        HostRoutes::new().tick(&mut sys, &v, &mut io(), Instant::now());
        assert!(
            sys.ran("nft delete element inet cfab-fwd cfab-work-vms-local { 192.168.20.199 }"),
            "{:?}",
            sys.calls
        );
        assert!(
            !sys.calls.iter().any(|c| c.contains("nft add element")),
            "192.168.20.103 is already there: {:?}",
            sys.calls
        );
    }

    /// No VM at all: an empty document in both places, the shape a bridge that has learned
    /// nothing yet, or a VM that has genuinely gone, presents.
    fn no_vm(mut sys: MockSys) -> MockSys {
        sys = sys.on_stdout(&["ip", "-j", "neigh", "show", "dev", "cfab-work-vms"], "[]");
        sys.on_stdout(&["bridge", "-j", "fdb", "show", "br", "primary"], "[]")
    }

    /// Gate B: the FIRST tick a row is ever reconciled is a baseline (already asserted by
    /// `the_tick_originates_the_leg_ifindex_and_the_wanted_set_and_adds_the_element`'s empty
    /// `said`); a VM appearing on a LATER tick is a real join and gets its own line.
    #[test]
    fn a_vm_that_appears_on_a_later_tick_is_journaled_as_a_join() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = no_vm(tick_sys(""));
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();
        assert!(
            hr.tick(&mut sys, &v, &mut io(), t0).is_empty(),
            "the baseline (nothing here yet) is not a join"
        );
        let sys2 = tick_sys(""); // the VM starts talking: NEIGH/FDB show it again
        sys.cmd_rules = sys2.cmd_rules;
        assert_eq!(
            hr.tick(&mut sys, &v, &mut io(), t0 + Duration::from_secs(1)),
            vec!["cfab: workload vms: vm 192.168.20.103 joined"]
        );
    }

    /// Gate B's core teeth: a VM that genuinely leaves gets its neighbor entry deleted and one
    /// journal line, at the SAME moment (post hold-down) its /32 already withdraws — never
    /// earlier. Three ticks: present (baseline), gone (inside the hold-down window: still
    /// wanted, nothing said), gone again past the deadline (withdrawn, deleted, journaled).
    #[test]
    fn a_vm_that_leaves_gets_its_neighbor_entry_deleted_and_one_journal_line() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();
        hr.tick(&mut sys, &v, &mut io(), t0); // baseline: .103 present

        sys = no_vm(sys);
        let said = hr.tick(&mut sys, &v, &mut io(), t0 + Duration::from_secs(1));
        assert!(
            said.iter().all(|l| !l.contains("left")),
            "still inside the hold-down window: {said:?}"
        );
        assert!(
            !sys.calls.iter().any(|c| c.contains("neigh del")),
            "not deleted while still held: {:?}",
            sys.calls
        );

        let said = hr.tick(
            &mut sys,
            &v,
            &mut io(),
            t0 + Duration::from_secs(1) + HOLDDOWN,
        );
        assert!(
            sys.ran("ip neigh del 192.168.20.103 dev cfab-work-vms"),
            "{:?}",
            sys.calls
        );
        assert_eq!(
            said,
            vec!["cfab: workload vms: vm 192.168.20.103 left (no longer seen as a local VM)"]
        );
    }

    /// A `neigh del` that the kernel refuses (the entry is already gone, a race with something
    /// else) is not swallowed: the "left" fact still stands, and the failure is named alongside
    /// it — fail loud, never a silent partial result.
    #[test]
    fn a_failed_neigh_del_is_named_but_the_departure_is_still_reported() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();
        hr.tick(&mut sys, &v, &mut io(), t0);
        sys = no_vm(sys).on_fail(&["ip", "neigh", "del"], 2, "No such file or directory");
        hr.tick(&mut sys, &v, &mut io(), t0 + Duration::from_secs(1)); // inside the window
        let said = hr.tick(
            &mut sys,
            &v,
            &mut io(),
            t0 + Duration::from_secs(1) + HOLDDOWN,
        );
        assert_eq!(
            said,
            vec![
                "cfab: workload vms: vm 192.168.20.103 left (no longer seen as a local VM); \
                 cannot delete its neighbor entry on cfab-work-vms"
            ]
        );
    }

    /// The race gate B's own doc comment names: a VM that reappears (a real packet, or gate C's
    /// `Cmd::DhcpAck` neighbor write) BEFORE the hold-down deadline is never treated as having
    /// left at all — no journal line, no `neigh del`, ever. The reconcile cannot tell a real
    /// packet from an ACK-driven `ip neigh replace`, which is exactly why this is race-safe
    /// without knowing anything about DHCP.
    #[test]
    fn a_vm_that_returns_inside_the_hold_down_window_is_never_deleted() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();
        hr.tick(&mut sys, &v, &mut io(), t0); // baseline: present

        sys = no_vm(sys);
        hr.tick(&mut sys, &v, &mut io(), t0 + Duration::from_secs(1)); // vanishes

        let sys2 = tick_sys("");
        sys.cmd_rules = sys2.cmd_rules; // …and returns, inside the window
        let said = hr.tick(
            &mut sys,
            &v,
            &mut io(),
            t0 + Duration::from_secs(1) + HOLDDOWN - Duration::from_millis(1),
        );
        assert!(
            said.is_empty(),
            "the return cancels the departure: {said:?}"
        );
        assert!(
            !sys.calls.iter().any(|c| c.contains("neigh del")),
            "never deleted: {:?}",
            sys.calls
        );
        // …and it stays wanted well past when the original deadline would have fired, proving
        // the clock genuinely restarted rather than merely being checked late.
        let said = hr.tick(
            &mut sys,
            &v,
            &mut io(),
            t0 + Duration::from_secs(1) + 2 * HOLDDOWN,
        );
        assert!(said.is_empty(), "{said:?}");
    }

    /// A deferred row forgets its membership baseline along with its hold-down: no leg exists
    /// to delete a neighbor entry from, and a later reinstall must not read the pre-deferral
    /// state as a mass, spurious "left" for every VM that was here before.
    #[test]
    fn a_deferred_row_reports_no_departures_and_reinstalling_reports_fresh_joins() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();
        hr.tick(&mut sys, &v, &mut io(), t0); // baseline: .103 present and installed

        sys = sys.file(&format!("{}/workload-deferred", v.fabric.run_dir), "vms\n");
        let said = hr.tick(&mut sys, &v, &mut io(), t0 + Duration::from_secs(1));
        assert!(
            said.iter().all(|l| !l.contains("left")),
            "a deferred row's leg is gone with every neighbor entry on it, not \"left\": {said:?}"
        );

        sys.files
            .remove(&format!("{}/workload-deferred", v.fabric.run_dir));
        assert_eq!(
            hr.tick(&mut sys, &v, &mut io(), t0 + Duration::from_secs(4)),
            vec!["cfab: workload vms: vm 192.168.20.103 joined"],
            "reinstalling is a fresh baseline that then reports the VM as joining, not silence"
        );
    }

    /// The idle-VM probe (spec §5.2 (a), gate B). Due immediately the first time a row is
    /// installed (same shape as the announcer's own first-beacon-immediate rule), then at the
    /// interval `probe_interval` derives from the bridge's `ageing_time` (30000 centiseconds =
    /// 300 s in the fixture, so a third of that = 100 s) — never sooner, never a broadcast.
    #[test]
    fn the_idle_probe_sends_one_unicast_arp_per_live_vm_at_the_derived_interval() {
        use crate::workload::announce::mock::{MOCK_MAC, SharedIo};
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        let shared = SharedIo::default();
        let mut io = shared.clone();
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();

        hr.tick(&mut sys, &v, &mut io, t0);
        let sent = shared.sent();
        assert_eq!(sent.len(), 1, "one probe, due immediately: {sent:?}");
        assert_eq!(sent[0].0, "cfab-work-vms");
        assert_eq!(
            sent[0].1,
            unicast_probe(
                MOCK_MAC,
                [0x02, 0xcf, 0xab, 0x00, 0x00, 0x01], // .103's own MAC, from FDB/NEIGH
                addr("192.168.20.254"),               // this host's own gw identity
                addr("192.168.20.103"),
            ),
            "unicast to the VM's own MAC, sender = gw, target = the VM"
        );

        hr.tick(&mut sys, &v, &mut io, t0 + Duration::from_secs(1));
        assert_eq!(shared.sent().len(), 1, "not due yet: {:?}", shared.sent());

        hr.tick(&mut sys, &v, &mut io, t0 + Duration::from_secs(100));
        assert_eq!(
            shared.sent().len(),
            2,
            "due again a third of the 300 s ageing_time later"
        );
    }

    /// S2: a probe fan-out failure is ONE aggregate line per cycle, never one per address, and
    /// `recovered` never fires in the same cycle a send failed. Before this fix, one failing
    /// send inserted a standing fault line and the loop's own later success then IMMEDIATELY
    /// cleared it and printed "… recovered" in the very same tick — a live contradiction that
    /// would repeat forever on any host with more than one VM where exactly one send keeps
    /// failing (the fault is per-INTERFACE, so that is the common case, not a corner case).
    #[test]
    fn a_partial_probe_failure_is_one_aggregate_line_never_a_same_tick_recovered() {
        use crate::error::{Error, Result};
        use crate::workload::announce::AnnounceIo;
        use crate::workload::announce::mock::MOCK_MAC;

        /// Fails the send addressed to one specific destination MAC and succeeds every other —
        /// the shape a real partial fan-out failure takes (one VM's tap gone mid-cycle, the
        /// rest fine). `RecordingIo`'s `fail` is all-or-nothing and cannot exercise this.
        struct PartialFailIo {
            fail_dst: [u8; 6],
        }
        impl AnnounceIo for PartialFailIo {
            fn send(&mut self, _ifname: &str, frame: &[u8]) -> Result<()> {
                if frame[0..6].to_vec() == self.fail_dst.to_vec() {
                    return Err(Error::fatal("send failed (test)"));
                }
                Ok(())
            }
            fn mac(&mut self, _ifname: &str) -> Result<[u8; 6]> {
                Ok(MOCK_MAC)
            }
        }

        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        // Two local VMs this time (the default fixture has only one): .103 (mac …01, sends
        // fine) and .150 (mac …0b, whose send `PartialFailIo` fails).
        let neigh = r#"[
          {"dst":"192.168.20.103","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:01","state":["REACHABLE"]},
          {"dst":"192.168.20.150","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:0b","state":["REACHABLE"]}
        ]"#;
        let fdb = r#"[
          {"mac":"02:cf:ab:00:00:01","ifname":"tap100i0","vlan":3,"master":"primary","state":""},
          {"mac":"02:cf:ab:00:00:0b","ifname":"tap150i0","vlan":3,"master":"primary","state":""}
        ]"#;
        let mut sys = tick_sys("")
            .on_stdout(
                &["ip", "-j", "neigh", "show", "dev", "cfab-work-vms"],
                neigh,
            )
            .on_stdout(&["bridge", "-j", "fdb", "show", "br", "primary"], fdb);
        let mut hr = HostRoutes::new();
        let mut fail_io = PartialFailIo {
            fail_dst: [0x02, 0xcf, 0xab, 0x00, 0x00, 0x0b],
        };
        let t0 = Instant::now();

        let said = hr.tick(&mut sys, &v, &mut fail_io, t0);
        let probe_lines: Vec<&String> = said
            .iter()
            .filter(|l| l.contains("idle-VM probe"))
            .collect();
        assert_eq!(
            probe_lines.len(),
            1,
            "one aggregate line for the whole cycle, not one per failing address: {said:?}"
        );
        assert!(
            probe_lines[0].contains("1 of 2 idle-VM probes on cfab-work-vms failed"),
            "{probe_lines:?}"
        );
        assert!(
            !said.iter().any(|l| l.contains("recovered")),
            "a fault that stood this very cycle must never be reported recovered in it: {said:?}"
        );
    }

    /// A VM that has already left is not probed: the probe reads the SAME fresh `live` map the
    /// rest of the tick derived this cycle, never a remembered roster.
    #[test]
    fn a_departed_vm_is_never_probed() {
        use crate::workload::announce::mock::SharedIo;
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        let shared = SharedIo::default();
        let mut io = shared.clone();
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();
        hr.tick(&mut sys, &v, &mut io, t0); // probes once, immediately
        assert_eq!(shared.sent().len(), 1);

        sys = no_vm(sys);
        // Advance to the probe's own next-due deadline (a third of the fixture's 300 s
        // ageing_time = 100 s) WHILE the VM is absent, so the probe actually runs its
        // `live.is_empty()` check rather than skipping on "not due yet" — still inside the
        // membership hold-down (5 s), which is the point: even a VM `wanted` still protects
        // from withdrawal is never probed once this tick's own fresh read no longer sees it.
        hr.tick(&mut sys, &v, &mut io, t0 + Duration::from_secs(100));
        assert_eq!(
            shared.sent().len(),
            1,
            "no probe for a VM this tick's own read no longer sees"
        );
    }

    /// A bridge `ageing_time` that cannot be read is named once and recovers once, and the probe
    /// still runs at the documented fallback (a third of 300 s) rather than stopping outright.
    #[test]
    fn an_unreadable_ageing_time_falls_back_and_is_named_once() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        sys.files
            .remove("/sys/class/net/primary/bridge/ageing_time");
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();
        assert_eq!(
            hr.tick(&mut sys, &v, &mut io(), t0),
            vec![
                "cfab: workload vms: cannot read \
                 /sys/class/net/primary/bridge/ageing_time; probing at the default 300s \
                 ageing_time assumption"
            ]
        );
        assert!(
            hr.tick(&mut sys, &v, &mut io(), t0 + Duration::from_secs(1))
                .is_empty(),
            "not due again yet, and said once"
        );
        sys.files.insert(
            "/sys/class/net/primary/bridge/ageing_time".into(),
            "30000\n".into(),
        );
        assert_eq!(
            hr.tick(&mut sys, &v, &mut io(), t0 + DEFAULT_AGEING / 3),
            vec!["cfab: workload vms: bridge ageing_time read recovered"]
        );
    }

    /// B2: `probe_interval`'s conversion (sysfs centiseconds -> milliseconds -> `/3`) is pinned
    /// with an `ageing_time` OTHER than the fixture's 30000 (the fixture's own value is 100 s
    /// either way `100 == 30000 / 30` and `100 == 30000 / 3 / 10`-shaped bugs both land on the
    /// same number, so it proves neither the unit nor the divisor). 6000 centiseconds = 60 s;
    /// a third of that is 20 s. Three ticks bracket the true deadline on both sides: a bug that
    /// drops the `* 10` (reads centiseconds as milliseconds outright) computes 2 s, floored to
    /// PERIOD = 5 s, and would already be due by the 19 s check; a bug in the divisor (anything
    /// but `/ 3`) lands the due time somewhere else again and misses the exact 20 s check.
    #[test]
    fn probe_interval_converts_centiseconds_and_divides_by_three() {
        use crate::workload::announce::mock::SharedIo;
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        sys.files.insert(
            "/sys/class/net/primary/bridge/ageing_time".into(),
            "6000\n".into(),
        );
        let shared = SharedIo::default();
        let mut io = shared.clone();
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();

        hr.tick(&mut sys, &v, &mut io, t0);
        assert_eq!(shared.sent().len(), 1, "one probe, due immediately");

        hr.tick(&mut sys, &v, &mut io, t0 + Duration::from_secs(19));
        assert_eq!(
            shared.sent().len(),
            1,
            "not yet due at 19s: a 60s ageing_time / 3 is 20s, not sooner"
        );

        hr.tick(&mut sys, &v, &mut io, t0 + Duration::from_secs(20));
        assert_eq!(
            shared.sent().len(),
            2,
            "due at exactly 20s: 6000 centiseconds -> 60s -> /3"
        );
    }

    /// B2: the `.max(PERIOD)` floor is pinned separately from the conversion above. 600
    /// centiseconds = 6 s of `ageing_time`; a third of that is 2 s, which the floor must raise
    /// to PERIOD (5 s) rather than let the probe run at 2 s (a pathologically low `ageing_time`
    /// must not turn the probe into a beacon). Bracketed the same way: not yet due at 3 s (the
    /// un-floored 2 s would already have fired), due at exactly 5 s.
    #[test]
    fn probe_interval_floors_at_the_announcer_period() {
        use crate::workload::announce::mock::SharedIo;
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        sys.files.insert(
            "/sys/class/net/primary/bridge/ageing_time".into(),
            "600\n".into(),
        );
        let shared = SharedIo::default();
        let mut io = shared.clone();
        let mut hr = HostRoutes::new();
        let t0 = Instant::now();

        hr.tick(&mut sys, &v, &mut io, t0);
        assert_eq!(shared.sent().len(), 1, "one probe, due immediately");

        hr.tick(&mut sys, &v, &mut io, t0 + Duration::from_secs(3));
        assert_eq!(
            shared.sent().len(),
            1,
            "not yet due at 3s: the un-floored 2s must not have fired"
        );

        hr.tick(&mut sys, &v, &mut io, t0 + PERIOD);
        assert_eq!(
            shared.sent().len(),
            2,
            "due at exactly PERIOD (5s), the floor"
        );
    }

    /// A deferred row has no leg: the wanted set is empty, the engine is told so with ifindex
    /// 0, and nothing is read off a netdev that does not exist.
    #[test]
    fn a_deferred_row_withdraws_everything_and_reads_no_neighbors() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys(r#","elem":["192.168.20.103"]"#)
            .file(&format!("{}/workload-deferred", v.fabric.run_dir), "vms\n");
        HostRoutes::new().tick(&mut sys, &v, &mut io(), Instant::now());
        assert!(
            sys.ran("unix_request /run/cfab/engine.sock workload-routes cfab-work-vms 42"),
            "{:?}",
            sys.calls
        );
        assert!(
            sys.ran("nft delete element inet cfab-fwd cfab-work-vms-local { 192.168.20.103 }"),
            "{:?}",
            sys.calls
        );
        assert!(
            !sys.calls.iter().any(|c| c.contains("neigh show")),
            "a deferred row reads no neighbors: {:?}",
            sys.calls
        );
    }

    /// A leg the watchdog has not rebuilt yet reads ifindex 0, which is never a real netdev:
    /// the engine learns the leg moved and re-resolves on the way back.
    #[test]
    fn an_absent_leg_reports_ifindex_zero() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        sys.files.remove("/sys/class/net/cfab-work-vms/ifindex");
        HostRoutes::new().tick(&mut sys, &v, &mut io(), Instant::now());
        assert!(
            sys.ran(
                "unix_request /run/cfab/engine.sock workload-routes cfab-work-vms 0 \
                 192.168.20.2/32 192.168.20.103/32"
            ),
            "{:?}",
            sys.calls
        );
    }

    /// A failed read is never a withdrawal: nothing is asked of the engine or of nft, and the
    /// line is said once however long it lasts, then cleared when the read works again.
    #[test]
    fn a_failed_neighbor_read_changes_nothing_and_is_said_once() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("").on_fail(
            &["ip", "-j", "neigh", "show", "dev", "cfab-work-vms"],
            1,
            "Cannot talk to rtnetlink",
        );
        let mut hr = HostRoutes::new();
        let now = Instant::now();
        assert_eq!(
            hr.tick(&mut sys, &v, &mut io(), now),
            vec![
                "cfab: workload vms: cannot read the neighbors of cfab-work-vms; host routes \
                 unchanged"
            ]
        );
        assert!(
            !sys.calls.iter().any(|c| c.contains("workload-routes")),
            "no route request on a failed read: {:?}",
            sys.calls
        );
        assert!(
            !sys.calls.iter().any(|c| c.contains("element")),
            "no set change on a failed read: {:?}",
            sys.calls
        );
        assert!(
            hr.tick(&mut sys, &v, &mut io(), now).is_empty(),
            "the standing line is said once"
        );
        let mut healthy = tick_sys("");
        assert_eq!(
            hr.tick(&mut healthy, &v, &mut io(), now),
            vec!["cfab: workload vms: VM read recovered"]
        );
    }

    /// An engine that will not take the request, and an nft set that cannot be read: two
    /// independent conditions, each with its own line and its own cost.
    #[test]
    fn an_engine_refusal_and_an_unreadable_set_are_named_apart() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("")
            .socket("/run/cfab/engine.sock", "{\"error\":\"no such leg\"}\n")
            .on_fail(
                &["nft", "-j", "list", "set"],
                1,
                "No such file or directory",
            );
        assert_eq!(
            HostRoutes::new().tick(&mut sys, &v, &mut io(), Instant::now()),
            vec![
                "cfab: workload vms: engine refused workload-routes cfab-work-vms 42 \
                 192.168.20.2/32 192.168.20.103/32: {\"error\":\"no such leg\"}; host routes unchanged"
                    .to_string(),
                "cfab: workload vms: cannot read the nft set inet cfab-fwd \
                 cfab-work-vms-local; the local set is unchanged"
                    .to_string(),
            ]
        );
    }

    /// The two-step ifindex move whose withdraw landed and whose install then failed: holo
    /// holds NO routes for the leg, so "host routes unchanged" would be a lie about the one
    /// failure that actually costs reach. Its own spelling, and its own cost.
    #[test]
    fn a_withdraw_that_landed_before_a_refused_install_is_not_called_unchanged() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("").socket(
            "/run/cfab/engine.sock",
            "{\"error\":\"the provider refused the install\",\"withdrew\":true}\n",
        );
        assert_eq!(
            HostRoutes::new().tick(&mut sys, &v, &mut io(), Instant::now())[0],
            "cfab: workload vms: engine withdrew the routes of cfab-work-vms and refused the \
             reinstall: the provider refused the install; retried next tick"
        );
    }

    /// What `apply` seeds the nft sets from: the same join, keyed by set name, so the emitter
    /// and the reconcile can never disagree about what belongs in one. A deferred row has no
    /// leg to read and seeds empty, and so does a row whose reads fail.
    #[test]
    fn the_apply_seed_is_the_same_join_and_a_deferred_row_seeds_nothing() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys("");
        assert_eq!(
            seed_locals(&mut sys, &v),
            [("cfab-work-vms-local".to_string(), set(&["192.168.20.103"]))]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        );
        let mut deferred = tick_sys("").file("/run/cfab/workload-deferred", "vms\n");
        assert!(seed_locals(&mut deferred, &v)["cfab-work-vms-local"].is_empty());
        let mut blind = tick_sys("").on_fail(&["ip", "-j", "neigh"], 1, "no such device");
        assert!(seed_locals(&mut blind, &v)["cfab-work-vms-local"].is_empty());
    }

    #[test]
    fn a_set_listing_parses_its_elements_and_an_empty_set_is_not_a_failure() {
        assert_eq!(
            parse_set_elements(
                r#"{"nftables":[{"metainfo":{}},{"set":{"name":"s","elem":["10.0.0.1","10.0.0.2"]}}]}"#
            )
            .unwrap(),
            set(&["10.0.0.1", "10.0.0.2"])
        );
        assert!(
            parse_set_elements(r#"{"nftables":[{"set":{"name":"s"}}]}"#)
                .unwrap()
                .is_empty(),
            "a set with no elements is an empty set, not a failure"
        );
        // An element carrying attributes is an object, not a bare string.
        assert_eq!(
            parse_set_elements(
                r#"{"nftables":[{"set":{"name":"s","elem":[{"elem":{"val":"10.0.0.3"}}]}}]}"#
            )
            .unwrap(),
            BTreeSet::new(),
            "an unrecognized element shape is skipped, never guessed at"
        );
        assert_eq!(parse_set_elements("not json"), None);
        assert_eq!(
            parse_set_elements(r#"{"nftables":[{"metainfo":{}}]}"#),
            None
        );
    }
}
