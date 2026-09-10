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
use crate::workload::announce::PERIOD;
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
/// `None` when either document does not parse as a JSON array — a failed read is never a fact
/// about VMs, and every caller treats it as "unchanged", never as "they are all gone".
pub fn local_vms(
    neigh_json: &str,
    fdb_json: &str,
    view: &View,
    wl: &Workload,
    uplink_ports: &[String],
) -> Option<BTreeSet<Ipv4Addr>> {
    let neigh: Value = serde_json::from_str(neigh_json).ok()?;
    let fdb: Value = serde_json::from_str(fdb_json).ok()?;
    let (neigh, fdb) = (neigh.as_array()?, fdb.as_array()?);

    // MAC -> the bridge ports it has been seen on. A MAC on both a VM port and the uplink (a
    // migration in flight) is local: the tap is the newer, more specific fact.
    let mut local_macs: BTreeSet<String> = BTreeSet::new();
    for e in fdb {
        let (Some(mac), Some(port)) = (e["mac"].as_str(), e["ifname"].as_str()) else {
            continue;
        };
        if uplink_ports.iter().any(|p| p == port) {
            continue;
        }
        local_macs.insert(mac.to_ascii_lowercase());
    }

    let exclude = fabric_addresses(view, wl);
    let mut out = BTreeSet::new();
    for e in neigh {
        let Some(dst) = e["dst"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        if !wl.prefix.contains(dst) || exclude.contains(&dst) {
            continue;
        }
        let resolved = e["state"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str())
            .any(|s| RESOLVED.contains(&s));
        if !resolved {
            continue;
        }
        let Some(mac) = e["lladdr"].as_str() else {
            continue;
        };
        if local_macs.contains(&mac.to_ascii_lowercase()) {
            out.insert(dst);
        }
    }
    Some(out)
}

/// Every address on this workload the fabric itself owns: each declared member's address on the
/// row (fabric-wide, not just this member — `View::workload_rows` is this-member-only), the
/// anycast `gw` and the VLAN's `router`. Without it a peer's own resolution of the gateway
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
    out.insert(wl.router);
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
}

impl Cond {
    /// What the recovery line calls this condition. One spelling, one sentence shape.
    fn as_str(self) -> &'static str {
        match self {
            Cond::Read => "VM read",
            Cond::Engine => "engine route request",
            Cond::Nft => "local set update",
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
    /// the caller owns stderr and the test trace.
    pub fn tick(&mut self, sys: &mut dyn Sys, view: &View, now: Instant) -> Vec<String> {
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
                // than hold routes for a leg that is not there.
                self.rows.entry(wl.name.clone()).or_default().holddown = Holddown::default();
                Some(BTreeSet::new())
            };
            // A read that failed costs one tick and nothing else — never a withdrawal.
            let Some(live) = live else { continue };
            let ifindex = leg_ifindex(sys, &wl.leg_ifname()).unwrap_or(0);
            let wanted = {
                let r = self.rows.entry(wl.name.clone()).or_default();
                r.holddown.observe(&live, now)
            };
            self.ask_engine(sys, view, wl, ifindex, &wanted, &mut out);
            self.sync_set(sys, wl, &wanted, &mut out);
        }
        out
    }

    /// The live local-VM set for one row, or `None` when a read this tick could not be made.
    fn observe(
        &mut self,
        sys: &mut dyn Sys,
        view: &View,
        wl: &Workload,
        out: &mut Vec<String>,
    ) -> Option<BTreeSet<Ipv4Addr>> {
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
        match local_vms(&neigh.stdout, &fdb.stdout, view, wl, &ports) {
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
        let why = match sys.unix_request(&sock, &line) {
            Ok(reply) if reply.contains("\"error\"") => {
                Some(format!("engine refused {}: {}", line.trim(), reply.trim()))
            }
            Ok(_) => None,
            Err(e) => Some(format!("engine would not take {}: {e}", line.trim())),
        };
        match why {
            Some(why) => self.fail(&name, Cond::Engine, why, out),
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
    fn fail(&mut self, name: &str, cond: Cond, why: String, out: &mut Vec<String>) {
        let cost = match cond {
            Cond::Read | Cond::Engine => "host routes unchanged",
            Cond::Nft => "the local set is unchanged",
        };
        self.rows.entry(name.to_string()).or_default().say_once(
            cond,
            format!("cfab: workload {name}: {why}; {cost}"),
            out,
        );
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

    fn wl_fabric() -> Fabric {
        Fabric::from_decl(
            &Declaration::parse(&fixtures::with_workload(&fixtures::example())).unwrap(),
        )
        .unwrap()
    }

    /// The fixture the plan names: one VM on a tap, this member and its peer, the router, one
    /// out-of-prefix neighbor, and one VLAN-3 address whose MAC lives on the uplink (a VM on
    /// another host). Only the first is local.
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
            "the peers' addresses, the router, the out-of-prefix entry and the VM whose MAC is \
             on the uplink are all excluded"
        );
        // The teeth: with the uplink not named, the VM on the OTHER host stops being excluded
        // and this member would originate a /32 for a VM it cannot reach.
        assert_eq!(
            local_vms(NEIGH, FDB, &v, wl, &[]).unwrap(),
            set(&["192.168.20.103", "192.168.20.104"])
        );
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
        let said = HostRoutes::new().tick(&mut sys, &v, Instant::now());
        assert!(said.is_empty(), "a healthy tick says nothing: {said:?}");
        assert!(
            sys.ran(
                "unix_request /run/cfab/engine.sock workload-routes cfab-work-vms 42 \
                 192.168.20.103/32"
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

    /// Level-triggered both ways: an element nft holds that we no longer want is deleted, and
    /// an element already in place is not re-added (the diff is the whole point).
    #[test]
    fn the_tick_deletes_what_nft_holds_and_we_no_longer_want() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys(r#","elem":["192.168.20.103","192.168.20.199"]"#);
        HostRoutes::new().tick(&mut sys, &v, Instant::now());
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

    /// A deferred row has no leg: the wanted set is empty, the engine is told so with ifindex
    /// 0, and nothing is read off a netdev that does not exist.
    #[test]
    fn a_deferred_row_withdraws_everything_and_reads_no_neighbors() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut sys = tick_sys(r#","elem":["192.168.20.103"]"#)
            .file(&format!("{}/workload-deferred", v.fabric.run_dir), "vms\n");
        HostRoutes::new().tick(&mut sys, &v, Instant::now());
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
        HostRoutes::new().tick(&mut sys, &v, Instant::now());
        assert!(
            sys.ran(
                "unix_request /run/cfab/engine.sock workload-routes cfab-work-vms 0 \
                 192.168.20.103/32"
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
            hr.tick(&mut sys, &v, now),
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
            hr.tick(&mut sys, &v, now).is_empty(),
            "the standing line is said once"
        );
        let mut healthy = tick_sys("");
        assert_eq!(
            hr.tick(&mut healthy, &v, now),
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
            HostRoutes::new().tick(&mut sys, &v, Instant::now()),
            vec![
                "cfab: workload vms: engine refused workload-routes cfab-work-vms 42 \
                 192.168.20.103/32: {\"error\":\"no such leg\"}; host routes unchanged"
                    .to_string(),
                "cfab: workload vms: cannot read the nft set inet cfab-fwd \
                 cfab-work-vms-local; the local set is unchanged"
                    .to_string(),
            ]
        );
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
