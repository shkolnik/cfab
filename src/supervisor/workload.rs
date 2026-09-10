//! The gateway announcers a member with `[[workload]]` rows runs (spec §5.1 item 8, ruling 12).
//!
//! One `Announcer` per row, driven by the supervisor's select loop: the loop sleeps to the
//! earliest deadline any of them has, fires the ones that are due, and hands each an ownership
//! change when the neighbor watch reports a MAC learned on one of that row's VM ports. The state
//! machine and the frame are `workload::announce`; the kernel facts are `workload::neigh` and
//! `workload::uplink`. What lives here is the glue that owns them: when an announcer may start,
//! which rows an event belongs to, and what the journal and `status` say.
//!
//! **An announcer never starts for a row `apply` deferred** (spec addendum 2026-09-09). A
//! deferred row has no gateway address on the wire yet — the forwarding watchdog adds it once
//! the uplink forwards — and announcing an address this host does not hold would point every
//! VM in the VLAN at a host that cannot answer. The row is picked up on a later tick, once its
//! name has left `<run_dir>/workload-deferred`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::derive::View;
use crate::sys::Sys;
use crate::workload::announce::{AnnounceIo, Announcer};
use crate::workload::hostroutes::HostRoutes;
use crate::workload::neigh::{self, NeighSignal};
use crate::workload::uplink::{self, Uplink};
use crate::workload::{Trigger, deferred_names};

use super::Shared;
use super::report::WorkloadAnnounce;
use super::trace_mark;

/// The supervisor's test-trace recorder (`Hooks::trace`), so a test can assert the exact
/// journal text without capturing the process's stderr. `None` in production.
type Trace = Option<Arc<Mutex<Vec<String>>>>;

/// Say it on the journal (and to the test trace). `eprintln!`, never `tracing`: the supervisor
/// installs no subscriber, so a `tracing` line here would go nowhere.
fn journal(trace: &Trace, line: String) {
    eprintln!("{line}");
    trace_mark(trace, line);
}

/// One running announcer and the facts it is driven by.
struct Row {
    name: String,
    announcer: Announcer,
    /// The row's bridge and uplink ports, as `apply` identified them. Re-read per event only
    /// for the port SET (a tap comes and goes); the bridge and uplink do not move under us.
    up: Uplink,
    /// The MAC the last frame went out with. Re-read at every beacon (a sub-interface's MAC
    /// follows its parent bridge, which can change under us); this is the fallback the row
    /// keeps announcing with when a read fails, never a permanent cache.
    mac: [u8; 6],
    /// The FDB poll's memory of `(port, mac)`; untouched on the event trigger.
    seen: BTreeSet<(String, String)>,
    /// The line standing for each repeating condition, so a fault that lasts costs one line
    /// and not one per period. Keyed, because the conditions are independent: a MAC that
    /// cannot be read while the socket works must not be un-deduplicated by the send's own
    /// recovery, and vice versa.
    standing: BTreeMap<Cond, String>,
}

/// The repeating conditions a row deduplicates its journal on. Each keeps its own standing
/// line and its own recovery, because they are independent: a socket that starts working again
/// says nothing about a netdev whose MAC still cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Cond {
    /// The send socket refused the frame.
    Send,
    /// The interface's MAC could not be read.
    Mac,
    /// The bridge's port set could not be scanned.
    Scan,
}

impl Cond {
    /// What the recovery line calls this condition. One spelling per condition, and one
    /// sentence shape for all three.
    fn as_str(self) -> &'static str {
        match self {
            Cond::Send => "announce",
            Cond::Mac => "MAC read",
            Cond::Scan => "bridge port scan",
        }
    }
}

impl Row {
    /// Say `line` unless it is the line already standing for `cond` on this row.
    fn journal_once(&mut self, cond: Cond, trace: &Trace, line: String) {
        if self.standing.get(&cond).map(String::as_str) == Some(line.as_str()) {
            return;
        }
        self.standing.insert(cond, line.clone());
        journal(trace, line);
    }

    /// `cond` is over: say so once, and only if it was standing.
    ///
    /// Clearing it is the load-bearing half. A standing line that is never cleared swallows the
    /// SECOND occurrence of the same fault for the life of the process — a netdev that vanishes,
    /// comes back, and vanishes again would be reported once and then never — so every path
    /// that observes `cond` succeeding must come through here.
    fn recovered(&mut self, cond: Cond, trace: &Trace) {
        if self.standing.remove(&cond).is_some() {
            let name = &self.name;
            journal(
                trace,
                format!("cfab: workload {name}: {} recovered", cond.as_str()),
            );
        }
    }

    /// Re-read the interface's MAC before announcing with it.
    ///
    /// A change is an ownership change like any other: the frames already on their way out
    /// carry a MAC the VLAN is about to stop answering for, so it is said once and burst on.
    /// A read that FAILS keeps the last known MAC and announces anyway — a beacon from a
    /// possibly stale MAC beats no beacon at all (availability first), and the line says so.
    fn refresh_mac(&mut self, io: &mut dyn AnnounceIo, trace: &Trace, now: Instant) {
        let (name, ifname) = (self.name.clone(), self.announcer.ifname.clone());
        match read_mac(io, &ifname) {
            Ok(mac) => {
                self.recovered(Cond::Mac, trace);
                if mac == self.mac {
                    return;
                }
                let (old, new) = (hex_mac(self.mac), hex_mac(mac));
                self.mac = mac;
                self.announcer.on_event(now);
                journal(
                    trace,
                    format!("cfab: workload {name}: {ifname} MAC changed {old} -> {new}"),
                );
            }
            Err(why) => self.journal_once(
                Cond::Mac,
                trace,
                format!("cfab: workload {name}: {why}; announcing the last known MAC"),
            ),
        }
    }
}

/// Every announcer this member runs, and the trigger they share.
pub(crate) struct Workloads {
    /// `None` on a member with no `[[workload]]` row: nothing was opened and nothing runs.
    trigger: Option<Trigger>,
    rows: Vec<Row>,
    /// Rows already reported as deferred, so the 3 s tick says it once rather than 20 times a
    /// minute for as long as an uplink takes to forward.
    deferred_said: BTreeSet<String>,
    /// The per-VM host routes (spec §5.2): the same rows, reconciled on the same tick, so the
    /// set an announcer bursts for and the set this member originates /32s for are read from
    /// one place at one moment.
    hostroutes: HostRoutes,
    trace: Trace,
}

impl Workloads {
    /// Open the member's neighbor subscription (`open`) and start an announcer for every row
    /// that is installed. A member with no `[[workload]]` row never calls `open` at all — it
    /// pays nothing for the feature.
    pub(crate) fn start(
        sys: &mut dyn Sys,
        view: &View,
        io: &mut dyn AnnounceIo,
        trace: Trace,
        open: impl FnOnce() -> Result<(), String>,
        now: Instant,
    ) -> Self {
        let mut w = Workloads {
            trigger: None,
            rows: Vec::new(),
            deferred_said: BTreeSet::new(),
            hostroutes: HostRoutes::new(),
            trace,
        };
        if view.workload_rows().is_empty() {
            return w;
        }
        w.trigger = Some(match open() {
            Ok(()) => Trigger::NeighEvents,
            Err(reason) => Trigger::FdbPoll {
                reason: format!("RTNLGRP_NEIGH subscription failed: {reason}"),
            },
        });
        w.start_pending(sys, view, io, now);
        w
    }

    /// The 3 s tick: pick up any row the watchdog has installed since the last one, and — on
    /// the fallback trigger only — poll the FDB for a MAC that has appeared on a VM port.
    pub(crate) fn tick(
        &mut self,
        sys: &mut dyn Sys,
        view: &View,
        io: &mut dyn AnnounceIo,
        now: Instant,
    ) {
        self.start_pending(sys, view, io, now);
        self.refresh_uplinks(sys, view);
        // The host-route reconcile (spec §5.2, ruling 6). Level triggered and independent of
        // the announcers: it runs for every declared row, including one still deferred (whose
        // wanted set is empty), and it owns its own standing-line dedup, so what arrives here
        // is only what has not been said yet.
        for line in self.hostroutes.tick(sys, view, now) {
            journal(&self.trace, line);
        }
        if !matches!(self.trigger, Some(Trigger::FdbPoll { .. })) {
            return;
        }
        for r in &mut self.rows {
            if neigh::fdb_poll_changed(sys, &r.up, &mut r.seen) {
                r.announcer.on_event(now);
            }
        }
    }

    /// Re-read every running row's uplink.
    ///
    /// A bridge port added since the last tick — a second NIC, a bond member, a VLAN trunk —
    /// is an uplink from then on. Without this it would still be classified as a VM port, so
    /// every peer MAC learned on it would read as this host's ownership changing and burst,
    /// which is exactly the amplification the uplink filter exists to prevent.
    ///
    /// Cheap: one `brif/` listing plus a `device` probe per port, the same reads `apply` does.
    /// A read that FAILS keeps the last known uplink rather than blanking it (a blank uplink
    /// set would make every port a VM port); the forwarding watchdog owns that alarm and
    /// already reports an unidentifiable uplink on its own tick, so this one does not
    /// double-report it.
    fn refresh_uplinks(&mut self, sys: &mut dyn Sys, view: &View) {
        for row in view.workload_rows() {
            let Ok(up) = uplink::identify_declared(sys, &row.wl.uplink, row.wl.vid) else {
                continue;
            };
            let Some(r) = self.rows.iter_mut().find(|r| r.name == row.wl.name) else {
                continue;
            };
            if r.up == up {
                continue;
            }
            let (name, old, new) = (r.name.clone(), r.up.ports.join(","), up.ports.join(","));
            r.up = up;
            if old != new {
                journal(
                    &self.trace,
                    format!("cfab: workload {name}: uplink ports {old} -> {new}"),
                );
            }
        }
    }

    /// Start an announcer for every declared row that has none yet and is not deferred.
    ///
    /// The steady state is one comparison: once every row has an announcer nothing is read at
    /// all, so the tick costs nothing on a converged member.
    fn start_pending(
        &mut self,
        sys: &mut dyn Sys,
        view: &View,
        io: &mut dyn AnnounceIo,
        now: Instant,
    ) {
        let rows = view.workload_rows();
        if rows.len() == self.rows.len() {
            return;
        }
        let Some(trigger) = self.trigger.clone() else {
            return;
        };
        let deferred = deferred_names(sys, view);
        for row in rows {
            let name = &row.wl.name;
            if self.rows.iter().any(|r| &r.name == name) {
                continue;
            }
            if deferred.contains(name) {
                if self.deferred_said.insert(name.clone()) {
                    journal(
                        &self.trace,
                        format!("cfab: workload {name}: deferred; announcer not started"),
                    );
                }
                continue;
            }
            let leg = row.wl.leg_ifname();
            let ifname = leg.as_str();
            let started = uplink::identify_declared(sys, &row.wl.uplink, row.wl.vid)
                .and_then(|up| read_mac(io, ifname).map(|mac| (up, mac)));
            match started {
                Ok((up, mac)) => {
                    self.rows.push(Row {
                        name: name.clone(),
                        announcer: Announcer::new(ifname, row.wl.gw, now),
                        up,
                        mac,
                        seen: BTreeSet::new(),
                        standing: BTreeMap::new(),
                    });
                    journal(
                        &self.trace,
                        format!("cfab: workload {name}: announcer trigger {trigger}"),
                    );
                }
                // Never fatal: the supervisor keeps every other announcer and the fabric
                // running, and the watchdog's own restores keep trying (availability first).
                Err(why) => journal(
                    &self.trace,
                    format!("cfab: workload {name}: {why}; announcer not started"),
                ),
            }
        }
    }

    /// The neighbor watch task has exited: every row moves to the FDB poll and says so.
    ///
    /// Without this a member whose subscription died would keep reporting `neigh events` while
    /// nothing ever woke it again — the beacon would still converge every PERIOD, but the
    /// ownership-change burst, which is what makes a migration sub-second, would be silently
    /// gone. Ruling 12 requires `status` to say which path is active; this keeps that true for
    /// the whole life of the process, not just its first second.
    pub(crate) fn watch_died(&mut self, why: &str) {
        if self.trigger.is_none() {
            return; // no rows on this member: nothing was watching
        }
        let trigger = Trigger::FdbPoll {
            reason: format!("neighbor watch died: {why}"),
        };
        if self.trigger.as_ref() == Some(&trigger) {
            return;
        }
        self.trigger = Some(trigger.clone());
        for r in &self.rows {
            journal(
                &self.trace,
                format!("cfab: workload {}: announcer trigger {trigger}", r.name),
            );
        }
    }

    /// When the caller must next wake, or `None` when nothing is running.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        self.rows.iter().map(|r| r.announcer.next_due()).min()
    }

    /// Send whatever is due now. A send failure never stops the schedule: the deadline has
    /// already advanced, so a dead socket costs frames, never a spin or a stuck beacon.
    pub(crate) fn fire_due(&mut self, io: &mut dyn AnnounceIo, now: Instant) {
        let Workloads { rows, trace, .. } = self;
        for r in rows {
            let (name, ifname) = (r.name.clone(), r.announcer.ifname.clone());
            r.refresh_mac(io, trace, now);
            match r.announcer.announce_due(io, r.mac, now) {
                Ok(true) => r.recovered(Cond::Send, trace),
                Ok(false) => {}
                Err(e) => r.journal_once(
                    Cond::Send,
                    trace,
                    format!("cfab: workload {name}: announce on {ifname} failed: {e}"),
                ),
            }
        }
    }

    /// A bridge FDB event, or the gap an ENOBUFS overflow left.
    ///
    /// An overflow bursts every row: we cannot know which port the dropped events were for, and
    /// the rate limit caps the cost at one burst per period per row. An add bursts the rows
    /// whose bridge has that ifindex as a NON-uplink port — a peer's MAC arriving on the uplink
    /// is not this host's ownership changing, and a permanent entry is not a VM at all.
    pub(crate) fn on_neigh(&mut self, sys: &mut dyn Sys, sig: &NeighSignal, now: Instant) {
        let ev = match sig {
            NeighSignal::Overflow => {
                for r in &mut self.rows {
                    r.announcer.on_event(now);
                }
                return;
            }
            NeighSignal::Add(ev) if ev.permanent => return,
            NeighSignal::Add(ev) => ev,
        };
        let Workloads { rows, trace, .. } = self;
        for r in rows {
            match uplink::non_uplink_ifindexes(sys, &r.up) {
                Ok(ports) => {
                    r.recovered(Cond::Scan, trace);
                    if ports.contains(&ev.ifindex) {
                        r.announcer.on_event(now);
                    }
                }
                // The scan is how we tell a VM port from the uplink. Without it the honest
                // move is to skip the burst and let the beacon converge within one period —
                // the same cost ruling 12 accepts for an ENOBUFS.
                Err(why) => {
                    let name = r.name.clone();
                    r.journal_once(
                        Cond::Scan,
                        trace,
                        format!("cfab: workload {name}: {why}; burst skipped"),
                    );
                }
            }
        }
    }

    /// The `components` rows (`status` and `/metrics` read these).
    pub(crate) fn rows_for_status(&self) -> Vec<WorkloadAnnounce> {
        let trigger = self
            .trigger
            .as_ref()
            .map(Trigger::to_string)
            .unwrap_or_default();
        self.rows
            .iter()
            .map(|r| {
                let (announces, bursts) = r.announcer.counters();
                WorkloadAnnounce {
                    name: r.name.clone(),
                    ifname: r.announcer.ifname.clone(),
                    trigger: trigger.clone(),
                    announces,
                    bursts,
                }
            })
            .collect()
    }

    /// Publish those rows into the shared state the socket server and `/metrics` read.
    pub(crate) fn publish(&self, shared: &Arc<Mutex<Shared>>) {
        shared.lock().unwrap().workloads = self.rows_for_status();
    }
}

/// The sub-interface's own MAC, through the same seam the frame goes out of (`getifaddrs` in
/// production). It is the sender MAC of every frame this row announces, so a row whose MAC
/// cannot be read at all starts no announcer rather than announce a wrong one.
fn read_mac(io: &mut dyn AnnounceIo, ifname: &str) -> Result<[u8; 6], String> {
    io.mac(ifname)
        .map_err(|e| format!("cannot read the MAC of {ifname}: {e}"))
}

/// `00:11:22:33:44:55` — the spelling every other tool prints a MAC in.
fn hex_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;
    use crate::workload::announce::{PERIOD, mock::RecordingIo};
    use crate::workload::neigh::{NeighEvent, NeighSignal};
    use std::time::Duration;

    fn rec() -> Arc<Mutex<Vec<String>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn said(t: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        t.lock().unwrap().clone()
    }

    /// pve1-tb carrying the "vms" row: `apply`'s own workload fixture (bridge `primary`, uplink
    /// eth0 forwarding at ifindex 2, one VM tap `tap100i0` at ifindex 10), plus the watchdog's
    /// deferred-row list where a test wants one. The MAC comes from the io seam, not from sysfs.
    ///
    /// It also answers everything the host-route reconcile reads on a HEALTHY member — the leg's
    /// ifindex, one VM neighbor whose MAC is on the tap, an empty nft set, an engine that takes
    /// the request — so a test about the announcers sees a quiet reconcile beside them, and a
    /// test about the reconcile breaks exactly one of those reads and asserts what it says.
    fn wl(deferred: Option<&str>) -> (MockSys, View<'static>) {
        let (sys, view) = crate::commands::apply::tests::wl_sys_and_view("pve1-tb");
        let mut sys = sys
            .file("/sys/class/net/cfab-work-vms/ifindex", "42\n")
            .on_stdout(
                &["ip", "-j", "neigh", "show", "dev", "cfab-work-vms"],
                r#"[{"dst":"192.168.20.103","dev":"cfab-work-vms","lladdr":"02:cf:ab:00:00:01","state":["REACHABLE"]}]"#,
            )
            .on_stdout(
                &["bridge", "-j", "fdb", "show", "br", "primary"],
                r#"[{"mac":"02:cf:ab:00:00:01","ifname":"tap100i0","master":"primary"}]"#,
            )
            .on_stdout(
                &["nft", "-j", "list", "set", "inet", "cfab-fwd"],
                r#"{"nftables":[{"set":{"name":"cfab-work-vms-local","type":"ipv4_addr"}}]}"#,
            )
            .socket("/run/cfab/engine.sock", "{\"workload_routes\":{}}\n");
        if let Some(names) = deferred {
            sys = sys.file(&deferred_path(&view), names);
        }
        (sys, view)
    }

    fn deferred_path(view: &View) -> String {
        format!("{}/workload-deferred", view.fabric.run_dir)
    }

    fn opens() -> Result<(), String> {
        Ok(())
    }

    const EPERM: &str = "Operation not permitted (os error 1)";

    /// The addendum (2026-09-09): `apply` may leave a row deferred — no gateway address on the
    /// wire — and the forwarding watchdog installs it later. Announcing a gateway this host does
    /// not yet hold would be a lie, so the row gets no announcer and the journal says which.
    #[test]
    fn a_row_listed_in_workload_deferred_gets_no_announcer_and_says_so() {
        let (mut sys, view) = wl(Some("vms"));
        let trace = rec();
        let w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            opens,
            Instant::now(),
        );
        assert!(
            w.rows_for_status().is_empty(),
            "no announcer for a deferred row"
        );
        assert_eq!(w.next_due(), None, "and nothing to wake for");
        assert_eq!(
            said(&trace),
            vec!["cfab: workload vms: deferred; announcer not started"]
        );
    }

    /// …and it starts on the tick after the watchdog installs it (the name leaves the file),
    /// journaling the trigger line then. The deferred line is said once, not every 3 s.
    #[test]
    fn a_deferred_row_starts_its_announcer_once_the_watchdog_installs_it() {
        let (mut sys, view) = wl(Some("vms"));
        let trace = rec();
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            opens,
            t0,
        );
        w.tick(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            t0 + Duration::from_secs(3),
        );
        assert!(w.rows_for_status().is_empty(), "still deferred");
        assert_eq!(said(&trace).len(), 1, "the deferred line is said once");

        sys.files.insert(deferred_path(&view), String::new());
        let t = t0 + Duration::from_secs(6);
        w.tick(&mut sys, &view, &mut RecordingIo::default(), t);
        let rows = w.rows_for_status();
        assert_eq!(
            (
                rows[0].name.as_str(),
                rows[0].ifname.as_str(),
                rows[0].trigger.as_str()
            ),
            ("vms", "cfab-work-vms", "neigh events")
        );
        assert_eq!(w.next_due(), Some(t), "the first beacon is immediate");
        assert_eq!(
            said(&trace)[1],
            "cfab: workload vms: announcer trigger neigh events"
        );
        w.tick(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            t0 + Duration::from_secs(9),
        );
        assert_eq!(said(&trace).len(), 2, "started once, said once");
        assert_eq!(w.rows_for_status().len(), 1);
    }

    /// Task 3: the host-route reconcile rides the announcers' own 3 s tick and the same row
    /// set, so a member with no `[[workload]]` row never runs it at all and a member with one
    /// originates the /32 and fills the nft set the stray drop reads.
    #[test]
    fn the_tick_reconciles_the_host_routes_beside_the_announcers() {
        let (mut sys, view) = wl(None);
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(rec()),
            opens,
            t0,
        );
        assert!(
            !sys.calls.iter().any(|c| c.contains("workload-routes")),
            "the reconcile is the tick's, not start's: {:?}",
            sys.calls
        );
        w.tick(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            t0 + Duration::from_secs(3),
        );
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
    }

    /// The reconcile's own journal is the supervisor's journal: a fault it names is said on
    /// stderr and to the trace, exactly once, like every other repeating condition here.
    #[test]
    fn what_the_host_route_reconcile_says_reaches_the_journal_once() {
        let (sys, view) = wl(None);
        let mut sys = sys.on_fail(
            &["ip", "-j", "neigh", "show", "dev", "cfab-work-vms"],
            1,
            "Cannot talk to rtnetlink",
        );
        let trace = rec();
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            opens,
            t0,
        );
        for n in [3, 6] {
            w.tick(
                &mut sys,
                &view,
                &mut RecordingIo::default(),
                t0 + Duration::from_secs(n),
            );
        }
        assert_eq!(
            said(&trace)
                .iter()
                .filter(|l| l.contains("host routes unchanged"))
                .collect::<Vec<_>>(),
            vec![
                "cfab: workload vms: cannot read the neighbors of cfab-work-vms; host routes \
                 unchanged"
            ]
        );
    }

    /// A member with no `[[workload]]` row pays nothing: no reconcile, no reads, no request.
    #[test]
    fn a_member_without_workload_rows_runs_no_reconcile() {
        let f = crate::model::Fabric::from_decl(
            &crate::decl::Declaration::parse(&crate::decl::fixtures::example()).unwrap(),
        )
        .unwrap();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(rec()),
            opens,
            Instant::now(),
        );
        w.tick(&mut sys, &view, &mut RecordingIo::default(), Instant::now());
        assert!(sys.calls.is_empty(), "{:?}", sys.calls);
    }

    /// An uplink that cannot be identified after a successful apply (the bridge's last
    /// off-host port went away under us): journal the reason, start nothing, never panic.
    #[test]
    fn an_uplink_that_cannot_be_identified_journals_the_reason_and_starts_no_announcer() {
        let (mut sys, view) = wl(None);
        sys.links.remove("/sys/class/net/eth0/device");
        let trace = rec();
        let w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            opens,
            Instant::now(),
        );
        assert!(w.rows_for_status().is_empty());
        assert_eq!(
            said(&trace),
            vec![
                "cfab: workload vms: bridge primary has no uplink port (no port has a \
                 /sys/class/net/<port>/device, directly or through lower links); ports: eth0, \
                 tap100i0; announcer not started"
            ]
        );
    }

    /// The same, for a sub-interface whose MAC cannot be read: one condition, one spelling.
    #[test]
    fn a_mac_that_cannot_be_read_journals_the_reason_and_starts_no_announcer() {
        let (mut sys, view) = wl(None);
        let trace = rec();
        let mut io = RecordingIo {
            mac: None,
            ..Default::default()
        };
        let w = Workloads::start(
            &mut sys,
            &view,
            &mut io,
            Some(trace.clone()),
            opens,
            Instant::now(),
        );
        assert!(w.rows_for_status().is_empty());
        assert_eq!(
            said(&trace),
            vec![
                "cfab: workload vms: cannot read the MAC of cfab-work-vms: FATAL: cfab-work-vms: no \
                 link-layer address (no netdev?); announcer not started"
            ]
        );
    }

    /// The MAC a row announces is re-read at every beacon, because a VLAN sub-interface's MAC
    /// follows its parent bridge and a bridge adopts the lowest MAC among its ports. A change
    /// is said once, bursts like any other ownership change, and the NEXT frame carries it.
    #[test]
    fn a_mac_that_changes_under_us_is_said_once_burst_on_and_announced() {
        let (mut sys, view) = wl(None);
        let trace = rec();
        let t0 = Instant::now();
        let mut io = RecordingIo::default();
        let mut w = Workloads::start(&mut sys, &view, &mut io, Some(trace.clone()), opens, t0);
        w.fire_due(&mut io, t0);
        assert_eq!(w.rows_for_status()[0].bursts, 0);

        const NEW: [u8; 6] = [0x02, 0xcf, 0xab, 0x00, 0x00, 0x09];
        io.mac = Some(NEW);
        w.fire_due(&mut io, t0 + PERIOD);
        assert_eq!(
            io.sent.last().unwrap().1,
            crate::workload::announce::gratuitous(NEW, "192.168.20.254".parse().unwrap()),
            "the frame carries the new MAC"
        );
        assert_eq!(
            w.rows_for_status()[0].bursts,
            1,
            "a MAC change is an ownership change: burst on it"
        );
        assert_eq!(
            said(&trace)
                .iter()
                .filter(|l| l.contains("MAC changed"))
                .collect::<Vec<_>>(),
            vec![
                "cfab: workload vms: cfab-work-vms MAC changed 00:11:22:33:44:55 -> 02:cf:ab:00:00:09"
            ]
        );
        // Unchanged from here on: the line is said once per change, not once per beacon.
        w.fire_due(&mut io, t0 + 2 * PERIOD);
        assert_eq!(
            said(&trace)
                .iter()
                .filter(|l| l.contains("MAC changed"))
                .count(),
            1
        );
    }

    /// A MAC read that fails does not silence the beacon: the row keeps announcing with the
    /// last MAC it had, and says so once (availability first).
    #[test]
    fn a_mac_read_failure_keeps_announcing_with_the_last_known_mac() {
        let (mut sys, view) = wl(None);
        let trace = rec();
        let t0 = Instant::now();
        let mut io = RecordingIo::default();
        let mut w = Workloads::start(&mut sys, &view, &mut io, Some(trace.clone()), opens, t0);
        w.fire_due(&mut io, t0);
        io.mac = None;
        w.fire_due(&mut io, t0 + PERIOD);
        w.fire_due(&mut io, t0 + 2 * PERIOD);
        assert_eq!(io.sent.len(), 3, "the beacon does not stop");
        assert!(
            io.sent
                .iter()
                .all(|(_, f)| f[22..28] == crate::workload::announce::mock::MOCK_MAC),
            "every frame keeps the last known MAC"
        );
        assert_eq!(
            said(&trace)
                .iter()
                .filter(|l| l.contains("cannot read the MAC"))
                .collect::<Vec<_>>(),
            vec![
                "cfab: workload vms: cannot read the MAC of cfab-work-vms: FATAL: cfab-work-vms: no \
                 link-layer address (no netdev?); announcing the last known MAC"
            ]
        );
    }

    /// Ruling 12's fallback: the subscription could not be opened, so the trigger is the FDB
    /// poll, `status` says so, and a new MAC on a VM port still bursts.
    #[test]
    fn the_fdb_poll_fallback_names_its_reason_and_bursts_on_a_new_mac() {
        let (sys, view) = wl(None);
        let mut sys = sys.on_stdout(
            &["bridge", "fdb", "show", "br", "primary"],
            "02:cf:ab:00:00:01 dev tap100i0 vlan 3 master primary\n",
        );
        let trace = rec();
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            || Err(EPERM.to_string()),
            t0,
        );
        assert_eq!(
            w.rows_for_status()[0].trigger,
            format!("fdb poll (RTNLGRP_NEIGH subscription failed: {EPERM})")
        );
        assert_eq!(
            said(&trace),
            vec![format!(
                "cfab: workload vms: announcer trigger fdb poll (RTNLGRP_NEIGH subscription \
                 failed: {EPERM})"
            )]
        );
        assert_eq!(w.rows_for_status()[0].bursts, 0);
        w.tick(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            t0 + Duration::from_secs(3),
        );
        assert_eq!(w.rows_for_status()[0].bursts, 1, "the VM MAC is new");
        w.tick(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            t0 + Duration::from_secs(3) + PERIOD,
        );
        assert_eq!(
            w.rows_for_status()[0].bursts,
            1,
            "nothing new: the poll does not re-burst on a MAC it has already seen"
        );
    }

    /// The event trigger can stop working mid-run (the socket loses readiness, an fd error).
    /// Every row moves to the FDB poll, `status` says why, and the poll runs from the next tick.
    #[test]
    fn a_dead_neigh_watch_moves_every_row_to_the_fdb_poll_and_says_why() {
        let (sys, view) = wl(None);
        let mut sys = sys.on_stdout(
            &["bridge", "fdb", "show", "br", "primary"],
            "02:cf:ab:00:00:01 dev tap100i0 vlan 3 master primary\n",
        );
        let trace = rec();
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            opens,
            t0,
        );
        assert_eq!(w.rows_for_status()[0].trigger, "neigh events");

        w.watch_died("readiness lost");
        assert_eq!(
            w.rows_for_status()[0].trigger,
            "fdb poll (neighbor watch died: readiness lost)"
        );
        assert_eq!(
            said(&trace)[1],
            "cfab: workload vms: announcer trigger fdb poll (neighbor watch died: readiness lost)"
        );
        // …and the fallback is really running, not just claimed.
        w.tick(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            t0 + Duration::from_secs(3),
        );
        assert!(sys.ran("bridge fdb show br primary"));
        assert_eq!(w.rows_for_status()[0].bursts, 1);
        // Said once: a second report of the same death is not a second trigger change.
        w.watch_died("readiness lost");
        assert_eq!(said(&trace).len(), 2);
    }

    /// A member on the event trigger does NOT poll the FDB: the poll is the fallback, never a
    /// belt-and-braces second source (ruling 12 — `status` says which path is active, and a
    /// member that says "neigh events" must not be quietly doing both).
    #[test]
    fn the_event_trigger_runs_no_fdb_poll() {
        let (sys, view) = wl(None);
        let mut sys = sys.on_stdout(
            &["bridge", "fdb", "show", "br", "primary"],
            "02:cf:ab:00:00:01 dev tap100i0 vlan 3 master primary\n",
        );
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            None,
            opens,
            t0,
        );
        w.tick(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            t0 + Duration::from_secs(3),
        );
        assert_eq!(w.rows_for_status()[0].bursts, 0);
        assert!(!sys.ran("bridge fdb show"));
    }

    /// Only a learned MAC on a non-uplink port of OUR bridge is an ownership change. A peer's
    /// MAC on the uplink, a permanent entry, and a port on some other bridge are not.
    #[test]
    fn only_a_learned_mac_on_a_non_uplink_port_starts_a_burst() {
        let (mut sys, view) = wl(None);
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            None,
            opens,
            t0,
        );
        let add = |ifindex, permanent| {
            NeighSignal::Add(NeighEvent {
                ifindex,
                mac: [2, 0xcf, 0xab, 0, 0, 1],
                permanent,
            })
        };
        w.on_neigh(&mut sys, &add(2, false), t0); // eth0: the uplink
        w.on_neigh(&mut sys, &add(10, true), t0); // the tap, but a permanent entry
        w.on_neigh(&mut sys, &add(4242, false), t0); // not a port of this bridge
        assert_eq!(w.rows_for_status()[0].bursts, 0);
        w.on_neigh(&mut sys, &add(10, false), t0); // a VM starts talking
        assert_eq!(w.rows_for_status()[0].bursts, 1);
    }

    /// A port added to the bridge after the announcer started is classified from the tick that
    /// sees it: a second uplink NIC must never be read as a VM port, or every peer MAC learned
    /// on it would burst.
    #[test]
    fn a_new_uplink_port_is_reclassified_on_the_next_tick() {
        let (mut sys, view) = wl(None);
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            None,
            opens,
            t0,
        );
        let add = |ifindex| {
            NeighSignal::Add(NeighEvent {
                ifindex,
                mac: [2, 0xcf, 0xab, 0, 0, 1],
                permanent: false,
            })
        };
        // A second physical NIC joins the bridge (ifindex 3), and a VM tap beside it (10).
        sys.files.insert(
            "/sys/class/net/primary/brif/eth1/state".into(),
            "3\n".into(),
        );
        sys.files
            .insert("/sys/class/net/eth1/ifindex".into(), "3\n".into());
        sys.links.insert(
            "/sys/class/net/eth1/device".into(),
            "../../../0000:02:00.0".into(),
        );

        let trace = rec();
        w.trace = Some(trace.clone());
        w.tick(&mut sys, &view, &mut RecordingIo::default(), t0);
        assert_eq!(
            said(&trace),
            vec!["cfab: workload vms: uplink ports eth0 -> eth0,eth1"]
        );
        w.on_neigh(&mut sys, &add(3), t0);
        assert_eq!(
            w.rows_for_status()[0].bursts,
            0,
            "a MAC on the new uplink is a peer's, not a VM starting here"
        );
        w.on_neigh(&mut sys, &add(10), t0);
        assert_eq!(w.rows_for_status()[0].bursts, 1, "the tap still bursts");
    }

    /// An uplink that momentarily cannot be identified keeps its last known ports: a blank
    /// uplink set would make every port a VM port, which is worse than a stale one. (The
    /// forwarding watchdog is what shouts about an unidentifiable uplink.)
    #[test]
    fn a_failed_uplink_read_keeps_the_last_known_ports() {
        let (mut sys, view) = wl(None);
        let trace = rec();
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            opens,
            t0,
        );
        sys.links.remove("/sys/class/net/eth0/device");
        w.tick(&mut sys, &view, &mut RecordingIo::default(), t0);
        w.on_neigh(
            &mut sys,
            &NeighSignal::Add(NeighEvent {
                ifindex: 2, // eth0, still the uplink as far as we last knew
                mac: [2, 0xcf, 0xab, 0, 0, 1],
                permanent: false,
            }),
            t0,
        );
        assert_eq!(w.rows_for_status()[0].bursts, 0);
        assert_eq!(
            said(&trace).len(),
            1,
            "only the start line: no second alarm"
        );
    }

    /// ENOBUFS: the kernel dropped events we will never see, so the gap itself is the signal.
    /// One burst, no bridge scan (there is no ifindex to scan for).
    #[test]
    fn an_enobufs_overflow_starts_one_burst() {
        let (mut sys, view) = wl(None);
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            None,
            opens,
            t0,
        );
        w.on_neigh(&mut sys, &NeighSignal::Overflow, t0);
        assert_eq!(w.rows_for_status()[0].bursts, 1);
    }

    /// A dead send socket must cost one journal line per distinct error, not one per beacon:
    /// at 0.2 Hz per row an undeduplicated line would be 17 000 a day.
    #[test]
    fn a_send_failure_is_journaled_once_per_distinct_error_text() {
        let (mut sys, view) = wl(None);
        let trace = rec();
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            opens,
            t0,
        );
        let mut io = RecordingIo {
            fail: Some("cfab-work-vms: cannot send probe: ENODEV".into()),
            ..Default::default()
        };
        w.fire_due(&mut io, t0);
        w.fire_due(&mut io, t0 + PERIOD);
        let failures: Vec<String> = said(&trace)
            .into_iter()
            .filter(|l| l.contains("announce on"))
            .collect();
        assert_eq!(
            failures,
            vec![
                "cfab: workload vms: announce on cfab-work-vms failed: FATAL: cfab-work-vms: cannot \
                 send probe: ENODEV"
            ],
            "the same error twice is one line"
        );
        assert_eq!(
            w.rows_for_status()[0].announces,
            2,
            "the schedule advances whether or not the socket takes the frame"
        );

        io.fail = Some("cfab-work-vms: cannot send probe: ENETDOWN".into());
        w.fire_due(&mut io, t0 + 2 * PERIOD);
        assert_eq!(
            said(&trace)
                .iter()
                .filter(|l| l.contains("announce on"))
                .count(),
            2,
            "a different error is a different fact"
        );

        io.fail = None;
        w.fire_due(&mut io, t0 + 3 * PERIOD);
        assert_eq!(
            said(&trace).last().unwrap(),
            "cfab: workload vms: announce recovered"
        );
    }

    /// The half that makes the dedupe safe: a fault that ends CLEARS its standing line, so the
    /// same fault occurring again is reported again. Without this a netdev that vanishes, comes
    /// back and vanishes again is reported once and then never for the life of the process.
    #[test]
    fn a_fault_that_recovers_and_returns_is_journaled_again() {
        let (mut sys, view) = wl(None);
        let trace = rec();
        let t0 = Instant::now();
        let mut io = RecordingIo::default();
        let mut w = Workloads::start(&mut sys, &view, &mut io, Some(trace.clone()), opens, t0);
        w.fire_due(&mut io, t0);

        io.mac = None; // the netdev vanishes
        w.fire_due(&mut io, t0 + PERIOD);
        io.mac = Some(crate::workload::announce::mock::MOCK_MAC); // …and comes back
        w.fire_due(&mut io, t0 + 2 * PERIOD);
        io.mac = None; // …and vanishes again, identically
        w.fire_due(&mut io, t0 + 3 * PERIOD);

        let said = said(&trace);
        assert_eq!(
            said.iter()
                .filter(|l| l.contains("cannot read the MAC"))
                .count(),
            2,
            "the second vanish is a second fact, not a swallowed duplicate: {said:?}"
        );
        assert_eq!(
            said.iter()
                .filter(|l| *l == "cfab: workload vms: MAC read recovered")
                .count(),
            1,
            "and the recovery is said once: {said:?}"
        );
    }

    /// The third condition, and the proof that all three recoveries have ONE sentence shape.
    #[test]
    fn a_bridge_scan_that_recovers_says_so_in_the_same_shape() {
        let (mut sys, view) = wl(None);
        let trace = rec();
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            Some(trace.clone()),
            opens,
            t0,
        );
        let ev = NeighSignal::Add(NeighEvent {
            ifindex: 10,
            mac: [2, 0xcf, 0xab, 0, 0, 1],
            permanent: false,
        });
        sys.files.insert(
            "/sys/class/net/tap100i0/ifindex".into(),
            "not-a-number\n".into(),
        );
        w.on_neigh(&mut sys, &ev, t0);
        assert_eq!(
            w.rows_for_status()[0].bursts,
            0,
            "no burst without the scan"
        );
        assert_eq!(
            said(&trace)[1],
            "cfab: workload vms: port tap100i0: cannot read ifindex from \
             /sys/class/net/tap100i0/ifindex; burst skipped"
        );

        sys.files
            .insert("/sys/class/net/tap100i0/ifindex".into(), "10\n".into());
        w.on_neigh(&mut sys, &ev, t0);
        assert_eq!(
            said(&trace)[2],
            "cfab: workload vms: bridge port scan recovered"
        );
        assert_eq!(w.rows_for_status()[0].bursts, 1);
    }

    /// The frame on the wire is the gratuitous request for `gw`, sourced from the
    /// sub-interface's own MAC, on the sub-interface itself.
    #[test]
    fn the_beacon_puts_the_gratuitous_request_on_the_workload_interface() {
        let (mut sys, view) = wl(None);
        let t0 = Instant::now();
        let mut w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            None,
            opens,
            t0,
        );
        let mut io = RecordingIo::default();
        w.fire_due(&mut io, t0);
        assert_eq!(io.sent.len(), 1);
        assert_eq!(io.sent[0].0, "cfab-work-vms");
        assert_eq!(
            io.sent[0].1,
            crate::workload::announce::gratuitous(
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                "192.168.20.254".parse().unwrap()
            )
        );
        w.fire_due(&mut io, t0 + Duration::from_secs(1));
        assert_eq!(io.sent.len(), 1, "not due");
    }

    /// A member with no `[[workload]]` row opens no subscription at all: `open` is never
    /// called, so a member that carries no VM VLAN pays nothing for the feature.
    #[test]
    fn a_member_without_a_workload_row_opens_nothing() {
        let f: &'static Fabric = Box::leak(Box::new(
            Fabric::from_decl(
                &crate::decl::Declaration::parse(&crate::decl::fixtures::with_workload(
                    &crate::decl::fixtures::example(),
                ))
                .unwrap(),
            )
            .unwrap(),
        ));
        let view = View::new(f, "pve3-tb").unwrap();
        let mut sys = MockSys::default();
        let w = Workloads::start(
            &mut sys,
            &view,
            &mut RecordingIo::default(),
            None,
            || panic!("a member with no workload row must not open a subscription"),
            Instant::now(),
        );
        assert!(w.rows_for_status().is_empty());
        assert_eq!(w.next_due(), None);
    }
}
