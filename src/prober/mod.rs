//! The ingress router prober (finding F21).
//!
//! The migrating ingress leg (`gw = { domain = "any" }`) is an active-backup bond over every
//! wire, and the kernel judges its slaves by carrier. An island whose uplink is dead — cable,
//! PoE, upstream port, or a switch still booting — keeps carrier and keeps switching locally,
//! so the fabric's own BFD stays fully up while the router can no longer reach this member's
//! identities. Measured on the rack 2026-09-07: goal 3 lost indefinitely, and for ~20 s on
//! every island boot.
//!
//! The kernel's own ARP monitor cannot answer this. VLAN 249 spans the islands through the
//! backbone, so the bond's slaves are three ports into ONE broadcast domain; the kernel probes
//! with the bond's MAC, so the router's unicast reply lands on whichever port last learned that
//! MAC rather than on the slave that asked. Both `fail_over_mac` modes flapped (measured).
//!
//! So cfab asks the question itself, per wire, with a frame of its own (`frame`) on a raw
//! socket bound to the slave (`io`), and folds the answers with the pure state machine and
//! decision function in `decide`.

pub mod decide;
pub mod frame;
pub mod io;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::derive::View;
use crate::supervisor::report::{IngressLeg, IngressSlave};
use crate::sys::Sys;

use decide::{Candidate, Hysteresis, decide};
use io::ProbeIo;

/// How often every slave is asked. Half the 3.3 s BGP hold floor the router's session runs on,
/// divided again by the 3-observation hysteresis: 1.5 s to call a wire dead, 1.5 s to call it
/// live, both comfortably inside the hold. Derived, not a knob — the declaration has nothing to
/// say about it.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// One ingress leg's probe state.
struct Leg {
    zone: String,
    /// The leg netdev: a bond when the leg migrates, a plain sub-interface otherwise.
    bond: String,
    /// Only a migrating leg has slaves to move between. A single-domain leg is still probed —
    /// per-wire router reachability is an observable either way — but never actuated on.
    migrates: bool,
    router: Ipv4Addr,
    /// The zone's wire order, rank 0 first: what decides which reachable wire ingress belongs on.
    prefs: Vec<String>,
    /// The slave `bonding/primary` must name. The prober owns `primary` on a migrating leg: an
    /// `active_slave` write alone survives only until the next link event, after which
    /// `primary_reselect=always` hands the bond back to the old primary (VERIFIED on the rack,
    /// 2026-09-07). It starts as the leg's home and only ever moves with the bond.
    held: String,
    /// The slave the KERNEL has active, as of this tick's read — which is not always the one we
    /// hold: with nothing reachable the prober leaves the bond alone and the kernel's own
    /// carrier reselect moves it. `None` before the first read, and for a leg that has none.
    active_now: Option<String>,
    slaves: Vec<ProbeSlave>,
}

struct ProbeSlave {
    /// The netdev the probe goes out of and the tap listens on.
    ifname: String,
    wire: String,
    island: String,
    mac: [u8; 6],
    state: Hysteresis,
    /// A probe went out on the previous tick, so this tick's silence means something. Without
    /// it the very first tick — which has asked nobody anything — would count as a miss.
    probed: bool,
    last_reply: Option<Instant>,
}

/// Which slave each migrating ingress bond's `primary` must name: the prober's current choice,
/// which is the leg's home until the prober has a reason to hold another.
///
/// The prober owns `primary` on those bonds — an `active_slave` write alone survives only until
/// the next link event — so anything else that re-asserts `primary` must ask here first. The
/// forwarding watchdog rebuilds legs a re-enumerated wire took with it, and writing the DECLARED
/// home there would snap a bond the prober had deliberately moved straight back onto a
/// router-dead wire on the next USB blip.
#[derive(Clone, Debug, Default)]
pub struct HeldPrimaries(BTreeMap<String, String>);

impl HeldPrimaries {
    /// The slave this bond's `primary` must name, if the prober is holding one for it.
    pub fn slave_for(&self, bond: &str) -> Option<&str> {
        self.0.get(bond).map(String::as_str)
    }

    /// Record a choice. The prober is the only production caller.
    pub fn hold(&mut self, bond: &str, slave: &str) {
        self.0.insert(bond.to_string(), slave.to_string());
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Every ingress leg this member carries, probed once per `PROBE_INTERVAL`.
pub struct Prober {
    legs: Vec<Leg>,
}

impl Prober {
    /// The legs to probe. Empty on a leaf: a leaf builds no ingress leg at all (the outside
    /// reaches a leaf at the leaf's own addresses, never at a fabric identity), so there is
    /// nothing to ask and nothing to move.
    pub fn from_view(view: &View) -> Prober {
        let mut legs = Vec::new();
        for r in view.gw_rows() {
            let Ok(z) = view.fabric.zone(&r.zone) else {
                continue;
            };
            let Some(gw) = &z.gw else { continue };
            // `resolve_gw` already refused anything that is not four octets, so this parse
            // cannot fail on a loaded fabric. Skipping rather than panicking keeps a future
            // address form from taking the supervisor down instead of the prober.
            let Ok(router) = gw.router.parse::<Ipv4Addr>() else {
                continue;
            };
            let prefs = view
                .prefs()
                .into_iter()
                .find(|p| p.zone == r.zone)
                .map(|p| p.order)
                .unwrap_or_default();
            let island_of = |wire: &str| {
                view.member
                    .wires
                    .iter()
                    .find(|w| w.name == wire)
                    .map(|w| w.domain.as_str().to_string())
                    .unwrap_or_default()
            };
            let slaves: Vec<ProbeSlave> = if r.migrates() {
                r.slaves
                    .iter()
                    .enumerate()
                    .map(|(i, s)| ProbeSlave {
                        ifname: s.ifname.clone(),
                        wire: s.wire.clone(),
                        island: island_of(&s.wire),
                        mac: frame::synthetic_mac(view.node(), z.id, i as u8),
                        state: Hysteresis::default(),
                        probed: false,
                        last_reply: None,
                    })
                    .collect()
            } else {
                vec![ProbeSlave {
                    ifname: r.ifname.clone(),
                    wire: r.home.clone(),
                    island: island_of(&r.home),
                    mac: frame::synthetic_mac(view.node(), z.id, 0),
                    state: Hysteresis::default(),
                    probed: false,
                    last_reply: None,
                }]
            };
            let held = slaves
                .iter()
                .find(|s| s.wire == r.home)
                .or_else(|| slaves.first())
                .map(|s| s.ifname.clone())
                .unwrap_or_default();
            legs.push(Leg {
                zone: r.zone.clone(),
                bond: r.ifname.clone(),
                migrates: r.migrates(),
                router,
                prefs,
                held,
                active_now: None,
                slaves,
            });
        }
        Prober { legs }
    }

    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }

    /// One round: read the previous round's answers, move the bond if it belongs elsewhere,
    /// then ask again. Returns the rows `Components` publishes.
    ///
    /// Draining BEFORE sending is what gives a reply a whole `PROBE_INTERVAL` to arrive; the
    /// measured round trip is 80 µs, so the window is three orders of magnitude of margin, and
    /// the alternative (send, then read immediately) would score every wire as dark.
    pub fn tick(
        &mut self,
        sys: &mut dyn Sys,
        io: &mut dyn ProbeIo,
        now: Instant,
    ) -> Vec<IngressLeg> {
        for leg in &mut self.legs {
            for s in &mut leg.slaves {
                let frames = io.recv(&s.ifname).unwrap_or_default();
                let replied = frames
                    .iter()
                    .any(|f| frame::reply_from(f, s.mac, leg.router).is_some());
                if replied {
                    s.last_reply = Some(now);
                }
                // A tick with no probe outstanding learns nothing on the RECEIVE side: the
                // first tick has asked nobody anything, and a tick whose send failed is
                // accounted for below instead. A failed `recv` IS a miss, though — the tap is
                // on the slave, so losing it is the wire being unusable.
                if s.probed {
                    s.state.observe(replied);
                }
            }
            leg.actuate(sys);
            for s in &mut leg.slaves {
                match io.send(&s.ifname, &frame::probe(s.mac, leg.router)) {
                    Ok(()) => s.probed = true,
                    // A probe we cannot even put on the wire is evidence about the wire, not a
                    // gap in our knowledge of it: the netdev went away with a re-enumerated USB
                    // NIC, or the socket cannot be bound. Fold it in HERE rather than leaving
                    // the slave un-observed, or its state freezes at whatever it last was and
                    // ingress stays pinned to a dead wire forever, silently.
                    Err(_) => {
                        s.probed = false;
                        s.state.observe(false);
                    }
                }
            }
        }
        self.report(now)
    }

    /// The slave each migrating ingress bond's `primary` must name right now.
    pub fn held_primaries(&self) -> HeldPrimaries {
        HeldPrimaries(
            self.legs
                .iter()
                .filter(|l| l.migrates)
                .map(|l| (l.bond.clone(), l.held.clone()))
                .collect(),
        )
    }

    fn report(&self, now: Instant) -> Vec<IngressLeg> {
        self.legs
            .iter()
            .map(|l| IngressLeg {
                zone: l.zone.clone(),
                bond: l.bond.clone(),
                active: l.active_now.clone(),
                slaves: l
                    .slaves
                    .iter()
                    .map(|s| IngressSlave {
                        wire: s.wire.clone(),
                        island: s.island.clone(),
                        reachable: s.state.reachable(),
                        last_reply_ms: s
                            .last_reply
                            .map(|t| now.saturating_duration_since(t).as_millis() as u64),
                    })
                    .collect(),
            })
            .collect()
    }
}

impl Leg {
    /// Move the bond if the decision says it belongs elsewhere. Reads only on a healthy leg.
    fn actuate(&mut self, sys: &mut dyn Sys) {
        if !self.migrates {
            return;
        }
        let base = format!("/sys/class/net/{}/bonding", self.bond);
        // An unreadable `bonding/` means the bond is not there (or is not a bond). Writing into
        // it would be a guess about a netdev we cannot see; `status` and the forwarding watchdog
        // own that fault.
        let Ok(active) = sys.read(&format!("{base}/active_slave")) else {
            return;
        };
        let active = active.trim();
        let active = (!active.is_empty()).then_some(active);
        self.active_now = active.map(str::to_string);
        let cands: Vec<Candidate> = self
            .slaves
            .iter()
            .map(|s| Candidate {
                ifname: s.ifname.clone(),
                wire: s.wire.clone(),
                reachable: s.state.reachable(),
            })
            .collect();
        let Some(target) = decide(active, &cands, &self.prefs) else {
            return;
        };
        let to = self
            .slaves
            .iter()
            .find(|s| s.ifname == target)
            .map(|s| s.wire.clone())
            .unwrap_or_else(|| target.clone());
        let from = active.and_then(|a| self.slaves.iter().find(|s| s.ifname == a));
        // `primary` FIRST, then `active_slave`, and both every time (VERIFIED on the rack
        // 2026-09-07): an `active_slave` write alone holds only until the next link event, at
        // which point `primary_reselect=always` hands the bond straight back to the primary the
        // declaration set. Writing `primary` is therefore not bookkeeping — it is what makes the
        // move survive.
        for file in ["primary", "active_slave"] {
            if let Err(e) = sys.write(&format!("{base}/{file}"), &target) {
                eprintln!(
                    "cfab: {} ingress: cannot move {} to {to}: {e}",
                    self.zone, self.bond
                );
                return;
            }
        }
        self.held = target.clone();
        self.active_now = Some(target);
        match from {
            Some(f) if !f.state.reachable() => eprintln!(
                "cfab: {} ingress: router unreachable on {}, moved {} to {to}",
                self.zone, f.wire, self.bond
            ),
            Some(f) => eprintln!(
                "cfab: {} ingress: router reachable on {to} again, moved {} back from {}",
                self.zone, self.bond, f.wire
            ),
            None => eprintln!(
                "cfab: {} ingress: no slave of ours was active on {}, moved it to {to}",
                self.zone, self.bond
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::io::mock::ScriptedIo;
    use super::*;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    const ROUTER: &str = "192.168.249.254";
    const BOND: &str = "cfab-gw249";
    /// mgmt's primary domain is `c`, so the leg homes on eth0 and `primary` names this slave.
    const HOME: &str = "cfab-gw249-c";
    /// mgmt's wire order is eth0, eth9, eth1 (rank 0 = the primary domain, then speed): the
    /// first backup is the 5G wire on island a, NOT the first-enslaved one.
    const BACKUP: &str = "cfab-gw249-a";

    /// The shipped example: three wires per host (eth9 island a, eth1 island b, eth0 island c)
    /// and `gw = { domain = "any" }` on mgmt — the migrating leg.
    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        Fabric::from_decl(&crate::decl::Declaration::parse(&text).unwrap()).unwrap()
    }

    /// The same declaration with the ingress leg pinned to one domain: a plain sub-interface.
    fn fabric_with_a_domain_gw() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        let text = crate::decl::fixtures::with_a_domain_gw(&text);
        Fabric::from_decl(&crate::decl::Declaration::parse(&text).unwrap()).unwrap()
    }

    fn bonding(active: &str) -> MockSys {
        MockSys::default()
            .file(
                &format!("/sys/class/net/{BOND}/bonding/active_slave"),
                active,
            )
            .file(&format!("/sys/class/net/{BOND}/bonding/primary"), active)
    }

    /// The prober for the host member, and its slave names in enslave order.
    fn prober(f: &Fabric) -> (Prober, Vec<String>) {
        let view = View::new(f, "pve1-tb").unwrap();
        let p = Prober::from_view(&view);
        let names = p.legs[0].slaves.iter().map(|s| s.ifname.clone()).collect();
        (p, names)
    }

    fn run_ticks(
        p: &mut Prober,
        sys: &mut MockSys,
        io: &mut ScriptedIo,
        n: usize,
    ) -> Vec<IngressLeg> {
        let mut last = Vec::new();
        for i in 0..n {
            last = p.tick(sys, io, Instant::now() + PROBE_INTERVAL * i as u32);
        }
        last
    }

    #[test]
    fn every_slave_is_probed_with_its_own_source_address() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &[]);
        p.tick(&mut sys, &mut io, Instant::now());
        assert_eq!(io.sent.len(), names.len(), "one probe per slave per tick");
        let mut macs: Vec<[u8; 6]> = io
            .sent
            .iter()
            .map(|(_, fr)| fr[6..12].try_into().unwrap())
            .collect();
        let n = macs.len();
        macs.sort();
        macs.dedup();
        assert_eq!(macs.len(), n, "each slave asks with its own MAC");
        for (_, fr) in &io.sent {
            assert_eq!(fr.len(), frame::PROBE_LEN);
            assert_eq!(&fr[0..6], &[0xff; 6], "broadcast");
        }
    }

    #[test]
    fn a_leaf_has_no_ingress_leg_to_probe() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let p = Prober::from_view(&view);
        assert!(p.is_empty());
        assert!(p.held_primaries().is_empty());
    }

    /// The healthy case, which is every second the fabric spends working: nothing is written.
    #[test]
    fn a_bond_whose_router_answers_everywhere_is_never_written() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        let rows = run_ticks(&mut p, &mut sys, &mut io, 8);
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "{:?}",
            sys.calls
        );
        assert!(rows[0].slaves.iter().all(|s| s.reachable), "{rows:?}");
        assert!(rows[0].slaves.iter().all(|s| s.last_reply_ms.is_some()));
    }

    /// The F21 fault: the active wire keeps carrier but the router stops answering over it.
    /// The bond must move, `primary` must be written BEFORE `active_slave`, and both must name
    /// the wire the zone's preference order puts next.
    #[test]
    fn a_router_dead_active_wire_moves_the_bond_primary_first() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        run_ticks(&mut p, &mut sys, &mut io, 3);
        io.dark(HOME);
        let rows = run_ticks(&mut p, &mut sys, &mut io, 4);
        let want = BACKUP;
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{BOND}/bonding/primary")),
            Some(want)
        );
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{BOND}/bonding/active_slave")),
            Some(want)
        );
        let order: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("write /sys"))
            .collect();
        assert!(
            order[0].ends_with("/bonding/primary") && order[1].ends_with("/bonding/active_slave"),
            "primary must be written first, else the next link event undoes the move: {order:?}"
        );
        assert!(!rows[0].slaves[2].reachable, "the home wire, island c");
        assert_eq!(rows[0].active.as_deref(), Some(want));
    }

    /// Nothing answers anywhere: the kernel's carrier-driven reselect is a better guess than
    /// ours, so the bond is left alone.
    #[test]
    fn a_bond_with_no_reachable_wire_is_left_to_the_kernel() {
        let f = fabric();
        let (mut p, _) = prober(&f);
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &[]);
        let rows = run_ticks(&mut p, &mut sys, &mut io, 8);
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "{:?}",
            sys.calls
        );
        assert!(rows[0].slaves.iter().all(|s| !s.reachable));
    }

    #[test]
    fn the_bond_comes_home_when_the_home_wire_answers_again() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        run_ticks(&mut p, &mut sys, &mut io, 3);
        io.dark(HOME);
        run_ticks(&mut p, &mut sys, &mut io, 4);
        io.lit(HOME);
        run_ticks(&mut p, &mut sys, &mut io, 4);
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{BOND}/bonding/primary")),
            Some(HOME)
        );
        assert_eq!(p.held_primaries().slave_for(BOND), Some(HOME));
    }

    /// The bond is absent (a wire re-enumerated and took the whole leg with it): the prober
    /// writes nothing at all, and the forwarding watchdog rebuilds it.
    #[test]
    fn an_absent_bond_is_never_written() {
        let f = fabric();
        let (mut p, _) = prober(&f);
        let mut sys = MockSys::default();
        let mut io = ScriptedIo::answering_on(ROUTER, &[]);
        run_ticks(&mut p, &mut sys, &mut io, 8);
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "{:?}",
            sys.calls
        );
    }

    /// A slave whose probe cannot even be SENT — the netdev went away with a re-enumerated USB
    /// NIC — is a wire the router cannot be reached over, and must be folded in as a miss like
    /// any other. Freezing its state at "reachable" instead would pin ingress to a dead wire
    /// indefinitely: no move, no log line, and a row that reports the wire healthy.
    #[test]
    fn a_slave_whose_probe_cannot_be_sent_goes_unreachable_and_the_bond_moves() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        io.send_fails.insert(HOME.to_string());
        let rows = run_ticks(&mut p, &mut sys, &mut io, 6);
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{BOND}/bonding/primary")),
            Some(BACKUP)
        );
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{BOND}/bonding/active_slave")),
            Some(BACKUP)
        );
        let home_row = rows[0]
            .slaves
            .iter()
            .find(|s| s.wire == "eth0")
            .expect("the home wire has a row");
        assert!(
            !home_row.reachable,
            "a wire we cannot even ask over is not reachable: {rows:?}"
        );
    }

    /// The first tick has asked nobody anything, so it cannot count as a miss: three misses
    /// means three ANSWERED-NOTHING rounds after a probe went out.
    #[test]
    fn the_first_tick_counts_no_miss() {
        let f = fabric();
        let (mut p, _) = prober(&f);
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &[]);
        let rows = run_ticks(&mut p, &mut sys, &mut io, 3);
        assert!(
            rows[0].slaves.iter().all(|s| s.reachable),
            "3 ticks = 2 observations, not yet 3"
        );
        let rows = run_ticks(&mut p, &mut sys, &mut io, 1);
        assert!(rows[0].slaves.iter().all(|s| !s.reachable));
    }

    /// Other traffic on the wire, and our own broadcast probe flooding back in through the
    /// other islands, must not read as an answer.
    #[test]
    fn noise_on_the_tap_is_not_an_answer() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        io.noise = vec![
            frame::probe(frame::synthetic_mac(9, 9, 9), ROUTER.parse().unwrap()).to_vec(),
            vec![0u8; 64],
        ];
        io.answering.clear();
        let rows = run_ticks(&mut p, &mut sys, &mut io, 8);
        assert!(rows[0].slaves.iter().all(|s| !s.reachable));
        assert!(rows[0].slaves.iter().all(|s| s.last_reply_ms.is_none()));
    }

    /// A tick where nothing has arrived must return, not block: the supervisor's main loop is
    /// also the systemd watchdog feed and the `cfab.sock` accept loop.
    #[test]
    fn a_tick_with_no_frames_returns_at_once() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &[]);
        p.tick(&mut sys, &mut io, Instant::now());
        assert_eq!(
            io.recv_calls,
            names.len(),
            "one non-blocking drain per slave"
        );
    }

    /// The rows `Components` publishes: one per zone with an ingress leg, every slave named by
    /// wire AND island, so an operator reading the JSON knows which switch to look at.
    #[test]
    fn the_report_names_every_slaves_wire_and_island() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        let rows = run_ticks(&mut p, &mut sys, &mut io, 4);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].zone, "mgmt");
        assert_eq!(rows[0].bond, BOND);
        let seen: Vec<(&str, &str)> = rows[0]
            .slaves
            .iter()
            .map(|s| (s.wire.as_str(), s.island.as_str()))
            .collect();
        assert_eq!(seen, vec![("eth9", "a"), ("eth1", "b"), ("eth0", "c")]);
    }

    /// A single-domain gw leg has one sub-interface and nothing to move between. Reachability
    /// is still an observable, so it is probed — and never actuated on.
    #[test]
    fn a_single_domain_gw_leg_is_probed_but_never_moved() {
        let f = fabric_with_a_domain_gw();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut p = Prober::from_view(&view);
        let leg = p.legs[0].bond.clone();
        let mut sys = bonding(&leg);
        let mut io = ScriptedIo::answering_on(ROUTER, &[]);
        let rows = run_ticks(&mut p, &mut sys, &mut io, 8);
        assert_eq!(
            io.sent_on(&leg).len(),
            8,
            "the leg itself is the probe target"
        );
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "a leg with no slaves is never actuated on: {:?}",
            sys.calls
        );
        assert!(rows[0].active.is_none());
        assert!(
            p.held_primaries().is_empty(),
            "nothing holds a primary here"
        );
    }

    /// With nothing reachable the prober does not touch the bond — but the kernel's own
    /// carrier-driven reselect may have moved it anyway. The row must then say where the bond
    /// IS, not where the prober would like it: a row that reported the wish would hide exactly
    /// the case where the prober's writes are not taking.
    #[test]
    fn the_report_names_the_kernels_active_slave_not_the_probers_wish() {
        let f = fabric();
        let (mut p, _) = prober(&f);
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &[]);
        // Nothing answers anywhere, so the prober writes nothing at all...
        run_ticks(&mut p, &mut sys, &mut io, 4);
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "{:?}",
            sys.calls
        );
        // ...and then the kernel's own carrier reselect moves the bond.
        sys.files.insert(
            format!("/sys/class/net/{BOND}/bonding/active_slave"),
            BACKUP.to_string(),
        );
        let rows = run_ticks(&mut p, &mut sys, &mut io, 1);
        assert_eq!(p.held_primaries().slave_for(BOND), Some(HOME));
        assert_eq!(
            rows[0].active.as_deref(),
            Some(BACKUP),
            "the row reports the kernel, not the prober's wish"
        );
    }

    /// The held primary is what the forwarding watchdog re-asserts, so it must start at the
    /// leg's home and follow the bond, never the declaration.
    #[test]
    fn the_held_primary_starts_home_and_follows_the_bond() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        assert_eq!(p.held_primaries().slave_for(BOND), Some(HOME));
        run_ticks(&mut p, &mut sys, &mut io, 3);
        io.dark(HOME);
        run_ticks(&mut p, &mut sys, &mut io, 4);
        assert_eq!(p.held_primaries().slave_for(BOND), Some(BACKUP));
    }
}
