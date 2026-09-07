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

pub mod bpf;
pub mod decide;
pub mod frame;
pub mod io;
pub mod passive;

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::derive::View;
use crate::supervisor::report::{ProbedLeg, ProbedSlave};
use crate::sys::Sys;

use decide::{Candidate, Hysteresis, decide};
use io::ProbeIo;
use passive::{Evidence, Verdict, Windows};

/// How often every slave is asked. Half the 3.3 s BGP hold floor the router's session runs on,
/// divided again by the 3-observation hysteresis: 1.5 s to call a wire dead, 1.5 s to call it
/// live, both comfortably inside the hold. Derived, not a knob — the declaration has nothing to
/// say about it.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// What one leg asks, and of whom.
enum Kind {
    /// The migrating ingress leg: ask the router, over every wire, twice a second.
    Ingress { router: Ipv4Addr },
    /// A zone's universal (fallback) segment: hear the peers' own OSPF, and only ask when a
    /// wire has gone quiet while its siblings have not.
    Fallback(Fallback),
}

/// The passive channel's per-leg knowledge: who is expected, who to ask when one wire goes
/// quiet, and the windows all of it is judged by.
struct Fallback {
    /// The peers' addresses on this segment (`10.<zone id>.<seg>.<node>`) — the escalation's
    /// targets, and the only frames the fallback prober ever sends.
    targets: Vec<Ipv4Addr>,
    /// The OSPF Router IDs of the members expected on this segment, self excluded. Empty when
    /// this member is alone in the zone's universal segment.
    peers: BTreeSet<u32>,
    /// Our own Router ID in this zone. A hello carrying it is not a peer — it is our own hello
    /// reflected back through the backbone, which is what makes a BACKUP slave judgeable even
    /// with no peer alive anywhere (spec §4).
    self_rid: u32,
    windows: Windows,
    /// No slave of this leg heard anything within its window on the last tick. Reported, so
    /// `status` can say the fault is not per-wire; distinct from "has never heard anything",
    /// which is also true of a leg whose first hello has not arrived yet.
    quiet_now: bool,
    /// The whole leg has gone quiet and it has been said. Cleared when anything is heard again,
    /// so the next silence is reported.
    noted_quiet: bool,
    /// No tap on this leg could be opened; said once, and the leg is not probed until one can
    /// be. The environment is an undeclared dependency: a container without the privileges for
    /// `AF_PACKET` must refuse the leg by name, not report every wire quiet forever.
    noted_deaf: bool,
}

/// One leg's probe state.
struct Leg {
    zone: String,
    /// The leg netdev: a bond when the leg migrates, a plain sub-interface otherwise.
    bond: String,
    /// Only a leg with slaves has anywhere to move to. A single-domain ingress leg is still
    /// probed — per-wire router reachability is an observable either way — but never actuated
    /// on. Every fallback leg has slaves by construction.
    actuates: bool,
    /// The zone's wire order, rank 0 first: what decides which live wire the leg belongs on.
    prefs: Vec<String>,
    /// The slave `bonding/primary` must name. The prober owns `primary` on a leg it actuates:
    /// an `active_slave` write alone survives only until the next link event, after which
    /// `primary_reselect=always` hands the bond back to the old primary (VERIFIED on the rack,
    /// 2026-09-07). It starts as the leg's home and only ever moves with the bond.
    held: String,
    /// The slave the KERNEL has active, as of this tick's read — which is not always the one we
    /// hold: with nothing usable the prober leaves the bond alone and the kernel's own carrier
    /// reselect moves it. `None` before the first read, and for a leg that has none.
    active_now: Option<String>,
    slaves: Vec<ProbeSlave>,
    /// The (skipped wire, wire we are on) pair the last no-carrier note named, so the same
    /// sentence is not repeated twice a second for as long as an island stays dark. `None`
    /// re-arms it: the next time the pair exists, it is said again.
    noted_no_carrier: Option<(String, String)>,
    /// The (target, active) the last refused sysfs write was for. The same write is not retried
    /// while nothing has changed — the kernel refused it for a reason we can no longer see, and
    /// a refusal repeated every 500 ms is noise, not a diagnosis.
    refused: Option<(String, Option<String>)>,
    kind: Kind,
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
    /// This slave's netdev had carrier as of this tick's read. Not folded into `state`: carrier
    /// is a fact the kernel hands over instantly and acts on instantly, so waiting three ticks
    /// to believe it is three refused `active_slave` writes (F23).
    carrier: bool,
    /// The netdev exists at all (its `carrier` file could be opened, whatever it said). A netdev
    /// that has just come back is a slave that has just been re-enslaved, which is where the
    /// grace period comes from.
    present: bool,
    last_reply: Option<Instant>,
    /// Passive evidence, fallback legs only: the last peer packet and the last reflection of our
    /// own hello heard on this slave.
    peer_heard: Option<Instant>,
    self_heard: Option<Instant>,
    /// Peers heard on this slave, most recent first — the escalation's targets, so it asks the
    /// members that were demonstrably reachable over this wire rather than all of them (spec §7).
    recent: Vec<u32>,
    /// Until when this slave may not be suspected: it has just appeared, or just been promoted.
    grace_until: Option<Instant>,
    /// The ARP escalation is running on this slave.
    escalating: bool,
    /// The reason this slave's tap could not be opened, as it was last reported. `None` once it
    /// opens again, so a tap that fails, recovers and fails again is said twice — and one that
    /// has been failing the same way for an hour is said once.
    deaf: Option<String>,
}

/// At most this many peers are asked when one wire is escalated. Four is the point past which
/// asking more stops adding evidence — any one answer clears the wire — and it is what bounds
/// the fabric-wide worst case to a burst rather than a storm (spec §7).
const ESCALATION_TARGETS: usize = 4;

impl ProbeSlave {
    fn new(ifname: String, wire: String, island: String, mac: [u8; 6]) -> ProbeSlave {
        ProbeSlave {
            ifname,
            wire,
            island,
            mac,
            state: Hysteresis::default(),
            probed: false,
            carrier: false,
            // Not present until a tick has read the netdev, so every slave starts its life in
            // the grace period a re-enslaved one gets: at leg start no hello has arrived on any
            // wire yet, and the first one to arrive must not condemn the others.
            present: false,
            last_reply: None,
            peer_heard: None,
            self_heard: None,
            recent: Vec::new(),
            grace_until: None,
            escalating: false,
            deaf: None,
        }
    }

    fn evidence(&self, active: Option<&str>) -> Evidence {
        Evidence {
            active: active == Some(self.ifname.as_str()),
            peer: self.peer_heard,
            reflected: self.self_heard,
            grace_until: self.grace_until,
        }
    }

    /// Record a peer, most recent first, without letting the list grow with the fabric.
    fn saw(&mut self, rid: u32) {
        self.recent.retain(|r| *r != rid);
        self.recent.insert(0, rid);
        self.recent.truncate(ESCALATION_TARGETS);
    }
}

/// Which slave each bond the prober actuates must name as `primary`: its current choice, which
/// is the leg's home until the prober has a reason to hold another.
///
/// The prober owns `primary` on those bonds — an `active_slave` write alone survives only until
/// the next link event — so anything else that re-asserts `primary` must ask here first. The
/// forwarding watchdog rebuilds legs a re-enumerated wire took with it, and writing the DECLARED
/// home there would snap a bond the prober had deliberately moved straight back onto a wire it
/// had moved off, on the next USB blip.
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

/// The two families of leg, as the supervisor publishes them.
#[derive(Clone, Debug, Default)]
pub struct ProbeRows {
    pub ingress: Vec<ProbedLeg>,
    pub fallback: Vec<ProbedLeg>,
}

/// Every leg this member probes, ticked once per `PROBE_INTERVAL`.
pub struct Prober {
    legs: Vec<Leg>,
    /// What the last ticks have to say, oldest first, ready-formatted. The prober decides and
    /// the supervisor prints: a line that is returned rather than written to stderr is a line a
    /// unit test can assert, and "said once, not on every tick" is a property only a test can
    /// hold on to.
    log: Vec<String>,
}

impl Prober {
    /// The legs to probe: this member's ingress legs (hosts only — a leaf builds none) and every
    /// zone's universal segment, leaves included. A leaf's fallback path is a real path and
    /// F20 is a real defect on it.
    pub fn from_view(view: &View) -> Prober {
        let mut legs = Vec::new();
        let island_of = |wire: &str| {
            view.member
                .wires
                .iter()
                .find(|w| w.name == wire)
                .map(|w| w.domain.as_str().to_string())
                .unwrap_or_default()
        };
        let prefs_for = |zone: &str| {
            view.prefs()
                .into_iter()
                .find(|p| p.zone == zone)
                .map(|p| p.order)
                .unwrap_or_default()
        };
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
            let slaves: Vec<ProbeSlave> = if r.migrates() {
                r.slaves
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        ProbeSlave::new(
                            s.ifname.clone(),
                            s.wire.clone(),
                            island_of(&s.wire),
                            frame::synthetic_mac(view.node(), z.id, i as u8),
                        )
                    })
                    .collect()
            } else {
                vec![ProbeSlave::new(
                    r.ifname.clone(),
                    r.home.clone(),
                    island_of(&r.home),
                    frame::synthetic_mac(view.node(), z.id, 0),
                )]
            };
            legs.push(Leg::new(
                r.zone.clone(),
                r.ifname.clone(),
                r.migrates(),
                prefs_for(&r.zone),
                &r.home,
                slaves,
                Kind::Ingress { router },
            ));
        }
        for r in view.fallback_rows() {
            let Ok(z) = view.fabric.zone(&r.zone) else {
                continue;
            };
            let addr_of = |node: u8| format!("{}.{}.{}", z.block(), r.seg, node).parse().ok();
            let rid_of = |m: &crate::model::Member| {
                crate::derive::identity_addr_of(z, m)
                    .parse::<Ipv4Addr>()
                    .ok()
                    .map(u32::from)
            };
            let Some(self_rid) = rid_of(view.member) else {
                continue;
            };
            let peer_members: Vec<&crate::model::Member> = view
                .fabric
                .members
                .iter()
                .filter(|m| m.name != view.member.name)
                .filter(|m| {
                    crate::derive::fallback_rows_of(view.fabric, m)
                        .iter()
                        .any(|p| p.zone == r.zone)
                })
                .collect();
            let slaves: Vec<ProbeSlave> = r
                .slaves
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    ProbeSlave::new(
                        s.ifname.clone(),
                        s.wire.clone(),
                        island_of(&s.wire),
                        // The same synthetic-MAC scheme as the ingress prober, and it cannot
                        // collide with one: the two families' slaves are different netdevs, and
                        // the index is per leg within a zone whose id is in the address.
                        frame::synthetic_mac(view.node(), z.id, i as u8),
                    )
                })
                .collect();
            legs.push(Leg::new(
                r.zone.clone(),
                r.ifname.clone(),
                true,
                prefs_for(&r.zone),
                &r.home,
                slaves,
                Kind::Fallback(Fallback {
                    targets: peer_members
                        .iter()
                        .filter_map(|m| addr_of(m.node))
                        .collect(),
                    peers: peer_members.iter().filter_map(|m| rid_of(m)).collect(),
                    self_rid,
                    windows: Windows::from_ospf(view.fabric.ospf_hello, view.fabric.ospf_dead),
                    quiet_now: false,
                    noted_quiet: false,
                    noted_deaf: false,
                }),
            ));
        }
        let mut log = Vec::new();
        // Said at start, once, because it is a property of the DECLARATION and not of anything
        // that happens later: with these timers a move cannot be decided before OSPF has already
        // torn the adjacency down, so the fallback prober can only ever be late. There is no
        // knob to offer — the remedy is the declared dead interval.
        let w = Windows::from_ospf(view.fabric.ospf_hello, view.fabric.ospf_dead);
        if legs.iter().any(|l| matches!(l.kind, Kind::Fallback(_)))
            && !w.move_fits_inside_dead(PROBE_INTERVAL, view.fabric.ospf_dead)
        {
            log.push(format!(
                "cfab: warn: [ospf] hello {} s with dead {} s leaves no room to move a fallback \
                 bond before the adjacency expires",
                view.fabric.ospf_hello, view.fabric.ospf_dead
            ));
        }
        Prober { legs, log }
    }

    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }

    /// Take everything the prober has to say since the last call. The supervisor drains this
    /// every tick and prints it; nothing else keeps it, so it cannot grow.
    pub fn drain_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    /// One round: read what has arrived, move a bond that belongs elsewhere, then ask again —
    /// where "ask" is every slave of an ingress leg and only an escalating slave of a fallback
    /// leg, whose steady state sends nothing at all.
    ///
    /// Draining BEFORE sending is what gives a reply a whole `PROBE_INTERVAL` to arrive; the
    /// measured round trip is 80 µs, so the window is three orders of magnitude of margin, and
    /// the alternative (send, then read immediately) would score every wire as dark.
    pub fn tick(&mut self, sys: &mut dyn Sys, io: &mut dyn ProbeIo, now: Instant) -> ProbeRows {
        let Prober { legs, log } = self;
        for leg in legs.iter_mut() {
            leg.tick(sys, io, now, log);
        }
        self.report(now)
    }

    /// The slave each bond the prober actuates must name as `primary`.
    pub fn held_primaries(&self) -> HeldPrimaries {
        HeldPrimaries(
            self.legs
                .iter()
                .filter(|l| l.actuates)
                .map(|l| (l.bond.clone(), l.held.clone()))
                .collect(),
        )
    }

    fn report(&self, now: Instant) -> ProbeRows {
        let mut rows = ProbeRows::default();
        for l in &self.legs {
            let row = ProbedLeg {
                zone: l.zone.clone(),
                bond: l.bond.clone(),
                active: l.active_now.clone(),
                quiet: l.quiet(),
                slaves: l
                    .slaves
                    .iter()
                    .map(|s| ProbedSlave {
                        wire: s.wire.clone(),
                        island: s.island.clone(),
                        // A wire with no carrier reaches nothing, whatever the last three probes
                        // said; reporting it reachable would have `status` blame the far end for
                        // an unplugged cable.
                        reachable: s.state.reachable() && s.carrier,
                        // Silent, being asked, not yet answered for: a fact `status` renders as
                        // a settling line rather than a standing verdict.
                        suspect: s.escalating,
                        last_reply_ms: s
                            .last_reply
                            .map(|t| now.saturating_duration_since(t).as_millis() as u64),
                    })
                    .collect(),
            };
            match l.kind {
                Kind::Ingress { .. } => rows.ingress.push(row),
                Kind::Fallback(_) => rows.fallback.push(row),
            }
        }
        rows
    }
}

/// Does this netdev have carrier? An unreadable file is NO carrier, deliberately: `carrier`
/// returns `EINVAL` on an interface that is administratively down and `ENOENT` on one that has
/// gone away, and the kernel refuses `bonding/active_slave` in both of those states too.
fn has_carrier(sys: &dyn Sys, ifname: &str) -> Option<bool> {
    sys.read(&format!("/sys/class/net/{ifname}/carrier"))
        .ok()
        .map(|s| s.trim() == "1")
}

/// One `Sys` error as a line a task that carries on may print. `Sys::write` reports every
/// failure as `Error::Fatal`, which Displays as `FATAL: …`; the prober's writes are not fatal to
/// anything — it logs, keeps the bond where it is and ticks again — so the word must not appear.
fn without_fatal(e: &crate::error::Error) -> String {
    if let crate::error::Error::Fatal(m) = e {
        m.clone()
    } else {
        e.to_string()
    }
}

impl Leg {
    fn new(
        zone: String,
        bond: String,
        actuates: bool,
        prefs: Vec<String>,
        home: &str,
        slaves: Vec<ProbeSlave>,
        kind: Kind,
    ) -> Leg {
        let held = slaves
            .iter()
            .find(|s| s.wire == home)
            .or_else(|| slaves.first())
            .map(|s| s.ifname.clone())
            .unwrap_or_default();
        Leg {
            zone,
            bond,
            actuates,
            prefs,
            held,
            active_now: None,
            slaves,
            noted_no_carrier: None,
            refused: None,
            kind,
        }
    }

    /// Can this leg be heard at all? A leg whose every tap failed to open knows nothing about
    /// any of its wires, so it is not a leg to move: `status` names the missing capability and
    /// the bond is left to the kernel.
    fn probed(&self) -> bool {
        !matches!(self.kind, Kind::Fallback(ref f) if f.noted_deaf)
    }

    /// Has this leg heard nothing at all, on any wire, this tick? Only a fallback leg can: an
    /// ingress leg asks rather than listens, and "nobody answered" is already reported per wire.
    fn quiet(&self) -> bool {
        matches!(self.kind, Kind::Fallback(ref f) if f.quiet_now)
    }

    fn tick(
        &mut self,
        sys: &mut dyn Sys,
        io: &mut dyn ProbeIo,
        now: Instant,
        log: &mut Vec<String>,
    ) {
        // The kernel's own answer to "where is this bond", read once and used by everything
        // below: the passive channel judges a slave by its role, and the decision compares
        // against it. A leg whose `bonding/` cannot be read is a leg we do not own this tick.
        // A leg with nowhere to move to is not asked where it sits: the read would be a
        // guess about a netdev that is not a bond, and nothing would be done with the answer.
        let active = self.actuates.then(|| self.read_active(sys)).flatten();
        self.observe(sys, io, now, active.as_deref(), log);
        if active.is_some() && self.probed() {
            self.actuate(sys, active.as_deref(), now, log);
        }
        self.ask(io, now);
    }

    /// `bonding/active_slave`, trimmed, or `None` when the leg is not a bond we can read. The
    /// empty string — a bond with no active slave — reads as `Some("")`, which no slave matches.
    fn read_active(&mut self, sys: &mut dyn Sys) -> Option<String> {
        let read = sys
            .read(&format!(
                "/sys/class/net/{}/bonding/active_slave",
                self.bond
            ))
            .ok()?;
        let active = read.trim().to_string();
        self.active_now = (!active.is_empty()).then(|| active.clone());
        Some(active)
    }

    /// Drain every tap, fold in what arrived, and decide what each slave's standing is now.
    fn observe(
        &mut self,
        sys: &mut dyn Sys,
        io: &mut dyn ProbeIo,
        now: Instant,
        active: Option<&str>,
        log: &mut Vec<String>,
    ) {
        let mut deaf = 0usize;
        // Wires whose tap has just started failing, and why. Held until the loop ends, because
        // whether this is "one wire cannot be judged" or "the leg is not probed at all" is not
        // known until every slave has been tried.
        let mut newly_deaf: Vec<(String, String)> = Vec::new();
        for s in &mut self.slaves {
            // Carrier is read for every slave, a deaf one included: whether the tap opened and
            // whether the cable is in are different facts, and reporting a tap failure as lost
            // carrier would send an operator to the wrong end of it.
            let present = has_carrier(&*sys, &s.ifname);
            s.carrier = present.unwrap_or(false);
            // A netdev that has just come back is a slave the kernel has just re-enslaved (F5).
            // Judging it before a hello can arrive on it would confirm it dead for being new.
            if present.is_some() && !s.present {
                s.grace_until = Some(now + grace_of(&self.kind));
            }
            s.present = present.is_some();
            // A fallback leg never sends in steady state, so the tap has to be asked for.
            if let Kind::Fallback(_) = self.kind {
                match io.listen(&s.ifname) {
                    Err(e) => {
                        deaf += 1;
                        let why = without_fatal(&e);
                        if s.deaf.as_deref() != Some(why.as_str()) {
                            newly_deaf.push((s.wire.clone(), why.clone()));
                            s.deaf = Some(why);
                        }
                        continue;
                    }
                    Ok(()) => s.deaf = None,
                }
            }
            let frames = io.recv(&s.ifname).unwrap_or_default();
            let mut replied = false;
            let mut heard_now = false;
            match &self.kind {
                Kind::Ingress { router } => {
                    replied = frames
                        .iter()
                        .any(|f| frame::reply_from(f, s.mac, &[*router]).is_some());
                }
                Kind::Fallback(f) => {
                    for fr in &frames {
                        if let Some(rid) = frame::hello_router_id(fr) {
                            if rid == f.self_rid {
                                s.self_heard = Some(now);
                                // Our own reflection proves only a BACKUP slave's path to the
                                // backbone; on the active slave it is not even expected.
                                heard_now |= active != Some(s.ifname.as_str());
                            } else if f.peers.contains(&rid) {
                                s.peer_heard = Some(now);
                                s.saw(rid);
                                heard_now = true;
                            }
                            // A hello from a Router ID we do not expect on this segment is not
                            // evidence about our fabric: another OSPF speaker on the VLAN would
                            // otherwise keep a wire looking live for peers that are gone.
                        } else if s.escalating && frame::reply_from(fr, s.mac, &f.targets).is_some()
                        {
                            replied = true;
                        }
                    }
                }
            }
            if replied || s.peer_heard == Some(now) || s.self_heard == Some(now) {
                s.last_reply = Some(now);
            }
            match &self.kind {
                // A tick with no probe outstanding learns nothing on the RECEIVE side: the
                // first tick has asked nobody anything, and a tick whose send failed is
                // accounted for in `ask`. A failed `recv` IS a miss, though — the tap is on
                // the slave, so losing it is the wire being unusable.
                Kind::Ingress { .. } => {
                    if s.probed {
                        s.state.observe(replied);
                    }
                }
                // The escalation's counted evidence, and only while it is running: a wire
                // nobody is asking is judged by the passive channel below, not by a count.
                Kind::Fallback(_) => {
                    // A frame that ARRIVED this tick is what makes a wire live again — not
                    // evidence that merely still sits inside a window. The difference matters
                    // the moment a wire is demoted to backup: its window widens from a hello
                    // and a half to the whole dead interval, and a stale timestamp would
                    // rehabilitate the very wire we had just confirmed dead.
                    if heard_now || replied {
                        s.state.heard();
                        s.escalating = false;
                    } else if s.escalating && s.probed {
                        s.state.observe(false);
                    }
                }
            }
        }
        let zone = self.zone.clone();
        let total = deaf > 0 && deaf == self.slaves.len();
        let Kind::Fallback(f) = &mut self.kind else {
            return;
        };
        for (wire, why) in newly_deaf {
            // One spelling per condition, and each says what is true: a leg whose other wires
            // still hear the fabric IS being probed — this one wire simply cannot be judged.
            let consequence = if total {
                "the leg is not probed".to_string()
            } else {
                format!("{wire} is not judged")
            };
            log.push(format!(
                "cfab: {zone} fallback: cannot listen on {wire} ({why}) — {consequence}"
            ));
        }
        f.noted_deaf = total;
        if total {
            return;
        }
        let evidence: Vec<Evidence> = self.slaves.iter().map(|s| s.evidence(active)).collect();
        let verdicts = passive::verdicts(now, &evidence, &f.windows, !f.peers.is_empty());
        let mut all_quiet = !self.slaves.is_empty();
        for (s, v) in self.slaves.iter_mut().zip(verdicts) {
            match v {
                // Within its window: nothing to ask. The verdict does not itself declare the
                // wire live — only a frame that arrived does, above.
                Verdict::Good => {
                    s.escalating = false;
                    s.probed = false;
                    all_quiet = false;
                }
                Verdict::Suspect => {
                    all_quiet = false;
                    if !s.escalating {
                        s.escalating = true;
                        s.probed = false;
                        s.state.precharge();
                    }
                }
                Verdict::Watch => all_quiet = false,
                Verdict::Quiet => {
                    // Nothing to move to and nothing to ask: whatever is wrong is not this wire.
                    s.escalating = false;
                    s.probed = false;
                }
            }
        }
        f.quiet_now = all_quiet;
        if all_quiet && !f.noted_quiet {
            f.noted_quiet = true;
            log.push(format!(
                "cfab: {} fallback: no peers heard on any wire — nothing to move to",
                self.zone
            ));
        } else if !all_quiet {
            f.noted_quiet = false;
        }
    }

    /// Ask, where asking is warranted: every slave of an ingress leg, and only an escalating
    /// slave of a fallback leg. A healthy fallback leg puts nothing on the wire at all.
    fn ask(&mut self, io: &mut dyn ProbeIo, now: Instant) {
        match &self.kind {
            Kind::Ingress { router } => {
                for s in &mut self.slaves {
                    match io.send(&s.ifname, &frame::probe(s.mac, *router)) {
                        Ok(()) => s.probed = true,
                        // A probe we cannot even put on the wire is evidence about the wire, not
                        // a gap in our knowledge of it: the netdev went away with a re-enumerated
                        // USB NIC, or the socket cannot be bound. Fold it in HERE rather than
                        // leaving the slave un-observed, or its state freezes at whatever it last
                        // was and the leg stays pinned to a dead wire forever, silently.
                        Err(_) => {
                            s.probed = false;
                            s.state.observe(false);
                        }
                    }
                }
            }
            Kind::Fallback(f) => {
                for s in &mut self.slaves {
                    if !s.escalating {
                        continue;
                    }
                    // The members demonstrably reachable over this wire until a moment ago, in
                    // preference to the whole segment: any one answer clears the wire, and the
                    // bound is what keeps a fabric-wide event a burst rather than a storm.
                    let mut targets: Vec<Ipv4Addr> = s
                        .recent
                        .iter()
                        .filter_map(|rid| target_of(&f.targets, *rid))
                        .collect();
                    for t in &f.targets {
                        if targets.len() >= ESCALATION_TARGETS {
                            break;
                        }
                        if !targets.contains(t) {
                            targets.push(*t);
                        }
                    }
                    let mut sent = false;
                    for t in &targets {
                        sent |= io.send(&s.ifname, &frame::probe(s.mac, *t)).is_ok();
                    }
                    if sent {
                        s.probed = true;
                    } else {
                        s.probed = false;
                        s.state.observe(false);
                        // Nothing can be put on this wire at all. That is the wire, not our
                        // knowledge of it, so it is folded in as a miss and the escalation stops
                        // there — the decision below has already been told.
                        s.escalating = s.state.reachable();
                    }
                    let _ = now;
                }
            }
        }
    }

    /// Move the bond if the decision says it belongs elsewhere. Reads only on a healthy leg.
    /// Anything worth saying is pushed onto `log` for the supervisor to print.
    fn actuate(
        &mut self,
        sys: &mut dyn Sys,
        active: Option<&str>,
        now: Instant,
        log: &mut Vec<String>,
    ) {
        if !self.actuates {
            return;
        }
        let noun = self.kind.noun();
        let base = format!("/sys/class/net/{}/bonding", self.bond);
        let active = active.filter(|a| !a.is_empty());
        let cands: Vec<Candidate> = self
            .slaves
            .iter()
            .map(|s| Candidate {
                ifname: s.ifname.clone(),
                wire: s.wire.clone(),
                reachable: s.state.reachable(),
                carrier: s.carrier,
            })
            .collect();
        let Some(target) = decide(active, &cands, &self.prefs) else {
            // Staying put. Say so once if the wire an operator would expect the leg on is out
            // of the running for a reason the bond cannot fix.
            self.note_no_carrier(active, &cands, log);
            return;
        };
        self.noted_no_carrier = None;
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
        // A refusal we have already reported and nothing has changed since: the write would be
        // refused again, and saying so twice a second is noise. Any change in what we want or
        // where the bond sits re-arms it below.
        let attempt = (target.clone(), active.map(str::to_string));
        if self.refused.as_ref() == Some(&attempt) {
            return;
        }
        for file in ["primary", "active_slave"] {
            if let Err(e) = sys.write(&format!("{base}/{file}"), &target) {
                // WARN, not FATAL: the supervisor is running, the bond is where it was, and the
                // next tick with different inputs will try again. `Sys::write` wraps every
                // failure as `Error::Fatal`, whose Display carries that word, so the message is
                // taken out of it rather than printed through it.
                log.push(format!(
                    "cfab: warn: {} {}: cannot move {} to {to} ({target}): {}",
                    self.zone,
                    self.kind.family(),
                    self.bond,
                    without_fatal(&e)
                ));
                self.refused = Some(attempt);
                return;
            }
        }
        self.refused = None;
        self.held = target.clone();
        self.active_now = Some(target.clone());
        let family = self.kind.family();
        let from_wire = from.map(|f| f.wire.clone());
        let from_carrier = from.map(|f| f.carrier);
        let from_reachable = from.map(|f| f.state.reachable());
        // The slave that has just been promoted gets its grace period here: it was chosen after
        // a bidirectional check, and if it is nonetheless dead the adjacency says so at the dead
        // interval. Without it a two-slave ping-pong could move once per tick.
        let grace = grace_of(&self.kind);
        if let Some(s) = self.slaves.iter_mut().find(|s| s.ifname == target) {
            s.grace_until = Some(now + grace);
        }
        match (from_wire, from_carrier, from_reachable) {
            // Carrier is tested FIRST, and not only because it is the actionable end of a wire
            // that has both faults: the carrier fast path moves the bond while the hysteresis
            // still calls the wire reachable, so keying on `reachable()` alone would announce a
            // move AWAY from a dead wire as a move back to a live one.
            (Some(w), Some(false), _) => log.push(format!(
                "cfab: {} {family}: {w} lost carrier, moved {} to {to}",
                self.zone, self.bond
            )),
            (Some(w), _, Some(false)) => log.push(format!(
                "cfab: {} {family}: {noun} unreachable on {w}, moved {} to {to}",
                self.zone, self.bond
            )),
            (Some(w), _, _) => log.push(format!(
                "cfab: {} {family}: {noun} reachable on {to} again, moved {} back from {w}",
                self.zone, self.bond
            )),
            (None, _, _) => log.push(format!(
                "cfab: {} {family}: no slave of ours was active on {}, moved it to {to}",
                self.zone, self.bond
            )),
        }
    }

    /// Say once that the leg is not on the wire the preference order asks for, because that
    /// wire has no carrier. Repeated every tick it would be a stuck island's log, twice a
    /// second; said once per (skipped wire, wire we are on) it is the diagnosis.
    fn note_no_carrier(
        &mut self,
        active: Option<&str>,
        cands: &[Candidate],
        log: &mut Vec<String>,
    ) {
        let on = active.and_then(|a| cands.iter().find(|c| c.ifname == a));
        let note = match (decide::skipped_for_carrier(active, cands, &self.prefs), on) {
            (Some(skipped), Some(on)) => Some((skipped.wire.clone(), on.wire.clone())),
            _ => None,
        };
        if note == self.noted_no_carrier {
            return;
        }
        if let Some((skipped, on)) = &note {
            log.push(format!(
                "cfab: {} {}: {skipped} has no carrier, staying on {on}",
                self.zone,
                self.kind.family()
            ));
        }
        self.noted_no_carrier = note;
    }
}

impl Kind {
    /// The word every line about this leg uses for what it is asking about. One spelling per
    /// condition: the two families' lines differ by this noun and nothing else.
    fn noun(&self) -> &'static str {
        match self {
            Kind::Ingress { .. } => "router",
            Kind::Fallback(_) => "peers",
        }
    }

    /// The word every line uses for the leg itself.
    fn family(&self) -> &'static str {
        match self {
            Kind::Ingress { .. } => "ingress",
            Kind::Fallback(_) => "fallback",
        }
    }
}

/// How long a slave of this leg is left alone after it appears or is promoted. An ingress leg
/// has no passive channel and no grace: it asks, every tick, and the answer is the answer.
fn grace_of(kind: &Kind) -> Duration {
    match kind {
        Kind::Ingress { .. } => Duration::ZERO,
        Kind::Fallback(f) => f.windows.grace,
    }
}

/// The address of the peer whose Router ID is `rid`. Both are built from the member's node
/// number, which is the last octet of each — so the map is the octet, not a second table.
fn target_of(targets: &[Ipv4Addr], rid: u32) -> Option<Ipv4Addr> {
    let node = Ipv4Addr::from(rid).octets()[3];
    targets.iter().find(|t| t.octets()[3] == node).copied()
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

    /// Every slave of the mgmt leg, enslave order.
    const SLAVES: [&str; 3] = ["cfab-gw249-a", "cfab-gw249-b", "cfab-gw249-c"];

    /// A bond sitting on `active`, with carrier on every slave — the healthy shape. Carrier is
    /// part of it because the kernel refuses `bonding/active_slave` on a slave whose netdev has
    /// none, so a test that wants a move to happen has to say the target can take it.
    fn bonding(active: &str) -> MockSys {
        let mut sys = MockSys::default()
            .file(
                &format!("/sys/class/net/{BOND}/bonding/active_slave"),
                active,
            )
            .file(&format!("/sys/class/net/{BOND}/bonding/primary"), active)
            .file(&format!("/sys/class/net/{active}/carrier"), "1\n");
        for s in SLAVES {
            sys = sys.file(&format!("/sys/class/net/{s}/carrier"), "1\n");
        }
        sys
    }

    /// The host member's INGRESS prober — the fallback legs are dropped, so these cases read
    /// exactly the leg they are about. The fallback legs have their own tests below.
    fn prober(f: &Fabric) -> (Prober, Vec<String>) {
        let view = View::new(f, "pve1-tb").unwrap();
        let mut p = Prober::from_view(&view);
        p.legs.retain(|l| matches!(l.kind, Kind::Ingress { .. }));
        let names = p.legs[0].slaves.iter().map(|s| s.ifname.clone()).collect();
        (p, names)
    }

    fn run_ticks(
        p: &mut Prober,
        sys: &mut MockSys,
        io: &mut ScriptedIo,
        n: usize,
    ) -> Vec<ProbedLeg> {
        let mut last = Vec::new();
        for i in 0..n {
            last = p
                .tick(sys, io, Instant::now() + PROBE_INTERVAL * i as u32)
                .ingress;
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
    fn a_leaf_has_no_ingress_leg_to_probe_and_every_fallback_leg() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let p = Prober::from_view(&view);
        let rows = p.report(Instant::now());
        assert!(
            rows.ingress.is_empty(),
            "the outside reaches a leaf at the leaf's own addresses, never at a fabric identity"
        );
        assert_eq!(
            rows.fallback
                .iter()
                .map(|l| l.zone.clone())
                .collect::<Vec<_>>(),
            vec!["storage", "cluster", "mgmt"],
            "a leaf's fallback path is a real path, and F20 is a real defect on it"
        );
        assert_eq!(
            p.held_primaries().slave_for("cfab-st-fb"),
            Some("cfab-st-fb-a"),
            "and the watchdog must be told which slave to re-assert"
        );
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
        p.legs.retain(|l| matches!(l.kind, Kind::Ingress { .. }));
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

    /// F23, seen on the rack 2026-09-07 21:06:01 UTC: the home island lost power, its slave lost
    /// carrier, and the kernel failed the bond over on its own. The prober's home wire was still
    /// inside its hysteresis, so the decision named it as the better-preferred target — and the
    /// kernel refuses `bonding/active_slave` on a slave with no carrier (EINVAL). A slave
    /// without carrier is not a place ingress can be put: never a target, never reachable.
    #[test]
    fn a_carrier_less_slave_is_never_a_move_target() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        // The kernel has already moved the bond off the dead island.
        let mut sys = bonding(BACKUP).file(&format!("/sys/class/net/{HOME}/carrier"), "0\n");
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        io.dark(HOME);
        let rows = run_ticks(&mut p, &mut sys, &mut io, 6);
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "a slave with no carrier is never written as active_slave: {:?}",
            sys.calls
        );
        let home = rows[0]
            .slaves
            .iter()
            .find(|s| s.wire == "eth0")
            .expect("the home wire has a row");
        assert!(
            !home.reachable,
            "no carrier is not router-reachable: {rows:?}"
        );
    }

    /// Carrier is believed at once, not three ticks later. The probe answers can even still be
    /// arriving — a switch that has just lost the link to this host answers nothing new, but the
    /// hysteresis remembers the last three that did — and the wire is still no longer one the
    /// router can be reached over. `status` reads this row to name a cause, so a carrier-less
    /// wire reported reachable is `status` blaming the router for an unplugged cable.
    #[test]
    fn a_carrier_less_wire_is_reported_unreachable_at_once() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(BACKUP).file(&format!("/sys/class/net/{HOME}/carrier"), "0\n");
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        let rows = run_ticks(&mut p, &mut sys, &mut io, 2);
        let home = rows[0]
            .slaves
            .iter()
            .find(|s| s.wire == "eth0")
            .expect("the home wire has a row");
        assert!(!home.reachable, "on the second tick already: {rows:?}");
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "{:?}",
            sys.calls
        );
    }

    /// The carrier fast path moves the bond while the hysteresis still calls the wire we are
    /// leaving reachable — that is the whole point of not waiting three ticks. The line must
    /// then say what actually happened: keyed on reachability alone it announced a flight from
    /// a dead wire as a return to a live one, which is the opposite of the truth and sends an
    /// operator looking at the wrong end of the fabric.
    #[test]
    fn a_move_off_a_wire_that_just_lost_carrier_says_so() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME);
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        // Every wire answers throughout, so every wire stays `reachable`: only the carrier goes.
        run_ticks(&mut p, &mut sys, &mut io, 2);
        assert!(p.drain_log().is_empty(), "nothing has happened yet");
        sys.files
            .insert(format!("/sys/class/net/{HOME}/carrier"), "0\n".to_string());
        run_ticks(&mut p, &mut sys, &mut io, 1);
        let log = p.drain_log();
        assert_eq!(
            log.first().map(String::as_str),
            Some("cfab: mgmt ingress: eth0 lost carrier, moved cfab-gw249 to eth9"),
            "{log:?}"
        );
        assert!(
            !log.iter().any(|l| l.contains("reachable")),
            "the router never stopped answering: {log:?}"
        );
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{BOND}/bonding/active_slave")),
            Some(BACKUP)
        );
    }

    /// The prober says the home wire is out of the running once, not twice a second forever.
    #[test]
    fn the_no_carrier_note_is_said_once_not_on_every_tick() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(BACKUP).file(&format!("/sys/class/net/{HOME}/carrier"), "0\n");
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        io.dark(HOME);
        run_ticks(&mut p, &mut sys, &mut io, 8);
        let log = p.drain_log();
        assert_eq!(
            log.iter()
                .filter(|l| *l == "cfab: mgmt ingress: eth0 has no carrier, staying on eth9")
                .count(),
            1,
            "{log:?}"
        );
        assert_eq!(log.len(), 1, "and nothing else: {log:?}");
    }

    /// A sysfs write that fails anyway (the kernel has a precondition of its own we did not
    /// model, or `/sys` is read-only): one WARN naming the slave and the OS error, no retry
    /// while nothing has changed, and never the word FATAL — the prober is still running and
    /// the bond is still where it was.
    #[test]
    fn a_refused_move_warns_once_and_is_not_retried() {
        let f = fabric();
        let (mut p, names) = prober(&f);
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sys = bonding(HOME).write_fail(&format!("/sys/class/net/{BOND}/bonding/primary"));
        let mut io = ScriptedIo::answering_on(ROUTER, &refs);
        run_ticks(&mut p, &mut sys, &mut io, 3);
        io.dark(HOME);
        run_ticks(&mut p, &mut sys, &mut io, 8);
        let log = p.drain_log();
        assert_eq!(log.len(), 1, "one line for one unchanged failure: {log:?}");
        assert!(
            log[0].starts_with("cfab: warn: mgmt ingress: cannot move cfab-gw249 to eth9 ")
                && log[0].contains(BACKUP)
                && log[0].contains("permission denied"),
            "{log:?}"
        );
        assert!(!log[0].contains("FATAL"), "{log:?}");
        assert_eq!(
            sys.calls
                .iter()
                .filter(|c| c.as_str() == format!("write /sys/class/net/{BOND}/bonding/primary"))
                .count(),
            1,
            "the identical write is not retried every tick: {:?}",
            sys.calls
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

    // ---- the fallback legs (F20 / F21 class on the universal segments) -----------------

    /// The storage zone's universal segment on pve1: a bond over all three wires, homed on the
    /// 5G wire (`eth9`, island a) because that is where the zone's cheapest segment lives.
    const FB: &str = "cfab-st-fb";
    const FB_A: &str = "cfab-st-fb-a";
    const FB_B: &str = "cfab-st-fb-b";
    const FB_C: &str = "cfab-st-fb-c";
    const FB_SLAVES: [&str; 3] = [FB_A, FB_B, FB_C];

    /// One OSPF hello from the member with this node number, in the storage zone (block 10.99,
    /// so Router ID `10.99.0.<node>`). Only the Router ID is ever read from it.
    fn hello(node: u8) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x05]);
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 89;
        ip[12..16].copy_from_slice(&[10, 99, 9, node]);
        ip[16..20].copy_from_slice(&[224, 0, 0, 5]);
        f.extend_from_slice(&ip);
        let mut ospf = vec![0u8; 24];
        ospf[0] = 2;
        ospf[1] = 1;
        ospf[4..8].copy_from_slice(&[10, 99, 0, node]);
        f.extend_from_slice(&ospf);
        f
    }

    /// The fallback bond sitting on `active`, every slave with carrier.
    fn fb_bonding(active: &str) -> MockSys {
        let mut sys = MockSys::default()
            .file(&format!("/sys/class/net/{FB}/bonding/active_slave"), active)
            .file(&format!("/sys/class/net/{FB}/bonding/primary"), active);
        for s in FB_SLAVES {
            sys = sys.file(&format!("/sys/class/net/{s}/carrier"), "1\n");
        }
        sys
    }

    /// Just the storage zone's fallback leg, so a case reads the leg it is about.
    fn fb_prober(f: &Fabric, member: &str) -> Prober {
        let view = View::new(f, member).unwrap();
        let mut p = Prober::from_view(&view);
        p.legs
            .retain(|l| matches!(l.kind, Kind::Fallback(_)) && l.bond == FB);
        p
    }

    /// A fabric this member is alone in: the other two members are gone, so the zone's universal
    /// segment has no peers to hear.
    fn alone(f: &Fabric) -> Fabric {
        let mut f = fabric_from(f);
        f.members.retain(|m| m.name == "pve1-tb");
        f
    }

    /// `Fabric` is not `Clone`; re-parsing the example is the cheap way to get a second one.
    fn fabric_from(_: &Fabric) -> Fabric {
        fabric()
    }

    /// Deliver `frames` on `slave` for the next tick only.
    fn hear(io: &mut ScriptedIo, slave: &str, frames: &[Vec<u8>]) {
        io.heard.insert(slave.to_string(), frames.to_vec());
    }

    fn fb_tick(p: &mut Prober, sys: &mut MockSys, io: &mut ScriptedIo, now: Instant) -> ProbedLeg {
        p.tick(sys, io, now).fallback.remove(0)
    }

    /// The peers of a leg are the members that carry the SAME zone's universal row, self
    /// excluded, addressed on that segment — leaves included, because a leaf carries the row.
    #[test]
    fn a_fallback_legs_expected_peers_are_the_zones_other_members() {
        let f = fabric();
        for (member, want_targets, want_rids) in [
            (
                "pve1-tb",
                vec![[10, 99, 9, 2], [10, 99, 9, 3]],
                vec![[10, 99, 0, 2], [10, 99, 0, 3]],
            ),
            (
                "pve3-tb",
                vec![[10, 99, 9, 1], [10, 99, 9, 2]],
                vec![[10, 99, 0, 1], [10, 99, 0, 2]],
            ),
        ] {
            let p = fb_prober(&f, member);
            let Kind::Fallback(fb) = &p.legs[0].kind else {
                panic!("the storage fallback leg");
            };
            assert_eq!(
                fb.targets,
                want_targets
                    .iter()
                    .map(|o| Ipv4Addr::from(*o))
                    .collect::<Vec<_>>(),
                "{member}: the peers' own addresses on this segment"
            );
            assert_eq!(
                fb.peers,
                want_rids
                    .iter()
                    .map(|o| u32::from(Ipv4Addr::from(*o)))
                    .collect::<BTreeSet<_>>(),
                "{member}: the peers' router ids, self excluded"
            );
        }
    }

    /// A member alone in a zone's universal segment expects nobody. It still runs the leg — its
    /// own reflected hello judges the backup slaves, and the bond can still be on the wrong wire
    /// — but it never asks, and never says it lost peers it does not have.
    #[test]
    fn a_lone_member_never_asks_and_still_fixes_the_wire() {
        let f = alone(&fabric());
        let mut p = fb_prober(&f, "pve1-tb");
        // The kernel re-enslaved the 1G wire last after a re-enumeration, so the bond sits on
        // it while the 5G wire is idle: F20, with nothing wrong anywhere.
        let mut sys = fb_bonding(FB_B);
        let mut io = ScriptedIo::answering_on("10.99.9.2", &[]);
        let t0 = Instant::now();
        // Our own hello comes back on the backup slaves, flooded through the backbone.
        hear(&mut io, FB_B, &[hello(1)]);
        hear(&mut io, FB_C, &[hello(1)]);
        let row = fb_tick(&mut p, &mut sys, &mut io, t0);
        assert!(!row.quiet, "the reflection is evidence, even with no peers");
        for _ in 1..8 {
            fb_tick(&mut p, &mut sys, &mut io, t0 + Duration::from_secs(10));
        }
        assert!(
            io.sent.is_empty(),
            "a lone member asks nobody: {:?}",
            io.sent
        );
        assert!(
            !p.drain_log()
                .iter()
                .any(|l| l.contains("peers unreachable") || l.contains("no peers heard")),
            "and never says a word about peers it does not have"
        );
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{FB}/bonding/active_slave")),
            Some(FB_A),
            "the bond still belongs on the preferred wire"
        );
    }

    /// The F21 class on a fallback bond: the active wire's island keeps carrier but its uplink
    /// is dead, so the peers go quiet on that wire alone. Suspicion, one unanswered escalation
    /// tick, and the bond moves — inside the dead interval.
    #[test]
    fn a_wire_that_goes_quiet_alone_is_asked_and_then_left() {
        let f = fabric();
        let mut p = fb_prober(&f, "pve1-tb");
        let mut sys = fb_bonding(FB_A);
        let mut io = ScriptedIo::answering_on("10.99.9.2", &[]);
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);

        // Steady state: every wire hears the peers, and nothing at all is sent.
        for tick in 0..4u64 {
            for s in FB_SLAVES {
                hear(&mut io, s, &[hello(2), hello(3)]);
            }
            fb_tick(&mut p, &mut sys, &mut io, at(tick * 500));
        }
        assert!(io.sent.is_empty(), "the steady state sends nothing");

        // Island a's uplink dies: only the other two wires still hear the peers.
        let mut last = None;
        for tick in 4..9u64 {
            for s in [FB_B, FB_C] {
                hear(&mut io, s, &[hello(2), hello(3)]);
            }
            last = Some(fb_tick(&mut p, &mut sys, &mut io, at(tick * 500)));
        }
        let moved = sys.writes_to(&format!("/sys/class/net/{FB}/bonding/active_slave"));
        assert_eq!(moved, Some(FB_B), "the bond left the wire that went quiet");
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{FB}/bonding/primary")),
            Some(FB_B),
            "primary first, or the next link event hands the bond back"
        );
        assert!(
            io.sent_on(FB_A).len() <= ESCALATION_TARGETS * 2,
            "the escalation is bounded to the suspect wire: {:?}",
            io.sent.iter().map(|(s, _)| s).collect::<Vec<_>>()
        );
        assert!(
            io.sent_on(FB_B).is_empty(),
            "a wire that is heard is not asked"
        );
        assert!(
            p.drain_log().iter().any(|l| l
                == "cfab: storage fallback: peers unreachable on eth9, moved cfab-st-fb to eth1"),
            "the move says which wire lost the peers"
        );
        let row = last.unwrap();
        assert!(!row.quiet);
        assert!(
            !row.slaves
                .iter()
                .find(|s| s.wire == "eth9")
                .unwrap()
                .reachable,
            "and the row blames that wire, not the bond"
        );
    }

    /// Dwell: the slave just promoted gets one dead interval before it can be suspected. Without
    /// it, a segment nobody can hear would walk the bond around its slaves once per tick.
    #[test]
    fn a_just_promoted_slave_is_not_suspected_again_within_the_dead_interval() {
        let f = fabric();
        let mut p = fb_prober(&f, "pve1-tb");
        let mut sys = fb_bonding(FB_A);
        let mut io = ScriptedIo::answering_on("10.99.9.2", &[]);
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        for tick in 0..4u64 {
            for s in FB_SLAVES {
                hear(&mut io, s, &[hello(2)]);
            }
            fb_tick(&mut p, &mut sys, &mut io, at(tick * 500));
        }
        // eth9 goes quiet, eth1 keeps hearing: the bond moves to eth1.
        for tick in 4..9u64 {
            for s in [FB_B, FB_C] {
                hear(&mut io, s, &[hello(2)]);
            }
            fb_tick(&mut p, &mut sys, &mut io, at(tick * 500));
        }
        assert_eq!(
            sys.writes_to(&format!("/sys/class/net/{FB}/bonding/active_slave")),
            Some(FB_B)
        );
        sys = fb_bonding(FB_B);
        p.drain_log();
        // Now eth1 hears nothing either, but it has only just been promoted.
        for tick in 9..14u64 {
            hear(&mut io, FB_C, &[hello(2)]);
            fb_tick(&mut p, &mut sys, &mut io, at(tick * 500));
        }
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "no second move inside the grace period: {:?}",
            sys.calls
        );
        assert!(
            io.sent_on(FB_B).is_empty(),
            "and nothing is asked of it either"
        );
    }

    /// Silence vs absence, on the wire: with every slave quiet the fault is not per-wire, so the
    /// bond is left where it is, nobody is asked, and it is said once.
    #[test]
    fn a_leg_that_hears_nothing_anywhere_is_left_alone_and_said_once() {
        let f = fabric();
        let mut p = fb_prober(&f, "pve1-tb");
        let mut sys = fb_bonding(FB_A);
        let mut io = ScriptedIo::answering_on("10.99.9.2", &[]);
        let t0 = Instant::now();
        for tick in 0..3u64 {
            for s in FB_SLAVES {
                hear(&mut io, s, &[hello(2)]);
            }
            fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            );
        }
        p.drain_log();
        let mut row = None;
        for tick in 3..24u64 {
            row = Some(fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            ));
        }
        assert!(row.unwrap().quiet, "the leg says the fault is not per-wire");
        // The active slave IS asked once on the way down — its window is a hello and a half
        // and the backups' is the dead interval, so for a moment it is the only silent wire.
        // What must not happen is asking after the leg has gone quiet, which is the state that
        // has no per-wire answer at all.
        // — and the bond may move once for it, which is the design working. What must not
        // happen is anything at all after the leg has gone quiet: that state has no per-wire
        // answer, so asking or moving again would be walking the bond around its slaves.
        let asked = io.sent.len();
        let written = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("write /sys"))
            .count();
        for tick in 24..40u64 {
            fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            );
        }
        assert_eq!(io.sent.len(), asked, "a quiet leg asks nobody");
        assert_eq!(
            sys.calls
                .iter()
                .filter(|c| c.starts_with("write /sys"))
                .count(),
            written,
            "and a quiet leg moves nothing: {:?}",
            sys.calls
        );
        assert!(io.sent_on(FB_C).is_empty(), "the last wire is never asked");
        assert_eq!(
            p.drain_log()
                .iter()
                .filter(|l| l.contains("no peers heard"))
                .count(),
            1,
            "said once, not twice a second"
        );
    }

    /// The kernel refuses `active_slave` on a slave with no carrier (F23), and a slave with no
    /// carrier reaches nothing anyway. Inherited whole from the ingress prober's decision.
    #[test]
    fn a_carrier_less_wire_is_never_a_target_and_never_written() {
        let f = fabric();
        let mut p = fb_prober(&f, "pve1-tb");
        let mut sys = fb_bonding(FB_B)
            .file(&format!("/sys/class/net/{FB_A}/carrier"), "0\n")
            .file(&format!("/sys/class/net/{FB_C}/carrier"), "0\n");
        let mut io = ScriptedIo::answering_on("10.99.9.2", &[]);
        let t0 = Instant::now();
        for tick in 0..6u64 {
            hear(&mut io, FB_B, &[hello(2)]);
            fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            );
        }
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "the preferred wire is dark, so there is nowhere better to be: {:?}",
            sys.calls
        );
        assert!(
            p.drain_log()
                .iter()
                .any(|l| l == "cfab: storage fallback: eth9 has no carrier, staying on eth1"),
            "and the skipped wire is named once"
        );
    }

    /// A leg whose `bonding/` cannot be read is a leg we do not own this tick: nothing is
    /// written into a netdev we cannot see.
    #[test]
    fn a_leg_whose_bonding_is_unreadable_is_never_written() {
        let f = fabric();
        let mut p = fb_prober(&f, "pve1-tb");
        let mut sys = MockSys::default();
        let mut io = ScriptedIo::answering_on("10.99.9.2", &[]);
        let t0 = Instant::now();
        for tick in 0..6u64 {
            hear(&mut io, FB_B, &[hello(2)]);
            fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            );
        }
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "{:?}",
            sys.calls
        );
    }

    /// One wire's tap fails while its siblings work. The leg is still probed — the other two
    /// wires judge it — so the line says what is true about the wire, and says it ONCE: repeated
    /// every 500 ms it would be a stuck container's whole log.
    #[test]
    fn one_deaf_wire_is_named_once_per_failure_not_per_tick() {
        let f = fabric();
        let mut p = fb_prober(&f, "pve1-tb");
        let mut sys = fb_bonding(FB_A);
        let mut io = ScriptedIo::answering_on("10.99.9.2", &[]);
        io.deaf = [FB_A.to_string()].into_iter().collect();
        let t0 = Instant::now();
        for tick in 0..4u64 {
            hear(&mut io, FB_B, &[hello(2)]);
            fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            );
        }
        let log = p.drain_log();
        assert_eq!(
            log.iter().filter(|l| l.contains("cannot listen")).count(),
            1,
            "once, not once per tick: {log:?}"
        );
        assert!(
            log[0].ends_with(" — eth9 is not judged"),
            "the leg IS probed; only this wire is not: {:?}",
            log[0]
        );

        // The tap comes back, then fails again: that is a new fact and is said again.
        io.deaf.clear();
        for tick in 4..8u64 {
            hear(&mut io, FB_A, &[hello(2)]);
            hear(&mut io, FB_B, &[hello(2)]);
            fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            );
        }
        assert!(
            p.drain_log().is_empty(),
            "a working tap says nothing at all"
        );
        io.deaf = [FB_A.to_string()].into_iter().collect();
        for tick in 8..12u64 {
            hear(&mut io, FB_B, &[hello(2)]);
            fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            );
        }
        assert_eq!(
            p.drain_log()
                .iter()
                .filter(|l| l.contains("cannot listen"))
                .count(),
            1,
            "the second failure is a second line"
        );
    }

    /// The environment is an undeclared dependency: a container without the privileges for a
    /// raw tap must refuse the leg by name, not report every wire quiet forever.
    #[test]
    fn a_leg_with_no_tap_at_all_refuses_itself_once_by_name() {
        let f = fabric();
        let mut p = fb_prober(&f, "pve3-tb");
        let mut sys = fb_bonding(FB_A);
        let mut io = ScriptedIo::answering_on("10.99.9.1", &[]);
        io.deaf = FB_SLAVES.iter().map(|s| s.to_string()).collect();
        let t0 = Instant::now();
        for tick in 0..6u64 {
            fb_tick(
                &mut p,
                &mut sys,
                &mut io,
                t0 + Duration::from_millis(tick * 500),
            );
        }
        let log = p.drain_log();
        assert_eq!(
            log.iter().filter(|l| l.contains("cannot listen")).count(),
            FB_SLAVES.len(),
            "once per wire, then never again: {log:?}"
        );
        assert!(
            log[0].starts_with(
                "cfab: storage fallback: cannot listen on eth9 (cfab-st-fb-a: cannot open \
                 AF_PACKET: Operation not permitted"
            ),
            "{:?}",
            log[0]
        );
        assert!(
            !sys.calls.iter().any(|c| c.starts_with("write /sys")),
            "a leg it cannot hear is a leg it does not move: {:?}",
            sys.calls
        );
    }
}
