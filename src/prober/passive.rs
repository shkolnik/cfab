//! The passive channel's arithmetic: how long silence on one port is allowed to last, and what
//! that silence means when the port next to it is hearing the same peers.
//!
//! Pure — no clock of its own, no `Sys`, no socket — because these are the parts that decide
//! whether a fabric moves its fallback path or leaves it alone.

use std::time::{Duration, Instant};

/// The windows one leg judges its ports by, all three derived from `[ospf]` (spec §5). Nothing
/// here is a knob: the fabric already declares how often it says hello and how long it waits
/// before declaring a neighbor dead, and those two numbers are the whole of the timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Windows {
    /// Silence on the ACTIVE port that still counts as healthy: one hello period and a half,
    /// so a single lost hello is not a verdict.
    pub active: Duration,
    /// Silence on a BACKUP port that still counts as healthy. A backup is judged by our own
    /// reflected hello, which crosses the backbone twice and is the thing a switch is most
    /// likely to delay, so it gets the full dead interval before it is suspected.
    pub backup: Duration,
    /// How long a port that has just been created, re-added, or promoted is left alone. A
    /// re-enumerated USB NIC (F5) would otherwise be confirmed dead before the first hello can
    /// arrive on it.
    pub grace: Duration,
    /// The declared dead interval itself: the moment OSPF stops believing in an adjacency, and
    /// so the moment hello silence on the active port stops being a matter of opinion (F27).
    /// Numerically the same as `backup`; kept as its own name because the two are answers to
    /// different questions and only one of them is about a backup port.
    pub dead: Duration,
    /// The declared hello interval itself (F28): once a wire is confirmed dead (the ARP
    /// escalation's own hysteresis has said so) but the passive channel still calls it Suspect,
    /// re-asking it is backed off to one round per hello interval rather than one every tick —
    /// the same cadence OSPF itself would use to notice the wire come back.
    pub hello: Duration,
}

impl Windows {
    pub fn from_ospf(hello_s: u32, dead_s: u32) -> Windows {
        let hello = Duration::from_secs(hello_s as u64);
        let dead = Duration::from_secs(dead_s as u64);
        Windows {
            active: hello + hello / 2,
            backup: dead,
            grace: dead,
            dead,
            hello,
        }
    }

    /// Does a move still land inside the dead interval? Suspicion on the active port takes
    /// `active`, the confirming escalation tick takes one more `tick`, and the move is written
    /// on that same tick — so `active + tick` must fit inside the dead interval, or OSPF gives
    /// up on the adjacency before the prober has finished having an opinion about it.
    pub fn move_fits_inside_dead(&self, tick: Duration, dead_s: u32) -> bool {
        self.active + tick <= Duration::from_secs(dead_s as u64)
    }
}

/// What one port has heard, and how it is being used, as this tick sees it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Evidence {
    /// This port is the one the bond is currently active on.
    pub active: bool,
    /// The last time a PEER's OSPF packet arrived on this port.
    pub peer: Option<Instant>,
    /// The last time OUR OWN hello arrived back on this port, flooded through the backbone.
    /// Only a backup port can see it (the active port's own hello leaves on that port and
    /// never comes back to it), and only that port's own reachability to the backbone is what
    /// it proves — which is exactly the fault a lone member could otherwise not see at all.
    pub reflected: Option<Instant>,
    /// Until when this port is in its grace period, if it is.
    pub grace_until: Option<Instant>,
}

impl Evidence {
    /// The last moment this port showed any life that counts for its current role.
    fn last(&self, now: Instant) -> Option<Instant> {
        // Our reflection is evidence for a BACKUP port only. On the active port it is never
        // expected, so its absence must never be read as a miss.
        let candidates = [
            self.peer,
            (!self.active).then_some(self.reflected).flatten(),
        ];
        candidates.into_iter().flatten().filter(|t| *t <= now).max()
    }
}

/// One port's standing for this tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Heard something within its window: live, and the counted hysteresis is reset.
    Good,
    /// Not heard from recently enough to be called good, and not for long enough — or not with
    /// enough company — to be called suspect. Nothing changes.
    Watch,
    /// Silent past its window while a sibling port of the same leg is hearing the fabric: this
    /// wire, specifically, is the problem. Escalate.
    Suspect,
    /// Silent, and so is every other port of this leg. The fault is not per-wire, so there is
    /// nowhere to move to and nothing to ask: say so once and leave the bond alone.
    Quiet,
}

/// Every port of one leg, judged together — because "this wire is dead" is only ever a claim
/// relative to the wires beside it (spec §5, silence vs absence).
///
/// `expect_peers` is false on a member that is alone in a zone's universal segment. Such a
/// member still runs the leg — its own reflection makes its backup ports judgeable, and F20
/// (the bond sitting on the wrong wire after a re-enumeration) is a real defect when alone —
/// but it never suspects a wire of losing peers it does not have, and never says it did.
pub fn verdicts(now: Instant, ports: &[Evidence], w: &Windows, expect_peers: bool) -> Vec<Verdict> {
    let good: Vec<bool> = ports
        .iter()
        .map(|e| {
            e.last(now)
                .is_some_and(|t| now.saturating_duration_since(t) <= window(e, w))
        })
        .collect();
    let any_good = good.iter().any(|g| *g);
    ports
        .iter()
        .zip(&good)
        .map(|(e, g)| {
            if *g {
                return Verdict::Good;
            }
            if e.grace_until.is_some_and(|t| now < t) {
                return Verdict::Watch;
            }
            if !expect_peers {
                return Verdict::Watch;
            }
            let silent_long_enough = e
                .last(now)
                .is_none_or(|t| now.saturating_duration_since(t) > window(e, w));
            if !silent_long_enough {
                return Verdict::Watch;
            }
            if any_good {
                Verdict::Suspect
            } else {
                Verdict::Quiet
            }
        })
        .collect()
}

fn window(e: &Evidence, w: &Windows) -> Duration {
    if e.active { w.active } else { w.backup }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The testbed's `[ospf]`: hello 1 s, dead 3 s.
    fn w() -> Windows {
        Windows::from_ospf(1, 3)
    }

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn the_windows_are_derived_from_the_declared_ospf_timers() {
        assert_eq!(w().active, Duration::from_millis(1500));
        assert_eq!(w().backup, Duration::from_secs(3));
        assert_eq!(w().grace, Duration::from_secs(3));
        let slow = Windows::from_ospf(10, 40);
        assert_eq!(slow.active, Duration::from_secs(15));
        assert_eq!(slow.backup, Duration::from_secs(40));
    }

    /// The invariant the whole design rests on: suspicion plus one confirming tick must land
    /// inside the dead interval, or OSPF has already given up before the prober decides.
    #[test]
    fn a_move_fits_inside_the_dead_interval_on_the_example_timers() {
        let tick = Duration::from_millis(500);
        assert!(w().move_fits_inside_dead(tick, 3), "1.5 s + 0.5 s ≤ 3 s");
        let tight = Windows::from_ospf(1, 2);
        assert!(
            tight.move_fits_inside_dead(tick, 2),
            "1.5 s + 0.5 s is exactly 2 s — the last declaration that fits"
        );
        let too_tight = Windows::from_ospf(2, 2);
        assert!(
            !too_tight.move_fits_inside_dead(tick, 2),
            "hello 2 s with dead 2 s leaves no room to decide anything"
        );
    }

    /// A hello from a peer within a hello and a half is the whole of the steady state.
    #[test]
    fn a_recent_peer_hello_is_good_on_either_role() {
        let t0 = Instant::now();
        for active in [true, false] {
            let e = Evidence {
                active,
                peer: Some(t0),
                ..Evidence::default()
            };
            assert_eq!(
                verdicts(at(t0, 1400), &[e], &w(), true),
                vec![Verdict::Good]
            );
        }
    }

    /// The reflection is a BACKUP port's evidence only. On the active port it is never
    /// expected — our own hello leaves on that port and does not come back to it — so its
    /// presence must not make the active port look good, and its absence is never a miss.
    #[test]
    fn our_reflection_counts_for_a_backup_port_and_never_for_the_active_one() {
        let t0 = Instant::now();
        let backup = Evidence {
            active: false,
            reflected: Some(t0),
            ..Evidence::default()
        };
        let active = Evidence {
            active: true,
            reflected: Some(t0),
            ..Evidence::default()
        };
        assert_eq!(
            verdicts(at(t0, 1000), &[backup], &w(), true),
            vec![Verdict::Good]
        );
        assert_ne!(
            verdicts(at(t0, 1000), &[active], &w(), true),
            vec![Verdict::Good],
            "the active port cannot be judged by a frame it can never receive"
        );
    }

    /// A backup gets the full dead interval before it is suspected; the active port gets a
    /// hello and a half.
    #[test]
    fn the_two_roles_are_suspected_on_different_clocks() {
        let t0 = Instant::now();
        // The active port is silent; a backup hears a peer, so there is somewhere to go.
        let ports = [
            Evidence {
                active: true,
                peer: Some(t0),
                ..Evidence::default()
            },
            Evidence {
                active: false,
                peer: Some(t0),
                ..Evidence::default()
            },
        ];
        let mut late = ports;
        late[1].peer = Some(at(t0, 2000));
        assert_eq!(
            verdicts(at(t0, 2200), &late, &w(), true),
            vec![Verdict::Suspect, Verdict::Good],
            "the active port is 2.2 s silent, past its 1.5 s"
        );
        let mut backup_silent = ports;
        backup_silent[0].peer = Some(at(t0, 2000));
        assert_eq!(
            verdicts(at(t0, 2200), &backup_silent, &w(), true),
            vec![Verdict::Good, Verdict::Good],
            "a backup 2.2 s silent is still good: its window is the 3 s dead interval, and the \
             same silence on the active port above was already suspect"
        );
        assert_eq!(
            verdicts(at(t0, 3200), &backup_silent, &w(), true),
            vec![Verdict::Good, Verdict::Suspect]
        );
    }

    /// Silence vs absence: with nobody hearing anything, the fault is not per-wire. No wire is
    /// suspected, so nothing is asked and nothing is moved.
    #[test]
    fn a_leg_where_no_port_hears_anyone_is_quiet_not_suspect() {
        let t0 = Instant::now();
        let ports = [
            Evidence {
                active: true,
                peer: Some(t0),
                ..Evidence::default()
            },
            Evidence {
                active: false,
                peer: Some(t0),
                ..Evidence::default()
            },
        ];
        assert_eq!(
            verdicts(at(t0, 4000), &ports, &w(), true),
            vec![Verdict::Quiet, Verdict::Quiet]
        );
    }

    /// A port that has never heard anything at all is in the same position as one that has
    /// gone silent — it is not quietly assumed good.
    #[test]
    fn a_port_that_has_never_heard_anything_is_judged_too() {
        let t0 = Instant::now();
        let ports = [
            Evidence {
                active: true,
                peer: Some(at(t0, 3900)),
                ..Evidence::default()
            },
            Evidence {
                active: false,
                ..Evidence::default()
            },
        ];
        assert_eq!(
            verdicts(at(t0, 4000), &ports, &w(), true),
            vec![Verdict::Good, Verdict::Suspect]
        );
    }

    /// Grace: a port that has just come back (a re-enumerated USB NIC, F5) or has just been
    /// promoted cannot be suspected before a hello has had time to arrive on it.
    #[test]
    fn a_port_in_its_grace_period_is_never_suspect() {
        let t0 = Instant::now();
        let ports = [
            Evidence {
                active: true,
                peer: Some(at(t0, 3900)),
                ..Evidence::default()
            },
            Evidence {
                active: false,
                grace_until: Some(at(t0, 5000)),
                ..Evidence::default()
            },
        ];
        assert_eq!(
            verdicts(at(t0, 4000), &ports, &w(), true),
            vec![Verdict::Good, Verdict::Watch]
        );
        assert_eq!(
            verdicts(at(t0, 5100), &ports, &w(), true),
            vec![Verdict::Good, Verdict::Suspect],
            "and is judged normally once the grace ends"
        );
    }

    /// A member alone in a zone's universal segment has no peers to hear. It still runs the leg
    /// — its own reflection judges the backups, and the bond can still be on the wrong wire —
    /// but it never suspects a wire of losing peers it does not have.
    #[test]
    fn a_lone_member_never_suspects_a_wire() {
        let t0 = Instant::now();
        let ports = [
            Evidence {
                active: true,
                ..Evidence::default()
            },
            Evidence {
                active: false,
                reflected: Some(at(t0, 3900)),
                ..Evidence::default()
            },
        ];
        assert_eq!(
            verdicts(at(t0, 4000), &ports, &w(), false),
            vec![Verdict::Watch, Verdict::Good],
            "the reflection still marks the backup good; nothing is ever suspected"
        );
    }
}
