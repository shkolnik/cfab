//! The two pure decisions the ingress prober makes: when a wire's router reachability changes,
//! and which slave the bond should be active on. Both are here, with no clock, no `Sys` and no
//! socket, because they are the parts that must be provably right — the rest is plumbing.

/// Consecutive observations before `reachable` flips, each way (spec §2). Three at the probe
/// cadence is 1.5 s to call a wire dead and 1.5 s to call it live again.
///
/// Both numbers are derived, not knobs. The floor they must beat is the router's BGP hold time
/// on the ingress session (3.3 s measured — the UDM's FRR has no bfdd, so the session is the
/// slowest thing that notices): detect + move must fit inside it with margin, or the prober
/// fixes the wire after the neighbor has already given up. Faster than that buys nothing, since
/// the neighbor is what the outside actually depends on.
pub const HYSTERESIS: u8 = 3;

/// One wire's router reachability, with the 3/3 hysteresis.
///
/// It starts **reachable**. A prober that woke up pessimistic would report every wire dark for
/// its first three ticks and — worse — would have to be taught not to act on that, since with
/// nothing reachable there is no target to move to. Presuming the fabric works until three
/// consecutive probes say otherwise is the availability-first reading and the one that makes
/// the "nothing reachable ⇒ do not touch the bond" rule fall out for free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteresis {
    reachable: bool,
    /// Consecutive observations of the state we are NOT in. Reset by any observation that
    /// agrees with the current state — "consecutive" is the whole point.
    streak: u8,
}

impl Default for Hysteresis {
    fn default() -> Self {
        Hysteresis {
            reachable: true,
            streak: 0,
        }
    }
}

impl Hysteresis {
    /// Fold in one tick's answer. Returns the state after folding.
    pub fn observe(&mut self, replied: bool) -> bool {
        if replied == self.reachable {
            self.streak = 0;
        } else {
            self.streak = self.streak.saturating_add(1);
            if self.streak >= HYSTERESIS {
                self.reachable = replied;
                self.streak = 0;
            }
        }
        self.reachable
    }

    pub fn reachable(&self) -> bool {
        self.reachable
    }
}

/// One slave the bond could be active on, as the decision sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The slave netdev (`cfab-gw249-a`), which is what `bonding/active_slave` names.
    pub ifname: String,
    /// The physical wire under it, which is what the zone's preference order ranks.
    pub wire: String,
    pub reachable: bool,
}

/// Which slave the bond should be active on, or `None` to leave it alone.
///
/// `prefs` is the zone's wire order, rank 0 first — the same order OSPF costs are laddered from,
/// so ingress prefers the wire the fabric already prefers. A wire missing from the order sorts
/// last (it cannot happen on a validated fabric; ranking it last rather than panicking keeps a
/// surprising declaration from taking ingress down).
///
/// The rules, in the order they bite:
/// - nothing reachable ⇒ `None`. The kernel's carrier-driven reselect is better than a guess.
/// - the active slave is reachable and nothing better-preferred is ⇒ `None`.
/// - anything else ⇒ the best reachable slave: the active one is dead, or a better-preferred
///   wire came back and ingress belongs on it.
pub fn decide(active: Option<&str>, cands: &[Candidate], prefs: &[String]) -> Option<String> {
    let rank = |wire: &str| {
        prefs
            .iter()
            .position(|w| w == wire)
            .unwrap_or(usize::MAX - 1)
    };
    // Ties (two wires outside the preference order) keep enslave order, which is `[[member]]`
    // order: a deterministic answer, so two consecutive ticks never disagree and flap.
    let best = cands
        .iter()
        .enumerate()
        .filter(|(_, c)| c.reachable)
        .min_by_key(|(i, c)| (rank(&c.wire), *i))
        .map(|(_, c)| c)?;
    match active.and_then(|a| cands.iter().find(|c| c.ifname == a)) {
        // Already where we want it, or already on an equally preferred live wire.
        Some(c) if c.reachable && rank(&c.wire) <= rank(&best.wire) => None,
        // Dead, or worse-preferred than a live wire — and the `None` arm also covers an
        // active_slave that is not a slave of ours at all (or none at all), which is a bond we
        // should own and do not.
        _ => Some(best.ifname.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cands(spec: &[(&str, &str, bool)]) -> Vec<Candidate> {
        spec.iter()
            .map(|(ifname, wire, reachable)| Candidate {
                ifname: ifname.to_string(),
                wire: wire.to_string(),
                reachable: *reachable,
            })
            .collect()
    }

    fn prefs(order: &[&str]) -> Vec<String> {
        order.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_wire_goes_unreachable_only_after_three_consecutive_misses() {
        let mut h = Hysteresis::default();
        assert!(h.reachable(), "a wire starts presumed reachable");
        assert!(h.observe(false));
        assert!(h.observe(false));
        assert!(!h.observe(false), "the third consecutive miss flips it");
    }

    #[test]
    fn one_reply_resets_the_miss_streak() {
        let mut h = Hysteresis::default();
        h.observe(false);
        h.observe(false);
        assert!(h.observe(true), "still reachable");
        assert!(h.observe(false));
        assert!(h.observe(false));
        assert!(
            h.reachable(),
            "the streak restarted, so two misses is not three"
        );
        assert!(!h.observe(false));
    }

    #[test]
    fn a_dead_wire_comes_back_only_after_three_consecutive_replies() {
        let mut h = Hysteresis::default();
        for _ in 0..HYSTERESIS {
            h.observe(false);
        }
        assert!(!h.reachable());
        assert!(!h.observe(true));
        assert!(!h.observe(true));
        assert!(h.observe(true), "the third consecutive reply flips it back");
    }

    #[test]
    fn one_miss_resets_the_recovery_streak() {
        let mut h = Hysteresis::default();
        for _ in 0..HYSTERESIS {
            h.observe(false);
        }
        h.observe(true);
        h.observe(true);
        h.observe(false);
        h.observe(true);
        h.observe(true);
        assert!(!h.reachable(), "the recovery streak restarted");
    }

    #[test]
    fn nothing_reachable_never_moves_the_bond() {
        let c = cands(&[
            ("cfab-gw249-a", "eth9", false),
            ("cfab-gw249-b", "eth1", false),
            ("cfab-gw249-c", "eth0", false),
        ]);
        assert_eq!(
            decide(Some("cfab-gw249-c"), &c, &prefs(&["eth9", "eth1", "eth0"])),
            None
        );
        assert_eq!(decide(None, &c, &prefs(&["eth9", "eth1", "eth0"])), None);
    }

    #[test]
    fn an_active_slave_on_the_best_reachable_wire_stays() {
        let c = cands(&[
            ("cfab-gw249-a", "eth9", true),
            ("cfab-gw249-b", "eth1", true),
        ]);
        assert_eq!(
            decide(Some("cfab-gw249-a"), &c, &prefs(&["eth9", "eth1"])),
            None
        );
    }

    #[test]
    fn an_unreachable_active_slave_moves_to_the_best_reachable_one() {
        let c = cands(&[
            ("cfab-gw249-a", "eth9", false),
            ("cfab-gw249-b", "eth1", true),
            ("cfab-gw249-c", "eth0", true),
        ]);
        assert_eq!(
            decide(Some("cfab-gw249-a"), &c, &prefs(&["eth9", "eth1", "eth0"])),
            Some("cfab-gw249-b".to_string()),
            "the preference order picks the backup, not the enslave order"
        );
    }

    /// F20's other half: the order that decides the backup is the zone's declared preference,
    /// so a `prefs` row that puts the slow wire last is honored here too.
    #[test]
    fn the_backup_is_chosen_by_preference_not_by_slave_order() {
        let c = cands(&[
            ("cfab-gw249-a", "eth9", false),
            ("cfab-gw249-b", "eth1", true),
            ("cfab-gw249-c", "eth0", true),
        ]);
        assert_eq!(
            decide(Some("cfab-gw249-a"), &c, &prefs(&["eth9", "eth0", "eth1"])),
            Some("cfab-gw249-c".to_string())
        );
    }

    #[test]
    fn a_better_preferred_wire_coming_back_moves_ingress_home() {
        let c = cands(&[
            ("cfab-gw249-a", "eth9", true),
            ("cfab-gw249-b", "eth1", true),
        ]);
        assert_eq!(
            decide(Some("cfab-gw249-b"), &c, &prefs(&["eth9", "eth1"])),
            Some("cfab-gw249-a".to_string())
        );
    }

    #[test]
    fn a_worse_preferred_wire_coming_back_does_not_move_a_live_bond() {
        let c = cands(&[
            ("cfab-gw249-a", "eth9", true),
            ("cfab-gw249-b", "eth1", true),
        ]);
        assert_eq!(
            decide(Some("cfab-gw249-a"), &c, &prefs(&["eth9", "eth1"])),
            None
        );
    }

    /// A bond with no active slave, and a bond whose active slave is a stranger, are both bonds
    /// we own and are not driving: claim them for the best reachable wire.
    #[test]
    fn no_active_slave_or_a_stranger_claims_the_best_reachable_wire() {
        let c = cands(&[
            ("cfab-gw249-a", "eth9", true),
            ("cfab-gw249-b", "eth1", true),
        ]);
        let p = prefs(&["eth9", "eth1"]);
        assert_eq!(decide(None, &c, &p), Some("cfab-gw249-a".to_string()));
        assert_eq!(
            decide(Some("enp3s0"), &c, &p),
            Some("cfab-gw249-a".to_string())
        );
    }

    /// A wire the preference order does not name must not outrank one it does, and two such
    /// wires must resolve the same way twice — a decision that flapped would move the bond
    /// every tick.
    #[test]
    fn a_wire_missing_from_the_preference_order_sorts_last_and_stably() {
        let c = cands(&[
            ("cfab-gw249-a", "usb0", true),
            ("cfab-gw249-b", "usb1", true),
            ("cfab-gw249-c", "eth0", true),
        ]);
        let p = prefs(&["eth0"]);
        assert_eq!(decide(None, &c, &p), Some("cfab-gw249-c".to_string()));
        let only_unranked = cands(&[
            ("cfab-gw249-a", "usb0", true),
            ("cfab-gw249-b", "usb1", true),
        ]);
        assert_eq!(
            decide(None, &only_unranked, &p),
            Some("cfab-gw249-a".to_string())
        );
        assert_eq!(decide(Some("cfab-gw249-a"), &only_unranked, &p), None);
    }
}
