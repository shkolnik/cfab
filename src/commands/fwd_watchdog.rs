//! `cfab fwd-watchdog` — the fail-closed forwarding check. Run every few seconds by the
//! transient systemd timer `cfab up` starts. If the forward policy is not loaded with a drop
//! default, switch forwarding OFF on every cfab interface and say so (recovery = re-run
//! `cfab up`). Forwarding flags on cfab's own interfaces that drifted from the declared value
//! are written back and logged: the flag is the belt, the (verified-present) policy is the
//! braces, and a foreign stack writing `ip_forward=1` propagates 1 onto every interface
//! including ours — that is drift to correct, not a breach. Interfaces cfab does not own are
//! never read or written (scoped posture; `View::owned_forwarding`). Per-interface forwarding
//! is what the kernel checks — so conf/<if>/forwarding is written, never ip_forward.
//!
//! It also reports foreign forward-hook chains whose policy is drop. Those are reported and
//! never corrected: every base chain at a hook runs and any one drop verdict ends the packet,
//! so cfab cannot out-accept them, and switching our own forwarding off would not restore a
//! single packet. Silence here was a real bug — with Docker running, transit was 100 % dead
//! while cfab's own counters recorded accepts and `cfab status` reported a healthy posture.

use crate::commands::common::{
    self, conf_interfaces, ensure_foreign_transit_accept, foreign_forward_remedy,
    unresolved_forward_drops,
};
use crate::commands::engine_ctl;
use crate::derive::View;
use crate::emit::engine::TransitCost;
use crate::error::Result;
use crate::model::MemberKind;
use crate::sys::{Sys, run_ignore};

pub struct WatchdogReport {
    /// None = healthy; Some(reason) = failed closed.
    pub failed: Option<String>,
    /// cfab interfaces whose forwarding flag was written back to the declared value.
    pub corrected: Vec<String>,
    /// Foreign forward-hook chains dropping what cfab accepts. Reported, never "corrected":
    /// cfab cannot override another table's verdict, and switching our own forwarding off
    /// would not restore a single packet.
    pub blocked: Vec<String>,
    /// A foreign-stack accept cfab installed on this tick (`None` = nothing needed doing).
    pub resolved: Option<String>,
    /// Objects cfab owns that had drifted and were put back: an rp_filter sysctl, an `ip rule`,
    /// a bond's membership. Restoring is always tried FIRST — a false positive then costs one
    /// idempotent write instead of an outage.
    pub restored: Vec<String>,
    /// Restores that failed, after which the narrowest thing that removes the hazard was
    /// brought down. The name says what went down and why.
    pub downed: Vec<String>,
    /// The engine would not take the `transit-cost` re-advertisement (it is down, or it
    /// refused the candidate). Loud, but never an exit code of its own: an engine that is not
    /// answering is `status`'s story, and the forwarding flags are already off.
    pub transit_cost_error: Option<String>,
    /// Restores that failed where there is nothing to actuate on — the drift stands, loudly,
    /// and `status` keeps reporting it. Never silent, never an outage.
    pub unrestored: Vec<String>,
}

pub fn run(sys: &mut dyn Sys, view: &View) -> Result<WatchdogReport> {
    // The forward policy is a transit fact: a leaf never transits and never loads the table, so
    // asking it for `policy drop` would fail it closed on a posture it is not supposed to have.
    // (`up` only schedules this timer on a forwarding host today; the guard makes the command
    // safe to run anywhere, which is what the rule restores below need.)
    let transits = view.kind() == MemberKind::Host && view.fabric.host_forward;
    let mut transit_cost_error = None;
    if transits {
        let chain = sys.run(&["nft", "list", "chain", "inet", "cfab-fwd", "forward"])?;
        if !chain.ok() || !chain.stdout.contains("policy drop;") {
            return fail_closed(
                sys,
                view,
                "table inet cfab-fwd / chain forward with policy drop is not loaded",
            );
        }
        // The policy is loaded, so this member may transit again: put the transit links back
        // at their declared cost. Re-asserted every tick, not remembered — the engine diffs
        // the candidate, so the cost already in force costs nothing, and no state file can
        // disagree with what is actually advertised.
        transit_cost_error = ask_transit_cost(sys, view, TransitCost::Declared);
    }
    let present = conf_interfaces(sys)?;
    let mut corrected = Vec::new();
    for (ifn, fwd) in view.owned_forwarding() {
        if !present.contains(&ifn) {
            continue;
        }
        let want = if fwd { "1" } else { "0" };
        let path = format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding");
        let v = sys
            .read(&path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if v != want {
            sys.write(&path, want)?;
            corrected.push(format!("{ifn} forwarding {v}->{want}"));
        }
    }
    if !corrected.is_empty() {
        run_ignore(
            sys,
            &[
                "logger",
                "-t",
                "cfab-fwd-watchdog",
                &format!(
                    "corrected forwarding on cfab interfaces: {} (a foreign stack wrote ip_forward?)",
                    corrected.join(", ")
                ),
            ],
        )?;
    }
    // ---- restore what cfab owns, and actuate only where a restore failed ----------------
    // Narrowest hazard first, and the one that can amputate LAST: a leg-wide sysctl, then one
    // bond's membership, then the member-wide rules. Running the rules first would down every
    // fabric leg — the bonds included — under a bond restore that had not been tried yet.
    let mut restored: Vec<String> = Vec::new();
    let mut downed: Vec<String> = Vec::new();
    let mut unrestored: Vec<String> = Vec::new();
    restore_rp_filter(sys, view, &mut restored, &mut unrestored)?;
    restore_bond_membership(sys, view, &mut restored, &mut downed)?;
    restore_rules(sys, view, &mut restored, &mut downed)?;
    for line in restored
        .iter()
        .chain(downed.iter())
        .chain(unrestored.iter())
    {
        run_ignore(sys, &["logger", "-t", "cfab-fwd-watchdog", line])?;
    }

    if !transits {
        return Ok(WatchdogReport {
            failed: None,
            corrected,
            blocked: Vec::new(),
            resolved: None,
            restored,
            downed,
            unrestored,
            transit_cost_error,
        });
    }
    // Ask the foreign stack to pass cfab transit before judging it: Docker's policy stays DROP
    // by its own design, so the question is never "is there a drop" but "is our accept in".
    let mut resolved = None;
    if let Some(rule) = ensure_foreign_transit_accept(sys)? {
        run_ignore(
            sys,
            &[
                "logger",
                "-t",
                "cfab-fwd-watchdog",
                &format!("installed a foreign-stack accept for cfab transit: {rule}"),
            ],
        )?;
        resolved = Some(rule);
    }
    let blocked = unresolved_forward_drops(sys)?;
    if !blocked.is_empty() {
        let ifs: Vec<String> = view
            .owned_forwarding()
            .into_iter()
            .filter(|(_, fwd)| *fwd)
            .map(|(ifn, _)| ifn)
            .collect();
        run_ignore(
            sys,
            &[
                "logger",
                "-t",
                "cfab-fwd-watchdog",
                &format!(
                    "BLOCKED by a foreign ruleset: {} — {}",
                    blocked.join(", "),
                    foreign_forward_remedy(&ifs)
                ),
            ],
        )?;
    }
    Ok(WatchdogReport {
        failed: None,
        corrected,
        blocked,
        resolved,
        restored,
        downed,
        unrestored,
        transit_cost_error,
    })
}

/// The L3 netdevs cfab owns: class segments and the fallback bonds. Their slaves are L2 only.
fn fabric_legs(view: &View) -> Vec<String> {
    view.class_rows()
        .into_iter()
        .map(|r| r.ifname)
        .chain(view.fallback_rows().into_iter().map(|r| r.ifname))
        .collect()
}

/// Row 4. cfab owns the value (loose, every role — strict rp_filter black-holed control for
/// ~5 s when all links returned at once), so drift is written back, never reported and left.
/// Radius is a leg and the fix is one idempotent write, so there is nothing here to actuate on.
/// A write that fails is recorded and the tick continues: one unwritable sysctl must not cost
/// the bond and rule restores that follow it.
fn restore_rp_filter(
    sys: &mut dyn Sys,
    view: &View,
    restored: &mut Vec<String>,
    unrestored: &mut Vec<String>,
) -> Result<()> {
    for ifname in fabric_legs(view) {
        let path = format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter");
        // An absent leg is not ours to create — `cfab up` does that.
        let Ok(v) = sys.read(&path) else { continue };
        let v = v.trim().to_string();
        if v != "2" {
            match sys.write(&path, "2") {
                Ok(()) => restored.push(format!("rp_filter {ifname} {v}->2 (want 2 = loose)")),
                Err(e) => unrestored.push(format!(
                    "rp_filter {ifname}={v}: could not write 2 ({e}) — re-run cfab up"
                )),
            }
        }
    }
    Ok(())
}

/// Rows 5 and 6: the leaf leak guard and the return path. Both are member-wide — with either
/// missing, fabric-block traffic can leave by a path cfab never sanctioned — and neither can be
/// narrowed to one leg. So: re-add first; only if the re-add fails do the fabric legs go down,
/// which removes the hazard by removing the fabric, and `status` then reads FAILED.
fn restore_rules(
    sys: &mut dyn Sys,
    view: &View,
    restored: &mut Vec<String>,
    downed: &mut Vec<String>,
) -> Result<()> {
    let mut rules = Vec::new();
    if view.kind() == MemberKind::Leaf {
        rules.extend(common::leak_guard_rules(view));
    }
    rules.extend(common::return_path_rules(view));
    let mut unrestorable: Vec<String> = Vec::new();
    for r in &rules {
        if common::fabric_rule_present(sys, r)? {
            continue;
        }
        let what = format!("pref {} {}", r.pref, r.needle);
        match common::ensure_fabric_rule(sys, r) {
            Ok(()) => restored.push(format!("re-added ip rule {what}")),
            Err(_) => unrestorable.push(what),
        }
    }
    if unrestorable.is_empty() {
        return Ok(());
    }
    for ifname in fabric_legs(view) {
        run_ignore(sys, &["ip", "link", "set", &ifname, "down"])?;
    }
    downed.push(format!(
        "fabric legs down: could not restore {} — re-run cfab up",
        unrestorable.join(", ")
    ));
    Ok(())
}

/// Row 19. The hazard is the FOREIGN slave, not the bond: something else enslaved a netdev into
/// a bond cfab created, and traffic cfab believes is on its own wire is on somebody else's. So
/// release the intruder and keep ours running; the bond goes down only if the release fails.
/// `active_slave` is compared against the names cfab itself created — an unreadable `bonding/`
/// file is row 17 (a reason line), never this.
fn restore_bond_membership(
    sys: &mut dyn Sys,
    view: &View,
    restored: &mut Vec<String>,
    downed: &mut Vec<String>,
) -> Result<()> {
    for r in view.fallback_rows() {
        let Ok(active) = sys.read(&format!("/sys/class/net/{}/bonding/active_slave", r.ifname))
        else {
            continue;
        };
        let active = active.trim().to_string();
        if active.is_empty() || r.slaves.iter().any(|s| s.ifname == active) {
            continue;
        }
        if sys.run(&["ip", "link", "set", &active, "nomaster"])?.ok() {
            restored.push(format!(
                "fallback {}: released foreign slave {active}",
                r.zone
            ));
        } else {
            run_ignore(sys, &["ip", "link", "set", &r.ifname, "down"])?;
            downed.push(format!(
                "fallback {} down: foreign slave {active} could not be released",
                r.zone
            ));
        }
    }
    Ok(())
}

/// Tell the engine what cost to advertise this member's transit links at (spec §12 (b)).
/// Returns the error text when the engine would not take it — loud, never fatal: the
/// forwarding flags are the actuator, this is only what the peers are told.
fn ask_transit_cost(sys: &mut dyn Sys, view: &View, at: TransitCost) -> Option<String> {
    let sock = engine_ctl::sock_path(view.fabric);
    let line = format!("transit-cost {}\n", at.word());
    match sys.unix_request(&sock, &line) {
        Ok(reply) if reply.contains("\"error\"") => {
            Some(format!("engine refused {}: {}", line.trim(), reply.trim()))
        }
        Ok(_) => None,
        Err(e) => Some(format!("engine would not take {}: {e}", line.trim())),
    }
}

fn fail_closed(sys: &mut dyn Sys, view: &View, reason: &str) -> Result<WatchdogReport> {
    let present = conf_interfaces(sys)?;
    for (ifn, _) in view.owned_forwarding() {
        if present.contains(&ifn) {
            sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
        }
    }
    // Forwarding is off here, so every packet a peer still sends through this member is a
    // black hole until the peers stop choosing it as transit. Re-advertise at the leaf offset:
    // still reachable, never a path through. A leaf is already offset and is never asked.
    let transit_cost_error = if view.kind() == MemberKind::Host && view.fabric.host_forward {
        ask_transit_cost(sys, view, TransitCost::LeafOffset)
    } else {
        None
    };
    run_ignore(
        sys,
        &[
            "logger",
            "-t",
            "cfab-fwd-watchdog",
            &format!(
                "FAIL-CLOSED: {reason} — forwarding=0 on every cfab interface; re-run cfab up"
            ),
        ],
    )?;
    Ok(WatchdogReport {
        failed: Some(reason.to_string()),
        corrected: Vec::new(),
        blocked: Vec::new(),
        resolved: None,
        restored: Vec::new(),
        downed: Vec::new(),
        unrestored: Vec::new(),
        transit_cost_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn view_fixture() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// `nft -j list chains` with only cfab's own tables. `extra` appends a foreign chain.
    fn chains_json(extra: &str) -> String {
        format!(
            r#"{{"nftables":[
              {{"chain":{{"family":"inet","table":"cfab-fwd","name":"forward",
                          "hook":"forward","prio":0,"policy":"drop"}}}}
              {extra}]}}"#
        )
    }

    const DOCKER_FORWARD: &str = r#",
      {"chain":{"family":"ip","table":"filter","name":"FORWARD",
                "hook":"forward","prio":0,"policy":"drop"}}"#;

    fn healthy_sys(view: &View) -> MockSys {
        let mut sys = MockSys::default()
            .socket(
                &engine_ctl::sock_path(view.fabric),
                "{\"transit_cost\":\"normal\"}",
            )
            .on_stdout(
                &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
                "chain forward {\n  type filter hook forward priority filter; policy drop;\n}",
            )
            .on_stdout(&["nft", "-j", "list", "chains"], &chains_json(""));
        for r in view.class_rows() {
            sys = sys.file(
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
        sys = sys
            .file("/proc/sys/net/ipv4/conf/eth0/forwarding", "0\n")
            .file("/proc/sys/net/ipv4/conf/lo/forwarding", "0\n")
            .file("/proc/sys/net/ipv4/conf/all/forwarding", "1\n");
        // Everything the NEW restores read, healthy: the loose rp_filter cfab owns on every L3
        // leg, every `ip rule` cfab installed, and each bond active on a slave of ours.
        for ifname in fabric_legs(view) {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"),
                "2\n",
            );
        }
        // The bonds are transit-eligible like a segment (a fallback leg for one zone can carry
        // another zone's island-disjoint traffic on a forwarding host).
        for r in view.fallback_rows() {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                "1\n",
            );
        }
        rules_present(sys, view)
    }

    /// `ip rule show pref <p>` answering with every rule cfab declared at that pref.
    fn rules_present(mut sys: MockSys, view: &View) -> MockSys {
        let mut by_pref: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for r in common::leak_guard_rules(view)
            .into_iter()
            .chain(common::return_path_rules(view))
        {
            by_pref
                .entry(r.pref.clone())
                .or_default()
                .push(format!("{}: from all {}\n", r.pref, r.needle));
        }
        for (pref, lines) in by_pref {
            sys = sys.on_stdout(&["ip", "rule", "show", "pref", &pref], &lines.concat());
        }
        for r in view.fallback_rows() {
            let home = r
                .slaves
                .iter()
                .find(|s| s.wire == r.home)
                .expect("the home wire is one of the slaves");
            sys = sys.file(
                &format!("/sys/class/net/{}/bonding/active_slave", r.ifname),
                &format!("{}\n", home.ifname),
            );
        }
        sys
    }

    #[test]
    fn healthy_posture_passes() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none());
        assert!(report.corrected.is_empty());
        assert!(!sys.ran("logger"));
    }

    #[test]
    fn missing_policy_fails_closed_on_cfab_interfaces_only() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view)
            .file("/proc/sys/net/ipv4/conf/docker0/forwarding", "1\n")
            .on_fail(
                &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
                1,
                "no such table",
            );
        let report = run(&mut sys, &view).unwrap();
        assert!(
            report
                .failed
                .as_deref()
                .unwrap_or("")
                .contains("policy drop"),
            "{:?}",
            report.failed
        );
        // cfab's interfaces written to 0; a foreign one and the `all` propagator untouched
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            Some("0")
        );
        // (the mock returns seeded content for an untouched path: "1\n" = never written)
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/all/forwarding"),
            Some("1\n")
        );
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/docker0/forwarding"),
            Some("1\n")
        );
        assert!(sys.ran("logger"));
    }

    #[test]
    fn foreign_forwarder_is_not_ours_to_police() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).file("/proc/sys/net/ipv4/conf/docker0/forwarding", "1\n");
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert!(report.corrected.is_empty());
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/docker0/forwarding"),
            Some("1\n")
        );
        assert!(!sys.ran("logger"));
    }

    #[test]
    fn drift_on_own_interface_is_corrected_and_logged() {
        // a foreign `ip_forward=1` propagates 1 onto the admin NIC: write it back, say so, stay up
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).file("/proc/sys/net/ipv4/conf/eth0/forwarding", "1\n");
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert_eq!(report.corrected, vec!["eth0 forwarding 1->0".to_string()]);
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/eth0/forwarding"),
            Some("0")
        );
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            Some("1\n")
        );
        assert!(sys.ran("logger"));
    }

    #[test]
    fn a_foreign_forward_drop_is_reported_loudly_and_does_not_fail_closed() {
        // Docker's `ip filter FORWARD` policy DROP kills transit that cfab accepts. Say so --
        // but do not switch our forwarding off: it would not restore a single packet, and
        // availability-first means we never make a foreign breakage worse.
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).on_stdout(
            &["nft", "-j", "list", "chains"],
            &chains_json(DOCKER_FORWARD),
        );
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert_eq!(
            report.blocked,
            vec!["ip filter FORWARD (policy drop)".to_string()]
        );
        assert!(sys.ran("logger"));
        // forwarding on a class interface is left exactly as declared
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            Some("1\n")
        );
    }

    /// PROVING existing behavior, not new logic: `owned_forwarding()` (Task 2) already flags
    /// the fallback bond `transit`-eligible like a class segment (a fallback leg for one zone can
    /// carry another zone's island-disjoint traffic on a forwarding host) — this test exercises
    /// that through the watchdog's own correction path rather than reading `owned_forwarding`
    /// directly, so a regression here fails where it would actually bite in production.
    #[test]
    fn a_fallback_bond_drifted_to_0_is_corrected_to_1_like_a_segment() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert!(
            !view.fallback_rows().is_empty(),
            "fixture must carry fallback rows"
        );
        let mut sys = healthy_sys(&view);
        for r in view.fallback_rows() {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                "0\n",
            );
        }
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        for r in view.fallback_rows() {
            assert!(
                report
                    .corrected
                    .iter()
                    .any(|c| c.starts_with(&format!("{} forwarding 0->1", r.ifname))),
                "{}: not corrected to 1 like a segment: {:?}",
                r.ifname,
                report.corrected
            );
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname)),
                Some("1")
            );
        }
    }

    /// A fallback slave is L2 only (`owned_forwarding` always pairs it with `false`): even if
    /// something turned its forwarding sysctl on, the watchdog writes it back to 0, same as
    /// the admin NIC — it is never flagged transit-eligible the way the bond is.
    #[test]
    fn a_fallback_slave_drifted_to_1_is_corrected_to_0_never_flagged_transit() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let slave_ifs: Vec<String> = view
            .fallback_rows()
            .into_iter()
            .flat_map(|r| r.slaves)
            .map(|s| s.ifname)
            .collect();
        assert!(!slave_ifs.is_empty(), "fixture must carry fallback slaves");
        let mut sys = healthy_sys(&view);
        for ifn in &slave_ifs {
            sys = sys.file(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "1\n");
        }
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        for ifn in &slave_ifs {
            assert!(
                report
                    .corrected
                    .iter()
                    .any(|c| c.starts_with(&format!("{ifn} forwarding 1->0"))),
                "{ifn}: slave was not corrected back to 0: {:?}",
                report.corrected
            );
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding")),
                Some("0")
            );
        }
    }

    /// A leaf environment for the leak guard (row 5): pve3-tb, every rule present.
    fn healthy_leaf_sys(view: &View) -> MockSys {
        let mut sys = MockSys::default();
        for ifname in fabric_legs(view) {
            sys = sys
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{ifname}/forwarding"),
                    "0\n",
                );
        }
        rules_present(sys, view)
    }

    /// Spec §12 (b). Failing closed turns forwarding off, which black-holes anything a peer
    /// still sends through this member — so the same tick tells the engine to re-advertise the
    /// transit links at the leaf offset. A healthy tick asks for the declared cost back: the
    /// request is re-asserted every tick rather than remembered, so no state file can disagree
    /// with what is actually advertised.
    #[test]
    fn failing_closed_re_advertises_at_the_leaf_offset_and_a_healthy_tick_puts_it_back() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let sock = engine_ctl::sock_path(view.fabric);

        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none());
        assert!(
            sys.ran(&format!("unix_request {sock} transit-cost normal")),
            "{:?}",
            sys.calls
        );
        assert_eq!(report.transit_cost_error, None);

        let mut sys = healthy_sys(&view)
            .socket(&sock, "{\"transit_cost\":\"leaf\"}")
            .on_stdout(
                &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
                "chain forward {\n  type filter hook forward priority filter; policy accept;\n}",
            );
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_some());
        assert!(
            sys.ran(&format!("unix_request {sock} transit-cost leaf")),
            "{:?}",
            sys.calls
        );
        assert!(
            !sys.ran(&format!("unix_request {sock} transit-cost normal")),
            "{:?}",
            sys.calls
        );
        assert_eq!(report.transit_cost_error, None);
    }

    /// An engine that is not answering must not turn a fail-closed tick into a panic or a
    /// silent success: the forwarding flags still go off, and the undelivered re-advertisement
    /// is named.
    #[test]
    fn an_engine_that_will_not_take_the_re_advertisement_is_loud_not_fatal() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).on_stdout(
            &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
            "chain forward {\n  type filter hook forward priority filter; policy accept;\n}",
        );
        sys.sockets.clear();
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_some());
        let e = report.transit_cost_error.expect("named");
        assert!(e.contains("transit-cost leaf"), "{e}");
        assert!(
            sys.ran("write /proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            "{:?}",
            sys.calls
        );
    }

    /// A leaf is offset by what it is and never transits: it asks for nothing, in either
    /// direction, so a leaf with no engine socket is not a fail-closed leaf.
    #[test]
    fn a_leaf_never_asks_for_a_transit_cost() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf_sys(&view);
        let report = run(&mut sys, &view).unwrap();
        assert_eq!(report.transit_cost_error, None);
        assert!(
            !sys.calls.iter().any(|c| c.contains("transit-cost")),
            "{:?}",
            sys.calls
        );
    }

    /// Row 4, restore. cfab owns the loose rp_filter, so drift is written back — and nothing is
    /// downed for a condition one idempotent write repairs.
    #[test]
    fn row4_rp_filter_drift_is_written_back_and_downs_nothing() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys =
            healthy_sys(&view).file("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter", "1\n");
        let report = run(&mut sys, &view).unwrap();
        assert_eq!(
            report.restored,
            vec!["rp_filter cfab-st-fb 1->2 (want 2 = loose)".to_string()]
        );
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter"),
            Some("2")
        );
        assert!(!sys.ran("ip link set"), "{:?}", sys.calls);
    }

    /// Row 4, false-positive guard: a leg that is not there is not ours to create.
    #[test]
    fn row4_leaves_an_absent_leg_alone() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        sys.files
            .remove("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter");
        let report = run(&mut sys, &view).unwrap();
        assert!(report.restored.is_empty(), "{:?}", report.restored);
    }

    /// Row 4, unrestorable. A read-only `/proc` (a container, a hardened host) must not cost
    /// the restores that follow it: the drift is reported loudly and the tick carries on to the
    /// bond and the rules. Availability-first — one stuck sysctl is not a reason to stop
    /// repairing everything else.
    #[test]
    fn row4_an_unwritable_rp_filter_is_loud_and_does_not_abort_the_tick() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view)
            .file("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter", "1\n")
            .write_fail("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter")
            .file(
                "/sys/class/net/cfab-cl-fb/bonding/active_slave",
                "someone-elses0\n",
            );
        let report = run(&mut sys, &view).unwrap();
        assert_eq!(report.unrestored.len(), 1, "{:?}", report.unrestored);
        assert!(
            report.unrestored[0].starts_with("rp_filter cfab-st-fb=1: could not write 2"),
            "{:?}",
            report.unrestored
        );
        // The bond restore behind it still ran.
        assert_eq!(
            report.restored,
            vec!["fallback cluster: released foreign slave someone-elses0".to_string()]
        );
        assert!(report.downed.is_empty(), "{:?}", report.downed);
    }

    /// Ordering: the member-wide amputation runs LAST. With the rules first, an unrestorable
    /// leak guard would down every fabric leg — the bonds included — under a bond restore that
    /// had not been tried yet, and the release would then be attempted on a dead bond.
    #[test]
    fn the_bond_release_is_tried_before_the_member_wide_amputation() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf_sys(&view)
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "someone-elses0\n",
            )
            .on_stdout(&["ip", "rule", "show", "pref", "1001"], "")
            .on_fail(
                &["ip", "rule", "add", "pref", "1001"],
                2,
                "RTNETLINK: EPERM",
            );
        let report = run(&mut sys, &view).unwrap();
        assert!(
            report
                .restored
                .contains(&"fallback storage: released foreign slave someone-elses0".to_string()),
            "{:?}",
            report.restored
        );
        let release = sys
            .calls
            .iter()
            .position(|c| c == "ip link set someone-elses0 nomaster")
            .expect("the release was attempted");
        let amputation = sys
            .calls
            .iter()
            .position(|c| c == "ip link set cfab-st-fb down")
            .expect("the legs went down");
        assert!(release < amputation, "{:?}", sys.calls);
    }

    /// Row 5, restore. A leaf's leak guard is re-added, and the fabric stays up.
    #[test]
    fn row5_a_missing_leak_guard_is_re_added() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys =
            healthy_leaf_sys(&view).on_stdout(&["ip", "rule", "show", "pref", "1001"], "");
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        for blk in ["10.99.0.0/16", "10.199.0.0/16", "10.249.0.0/16"] {
            assert!(
                sys.ran(&format!("ip rule add pref 1001 to {blk} unreachable")),
                "{:?}",
                sys.calls
            );
        }
        assert!(!sys.ran("ip link set"), "restored: nothing to amputate");
    }

    /// Row 5, actuate. The re-add itself fails, so the hazard is member-wide and unrestorable:
    /// every fabric leg goes down and `status` then reads FAILED. This is the arm that proves
    /// the actuator bites — without it "restore first" is just a comment.
    #[test]
    fn row5_an_unrestorable_leak_guard_downs_the_fabric_legs() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf_sys(&view)
            .on_stdout(&["ip", "rule", "show", "pref", "1001"], "")
            .on_fail(
                &["ip", "rule", "add", "pref", "1001"],
                2,
                "RTNETLINK: EPERM",
            );
        let report = run(&mut sys, &view).unwrap();
        assert_eq!(report.downed.len(), 1, "{:?}", report.downed);
        assert!(
            report.downed[0].starts_with("fabric legs down: could not restore pref 1001"),
            "{:?}",
            report.downed
        );
        for ifname in fabric_legs(&view) {
            assert!(
                sys.ran(&format!("ip link set {ifname} down")),
                "{ifname} still up: {:?}",
                sys.calls
            );
        }
    }

    /// Row 6, restore then actuate, same pair on the return path.
    #[test]
    fn row6_a_missing_return_path_rule_is_re_added_then_actuated_if_it_cannot_be() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();

        let mut sys = healthy_sys(&view).on_stdout(&["ip", "rule", "show", "pref", "2002"], "");
        let report = run(&mut sys, &view).unwrap();
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert!(
            sys.ran("ip rule add pref 2002 from 10.99.0.0/16 unreachable"),
            "{:?}",
            sys.calls
        );
        assert!(!sys.ran("ip link set"));

        let mut sys = healthy_sys(&view)
            .on_stdout(&["ip", "rule", "show", "pref", "2002"], "")
            .on_fail(
                &["ip", "rule", "add", "pref", "2002"],
                2,
                "RTNETLINK: EPERM",
            );
        let report = run(&mut sys, &view).unwrap();
        assert_eq!(report.downed.len(), 1, "{:?}", report.downed);
        for ifname in fabric_legs(&view) {
            assert!(sys.ran(&format!("ip link set {ifname} down")), "{ifname}");
        }
    }

    /// Row 19, restore. The hazard is the foreign slave, so the intruder is released and ours
    /// keeps running — the bond is never downed for something an eviction fixes.
    #[test]
    fn row19_a_foreign_active_slave_is_released_not_the_bond_downed() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).file(
            "/sys/class/net/cfab-st-fb/bonding/active_slave",
            "someone-elses0\n",
        );
        let report = run(&mut sys, &view).unwrap();
        assert_eq!(
            report.restored,
            vec!["fallback storage: released foreign slave someone-elses0".to_string()]
        );
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert!(
            sys.ran("ip link set someone-elses0 nomaster"),
            "{:?}",
            sys.calls
        );
        assert!(
            !sys.ran("ip link set cfab-st-fb down"),
            "the bond must survive the eviction: {:?}",
            sys.calls
        );
    }

    /// Row 19, actuate. The release fails, so the narrowest thing that removes the hazard is
    /// the bond itself — and only the bond.
    #[test]
    fn row19_an_unreleasable_foreign_slave_downs_only_that_bond() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view)
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "someone-elses0\n",
            )
            .on_fail(
                &["ip", "link", "set", "someone-elses0", "nomaster"],
                2,
                "RTNETLINK: EPERM",
            );
        let report = run(&mut sys, &view).unwrap();
        assert_eq!(
            report.downed,
            vec![
                "fallback storage down: foreign slave someone-elses0 could not be released"
                    .to_string()
            ]
        );
        assert!(sys.ran("ip link set cfab-st-fb down"), "{:?}", sys.calls);
        for other in ["cfab-cl-fb", "cfab-mg-fb", "cfab-st"] {
            assert!(
                !sys.ran(&format!("ip link set {other} down")),
                "{other} was downed for another bond's hazard: {:?}",
                sys.calls
            );
        }
    }

    /// Row 19, false-positive guard: an `active_slave` that IS ours must write nothing at all,
    /// and an unreadable `bonding/` file is row 17 (a reason line in `status`), never this.
    #[test]
    fn row19_leaves_our_own_active_slave_and_an_unreadable_file_alone() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view).unwrap();
        assert!(report.restored.is_empty(), "{:?}", report.restored);
        assert!(!sys.ran("nomaster"), "{:?}", sys.calls);

        let mut sys = healthy_sys(&view);
        for r in view.fallback_rows() {
            sys.files
                .remove(&format!("/sys/class/net/{}/bonding/active_slave", r.ifname));
        }
        let report = run(&mut sys, &view).unwrap();
        assert!(report.restored.is_empty(), "{:?}", report.restored);
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert!(!sys.ran("nomaster"), "{:?}", sys.calls);
    }

    /// A leaf loads no forward policy and never transits, so asking it for `policy drop` would
    /// fail it closed on a posture it is not supposed to have. It must still get its restores.
    #[test]
    fn a_leaf_is_not_failed_closed_for_having_no_forward_policy() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf_sys(&view);
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert!(
            !sys.ran("nft list chain inet cfab-fwd"),
            "a leaf's posture is not a transit posture: {:?}",
            sys.calls
        );
    }

    #[test]
    fn a_healthy_host_reports_nothing_blocked() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view).unwrap();
        assert!(report.blocked.is_empty(), "{:?}", report.blocked);
    }
}
