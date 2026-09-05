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
//! while cfab's own counters recorded accepts and `verify` printed `posture ok`.

use crate::commands::common::{
    conf_interfaces, ensure_foreign_transit_accept, foreign_forward_remedy,
    unresolved_forward_drops,
};
use crate::derive::View;
use crate::error::Result;
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
}

pub fn run(sys: &mut dyn Sys, view: &View) -> Result<WatchdogReport> {
    let chain = sys.run(&["nft", "list", "chain", "inet", "cfab-fwd", "forward"])?;
    if !chain.ok() || !chain.stdout.contains("policy drop;") {
        return fail_closed(
            sys,
            view,
            "table inet cfab-fwd / chain forward with policy drop is not loaded",
        );
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
    })
}

fn fail_closed(sys: &mut dyn Sys, view: &View, reason: &str) -> Result<WatchdogReport> {
    let present = conf_interfaces(sys)?;
    for (ifn, _) in view.owned_forwarding() {
        if present.contains(&ifn) {
            sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
        }
    }
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
        sys.file("/proc/sys/net/ipv4/conf/eth0/forwarding", "0\n")
            .file("/proc/sys/net/ipv4/conf/lo/forwarding", "0\n")
            .file("/proc/sys/net/ipv4/conf/all/forwarding", "1\n")
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
    /// the rescue bond `transit`-eligible like a class segment (a rescue leg for one zone can
    /// carry another zone's island-disjoint traffic on a forwarding host) — this test exercises
    /// that through the watchdog's own correction path rather than reading `owned_forwarding`
    /// directly, so a regression here fails where it would actually bite in production.
    #[test]
    fn a_rescue_bond_drifted_to_0_is_corrected_to_1_like_a_segment() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert!(
            !view.rescue_rows().is_empty(),
            "fixture must carry rescue rows"
        );
        let mut sys = healthy_sys(&view);
        for r in view.rescue_rows() {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                "0\n",
            );
        }
        let report = run(&mut sys, &view).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        for r in view.rescue_rows() {
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

    /// A rescue slave is L2 only (`owned_forwarding` always pairs it with `false`): even if
    /// something turned its forwarding sysctl on, the watchdog writes it back to 0, same as
    /// the admin NIC — it is never flagged transit-eligible the way the bond is.
    #[test]
    fn a_rescue_slave_drifted_to_1_is_corrected_to_0_never_flagged_transit() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let slave_ifs: Vec<String> = view
            .rescue_rows()
            .into_iter()
            .flat_map(|r| r.slaves)
            .map(|s| s.ifname)
            .collect();
        assert!(!slave_ifs.is_empty(), "fixture must carry rescue slaves");
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

    #[test]
    fn a_healthy_host_reports_nothing_blocked() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view).unwrap();
        assert!(report.blocked.is_empty(), "{:?}", report.blocked);
    }
}
