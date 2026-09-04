//! `cfab fwd-watchdog` — the fail-closed forwarding check. Run every few seconds by the
//! transient systemd timer `cfab up` starts. If the forward policy is not loaded with a drop
//! default, switch forwarding OFF on every cfab interface and say so (recovery = re-run
//! `cfab up`). Forwarding flags on cfab's own interfaces that drifted from the declared value
//! are written back and logged: the flag is the belt, the (verified-present) policy is the
//! braces, and a foreign stack writing `ip_forward=1` propagates 1 onto every interface
//! including ours — that is drift to correct, not a breach. Interfaces cfab does not own are
//! never read or written (scoped posture; `View::owned_forwarding`). Per-interface forwarding
//! is what the kernel checks — so conf/<if>/forwarding is written, never ip_forward.

use crate::commands::common::conf_interfaces;
use crate::derive::View;
use crate::error::Result;
use crate::sys::{Sys, run_ignore};

pub struct WatchdogReport {
    /// None = healthy; Some(reason) = failed closed.
    pub failed: Option<String>,
    /// cfab interfaces whose forwarding flag was written back to the declared value.
    pub corrected: Vec<String>,
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
    Ok(WatchdogReport {
        failed: None,
        corrected,
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

    fn healthy_sys(view: &View) -> MockSys {
        let mut sys = MockSys::default().on_stdout(
            &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
            "chain forward {\n  type filter hook forward priority filter; policy drop;\n}",
        );
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
}
