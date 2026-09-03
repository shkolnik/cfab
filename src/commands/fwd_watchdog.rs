//! `cfab fwd-watchdog` — the fail-closed forwarding check. Run every few seconds by the
//! transient systemd timer `cfab up` starts. If the forward policy is not loaded with a drop
//! default, or any interface outside the class table's zones has forwarding on, switch
//! forwarding OFF on EVERY interface and say so. Recovery = re-run `cfab up`.
//! Per-interface forwarding is what the kernel checks — so every conf/<if>/forwarding is
//! written, not ip_forward.

use crate::commands::common::conf_interfaces;
use crate::derive::View;
use crate::error::Result;
use crate::sys::{Sys, run_ignore};

pub struct WatchdogReport {
    /// None = healthy; Some(reason) = failed closed.
    pub failed: Option<String>,
}

pub fn run(sys: &mut dyn Sys, view: &View) -> Result<WatchdogReport> {
    let f = view.fabric;
    let chain = sys.run(&["nft", "list", "chain", "inet", "cfab-fwd", "forward"])?;
    if !chain.ok() || !chain.stdout.contains("policy drop;") {
        return fail_closed(
            sys,
            "table inet cfab-fwd / chain forward with policy drop is not loaded",
        );
    }
    let mut allowed: Vec<String> = Vec::new();
    for z in &f.zones {
        allowed.extend(view.zone_ifs(&z.name));
    }
    if f.vrrp_gw {
        allowed.push(f.vrrp_if.clone());
    }
    for ifn in conf_interfaces(sys)? {
        if matches!(ifn.as_str(), "all" | "default" | "lo") {
            continue;
        }
        let v = sys
            .read(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if v == "1" && !allowed.contains(&ifn) {
            return fail_closed(
                sys,
                &format!("forwarding=1 on '{ifn}', which is not a class-table interface"),
            );
        }
    }
    Ok(WatchdogReport { failed: None })
}

fn fail_closed(sys: &mut dyn Sys, reason: &str) -> Result<WatchdogReport> {
    for ifn in conf_interfaces(sys)? {
        sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
    }
    run_ignore(
        sys,
        &[
            "logger",
            "-t",
            "cfab-fwd-watchdog",
            &format!("FAIL-CLOSED: {reason} — forwarding=0 on all interfaces; re-run cfab up"),
        ],
    )?;
    Ok(WatchdogReport {
        failed: Some(reason.to_string()),
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
        assert!(!sys.ran("logger"));
    }

    #[test]
    fn missing_policy_fails_closed_everywhere() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).on_fail(
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
        // every interface written to 0, including the class-table ones
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            Some("0")
        );
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/all/forwarding"),
            Some("0")
        );
        assert!(sys.ran("logger"));
    }

    #[test]
    fn rogue_interface_fails_closed() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).file("/proc/sys/net/ipv4/conf/docker0/forwarding", "1\n");
        let report = run(&mut sys, &view).unwrap();
        assert!(
            report.failed.as_deref().unwrap_or("").contains("'docker0'"),
            "{:?}",
            report.failed
        );
    }
}
