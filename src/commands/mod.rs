//! Imperative subcommands. All host access goes through the `Sys` trait so the imperative
//! branches are testable against `MockSys`.

pub mod apply;
pub mod check;
pub mod cluster;
pub mod common;
pub mod conf_sync;
pub mod engine_ctl;
pub mod fwd_watchdog;
pub mod measure_cap;
pub mod policy_teeth;
pub mod shape_daemon;
pub mod status;
pub mod teardown;

/// Gate C acceptance (Task 7d): `apply`, `fwd_watchdog` and `teardown` together, over the same
/// `MockSys`, prove the whole workload lifecycle leaves nothing behind — the three unit-tested
/// halves (7a/7b/7c) could each look right and still drift out of step with each other.
#[cfg(test)]
mod workload_lifecycle {
    use crate::commands::{apply, fwd_watchdog, teardown};
    use crate::prober::HeldPrimaries;

    #[test]
    fn apply_then_watchdog_restore_then_down_removes_every_workload_object_exactly_once() {
        let (mut sys, view) = apply::tests::wl_sys_and_view("pve1-tb");
        apply::run(&mut sys, &view, &apply::tests::opts()).unwrap();

        // an operator deletes the sibling rule and the guard table
        let mut sys = sys
            .on_stdout(
                &["ip", "rule", "show", "pref", "2000"],
                "2000:\tfrom 10.99.0.0/16 to 10.99.0.0/16 lookup main suppress_prefixlength 0\n",
            )
            .on_fail(
                &["nft", "list", "table", "bridge", "cfab"],
                1,
                "Error: No such file or directory",
            );
        fwd_watchdog::run(&mut sys, &view, &HeldPrimaries::default()).unwrap();

        // healthy again: both rules, the table and the gw address are present for down to find
        let mut sys = sys
            .on_stdout(
                &["ip", "rule", "show", "pref", "2000"],
                "2000:\tfrom 10.99.0.0/16 to 10.99.0.0/16 lookup main suppress_prefixlength 0\n\
                 2000:\tfrom 10.99.0.0/16 to 192.168.20.0/24 lookup main\n",
            )
            .on_stdout(
                &["nft", "list", "table", "bridge", "cfab"],
                "table bridge cfab {\n}\n",
            )
            .on_stdout(
                &["ip", "-4", "-br", "addr", "show", "dev", "primary.3"],
                "primary.3 UP 192.168.20.2/24 192.168.20.254/24\n",
            );
        teardown::run(&mut sys, &view).unwrap();

        let calls = &sys.calls;
        let count = |s: &str| calls.iter().filter(|c| c.contains(s)).count();
        assert_eq!(
            count("ip rule add pref 2000 from 10.99.0.0/16 to 192.168.20.0/24 lookup main"),
            2,
            "apply + restore"
        );
        assert_eq!(
            count("nft -f /run/cfab/workload-bridge.nft"),
            2,
            "apply + restore"
        );
        assert_eq!(count("ip addr replace 192.168.20.254/24 dev primary.3"), 1);
        assert_eq!(count("nft delete table bridge cfab"), 1);
        assert_eq!(count("ip addr del 192.168.20.254/24 dev primary.3"), 1);
        assert_eq!(
            count("ip rule del pref 2000 from 10.99.0.0/16 to 192.168.20.0/24 lookup main"),
            1
        );
        assert_eq!(count("ip link del primary.3"), 0);
        assert_eq!(count("ip link set primary.3 down"), 0);
        let down_at = calls
            .iter()
            .position(|c| c.contains("nft delete table bridge cfab"))
            .unwrap();
        assert!(
            !calls[down_at..].iter().any(|c| c.contains("workload-bridge.nft")
                || c.contains("rule add pref 2000 from 10.99.0.0/16 to 192.168.20.0/24")),
            "nothing re-adds after down: {:#?}",
            &calls[down_at..]
        );
        assert_eq!(
            sys.writes_of("/proc/sys/net/ipv4/conf/primary.3/forwarding").last(),
            Some(&"0"),
            "down leaves forwarding off"
        );
        assert_eq!(
            sys.writes_of("/proc/sys/net/ipv4/conf/all/arp_ignore"),
            vec!["1"],
            "set once by apply; the watchdog tick found it at 1 (wl_sys file) and wrote nothing; down leaves it"
        );
    }
}
