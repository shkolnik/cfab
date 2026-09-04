//! Helpers shared by the imperative commands (up/down/verify/daemons).

use crate::error::Result;
use crate::sys::{Sys, run_ok};

pub fn link_exists(sys: &mut dyn Sys, dev: &str) -> Result<bool> {
    Ok(sys.run(&["ip", "link", "show", dev])?.ok())
}

/// `ip -d link show <dev>` contains the marker (e.g. " veth ", "vlan protocol 802.1Q id 100 ").
pub fn link_kind_is(sys: &mut dyn Sys, dev: &str, marker: &str) -> Result<bool> {
    let out = sys.run(&["ip", "-d", "link", "show", dev])?;
    Ok(out.ok() && out.stdout.contains(marker))
}

/// Idempotent `ip rule` presence: `ip rule show pref <pref>` must contain `needle`, else add.
pub fn ensure_rule(sys: &mut dyn Sys, pref: &str, needle: &str, add: &[&str]) -> Result<()> {
    let shown = sys.run(&["ip", "rule", "show", "pref", pref])?;
    if !shown.stdout.contains(needle) {
        let mut argv = vec!["ip", "rule", "add", "pref", pref];
        argv.extend_from_slice(add);
        run_ok(sys, &argv)?;
    }
    Ok(())
}

/// Delete every matching rule (teardown: loop while present, prove-ownership by pref+selector).
pub fn drop_rules(sys: &mut dyn Sys, pref: &str, needle: &str, del: &[&str]) -> Result<()> {
    loop {
        let shown = sys.run(&["ip", "rule", "show", "pref", pref])?;
        if !shown.stdout.contains(needle) {
            return Ok(());
        }
        let mut argv = vec!["ip", "rule", "del", "pref", pref];
        argv.extend_from_slice(del);
        run_ok(sys, &argv)?;
    }
}

/// Write a per-interface sysctl through /proc (sysctl(8) mangles interface names).
pub fn proc_sysctl(sys: &mut dyn Sys, ifname: &str, key: &str, value: &str) -> Result<()> {
    sys.write(&format!("/proc/sys/net/ipv4/conf/{ifname}/{key}"), value)
}

/// Interface names under /proc/sys/net/ipv4/conf (the kernel's per-interface view).
pub fn conf_interfaces(sys: &mut dyn Sys) -> Result<Vec<String>> {
    sys.list_dir("/proc/sys/net/ipv4/conf")
}
