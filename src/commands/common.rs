//! Helpers shared by the imperative commands (up/down/verify/daemons).

use crate::error::Result;
use crate::sys::{Sys, run_ignore, run_ok};

pub const FRR_CONF: &str = "/etc/frr/frr.conf";
/// The original frr.conf, restored by `down`. Created by the operator's `mv` (the guard in
/// `up` names it), or by legacy `up` runs that backed the file up themselves.
pub const FRR_CONF_BACKUP: &str = "/etc/frr/frr.conf.pre-cfab";
pub const FRR_DAEMONS: &str = "/etc/frr/daemons";
/// The daemons file as found before cfab's first edit; `down` restores the managed keys
/// from it and removes it.
pub const FRR_DAEMONS_SNAPSHOT: &str = "/etc/frr/daemons.pre-cfab";

/// FRR is driven by systemd where there is one; a container has no systemd → the package's own
/// init. Probed, not declared (fabric.conf's frr_ctl).
pub fn frr_ctl(sys: &mut dyn Sys, action: &str) -> Result<()> {
    if sys.exists("/run/systemd/system") {
        run_ok(sys, &["systemctl", action, "frr"])?;
    } else {
        run_ok(sys, &["/usr/lib/frr/frrinit.sh", action])?;
    }
    Ok(())
}

pub fn frr_ctl_stop_ignore(sys: &mut dyn Sys) -> Result<()> {
    if sys.exists("/run/systemd/system") {
        run_ignore(sys, &["systemctl", "stop", "frr"])
    } else {
        run_ignore(sys, &["/usr/lib/frr/frrinit.sh", "stop"])
    }
}

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

/// The lines of an `interface <ifname>` block in an FRR running config (up to `exit`).
pub fn frr_interface_block<'a>(running: &'a str, ifname: &str) -> Vec<&'a str> {
    let mut in_block = false;
    let mut lines = Vec::new();
    for line in running.lines() {
        if line == format!("interface {ifname}") {
            in_block = true;
            continue;
        }
        if in_block {
            if line == "exit" || line.starts_with("interface ") {
                break;
            }
            lines.push(line);
        }
    }
    lines
}
