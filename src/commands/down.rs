//! `cfab down` — remove the fabric from THIS member (a reboot does the same, harder).
//! Order matters: forwarding OFF first (fail closed even mid-teardown), then policy, then
//! netdevs. Prove-ownership: only deletes cfab-* netdevs of the expected kind.

use crate::commands::common::{
    FRR_CONF, FRR_CONF_BACKUP, FRR_DAEMONS, FRR_DAEMONS_SNAPSHOT, conf_interfaces, drop_rules,
    frr_ctl_stop_ignore, link_exists, link_kind_is,
};
use crate::derive::View;
use crate::error::{Error, Result};
use crate::model::MemberKind;
use crate::sys::{Sys, have_tool, run_ignore, run_ok};

pub fn run(sys: &mut dyn Sys, view: &View) -> Result<String> {
    let f = view.fabric;
    let kind = view.kind();
    let mut notes = Vec::new();

    // conf-sync goes first, so a cluster publish landing mid-teardown cannot re-apply.
    // Guarded: a leaf's container has no systemd (and the daemon only starts where pmxcfs is).
    if have_tool(sys, "systemctl")? {
        run_ignore(sys, &["systemctl", "stop", "cfab-conf-sync.service"])?;
    }

    if kind == MemberKind::Host {
        run_ignore(
            sys,
            &[
                "systemctl",
                "stop",
                "cfab-fwd-watchdog.timer",
                "cfab-fwd-watchdog.service",
                "cfab-shape.service",
            ],
        )?;
        for ifn in conf_interfaces(sys)? {
            sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
        }
        if have_tool(sys, "nft")? {
            run_ignore(sys, &["nft", "delete", "table", "inet", "cfab-fwd"])?;
            run_ignore(sys, &["nft", "delete", "table", "inet", "cfab"])?;
        }
    } else {
        // a leaf owns nothing global: its own rules (prove ownership by pref + our block)
        for z in &f.zones {
            let blk = format!("{}.0.0/16", z.block());
            drop_rules(
                sys,
                "1000",
                &format!("to {blk} iif lo lookup main"),
                &["to", &blk, "iif", "lo", "lookup", "main"],
            )?;
            drop_rules(
                sys,
                "1001",
                &format!("to {blk} unreachable"),
                &["to", &blk, "unreachable"],
            )?;
        }
    }
    frr_ctl_stop_ignore(sys)?;
    // return-path rules (both kinds); the zone tables hold only FRR's static, which FRR
    // withdraws on stop — anything left there is not ours and is left alone (said so).
    for z in &f.zones {
        let blk = format!("{}.0.0/16", z.block());
        let id = z.id.to_string();
        drop_rules(
            sys,
            "2000",
            &format!("from {blk} to {blk} lookup main suppress_prefixlength 0"),
            &[
                "from",
                &blk,
                "to",
                &blk,
                "lookup",
                "main",
                "suppress_prefixlength",
                "0",
            ],
        )?;
        drop_rules(
            sys,
            "2001",
            &format!("from {blk} lookup {id}"),
            &["from", &blk, "lookup", &id],
        )?;
        drop_rules(
            sys,
            "2002",
            &format!("from {blk} unreachable"),
            &["from", &blk, "unreachable"],
        )?;
    }
    sys.remove(&f.run_dir)?;
    if sys.exists(FRR_CONF_BACKUP) {
        sys.rename(FRR_CONF_BACKUP, FRR_CONF)?;
    }
    restore_daemons(sys)?;

    // Netdevs, prove-ownership-before-destroy: expected kind or refuse.
    if link_exists(sys, &f.vrrp_if)? {
        if !link_kind_is(sys, &f.vrrp_if, " macvlan ")? {
            return Err(Error::fatal(format!(
                "REFUSING: {} exists but is not a macvlan",
                f.vrrp_if
            )));
        }
        run_ok(sys, &["ip", "link", "del", &f.vrrp_if])?;
    }
    let mut ifnames: Vec<String> = view.class_rows().into_iter().map(|r| r.ifname).collect();
    ifnames.extend(view.gw_rows().into_iter().map(|r| r.ifname));
    for dev in &ifnames {
        if link_exists(sys, dev)? {
            if !link_kind_is(sys, dev, " macvlan ")? && !link_kind_is(sys, dev, " vlan ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {dev} exists but is neither macvlan nor vlan"
                )));
            }
            run_ok(sys, &["ip", "link", "del", dev])?;
        }
    }
    for z in &f.zones {
        let dev = View::identity_if(z);
        if link_exists(sys, &dev)? {
            if !link_kind_is(sys, &dev, " veth ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {dev} exists but is not a veth"
                )));
            }
            run_ok(sys, &["ip", "link", "del", &dev])?; // deletes the pair
        }
        if link_exists(sys, &format!("{dev}-peer"))? {
            return Err(Error::fatal(format!(
                "REFUSING: {dev}-peer exists without {dev} (not ours)"
            )));
        }
        run_ignore(
            sys,
            &[
                "ip",
                "route",
                "del",
                "unreachable",
                &format!("{}.0.0/16", z.block()),
            ],
        )?;
        let left = sys.run(&["ip", "route", "show", "table", &z.id.to_string()])?;
        if !left.stdout.trim().is_empty() {
            notes.push(format!(
                "note: table {} still holds routes not ours (left alone): {}",
                z.id,
                left.stdout.trim()
            ));
        }
    }
    if kind == MemberKind::Host {
        for dev in view.wires() {
            run_ignore(sys, &["tc", "qdisc", "del", "dev", &dev, "root"])?;
        }
    }
    let mut msg = notes.join("\n");
    if !msg.is_empty() {
        msg.push('\n');
    }
    msg.push_str(&format!("teardown OK on {}\n", view.member.name));
    Ok(msg)
}

/// The daemons keys `up` manages. One spelling, shared by edit and restore.
const MANAGED_DAEMON_KEYS: [&str; 5] = ["ospfd", "bfdd", "vrrpd", "bgpd", "ospfd_instances"];

/// Put the managed daemons keys back to their pre-cfab values (recorded by `up` at its first
/// edit), then drop the record. Key-wise, not whole-file: unrelated daemons edits made while
/// the fabric was up are not ours to destroy. Without a snapshot (an install first upped by an
/// older cfab) fall back to the historical guess — vrrpd/bgpd off, ospfd/bfdd left enabled.
fn restore_daemons(sys: &mut dyn Sys) -> Result<()> {
    if !sys.exists(FRR_DAEMONS) {
        return Ok(());
    }
    let cur = sys.read(FRR_DAEMONS)?;
    if !sys.exists(FRR_DAEMONS_SNAPSHOT) {
        let restored: String = cur
            .lines()
            .map(|l| match l {
                "vrrpd=yes" => "vrrpd=no".to_string(),
                "bgpd=yes" => "bgpd=no".to_string(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        return sys.write(FRR_DAEMONS, &restored);
    }
    let snap = sys.read(FRR_DAEMONS_SNAPSHOT)?;
    fn managed(line: &str) -> Option<&str> {
        let (key, _) = line.split_once('=')?;
        MANAGED_DAEMON_KEYS.contains(&key).then_some(key)
    }
    let orig: std::collections::BTreeMap<&str, &str> = snap
        .lines()
        .filter_map(|l| managed(l).map(|k| (k, l)))
        .collect();
    let mut out: Vec<&str> = Vec::new();
    for line in cur.lines() {
        match managed(line) {
            None => out.push(line),
            // A managed line the snapshot never had (e.g. the appended ospfd_instances) is
            // dropped; otherwise the original line replaces ours.
            Some(key) => {
                if let Some(o) = orig.get(key) {
                    out.push(o);
                }
            }
        }
    }
    sys.write(FRR_DAEMONS, &(out.join("\n") + "\n"))?;
    sys.remove(FRR_DAEMONS_SNAPSHOT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    #[test]
    fn restore_daemons_puts_managed_keys_back_from_snapshot() {
        let mut sys = MockSys::default()
            .file(
                FRR_DAEMONS,
                "zebra=yes\nospfd=yes\nbfdd=yes\nvrrpd=yes\nbgpd=no\nstaticd=no\n\
                 ospfd_instances=\"100,200,250\"\n",
            )
            .file(
                FRR_DAEMONS_SNAPSHOT,
                "zebra=yes\nospfd=no\nbfdd=no\nvrrpd=no\nbgpd=yes\nstaticd=no\n",
            );
        restore_daemons(&mut sys).unwrap();
        let got = sys.files.get(FRR_DAEMONS).unwrap();
        assert_eq!(
            got, "zebra=yes\nospfd=no\nbfdd=no\nvrrpd=no\nbgpd=yes\nstaticd=no\n",
            "managed keys back to pre-cfab values (bgpd back ON), appended instances line \
             dropped, unmanaged lines untouched"
        );
        assert!(
            !sys.files.contains_key(FRR_DAEMONS_SNAPSHOT),
            "snapshot consumed"
        );
    }

    #[test]
    fn restore_daemons_keeps_operator_edits_to_unmanaged_keys() {
        let mut sys = MockSys::default()
            .file(FRR_DAEMONS, "ospfd=yes\nripd=yes\n")
            .file(FRR_DAEMONS_SNAPSHOT, "ospfd=no\nripd=no\n");
        restore_daemons(&mut sys).unwrap();
        assert_eq!(
            sys.files.get(FRR_DAEMONS).unwrap(),
            "ospfd=no\nripd=yes\n",
            "ripd is not cfab's — the operator's mid-lifecycle edit survives"
        );
    }

    #[test]
    fn restore_daemons_without_snapshot_uses_historical_fallback() {
        let mut sys =
            MockSys::default().file(FRR_DAEMONS, "ospfd=yes\nbfdd=yes\nvrrpd=yes\nbgpd=yes\n");
        restore_daemons(&mut sys).unwrap();
        assert_eq!(
            sys.files.get(FRR_DAEMONS).unwrap(),
            "ospfd=yes\nbfdd=yes\nvrrpd=no\nbgpd=no\n"
        );
    }

    #[test]
    fn restore_daemons_no_file_is_a_noop() {
        let mut sys = MockSys::default();
        restore_daemons(&mut sys).unwrap();
        assert!(sys.files.is_empty());
    }
}
