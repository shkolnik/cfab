//! `cfab down` — remove the fabric from THIS member (a reboot does the same, harder).
//! Order matters: forwarding OFF first (fail closed even mid-teardown), then policy, then
//! netdevs. Prove-ownership: only deletes cfab-* netdevs of the expected kind.

use crate::commands::common::{
    conf_interfaces, drop_rules, frr_ctl_stop_ignore, link_exists, link_kind_is,
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
    if sys.exists("/etc/frr/frr.conf.pre-cfab") {
        sys.rename("/etc/frr/frr.conf.pre-cfab", "/etc/frr/frr.conf")?;
    }
    if sys.exists("/etc/frr/daemons") {
        let daemons = sys.read("/etc/frr/daemons")?;
        let restored: String = daemons
            .lines()
            .map(|l| match l {
                "vrrpd=yes" => "vrrpd=no".to_string(),
                "bgpd=yes" => "bgpd=no".to_string(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        sys.write("/etc/frr/daemons", &restored)?;
    }

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
