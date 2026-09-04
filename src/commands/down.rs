//! `cfab down` — remove the fabric from THIS member (a reboot does the same, harder).
//! Order matters: forwarding OFF first (fail closed even mid-teardown), then policy, then
//! netdevs. Prove-ownership: only deletes cfab-* netdevs of the expected kind.

use crate::commands::common::{conf_interfaces, drop_rules, link_exists, link_kind_is};
use crate::commands::engine_ctl;
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
            if view.owns_if(&ifn) {
                sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
            }
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
    // The engine stops (and its routes are swept) before any interface goes away, so it never
    // acts on vanished links. The zone tables hold only the engine's static, gone with it —
    // anything left there is not ours and is left alone (said so).
    engine_ctl::stop_and_sweep(sys, f)?;
    // return-path rules (both kinds)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// Routes the engine left behind (a crash) are swept by `down`, one delete per route,
    /// before the first interface is deleted.
    #[test]
    fn down_sweeps_private_proto_routes() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        // No netdevs left but one identity veth, so exactly one `ip link del` follows the sweep.
        let mut sys = MockSys::default()
            .on_stdout(
                &["ip", "-4", "route", "show", "table", "all", "proto", "201"],
                "10.99.0.1 via 10.99.1.1 dev cfab-st proto 201 metric 20\n\
                 10.199.0.1 via 10.199.1.1 dev cfab-cl proto 201 metric 20\n",
            )
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .on_stdout(
                &["ip", "link", "show", "cfab-id99"],
                "5: cfab-id99@cfab-id99-peer\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-id99"],
                "5: cfab-id99: veth \n",
            );
        run(&mut sys, &view).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.contains("proto 201"))
            .filter(|c| c.starts_with("ip route del"))
            .collect();
        assert_eq!(
            dels,
            [
                "ip route del 10.99.0.1 metric 20 proto 201",
                "ip route del 10.199.0.1 metric 20 proto 201"
            ]
        );
        let last_del = sys
            .calls
            .iter()
            .rposition(|c| c.starts_with("ip route del") && c.contains("proto 201"))
            .unwrap();
        let first_link_del = sys
            .calls
            .iter()
            .position(|c| c.starts_with("ip link del"))
            .unwrap();
        assert!(
            last_del < first_link_del,
            "sweep precedes interface deletion"
        );
    }
}
