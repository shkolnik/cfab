//! `cfab down` — remove the fabric from THIS member (a reboot does the same, harder).
//! Order matters: forwarding OFF first (fail closed even mid-teardown), then policy, then
//! netdevs. Prove-ownership: only deletes cfab-* netdevs of the expected kind.

use crate::commands::common::{
    conf_interfaces, drop_rules, link_exists, link_kind_is, remove_foreign_transit_accept,
};
use crate::commands::engine_ctl;
use crate::derive::{Slave, View};
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
        }
        // custody: the accept `up` put in a foreign user hook is ours to remove, and only the
        // rule carrying our tag is touched
        remove_foreign_transit_accept(sys)?;
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
    // The mark table (marking + the fallback control-egress ceiling) is installed on every
    // kind, so it comes off on every kind. Guarded like the policy table above: `have_tool`
    // keeps teardown working on a member where `nft` has since been removed.
    if have_tool(sys, "nft")? {
        run_ignore(sys, &["nft", "delete", "table", "inet", "cfab"])?;
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
    // Fallback legs, bonds before slaves: `ip link del <bond>` RELEASES its slaves, it does not
    // delete them, which is why the second loop exists. The engine is already stopped and its
    // routes swept above, so this order is ownership-proof clarity, nothing more.
    let fallback_rows = view.fallback_rows();
    let gw_rows = view.gw_rows();
    // An ingress leg on gw island `any` is the same bond and is torn down the same way.
    let bond_legs: Vec<(&str, &[Slave])> = fallback_rows
        .iter()
        .map(|r| (r.ifname.as_str(), r.slaves.as_slice()))
        .chain(
            gw_rows
                .iter()
                .filter(|r| r.migrates())
                .map(|r| (r.ifname.as_str(), r.slaves.as_slice())),
        )
        .collect();
    for (ifname, _) in &bond_legs {
        if link_exists(sys, ifname)? {
            if !link_kind_is(sys, ifname, " bond ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {ifname} exists but is not a bond"
                )));
            }
            run_ok(sys, &["ip", "link", "del", ifname])?;
        }
    }
    for s in bond_legs.iter().flat_map(|(_, slaves)| *slaves) {
        if link_exists(sys, &s.ifname)? {
            if !link_kind_is(sys, &s.ifname, " vlan ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {} exists but is not a vlan",
                    s.ifname
                )));
            }
            run_ok(sys, &["ip", "link", "del", &s.ifname])?;
        }
    }
    let mut ifnames: Vec<String> = view.class_rows().into_iter().map(|r| r.ifname).collect();
    // A migrating leg was deleted above as a bond; the rest are plain sub-interfaces.
    ifnames.extend(
        gw_rows
            .iter()
            .filter(|r| !r.migrates())
            .map(|r| r.ifname.clone()),
    );
    for dev in &ifnames {
        if link_exists(sys, dev)? {
            if !link_kind_is(sys, dev, " vlan ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {dev} exists but is not a vlan"
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

    /// Every netdev absent except the fallback leg of the storage zone, correctly typed.
    fn sys_with_a_storage_fallback_leg() -> MockSys {
        MockSys::default()
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .on_stdout(&["ip", "link", "show", "cfab-st-fb"], "9: cfab-st-fb\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb"],
                "9: cfab-st-fb: bond \n",
            )
            .on_stdout(
                &["ip", "link", "show", "cfab-st-fb-st"],
                "10: cfab-st-fb-st\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb-st"],
                "10: cfab-st-fb-st@eth9: vlan protocol 802.1Q id 300 \n",
            )
    }

    /// `ip link del <bond>` RELEASES its slaves, it does not delete them — so the slaves get
    /// their own deletes, and the bond goes first (ownership-proof clarity: the engine is
    /// already stopped and swept before any netdev is touched).
    #[test]
    fn down_deletes_a_fallback_bond_before_its_slaves() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg();
        run(&mut sys, &view).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("ip link del"))
            .collect();
        assert_eq!(
            dels,
            ["ip link del cfab-st-fb", "ip link del cfab-st-fb-st"]
        );
    }

    /// The same declaration with the ingress leg on island `any`.
    fn fabric_with_a_migrating_gw() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace("mg:249:", "any:249:");
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// Task 9: a migrating ingress leg is a bond, so it is torn down as one — bond first,
    /// then its slaves. Deleting it in the plain sub-interface loop would REFUSE it
    /// ("not a vlan") and strand the leg on a `cfab down`.
    #[test]
    fn down_deletes_a_migrating_gw_bond_before_its_slaves() {
        let f = fabric_with_a_migrating_gw();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg()
            .on_stdout(&["ip", "link", "show", "cfab-gw249"], "20: cfab-gw249\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249"],
                "20: cfab-gw249: bond \n",
            )
            .on_stdout(
                &["ip", "link", "show", "cfab-gw249-mg"],
                "21: cfab-gw249-mg\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249-mg"],
                "21: cfab-gw249-mg@eth0: vlan protocol 802.1Q id 249 \n",
            );
        run(&mut sys, &view).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("ip link del"))
            .collect();
        assert_eq!(
            dels,
            [
                "ip link del cfab-st-fb",
                "ip link del cfab-gw249",
                "ip link del cfab-st-fb-st",
                "ip link del cfab-gw249-mg",
            ]
        );
    }

    /// Prove ownership before destroy: a stranger wearing the bond's name is refused, and a
    /// slave name carrying something that is not a vlan is refused too.
    #[test]
    fn down_refuses_a_fallback_netdev_of_the_wrong_kind() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();

        let mut sys = sys_with_a_storage_fallback_leg().on_stdout(
            &["ip", "-d", "link", "show", "cfab-st-fb"],
            "9: cfab-st-fb: bridge \n",
        );
        let e = run(&mut sys, &view).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-fb exists but is not a bond"),
            "{e}"
        );
        assert!(!sys.ran("ip link del cfab-st-fb"));

        let mut sys = sys_with_a_storage_fallback_leg().on_stdout(
            &["ip", "-d", "link", "show", "cfab-st-fb-st"],
            "10: cfab-st-fb-st: macvlan \n",
        );
        let e = run(&mut sys, &view).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-fb-st exists but is not a vlan"),
            "{e}"
        );
        assert!(!sys.ran("ip link del cfab-st-fb-st"));
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

    /// `up` installs `table inet cfab` on every kind, so `down` removes it on every kind — a
    /// leaf that tore the fabric down must not be left dropping its own OSPF at a ceiling
    /// derived for a fabric that is gone. The forward policy stays host-only (a leaf never
    /// installs `cfab-fwd`).
    #[test]
    fn down_removes_the_mark_table_on_a_leaf_and_never_the_forward_policy() {
        let f = fabric();
        for (host, kind) in [("pve1-tb", "host"), ("pve3-tb", "leaf")] {
            let view = View::new(&f, host).unwrap();
            let mut sys = MockSys::default().on_fail(&["ip", "link", "show"], 1, "no");
            run(&mut sys, &view).unwrap();
            assert_eq!(
                sys.calls
                    .iter()
                    .filter(|c| c.as_str() == "nft delete table inet cfab")
                    .count(),
                1,
                "{kind}: {:?}",
                sys.calls
            );
            let fwd = sys
                .calls
                .iter()
                .filter(|c| c.as_str() == "nft delete table inet cfab-fwd")
                .count();
            assert_eq!(fwd, usize::from(kind == "host"), "{kind}: {:?}", sys.calls);
        }
    }
}
