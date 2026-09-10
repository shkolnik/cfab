//! `cfab check`: validate the declaration and report the fabric as declared, what THIS member
//! gets, and (with `[[workload]]` rows) each row.

use std::collections::BTreeSet;

use crate::derive::View;
use crate::error::{Error, Result};
use crate::model::{Fabric, MemberKind};
use crate::sys::Sys;
use crate::workload::uplink;

/// Host facts a `[[workload]]` row needs that the declaration cannot state, read where the
/// member actually runs: `check` calls it before it prints, and `apply`'s pass 1 calls it
/// again, so the refusal has one spelling and an operator meets it before `up` touches a
/// netdev.
///
/// The one condition today is the uplink bridge's `vlan_filtering`: cfab's leg only receives
/// its tag while the bridge carries that vid on itself (`bridge vlan ... self`), which a bridge
/// that is not vlan-aware has no notion of — the leg would come up and silently see nothing.
/// A bridge that is not there at all is NOT a refusal: that row defers (spec 5.1), on this host
/// and at `up` alike. A present bridge whose `vlan_filtering` cannot be read is refused with the
/// rest: cfab cannot prove the leg would work, and this is the gate that exists to say so.
pub fn host_preflight(sys: &dyn Sys, view: &View) -> Result<()> {
    for row in view.workload_rows() {
        let bridge = &row.wl.uplink;
        if !uplink::bridge_present(sys, bridge) {
            continue;
        }
        let path = format!("/sys/class/net/{bridge}/bridge/vlan_filtering");
        let vlan_aware = sys.read(&path).is_ok_and(|v| v.trim() == "1");
        if !vlan_aware {
            return Err(Error::fatal(format!(
                "workload {}: bridge {bridge} is not vlan-aware (bridge-vlan-aware yes in \
                 /etc/network/interfaces)",
                row.wl.name
            )));
        }
    }
    Ok(())
}

/// Can this row's relay plausibly route to `server`? Two ways, and no third: the address sits
/// inside a zone this row is allowed into (its own `10.<id>.0.0/16` block or that zone's
/// ingress /24), or some zone declares a `gw`, which gives the member a default route that
/// reaches anything off-fabric. Neither means the relay's traffic is FORWARDED — the relay
/// speaks from the host itself, so `allow` does not gate it — only that a route can exist. A
/// declaration failing both is a warning, never a refusal: cfab cannot see the host's own
/// routing table from here, and an operator may have one.
fn reaches(fabric: &Fabric, wl: &crate::model::Workload, server: std::net::Ipv4Addr) -> bool {
    if fabric.zones.iter().any(|z| z.gw.is_some()) {
        return true;
    }
    let o = server.octets();
    fabric
        .zones
        .iter()
        .filter(|z| wl.allow.iter().any(|a| a == &z.name))
        .any(|z| {
            z.block() == format!("{}.{}", o[0], o[1])
                || z.gw
                    .as_ref()
                    .is_some_and(|g| g.subnet_prefix() == format!("{}.{}.{}", o[0], o[1], o[2]))
        })
}

/// The lines `cfab check` prints. The per-member line is the last thing an operator sees before
/// `up` creates the netdevs, so it names every leg `up` will build — the fallback legs included:
/// their ports fan out per wire, so their count is member-dependent and not derivable from the
/// fabric-wide line. With `[[workload]]` rows declared, one line per row follows (name, uplink,
/// vid, the leg cfab creates, prefix, gw, the relay's server if the row declares one, allow, and
/// the members that carry it). The VLAN is host-local, so there is no aggregate and no DHCP
/// option-121 snippet to paste: a VM's default route is `gw`, which is option 3.
pub fn report(fabric: &Fabric, view: &View) -> String {
    let kind = match view.kind() {
        MemberKind::Host => "host",
        MemberKind::Leaf => "leaf",
    };
    let fallback_legs = fabric
        .segments
        .iter()
        .filter(|r| r.scope.is_universal())
        .count();
    let mut out = format!(
        "fabric.toml OK: {} zones, {} segments, {} fallback legs, {} members\n\
         this member: {} (node {}, {kind}); {} segment sub-ifs on wires [{}], {} fallback leg(s), \
         {} ingress leg(s)\n",
        fabric.zones.len(),
        fabric.segments.len() - fallback_legs,
        fallback_legs,
        fabric.members.len(),
        view.member.name,
        view.node(),
        view.class_rows().len(),
        view.wires().join(" "),
        view.fallback_rows().len(),
        view.gw_rows().len(),
    );
    if !fabric.workloads.is_empty() {
        for wl in &fabric.workloads {
            let carried_by = fabric
                .members
                .iter()
                .filter(|m| m.workloads.iter().any(|w| w.name == wl.name))
                .map(|m| m.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let relay = match wl.dhcp_server {
                Some(s) => format!("dhcp_server {s}"),
                None => "no dhcp_server (no relay)".to_string(),
            };
            out.push_str(&format!(
                "workload {}: {} vid {} ({}) {} gw {} host-local, {relay}, allow {}; carried by \
                 {}\n",
                wl.name,
                wl.uplink,
                wl.vid,
                wl.leg_ifname(),
                wl.prefix,
                wl.gw,
                wl.allow.join(", "),
                carried_by
            ));
            if let Some(server) = wl.dhcp_server {
                if !reaches(fabric, wl, server) {
                    out.push_str(&format!(
                        "warning: workload {}: dhcp_server {server} is in no zone this row is \
                         allowed into ({}) and no zone declares a gw, so the relay has no route \
                         to it\n",
                        wl.name,
                        wl.allow.join(", ")
                    ));
                }
            }
        }
        // Conflict 11 (holo `b01dab56`): the `redistribution` entry cfab writes on a zone's
        // OSPF instance subscribes to ALL static routes in the RIB, not to the ones belonging
        // to the row that zone allows. With one row that is moot; with two whose `allow` sets
        // differ, each zone advertises both rows' /32s. Said once, naming the rows, because an
        // operator would otherwise read `allow` as a route filter — it is a forward-policy
        // filter, which is what actually decides reach.
        // As SETS, not as declared: `allow` names zones, so ["storage", "mgmt"] and
        // ["mgmt", "storage"] are one policy and must not read as a conflict.
        let allow_sets: BTreeSet<BTreeSet<&str>> = fabric
            .workloads
            .iter()
            .map(|w| w.allow.iter().map(String::as_str).collect())
            .collect();
        if allow_sets.len() > 1 {
            out.push_str(&format!(
                "warning: workload rows {} declare different allow sets; every allowed zone's \
                 OSPF instance advertises the per-VM routes of ALL rows (holo redistributes \
                 static routes per instance, not per route) — reach is decided by the forward \
                 policy, not by which routes exist\n",
                fabric
                    .workloads
                    .iter()
                    .map(|w| w.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::Declaration;
    use crate::sys::mock::MockSys;

    fn wl_fabric() -> Fabric {
        Fabric::from_decl(
            &Declaration::parse(&crate::decl::fixtures::with_workload(
                &crate::decl::fixtures::example(),
            ))
            .unwrap(),
        )
        .unwrap()
    }

    /// A vlan-aware bridge, its `vlan_filtering` off, and no bridge at all.
    fn bridge_sys(vlan_filtering: Option<&str>) -> MockSys {
        let mut sys = MockSys::default().file("/sys/class/net/primary/brif/eth0/state", "3\n");
        if let Some(v) = vlan_filtering {
            sys = sys.file("/sys/class/net/primary/bridge/vlan_filtering", v);
        }
        sys
    }

    #[test]
    fn host_preflight_refuses_an_uplink_bridge_that_is_not_vlan_aware() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let want = "FATAL: workload vms: bridge primary is not vlan-aware (bridge-vlan-aware \
                    yes in /etc/network/interfaces)";
        assert_eq!(
            host_preflight(&bridge_sys(Some("0\n")), &view)
                .unwrap_err()
                .to_string(),
            want
        );
        // Present but unreadable: cfab cannot prove the leg would receive its tag, and this is
        // the gate that exists to say so — same condition, same words.
        assert_eq!(
            host_preflight(&bridge_sys(None), &view)
                .unwrap_err()
                .to_string(),
            want
        );
        host_preflight(&bridge_sys(Some("1\n")), &view).expect("vlan-aware passes");
    }

    /// An uplink that is not there yet defers (spec 5.1) — `check` on a host whose bridge is
    /// still coming up, or on any other machine, must not refuse the declaration for it.
    #[test]
    fn host_preflight_passes_when_the_uplink_bridge_is_absent() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        host_preflight(&MockSys::default(), &view).expect("an absent bridge is a deferral");
        // ...and a member with no workload row reads nothing at all.
        let leaf = View::new(&f, "pve3-tb").unwrap();
        host_preflight(&MockSys::default(), &leaf).expect("no rows, no host facts");
    }

    /// Conflict 11: holo's `redistribution` list is per-INSTANCE, not per-route, so an entry
    /// for `ietf-routing:static` on a zone's OSPF instance advertises every static route cfab
    /// installs — including the /32s of a workload row that zone is not in the `allow` list of.
    /// `check` says so once, naming the rows, rather than letting an operator read the `allow`
    /// lists as route filters.
    #[test]
    fn check_warns_when_two_workload_rows_declare_different_allow_sets() {
        let two = format!(
            "{}\n[[workload]]\nname = \"dmz\"\nuplink = \"primary\"\nvid = 4\n\
             prefix = \"192.168.21.0/24\"\ngw = \"192.168.21.254\"\n\
             allow = [\"storage\", \"mgmt\"]\n",
            crate::decl::fixtures::with_workload(&crate::decl::fixtures::example()).replace(
                "workloads = [{ name = \"vms\", address = \"192.168.20.2/24\" }]",
                "workloads = [{ name = \"vms\", address = \"192.168.20.2/24\" }, \
                 { name = \"dmz\", address = \"192.168.21.2/24\" }]",
            )
        );
        let f = Fabric::from_decl(&Declaration::parse(&two).unwrap()).unwrap();
        let view = View::new(&f, "pve1-tb").unwrap();
        let want = "warning: workload rows vms, dmz declare different allow sets; every allowed \
                    zone's OSPF instance advertises the per-VM routes of ALL rows (holo \
                    redistributes static routes per instance, not per route) — reach is decided \
                    by the forward policy, not by which routes exist\n";
        assert!(report(&f, &view).contains(want), "{}", report(&f, &view));
        // One row, or two that agree: nothing to warn about, and the line is absent.
        let one = wl_fabric();
        assert!(!report(&one, &View::new(&one, "pve1-tb").unwrap()).contains("warning:"));
        let agree = two.replace("allow = [\"storage\", \"mgmt\"]", "allow = [\"storage\"]");
        let f2 = Fabric::from_decl(&Declaration::parse(&agree).unwrap()).unwrap();
        assert!(!report(&f2, &View::new(&f2, "pve1-tb").unwrap()).contains("warning:"));
        // ...and the same two zones in the other order is the SAME set: `allow` is a set of
        // zones, so declaration order must not decide whether an operator is warned.
        // vms becomes ["mgmt", "storage"] beside dmz's ["storage", "mgmt"]: one set, two orders.
        let reordered = two.replace("allow = [\"storage\"]", "allow = [\"mgmt\", \"storage\"]");
        let f3 = Fabric::from_decl(&Declaration::parse(&reordered).unwrap()).unwrap();
        assert!(
            !report(&f3, &View::new(&f3, "pve1-tb").unwrap()).contains("warning:"),
            "{}",
            report(&f3, &View::new(&f3, "pve1-tb").unwrap())
        );
    }

    #[test]
    fn report_lists_workloads() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            report(&f, &view),
            "fabric.toml OK: 3 zones, 9 segments, 3 fallback legs, 3 members\n\
             this member: pve1-tb (node 1, host); 9 segment sub-ifs on wires [eth0 eth1 eth9], \
             3 fallback leg(s), 1 ingress leg(s)\n\
             workload vms: primary vid 3 (cfab-work-vms) 192.168.20.0/24 gw 192.168.20.254 \
             host-local, no dhcp_server (no relay), allow storage; carried by pve1-tb, pve2-tb\n"
        );
    }

    /// A declared `dhcp_server` is named on the row's line, and — since this fabric has a gw
    /// zone, i.e. a default route off-fabric — draws no warning.
    #[test]
    fn report_names_a_declared_dhcp_server_and_does_not_warn_when_a_gw_zone_exists() {
        let text = crate::decl::fixtures::with_workload(&crate::decl::fixtures::example()).replace(
            "gw = \"192.168.20.254\"",
            "gw = \"192.168.20.254\"\ndhcp_server = \"192.168.10.11\"",
        );
        let f = Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap();
        let view = View::new(&f, "pve1-tb").unwrap();
        let out = report(&f, &view);
        assert!(
            out.contains("host-local, dhcp_server 192.168.10.11, allow storage;"),
            "{out}"
        );
        assert!(!out.contains("has no route to it"), "{out}");
    }

    /// ...and with no gw zone anywhere and the server outside every allowed zone's block, the
    /// relay would have nothing to route over: a WARNING, never a refusal (cfab cannot see the
    /// host's own routing table, and an operator may have a route of their own).
    #[test]
    fn report_warns_when_no_zone_can_reach_the_declared_dhcp_server() {
        let text = crate::decl::fixtures::with_workload(&crate::decl::fixtures::example())
            .replace(
                "gw = \"192.168.20.254\"",
                "gw = \"192.168.20.254\"\ndhcp_server = \"192.168.10.11\"",
            )
            .lines()
            .filter(|l| !l.starts_with("gw = { domain"))
            .collect::<Vec<_>>()
            .join("\n");
        let f = Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert!(
            report(&f, &view).contains(
                "warning: workload vms: dhcp_server 192.168.10.11 is in no zone this row is \
                 allowed into (storage) and no zone declares a gw, so the relay has no route to \
                 it\n"
            ),
            "{}",
            report(&f, &view)
        );
        // A server INSIDE an allowed zone's own block needs no gw zone and draws no warning.
        let inside = text.replace("192.168.10.11", "10.99.5.11");
        let f2 = Fabric::from_decl(&Declaration::parse(&inside).unwrap()).unwrap();
        let v2 = View::new(&f2, "pve1-tb").unwrap();
        assert!(
            !report(&f2, &v2).contains("has no route to it"),
            "{}",
            report(&f2, &v2)
        );
    }
}
