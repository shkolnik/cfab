//! `cfab check`: validate the declaration and report the fabric as declared, what THIS member
//! gets, and (with `[[workload]]` rows) each row and the fabric aggregate.

use crate::derive::View;
use crate::model::{Fabric, MemberKind};

/// The lines `cfab check` prints. The per-member line is the last thing an operator sees before
/// `up` creates the netdevs, so it names every leg `up` will build — the fallback legs included:
/// their ports fan out per wire, so their count is member-dependent and not derivable from the
/// fabric-wide line. With `[[workload]]` rows declared, one line per row follows (name, uplink,
/// vid, the leg cfab creates, prefix, gw, router, allow, and the members that carry it), then
/// the fabric aggregate — the
/// smallest set of prefixes covering every declared zone block — followed by one RFC 3442
/// option-121 dhcpd.conf snippet per row (the aggregate is fabric-wide and shared; `gw`, `router`,
/// and the row's own `prefix` differ per row): each snippet is a comment naming the EXISTING
/// subnet block (of that row's own VLAN) the `option` line pastes into, never a `subnet { … }`
/// block of its own — a second declaration of an existing subnet loads with only a warning and
/// the lease silently picks one (I3, whole-branch review, VERIFIED pve3-tb isc-dhcpd 4.4.3-P1).
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
            out.push_str(&format!(
                "workload {}: {} vid {} ({}) {} gw {} router {} allow {}; carried by {}\n",
                wl.name,
                wl.uplink,
                wl.vid,
                wl.leg_ifname(),
                wl.prefix,
                wl.gw,
                wl.router,
                wl.allow.join(", "),
                carried_by
            ));
        }
        let aggregate = fabric.aggregate();
        out.push_str(&format!(
            "fabric aggregate (for DHCP option 121): {}\n",
            aggregate
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out.push_str(crate::emit::workload::DHCP_OPTION_121_DEFINITION);
        for wl in &fabric.workloads {
            out.push_str(&crate::emit::workload::dhcp_option_121(
                wl.prefix, &aggregate, wl.gw, wl.router,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::Declaration;

    fn wl_fabric() -> Fabric {
        Fabric::from_decl(
            &Declaration::parse(&crate::decl::fixtures::with_workload(
                &crate::decl::fixtures::example(),
            ))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn report_lists_workloads_and_the_aggregate() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            report(&f, &view),
            "fabric.toml OK: 3 zones, 9 segments, 3 fallback legs, 3 members\n\
             this member: pve1-tb (node 1, host); 9 segment sub-ifs on wires [eth0 eth1 eth9], \
             3 fallback leg(s), 1 ingress leg(s)\n\
             workload vms: primary vid 3 (cfab-work-vms) 192.168.20.0/24 gw 192.168.20.254 \
             router 192.168.20.1 \
             allow storage; carried by pve1-tb, pve2-tb\n\
             fabric aggregate (for DHCP option 121): 10.99.0.0/16, 10.199.0.0/16, \
             10.249.0.0/16\n\
             # dhcpd.conf (ISC): option 121 is defined ONCE, globally; dhcpd refuses a definition \
             inside a subnet block.\n\
             option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n\
             # dhcpd.conf (ISC): RFC 3442 classless static routes for this workload's subnet. A \
             client that receives\n\
             # option 121 IGNORES option 3, so the default route (0.0.0.0/0 via 192.168.20.1) \
             is INSIDE 121 (last entry).\n\
             # 10.99.0.0/16 via 192.168.20.254, 10.199.0.0/16 via 192.168.20.254, \
             10.249.0.0/16 via 192.168.20.254, 0.0.0.0/0 via 192.168.20.1\n\
             # paste the next line inside the existing 'subnet 192.168.20.0 netmask \
             255.255.255.0 { ... }' block of this VLAN (do not add a second subnet block: \
             dhcpd loads overlapping subnets with a warning and the lease picks one)\n\
             \toption rfc3442-classless-static-routes 16, 10, 99, 192, 168, 20, 254, 16, 10, \
             199, 192, 168, 20, 254, 16, 10, 249, 192, 168, 20, 254, 0, 192, 168, 20, 1;\n"
        );
    }
}
