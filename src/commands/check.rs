//! `cfab check`: validate the declaration and report the fabric as declared, what THIS member
//! gets, and (with `[[workload]]` rows) each row and the fabric aggregate.

use crate::derive::View;
use crate::model::{Fabric, MemberKind};

/// The lines `cfab check` prints. The per-member line is the last thing an operator sees before
/// `up` creates the netdevs, so it names every leg `up` will build — the fallback legs included:
/// their ports fan out per wire, so their count is member-dependent and not derivable from the
/// fabric-wide line. With `[[workload]]` rows declared, one line per row follows (name, ifname,
/// prefix, gw, router, allow, and the members that carry it), then the fabric aggregate — the
/// smallest set of prefixes covering every declared zone block — for the DHCP option 121 snippet
/// (the snippet itself is a later lane).
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
                "workload {}: {} {} gw {} router {} allow {}; carried by {}\n",
                wl.name,
                wl.ifname,
                wl.prefix,
                wl.gw,
                wl.router,
                wl.allow.join(", "),
                carried_by
            ));
        }
        out.push_str(&format!(
            "fabric aggregate (for DHCP option 121): {}\n",
            fabric.aggregate().join(", ")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::Declaration;

    fn example() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
            .unwrap()
    }

    fn wl_fabric() -> Fabric {
        Fabric::from_decl(
            &Declaration::parse(&crate::decl::fixtures::with_workload(
                &crate::decl::fixtures::example(),
            ))
            .unwrap(),
        )
        .unwrap()
    }

    /// The per-member line is the only output that says what THIS host will get, and `up`
    /// builds one bond per fallback leg with one port per wire under it. It must say so.
    #[test]
    fn check_names_this_members_fallback_legs() {
        let f = Fabric::from_decl(&Declaration::parse(&example()).unwrap()).unwrap();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            report(&f, &view),
            "fabric.toml OK: 3 zones, 9 segments, 3 fallback legs, 3 members\n\
             this member: pve1-tb (node 1, host); 9 segment sub-ifs on wires [eth0 eth1 eth9], \
             3 fallback leg(s), 1 ingress leg(s)\n"
        );
    }

    /// A fabric declaring no universal segment: one spelling, counted zero, never absent.
    #[test]
    fn check_on_a_fallback_free_fabric_counts_zero() {
        let text = example()
            .lines()
            .filter(|l| !l.starts_with("universal = "))
            .collect::<Vec<_>>()
            .join("\n");
        let f = Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            report(&f, &view),
            "fabric.toml OK: 3 zones, 9 segments, 0 fallback legs, 3 members\n\
             this member: pve1-tb (node 1, host); 9 segment sub-ifs on wires [eth0 eth1 eth9], \
             0 fallback leg(s), 1 ingress leg(s)\n"
        );
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
             workload vms: primary.3 192.168.20.0/24 gw 192.168.20.254 router 192.168.20.1 \
             allow storage; carried by pve1-tb, pve2-tb\n\
             fabric aggregate (for DHCP option 121): 10.99.0.0/16, 10.199.0.0/16, \
             10.249.0.0/16\n"
        );
    }
}
