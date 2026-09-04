//! Derivations from the typed model — the resolved, per-member view the runtime works from.
//! Pure functions, no I/O: everything downstream (generators, `up`, `verify`) reads the
//! `View`, never the declaration tables directly.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::model::{Fabric, Island, Member, MemberKind, Role, Zone};

/// A CLASS_TABLE row resolved for one member: island → that member's wire. A member with no
/// wire on a row's island simply has no such row (heterogeneity is generated, not branched).
#[derive(Debug, Clone)]
pub struct ClassRow {
    pub ifname: String,
    pub wire: String,
    pub zone: String,
    pub seg: u8,
    pub vid: u16,
    pub role: Role,
    pub ospf_cost: u32,
}

/// An ingress leg this member carries (hosts only: leaves never peer).
#[derive(Debug, Clone)]
pub struct GwRow {
    pub ifname: String,
    pub wire: String,
    pub zone: String,
    pub vid: u16,
}

/// One slave of a rescue bond: a physical wire, tagged with the rescue segment's vid.
#[derive(Debug, Clone)]
pub struct Slave {
    pub ifname: String,
    pub wire: String,
    pub island: Island,
}

/// A rescue segment resolved for one member: an active-backup bond over every wire the
/// member has, one VLAN sub-interface per wire as a slave. `home` is the wire carrying this
/// zone's cheapest class segment this member actually has — derived, never declared.
#[derive(Debug, Clone)]
pub struct RescueRow {
    pub ifname: String,
    pub zone: String,
    pub seg: u8,
    pub vid: u16,
    pub ospf_cost: u32,
    pub home: String,
    pub slaves: Vec<Slave>,
}

/// The fabric resolved for the member running the binary.
pub struct View<'a> {
    pub fabric: &'a Fabric,
    pub member: &'a Member,
}

impl<'a> View<'a> {
    pub fn new(fabric: &'a Fabric, member_name: &str) -> Result<View<'a>> {
        Ok(View {
            fabric,
            member: fabric.member(member_name)?,
        })
    }

    pub fn node(&self) -> u8 {
        self.member.node
    }

    pub fn kind(&self) -> MemberKind {
        self.member.kind
    }

    /// The member's resolved CLASS_TABLE rows, in table order.
    pub fn class_rows(&self) -> Vec<ClassRow> {
        class_rows_of(self.fabric, self.member)
    }

    /// The ingress legs this member carries, in ZONE_TABLE order.
    pub fn gw_rows(&self) -> Vec<GwRow> {
        gw_rows_of(self.fabric, self.member)
    }

    /// This member's rescue segments, one per zone this member has a rescue row for (table
    /// order), each a bond over every wire the member has.
    pub fn rescue_rows(&self) -> Vec<RescueRow> {
        rescue_rows_of(self.fabric, self.member)
    }

    /// This member's interfaces in a zone: segments (table order), then the rescue bond, then
    /// the ingress leg — adjacency interfaces before the router-facing one.
    pub fn zone_ifs(&self, zone: &str) -> Vec<String> {
        let mut ifs: Vec<String> = self
            .class_rows()
            .into_iter()
            .filter(|r| r.zone == zone)
            .map(|r| r.ifname)
            .collect();
        ifs.extend(
            self.rescue_rows()
                .into_iter()
                .filter(|r| r.zone == zone)
                .map(|r| r.ifname),
        );
        ifs.extend(
            self.gw_rows()
                .into_iter()
                .filter(|r| r.zone == zone)
                .map(|r| r.ifname),
        );
        ifs
    }

    /// Unique physical wires under the member's segments, sorted.
    pub fn wires(&self) -> Vec<String> {
        let set: BTreeSet<String> = self.class_rows().into_iter().map(|r| r.wire).collect();
        set.into_iter().collect()
    }

    /// The admin interface: a host's mg wire — the untagged, routing-stack-independent
    /// lifeline. A leaf has none of ours to guard (it never owns any wire's L3).
    pub fn admin_if(&self) -> Option<&'a str> {
        match self.member.kind {
            MemberKind::Host => self.member.wire(Island::Mg).map(|w| w.name.as_str()),
            MemberKind::Leaf => None,
        }
    }

    /// Every interface cfab owns on this member with the forwarding flag cfab sets on it:
    /// declared wires and the admin NIC (never), class-table segments, ingress legs, rescue
    /// bonds (transit like a segment — a rescue leg for one zone can carry another zone's
    /// island-disjoint traffic) and the VRRP macvlan (only a forwarding host), rescue slaves
    /// and identity veths (never: a slave is L2 only, the bond is the L3 interface). Scoped
    /// posture: cfab's forwarding authority is exactly this set — it neither reads nor writes
    /// the flag on any other interface, so a foreign forwarder (Docker, a routed bridge, a
    /// host-level CNI) is not cfab's to police. Declared names only; `owns_if` adds the
    /// `cfab-` name family.
    pub fn owned_forwarding(&self) -> Vec<(String, bool)> {
        let f = self.fabric;
        let transit = self.member.kind == MemberKind::Host && f.host_forward;
        let mut out: Vec<(String, bool)> = Vec::new();
        for w in self.wires() {
            out.push((w, false));
        }
        if let Some(a) = self.admin_if() {
            out.push((a.to_string(), false));
        }
        for r in self.class_rows() {
            out.push((r.ifname, transit));
        }
        for r in self.gw_rows() {
            out.push((r.ifname, transit));
        }
        for r in self.rescue_rows() {
            out.push((r.ifname, transit));
            for s in r.slaves {
                out.push((s.ifname, false));
            }
        }
        if f.vrrp_gw {
            out.push((f.vrrp_if.clone(), transit));
        }
        for z in &f.zones {
            let id = Self::identity_if(z);
            out.push((format!("{id}-peer"), false));
            out.push((id, false));
        }
        out.sort();
        out.dedup_by(|a, b| a.0 == b.0);
        out
    }

    /// Is `ifname` cfab's? The declared set plus anything in the `cfab-` name family (identity
    /// veths and their peers are created by name, never declared).
    pub fn owns_if(&self, ifname: &str) -> bool {
        ifname.starts_with("cfab-") || self.owned_forwarding().iter().any(|(n, _)| n == ifname)
    }

    /// Declared link speed for one of this member's wires (Mb/s).
    pub fn link_speed(&self, wire: &str) -> Result<u32> {
        for w in self.member.wires.iter().flatten() {
            if w.name == wire {
                return Ok(w.speed_mbit);
            }
        }
        Err(Error::config(format!(
            "no declared link speed for {}:{wire} in MEMBER_TABLE",
            self.member.name
        )))
    }

    /// The identity netdev for a zone: `cfab-id<id>`.
    pub fn identity_if(zone: &Zone) -> String {
        format!("cfab-id{}", zone.id)
    }

    /// The identity address for this member in a zone: `10.<id>.0.<node>`.
    pub fn identity_addr(&self, zone: &Zone) -> String {
        format!("{}.0.{}", zone.block(), self.node())
    }

    /// This member's address on a zone's segment `seg`: `10.<id>.<seg>.<node>`.
    pub fn segment_addr(&self, zone: &Zone, seg: u8) -> String {
        format!("{}.{seg}.{}", zone.block(), self.node())
    }

    /// The floating storage gateway VIP: `10.<storage id>.1.254` — on the primary segment,
    /// `.254` beside the node addresses. Derived, never declared.
    pub fn vrrp_vip(&self) -> Result<String> {
        Ok(format!("{}.1.254", self.fabric.zone("storage")?.block()))
    }

    /// VRRP priority by node id — a fixed table for now (a known design wart: a new member
    /// needs an edit here; the priority should derive from the declaration).
    pub fn vrrp_prio(&self) -> Result<u32> {
        match self.node() {
            3 => Ok(200),
            1 => Ok(100),
            2 => Ok(50),
            n => Err(Error::config(format!(
                "no VRRP priority for node {n} (vrrp_prio table)"
            ))),
        }
    }
}

pub fn class_rows_of(fabric: &Fabric, member: &Member) -> Vec<ClassRow> {
    fabric
        .class_table
        .iter()
        .filter_map(|r| {
            member.wire(r.island).map(|w| ClassRow {
                ifname: r.ifname.clone(),
                wire: w.name.clone(),
                zone: r.zone.clone(),
                seg: r.seg,
                vid: r.vid,
                role: r.role,
                ospf_cost: r.ospf_cost,
            })
        })
        .collect()
}

/// The wire carrying this member's cheapest class segment of `zone` — the rescue leg's home,
/// derived (never declared). Ties keep the first row in CLASS_TABLE order.
fn home_wire(fabric: &Fabric, member: &Member, zone: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;
    for r in class_rows_of(fabric, member) {
        if r.zone != zone {
            continue;
        }
        if best.as_ref().is_none_or(|(cost, _)| r.ospf_cost < *cost) {
            best = Some((r.ospf_cost, r.wire));
        }
    }
    best.map(|(_, wire)| wire)
}

/// This member's rescue segments (table order): each `any` row fanned out over the member's
/// wires in st/cl/mg order, one slave per wire, homed on the zone's cheapest wire this member
/// has. A member with no wires at all has no rescue row (it has no fabric).
pub fn rescue_rows_of(fabric: &Fabric, member: &Member) -> Vec<RescueRow> {
    if member.wires.iter().all(Option::is_none) {
        return Vec::new();
    }
    fabric
        .class_table
        .iter()
        .filter(|r| r.role == Role::Rescue)
        .filter_map(|r| {
            let home = home_wire(fabric, member, &r.zone)?;
            let slaves = [Island::St, Island::Cl, Island::Mg]
                .into_iter()
                .filter_map(|island| {
                    member.wire(island).map(|w| Slave {
                        ifname: format!("{}-{}", r.ifname, island.as_str()),
                        wire: w.name.clone(),
                        island,
                    })
                })
                .collect();
            Some(RescueRow {
                ifname: r.ifname.clone(),
                zone: r.zone.clone(),
                seg: r.seg,
                vid: r.vid,
                ospf_cost: r.ospf_cost,
                home,
                slaves,
            })
        })
        .collect()
}

pub fn gw_rows_of(fabric: &Fabric, member: &Member) -> Vec<GwRow> {
    if member.kind != MemberKind::Host {
        return Vec::new();
    }
    fabric
        .zones
        .iter()
        .filter_map(|z| {
            let gw = z.gw.as_ref()?;
            let wire = member.wire(gw.island)?;
            Some(GwRow {
                ifname: format!("cfab-gw{}", z.id),
                wire: wire.name.clone(),
                zone: z.name.clone(),
                vid: gw.vid,
            })
        })
        .collect()
}

/// The (zone, seg) pairs a member carries, as sorted `zone:seg` strings — what two members
/// must share for a BFD session to exist between them.
pub fn segments_of(fabric: &Fabric, member: &Member) -> BTreeSet<String> {
    class_rows_of(fabric, member)
        .into_iter()
        .map(|r| format!("{}:{}", r.zone, r.seg))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    #[test]
    fn class_rows_resolve_wires_per_member() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let rows = v.class_rows();
        assert_eq!(rows.len(), 9);
        assert_eq!(rows[0].ifname, "cfab-st");
        assert_eq!(rows[0].wire, "eth9");
        assert_eq!(rows[1].ifname, "cfab-st-bk");
        assert_eq!(rows[1].wire, "eth1");
        assert_eq!(rows[2].wire, "eth0");
    }

    #[test]
    fn gw_rows_only_on_hosts_with_the_wire() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let rows = host.gw_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ifname, "cfab-gw249");
        assert_eq!(rows[0].wire, "eth0");
        assert_eq!(rows[0].vid, 249);
        let leaf = View::new(&f, "pve3-tb").unwrap();
        assert!(leaf.gw_rows().is_empty());
    }

    #[test]
    fn zone_ifs_are_segments_then_leg() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            v.zone_ifs("mgmt"),
            vec![
                "cfab-mg",
                "cfab-mg-bk",
                "cfab-mg-b2",
                "cfab-mg-rs",
                "cfab-gw249"
            ]
        );
        assert_eq!(
            v.zone_ifs("storage"),
            vec!["cfab-st", "cfab-st-bk", "cfab-st-b2", "cfab-st-rs"]
        );
    }

    #[test]
    fn owned_forwarding_is_the_declared_set_with_transit_only_on_a_forwarding_host() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let owned = host.owned_forwarding();
        let fwd: Vec<&str> = owned
            .iter()
            .filter(|(_, x)| *x)
            .map(|(n, _)| n.as_str())
            .collect();
        let off: Vec<&str> = owned
            .iter()
            .filter(|(_, x)| !*x)
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(
            fwd,
            vec![
                "cfab-cl",
                "cfab-cl-b2",
                "cfab-cl-bk",
                "cfab-cl-rs",
                "cfab-gw249",
                "cfab-mg",
                "cfab-mg-b2",
                "cfab-mg-bk",
                "cfab-mg-rs",
                "cfab-st",
                "cfab-st-b2",
                "cfab-st-bk",
                "cfab-st-rs",
                "cfab-st-vr"
            ]
        );
        assert_eq!(
            off,
            vec![
                "cfab-cl-rs-cl",
                "cfab-cl-rs-mg",
                "cfab-cl-rs-st",
                "cfab-id199",
                "cfab-id199-peer",
                "cfab-id249",
                "cfab-id249-peer",
                "cfab-id99",
                "cfab-id99-peer",
                "cfab-mg-rs-cl",
                "cfab-mg-rs-mg",
                "cfab-mg-rs-st",
                "cfab-st-rs-cl",
                "cfab-st-rs-mg",
                "cfab-st-rs-st",
                "eth0",
                "eth1",
                "eth9"
            ]
        );
        assert!(host.owns_if("eth9") && host.owns_if("cfab-anything"));
        assert!(!host.owns_if("docker0") && !host.owns_if("vmbr0"));
        // a leaf never forwards on anything it owns
        let leaf = View::new(&f, "pve3-tb").unwrap();
        assert!(leaf.owned_forwarding().iter().all(|(_, x)| !*x));
        assert!(!leaf.owned_forwarding().is_empty());
    }

    #[test]
    fn admin_if_host_vs_leaf() {
        let f = fabric();
        assert_eq!(View::new(&f, "pve1-tb").unwrap().admin_if(), Some("eth0"));
        assert_eq!(View::new(&f, "pve3-tb").unwrap().admin_if(), None);
    }

    #[test]
    fn wires_unique_sorted() {
        let f = fabric();
        assert_eq!(
            View::new(&f, "pve2-tb").unwrap().wires(),
            vec!["eth0", "eth1", "eth9"]
        );
    }

    #[test]
    fn vip_and_prio() {
        let f = fabric();
        let v = View::new(&f, "pve3-tb").unwrap();
        assert_eq!(v.vrrp_vip().unwrap(), "10.99.1.254");
        assert_eq!(v.vrrp_prio().unwrap(), 200);
    }

    #[test]
    fn rescue_rows_fan_out_over_every_wire_homed_on_the_cheapest_segment() {
        for name in ["pve1-tb", "pve3-tb"] {
            let f = fabric();
            let v = View::new(&f, name).unwrap();
            let rows = v.rescue_rows();
            assert_eq!(rows.len(), 3, "{name}: one rescue row per zone");
            let expect_home = [
                ("cfab-st-rs", "eth9"),
                ("cfab-cl-rs", "eth1"),
                ("cfab-mg-rs", "eth0"),
            ];
            for (i, (ifname, home)) in expect_home.into_iter().enumerate() {
                let row = &rows[i];
                assert_eq!(row.ifname, ifname, "{name}");
                assert_eq!(row.home, home, "{name}: {ifname} home wire");
                assert_eq!(row.slaves.len(), 3, "{name}: {ifname} slaves");
                assert_eq!(
                    row.slaves
                        .iter()
                        .map(|s| s.ifname.as_str())
                        .collect::<Vec<_>>(),
                    vec![
                        format!("{ifname}-st"),
                        format!("{ifname}-cl"),
                        format!("{ifname}-mg")
                    ]
                );
                assert_eq!(
                    row.slaves
                        .iter()
                        .map(|s| s.wire.as_str())
                        .collect::<Vec<_>>(),
                    vec!["eth9", "eth1", "eth0"]
                );
            }
        }
    }

    #[test]
    fn wires_and_segments_of_never_see_the_rescue_bond_or_its_slaves() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        // wires() feeds the shaper, down's qdisc sweep and verify's link-speed checks: a
        // rescue row must never enter it (only class_rows() does).
        assert_eq!(v.wires(), vec!["eth0", "eth1", "eth9"]);
        assert!(!v.wires().iter().any(|w| w.contains("-rs")));
        // segments_of feeds BFD pairing: no rescue segment, no BFD.
        assert!(!segments_of(&f, v.member).iter().any(|s| s.contains(":9")));
    }

    #[test]
    fn segments_of_sorted_unique() {
        let f = fabric();
        let s = segments_of(&f, f.member("pve1-tb").unwrap());
        let v: Vec<&str> = s.iter().map(String::as_str).collect();
        assert_eq!(
            v,
            vec![
                "cluster:1",
                "cluster:2",
                "cluster:3",
                "mgmt:1",
                "mgmt:2",
                "mgmt:3",
                "storage:1",
                "storage:2",
                "storage:3"
            ]
        );
    }
}
