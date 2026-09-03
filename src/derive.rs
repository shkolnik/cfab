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

    /// This member's interfaces in a zone: segments (table order), then the ingress leg.
    pub fn zone_ifs(&self, zone: &str) -> Vec<String> {
        let mut ifs: Vec<String> = self
            .class_rows()
            .into_iter()
            .filter(|r| r.zone == zone)
            .map(|r| r.ifname)
            .collect();
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
            vec!["cfab-mg", "cfab-mg-bk", "cfab-mg-b2", "cfab-gw249"]
        );
        assert_eq!(
            v.zone_ifs("storage"),
            vec!["cfab-st", "cfab-st-bk", "cfab-st-b2"]
        );
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
