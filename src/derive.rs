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

/// An ingress leg this member carries (hosts only: leaves never peer). Shaped exactly like
/// `FallbackRow`: on a physical gw island the leg is a plain sub-interface on `home` and
/// `slaves` is empty; on island `any` it is a bond over `slaves`, one per wire, and `home`
/// names the wire the bond takes as `primary` — so the leg survives an island's isolation
/// with one leg and one BGP session, not two.
#[derive(Debug, Clone)]
pub struct GwRow {
    pub ifname: String,
    pub home: String,
    pub zone: String,
    pub vid: u16,
    pub slaves: Vec<Slave>,
}

impl GwRow {
    /// Does this leg migrate between wires (island `any`)? The one branch every consumer
    /// keys on, so no consumer re-derives it from the declaration.
    pub fn migrates(&self) -> bool {
        !self.slaves.is_empty()
    }
}

/// One slave of a bond leg (a fallback segment, or a migrating ingress leg): a physical wire,
/// tagged with that leg's vid.
#[derive(Debug, Clone)]
pub struct Slave {
    pub ifname: String,
    pub wire: String,
    pub island: Island,
}

/// A fallback segment resolved for one member: an active-backup bond over every wire the
/// member has, one VLAN sub-interface per wire as a slave. `home` is the wire carrying this
/// zone's cheapest class segment this member actually has — derived, never declared.
#[derive(Debug, Clone)]
pub struct FallbackRow {
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

    /// This member's fallback segments, one per zone this member has a fallback row for (table
    /// order), each a bond over every wire the member has.
    pub fn fallback_rows(&self) -> Vec<FallbackRow> {
        fallback_rows_of(self.fabric, self.member)
    }

    /// This member's interfaces in a zone: segments (table order), then the fallback bond, then
    /// the ingress leg — adjacency interfaces before the router-facing one.
    pub fn zone_ifs(&self, zone: &str) -> Vec<String> {
        let mut ifs: Vec<String> = self
            .class_rows()
            .into_iter()
            .filter(|r| r.zone == zone)
            .map(|r| r.ifname)
            .collect();
        ifs.extend(
            self.fallback_rows()
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
    /// declared wires and the admin NIC (never), class-table segments, ingress legs, fallback
    /// bonds (transit like a segment — a fallback leg for one zone can carry another zone's
    /// island-disjoint traffic), fallback slaves and identity veths (never: a slave is L2 only, the bond is the L3 interface). Scoped
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
            // A migrating leg's slaves, like a fallback leg's: L2 only, never transit.
            for s in r.slaves {
                out.push((s.ifname, false));
            }
        }
        for r in self.fallback_rows() {
            out.push((r.ifname, transit));
            for s in r.slaves {
                out.push((s.ifname, false));
            }
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

/// The slaves of a bond leg named `ifname`: one tagged sub-interface per wire this member
/// has, in st/cl/mg order, named `<ifname>-<island>`. Shared by the fallback segment and a
/// migrating ingress leg — one fan-out, so the two legs cannot drift apart.
fn slaves_of(member: &Member, ifname: &str) -> Vec<Slave> {
    [Island::St, Island::Cl, Island::Mg]
        .into_iter()
        .filter_map(|island| {
            member.wire(island).map(|w| Slave {
                ifname: format!("{ifname}-{}", island.as_str()),
                wire: w.name.clone(),
                island,
            })
        })
        .collect()
}

/// The wire carrying this member's cheapest class segment of `zone` — the fallback leg's home,
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

/// This member's fallback segments (table order): each `any` row fanned out over the member's
/// wires in st/cl/mg order, one slave per wire, homed on the zone's cheapest wire this member
/// has. A member with no wires at all has no fallback row (it has no fabric).
pub fn fallback_rows_of(fabric: &Fabric, member: &Member) -> Vec<FallbackRow> {
    if member.wires.iter().all(Option::is_none) {
        return Vec::new();
    }
    fabric
        .class_table
        .iter()
        .filter(|r| r.role == Role::Fallback)
        .filter_map(|r| {
            // A zone with a fallback row but no class row on this member has no cheapest wire,
            // and the row is DROPPED — deliberately, and the opposite of what `gw_rows_of`
            // does with the same condition (it falls back to the member's first wire rather
            // than take the outside away silently). Whether a home-less fallback leg should
            // exist at all is an open question; the two sides are not reconciled yet.
            let home = home_wire(fabric, member, &r.zone)?;
            let slaves = slaves_of(member, &r.ifname);
            Some(FallbackRow {
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
            let ifname = format!("cfab-gw{}", z.id);
            let (home, slaves) = match gw.island {
                // One island: the leg is that wire's sub-interface, as it has always been.
                Island::St | Island::Cl | Island::Mg => {
                    (member.wire(gw.island)?.name.clone(), Vec::new())
                }
                // Every island: a bond, homed like a fallback leg on the wire carrying this
                // zone's cheapest segment. A zone can have an ingress and no segment on this
                // member, and then there is no cheapest wire — fall back to the first wire in
                // st/cl/mg order rather than dropping the leg, which would take the outside
                // away silently. A member with no wires at all has no leg (and no fabric).
                Island::Any => {
                    let slaves = slaves_of(member, &ifname);
                    let home = home_wire(fabric, member, &z.name)
                        .or_else(|| slaves.first().map(|s| s.wire.clone()))?;
                    (home, slaves)
                }
            };
            Some(GwRow {
                ifname,
                home,
                zone: z.name.clone(),
                vid: gw.vid,
                slaves,
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

    /// The tie rule is load-bearing, not incidental: `home_wire`'s strict `<` keeps the
    /// FIRST CLASS_TABLE row of the zone when two segments cost the same, and that choice
    /// decides which slave the fallback bond takes as `primary`. Storage's two cheapest rows
    /// sit on different wires (st = eth9 first, cl = eth1 second); tie them and eth9 must
    /// still win. A `<=` would silently hand `primary` to the last row instead.
    #[test]
    fn a_cost_tie_keeps_the_first_class_table_row() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace(
                    "cfab-st-bk  cl storage 2 101 backup  100",
                    "cfab-st-bk  cl storage 2 101 backup  10",
                );
        let f = Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap();
        let m = f.members.iter().find(|m| m.name == "pve1-tb").unwrap();
        let rows = class_rows_of(&f, m);
        let storage: Vec<_> = rows
            .iter()
            .filter(|r| r.zone == "storage")
            .map(|r| (r.ifname.as_str(), r.wire.as_str(), r.ospf_cost))
            .collect();
        assert_eq!(storage[0], ("cfab-st", "eth9", 10));
        assert_eq!(storage[1], ("cfab-st-bk", "eth1", 10), "the tie is real");
        assert_eq!(home_wire(&f, m, "storage"), Some("eth9".to_string()));
    }

    #[test]
    fn gw_rows_only_on_hosts_with_the_wire() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let rows = host.gw_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ifname, "cfab-gw249");
        assert_eq!(rows[0].home, "eth0");
        assert_eq!(rows[0].vid, 249);
        // An island leg is a plain sub-interface: no bond, no slaves, unchanged by task 9.
        assert!(rows[0].slaves.is_empty());
        assert!(!rows[0].migrates());
        let leaf = View::new(&f, "pve3-tb").unwrap();
        assert!(leaf.gw_rows().is_empty());
    }

    /// The same declaration with the ingress on island `any`.
    fn fabric_with_a_migrating_gw() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace("mg:249:", "any:249:");
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// Task 9: a gw island of `any` fans the leg out into a bond over every wire, exactly
    /// like a fallback leg — same slave naming, same home rule (mgmt's cheapest segment is on
    /// the mg island, so the bond homes on eth0), and still hosts only.
    #[test]
    fn a_gw_island_of_any_fans_out_into_a_bond() {
        let f = fabric_with_a_migrating_gw();
        let host = View::new(&f, "pve1-tb").unwrap();
        let rows = host.gw_rows();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert!(r.migrates());
        assert_eq!(r.ifname, "cfab-gw249");
        assert_eq!(r.home, "eth0");
        assert_eq!(
            r.slaves
                .iter()
                .map(|s| (s.ifname.as_str(), s.wire.as_str()))
                .collect::<Vec<_>>(),
            [
                ("cfab-gw249-st", "eth9"),
                ("cfab-gw249-cl", "eth1"),
                ("cfab-gw249-mg", "eth0"),
            ]
        );
        assert!(View::new(&f, "pve3-tb").unwrap().gw_rows().is_empty());
    }

    /// Every derived slave name fits IFNAMSIZ — the guard `Fabric::validate` enforces.
    #[test]
    fn a_migrating_gw_slave_name_fits_ifnamsiz() {
        let f = fabric_with_a_migrating_gw();
        for m in &f.members {
            for s in gw_rows_of(&f, m).iter().flat_map(|r| &r.slaves) {
                assert!(s.ifname.len() <= 15, "{}", s.ifname);
            }
        }
    }

    /// A migrating leg's slaves are cfab's and never forward — the bond holds the L3, as for
    /// a fallback leg. The bond itself stays `transit` on a forwarding host.
    #[test]
    fn owned_forwarding_carries_a_migrating_gw_bond_and_its_slaves() {
        let f = fabric_with_a_migrating_gw();
        let v = View::new(&f, "pve1-tb").unwrap();
        let owned = v.owned_forwarding();
        let get = |n: &str| owned.iter().find(|(i, _)| i == n).map(|(_, t)| *t);
        assert_eq!(get("cfab-gw249"), Some(true));
        for s in ["cfab-gw249-st", "cfab-gw249-cl", "cfab-gw249-mg"] {
            assert_eq!(get(s), Some(false), "{s}");
            assert!(v.owns_if(s), "{s}");
        }
        // ...and a slave is not a wire and not a segment.
        assert!(!v.wires().iter().any(|w| w.starts_with("cfab-")));
        assert!(!v.zone_ifs("mgmt").iter().any(|i| i.contains("gw249-")));
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
                "cfab-mg-fb",
                "cfab-gw249"
            ]
        );
        assert_eq!(
            v.zone_ifs("storage"),
            vec!["cfab-st", "cfab-st-bk", "cfab-st-b2", "cfab-st-fb"]
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
                "cfab-cl-fb",
                "cfab-gw249",
                "cfab-mg",
                "cfab-mg-b2",
                "cfab-mg-bk",
                "cfab-mg-fb",
                "cfab-st",
                "cfab-st-b2",
                "cfab-st-bk",
                "cfab-st-fb"
            ]
        );
        assert_eq!(
            off,
            vec![
                "cfab-cl-fb-cl",
                "cfab-cl-fb-mg",
                "cfab-cl-fb-st",
                "cfab-id199",
                "cfab-id199-peer",
                "cfab-id249",
                "cfab-id249-peer",
                "cfab-id99",
                "cfab-id99-peer",
                "cfab-mg-fb-cl",
                "cfab-mg-fb-mg",
                "cfab-mg-fb-st",
                "cfab-st-fb-cl",
                "cfab-st-fb-mg",
                "cfab-st-fb-st",
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
    fn fallback_rows_fan_out_over_every_wire_homed_on_the_cheapest_segment() {
        for name in ["pve1-tb", "pve3-tb"] {
            let f = fabric();
            let v = View::new(&f, name).unwrap();
            let rows = v.fallback_rows();
            assert_eq!(rows.len(), 3, "{name}: one fallback row per zone");
            let expect_home = [
                ("cfab-st-fb", "eth9"),
                ("cfab-cl-fb", "eth1"),
                ("cfab-mg-fb", "eth0"),
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
    fn wires_and_segments_of_never_see_the_fallback_bond_or_its_slaves() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        // wires() feeds the shaper, down's qdisc sweep and verify's link-speed checks: a
        // fallback row must never enter it (only class_rows() does).
        assert_eq!(v.wires(), vec!["eth0", "eth1", "eth9"]);
        assert!(!v.wires().iter().any(|w| w.contains("-fb")));
        // segments_of feeds BFD pairing: no fallback segment, no BFD.
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
