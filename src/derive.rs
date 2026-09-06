//! Derivations from the typed model — the resolved, per-member view the runtime works from.
//! Pure functions, no I/O: everything downstream (generators, `up`, `status`) reads the
//! `View`, never the declaration tables directly.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::model::{Fabric, Member, MemberKind, SegScope, Zone};

/// A SEGMENT_TABLE row resolved for one member: domain → that member's wire. A member with no
/// wire on a row's domain simply has no such row (heterogeneity is generated, not branched).
#[derive(Debug, Clone)]
pub struct ClassRow {
    pub ifname: String,
    pub wire: String,
    pub zone: String,
    pub seg: u8,
    pub vid: u16,
    pub ospf_cost: u32,
}

/// An ingress leg this member carries (hosts only: leaves never peer). Shaped exactly like
/// `FallbackRow`: on a physical gw domain the leg is a plain sub-interface on `home` and
/// `slaves` is empty; on scope `any` it is a bond over `slaves`, one per wire, and `home`
/// names the wire the bond takes as `primary` — so the leg survives a domain's isolation
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
    /// Does this leg migrate between wires (scope `any`)? The one branch every consumer
    /// keys on, so no consumer re-derives it from the declaration.
    pub fn migrates(&self) -> bool {
        !self.slaves.is_empty()
    }
}

/// One slave of a bond leg (a universal segment, or a migrating ingress leg): a physical wire,
/// tagged with that leg's vid.
#[derive(Debug, Clone)]
pub struct Slave {
    pub ifname: String,
    pub wire: String,
}

/// A universal segment resolved for one member: an active-backup bond over every wire the
/// member has, one VLAN sub-interface per wire as a slave. `home` is the wire carrying this
/// zone's cheapest segment this member actually has — derived, never declared.
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

/// Where a (member, zone) wire order came from: the default producer, or a WIRE_PREF row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefSource {
    Derived,
    Override,
}

impl PrefSource {
    pub fn as_str(self) -> &'static str {
        match self {
            PrefSource::Derived => "derived",
            PrefSource::Override => "override",
        }
    }
}

/// One member's wire order for one zone: rank 0 first. The representation preference lives in
/// (D1), whether it was declared or produced.
#[derive(Debug, Clone)]
pub struct HostZonePref {
    pub zone: String,
    pub order: Vec<String>,
    pub source: PrefSource,
}

impl HostZonePref {
    /// `storage: eth9 eth1 eth0 (derived)` — the one spelling `gen prefs` and `status` share.
    pub fn render(&self) -> String {
        format!(
            "{}: {} ({})",
            self.zone,
            if self.order.is_empty() {
                "-".to_string()
            } else {
                self.order.join(" ")
            },
            self.source.as_str()
        )
    }
}

/// The OSPF cost of a wire at rank `r` in its zone's order. Rank 0 is 10 and every rank below
/// it is 100·r, so a two-hop path over rank-0 wires (20) still beats any one-hop rank-1 wire
/// (100) — the property both measured failover rounds relied on.
pub fn ladder_cost(rank: usize) -> u32 {
    if rank == 0 { 10 } else { 100 * rank as u32 }
}

/// One ladder step: what a universal segment's cost sits above the zone's longest host path by.
const LADDER_STEP: u32 = 100;

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

    /// The member's resolved segment rows, in table order.
    pub fn class_rows(&self) -> Vec<ClassRow> {
        class_rows_of(self.fabric, self.member)
    }

    /// The ingress legs this member carries, in ZONE_TABLE order.
    pub fn gw_rows(&self) -> Vec<GwRow> {
        gw_rows_of(self.fabric, self.member)
    }

    /// This member's universal segments, one per zone this member has a universal row for
    /// (table order), each a bond over every wire the member has.
    pub fn fallback_rows(&self) -> Vec<FallbackRow> {
        fallback_rows_of(self.fabric, self.member)
    }

    /// This member's wire order per zone, marked derived or overridden (ZONE_TABLE order).
    pub fn prefs(&self) -> Vec<HostZonePref> {
        prefs_of(self.fabric, self.member)
    }

    /// This member's interfaces in a zone: segments (table order), then the universal bond, then
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

    /// The admin interfaces: on a host, EVERY declared wire — the untagged path of each wire is
    /// the routing-stack-independent lifeline, so each one is kept out of transit and each one
    /// gets its own untagged ADMIN_FLOOR band. A leaf has none of ours to guard (it never owns
    /// any wire's L3). Declaration order, which is MEMBER_TABLE order.
    pub fn admin_ifs(&self) -> Vec<&'a str> {
        match self.member.kind {
            MemberKind::Host => self.member.wires.iter().map(|w| w.name.as_str()).collect(),
            MemberKind::Leaf => Vec::new(),
        }
    }

    /// Is `ifname` one of this member's admin (untagged) wires?
    pub fn is_admin_if(&self, ifname: &str) -> bool {
        self.admin_ifs().contains(&ifname)
    }

    /// Every interface cfab owns on this member with the forwarding flag cfab sets on it:
    /// declared wires (never — they carry the untagged admin plane), segment sub-interfaces,
    /// ingress legs, universal bonds (transit like a segment — a universal leg for one zone can
    /// carry another zone's domain-disjoint traffic), bond slaves and identity veths (never: a
    /// slave is L2 only, the bond is the L3 interface). Scoped posture: cfab's forwarding
    /// authority is exactly this set — it neither reads nor writes the flag on any other
    /// interface, so a foreign forwarder (Docker, a routed bridge, a host-level CNI) is not
    /// cfab's to police. Declared names only; `owns_if` adds the `cfab-` name family.
    pub fn owned_forwarding(&self) -> Vec<(String, bool)> {
        let f = self.fabric;
        let transit = self.member.kind == MemberKind::Host && f.host_forward;
        let mut out: Vec<(String, bool)> = Vec::new();
        // Every declared wire, whether or not a segment landed on it: the wire itself never
        // forwards (its untagged path is the admin plane).
        for w in &self.member.wires {
            out.push((w.name.clone(), false));
        }
        for r in self.class_rows() {
            out.push((r.ifname, transit));
        }
        for r in self.gw_rows() {
            out.push((r.ifname, transit));
            // A migrating leg's slaves, like a universal leg's: L2 only, never transit.
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
        self.member
            .wire_named(wire)
            .map(|w| w.speed_mbit)
            .ok_or_else(|| {
                Error::config(format!(
                    "no declared link speed for {}:{wire} in MEMBER_TABLE",
                    self.member.name
                ))
            })
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

/// The default producer (spec §4, option (c)): rank 0 is the wire on the zone's DECLARED
/// primary domain when this member has one, and the remaining candidates follow by declared
/// speed descending, ties keeping MEMBER_TABLE order. A `WIRE_PREF` row replaces the WHOLE
/// order — never blended, and `Fabric::validate` has already proven it complete.
pub fn prefs_of(fabric: &Fabric, member: &Member) -> Vec<HostZonePref> {
    fabric
        .zones
        .iter()
        .map(|z| {
            if let Some(p) = fabric.wire_pref(&member.name, &z.name) {
                return HostZonePref {
                    zone: z.name.clone(),
                    order: p.order.clone(),
                    source: PrefSource::Override,
                };
            }
            let candidates = fabric.candidate_wires(member, &z.name);
            let mut rest: Vec<(usize, &crate::model::Wire)> = candidates
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, w)| w.domain != z.primary)
                .collect();
            // Speed descending; the enumerate index keeps MEMBER_TABLE order on a tie, which is
            // the only tie-break the operator can see in the declaration.
            rest.sort_by(|a, b| b.1.speed_mbit.cmp(&a.1.speed_mbit).then(a.0.cmp(&b.0)));
            let mut order: Vec<String> = Vec::new();
            if let Some(w) = candidates.iter().find(|w| w.domain == z.primary) {
                order.push(w.name.clone());
            }
            order.extend(rest.into_iter().map(|(_, w)| w.name.clone()));
            HostZonePref {
                zone: z.name.clone(),
                order,
                source: PrefSource::Derived,
            }
        })
        .collect()
}

pub fn class_rows_of(fabric: &Fabric, member: &Member) -> Vec<ClassRow> {
    let prefs = prefs_of(fabric, member);
    fabric
        .segments
        .iter()
        .filter_map(|r| {
            let domain = r.scope.domain()?;
            let w = member.wire_on(domain)?;
            // Not a `?`: every zone has a pref row (prefs_of maps over fabric.zones) and the
            // order always contains this wire (candidate_wires is exactly the wires whose
            // domain has a segment in the zone, and this row IS such a segment). A bad
            // declaration cannot reach here — only a refactor that breaks the invariant
            // across model.rs and derive.rs can, and it must not degrade to a missing row.
            let rank = prefs
                .iter()
                .find(|p| p.zone == r.zone)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: no wire preference for zone {} (segment {})",
                        member.name, r.zone, r.ifname
                    )
                })
                .order
                .iter()
                .position(|n| *n == w.name)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: zone {} preference order does not contain wire {} (segment {} on \
                         domain {})",
                        member.name, r.zone, w.name, r.ifname, domain
                    )
                });
            Some(ClassRow {
                ifname: r.ifname.clone(),
                wire: w.name.clone(),
                zone: r.zone.clone(),
                seg: r.seg,
                vid: r.vid,
                ospf_cost: ladder_cost(rank),
            })
        })
        .collect()
}

/// The slaves of a bond leg named `ifname`: one tagged sub-interface per wire this member
/// has, in MEMBER_TABLE order, named `<ifname>-<domain>`. Shared by the universal segment and a
/// migrating ingress leg — one fan-out, so the two legs cannot drift apart.
fn slaves_of(member: &Member, ifname: &str) -> Vec<Slave> {
    member
        .wires
        .iter()
        .map(|w| Slave {
            ifname: format!("{ifname}-{}", w.domain),
            wire: w.name.clone(),
        })
        .collect()
}

/// The wire carrying this member's cheapest segment of `zone` — the bond leg's home, derived
/// (never declared). Ties keep the first row in SEGMENT_TABLE order.
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

/// A zone's universal-segment cost: the zone's longest host path (the sum, over the zone's
/// domain segments, of the highest cost any member gives that segment) plus one ladder step.
/// Fabric-wide by construction, so every member advertises the same number.
pub fn universal_cost(fabric: &Fabric, zone: &str) -> u32 {
    let longest: u32 = fabric
        .segments
        .iter()
        .filter(|s| s.zone == zone && !s.scope.is_universal())
        .map(|s| {
            fabric
                .members
                .iter()
                .filter_map(|m| {
                    class_rows_of(fabric, m)
                        .into_iter()
                        .find(|r| r.ifname == s.ifname)
                        .map(|r| r.ospf_cost)
                })
                .max()
                .unwrap_or(0)
        })
        .sum();
    longest + LADDER_STEP
}

/// This member's universal segments (table order): each `any` row fanned out over the member's
/// wires in MEMBER_TABLE order, one slave per wire, homed on the zone's cheapest wire this
/// member has. A member with no wires at all has no such row (it has no fabric).
pub fn fallback_rows_of(fabric: &Fabric, member: &Member) -> Vec<FallbackRow> {
    if member.wires.is_empty() {
        return Vec::new();
    }
    fabric
        .segments
        .iter()
        .filter(|r| r.scope.is_universal())
        .filter_map(|r| {
            let slaves = slaves_of(member, &r.ifname);
            // A zone with a universal row but no domain segment on this member has no cheapest
            // wire. Both bond legs then home on the member's FIRST wire rather than vanish
            // (spec §6 D): an ingress or a fallback path that silently does not exist is worse
            // than one that exists unused, and `gw_rows_of` below applies the identical rule.
            let home = home_wire(fabric, member, &r.zone)
                .or_else(|| slaves.first().map(|s| s.wire.clone()))?;
            Some(FallbackRow {
                ifname: r.ifname.clone(),
                zone: r.zone.clone(),
                seg: r.seg,
                vid: r.vid,
                ospf_cost: universal_cost(fabric, &r.zone),
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
            let (home, slaves) = match &gw.scope {
                // One domain: the leg is that wire's sub-interface, as it has always been.
                SegScope::Domain(d) => (member.wire_on(d)?.name.clone(), Vec::new()),
                // Every wire: a bond, homed like a universal leg on the wire carrying this
                // zone's cheapest segment, else on the member's first wire (spec §6 D).
                SegScope::Universal => {
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

// ---- validate-time checks that need the derivation (spec §4) --------------------------------

/// The last gate of `Fabric::validate`: everything that can only be seen once the costs are
/// DERIVED. Kept here, beside the producer, so a change to the ladder cannot leave a stale
/// check behind in the model.
pub fn validate_derived(fabric: &Fabric) -> Result<()> {
    for z in &fabric.zones {
        if !fabric
            .segments
            .iter()
            .any(|s| s.zone == z.name && s.scope.is_universal())
        {
            continue;
        }
        let cost = universal_cost(fabric, &z.name);
        if cost >= fabric.leaf_cost_offset {
            return Err(Error::config(format!(
                "zone {}: the derived universal-segment cost {cost} is not below \
                 LEAF_COST_OFFSET ({}) — a universal path must still beat a black-holing leaf. \
                 The cost is no longer declared, so the remedy is to raise LEAF_COST_OFFSET \
                 (or shorten the zone: it is the sum of its domain segments' costs + \
                 {LADDER_STEP})",
                z.name, fabric.leaf_cost_offset
            )));
        }
    }
    for z in &fabric.zones {
        check_rank0_is_shared(fabric, &z.name)?;
        check_no_equal_cost_paths(fabric, &z.name)?;
    }
    Ok(())
}

/// A transit host contributes ITS rank-0 cost, so ranking first a domain no neighbor shares
/// makes the "20 beats 100" property fail for every path through that host: its cheapest
/// interface in the zone reaches nobody, while a wire that DOES reach somebody sits at 100 or
/// worse.
///
/// DEVIATION from spec §4, deliberate and reported: the spec words this as "every member's
/// rank-0 domain must be one at least one other member wires into", flat. That refuses a
/// member alone on its domain — exactly the domain-disjoint member the universal segment
/// exists to serve (`status.rs::half_disjoint_fabric`, a supported and tested topology). The
/// fault the rationale describes is CHOOSING an unshared wire over a shared one, so the check
/// fires only when a shared candidate exists and was ranked below, and only on a host (a leaf
/// never transits, so its own ranking costs nobody else anything).
fn check_rank0_is_shared(fabric: &Fabric, zone: &str) -> Result<()> {
    let shared = |m: &Member, domain: &crate::model::DomainId| {
        fabric
            .members
            .iter()
            .any(|other| other.name != m.name && other.wire_on(domain).is_some())
    };
    for m in &fabric.members {
        if m.kind != MemberKind::Host {
            continue;
        }
        let Some(p) = prefs_of(fabric, m).into_iter().find(|p| p.zone == zone) else {
            continue;
        };
        let Some(first) = p.order.first() else {
            continue;
        };
        let domain = &m
            .wire_named(first)
            .expect("a pref order names this member's wires")
            .domain;
        if shared(m, domain) {
            continue;
        }
        let Some(reaches) = p
            .order
            .iter()
            .skip(1)
            .find(|w| shared(m, &m.wire_named(w).expect("a declared wire").domain))
        else {
            // No wire of this member reaches anyone in this zone: it is domain-disjoint and
            // lives on the universal bond. Legitimate, and not what this check is about.
            continue;
        };
        return Err(Error::config(format!(
            "zone {zone}: {}'s rank-0 wire {first} is on domain {domain}, which no other member \
             wires into, while {reaches} does reach a peer — the cheapest interface reaches \
             nobody, so every path through {} costs more than a one-hop backup. Rank {reaches} \
             first (WIRE_PREF), or change the zone's primary domain",
            m.name, m.name
        )));
    }
    Ok(())
}

/// Distinct interface costs do NOT imply distinct path costs: in domain-disjoint topologies a
/// rank-2 link (200) can tie two rank-1 hops (100 + 100), and the kernel prunes a dead ECMP
/// nexthop without a route event. So: for every ordered pair of members, count the SHORTEST
/// paths in the zone's derived graph; two of them is an ECMP pair the fabric never asked for.
///
/// Directed, because OSPF costs are per-router per-interface: the edge m→n costs whatever `m`
/// gives the interface it leaves by. A leaf is never expanded as an intermediate node (it does
/// not transit), only reached.
fn check_no_equal_cost_paths(fabric: &Fabric, zone: &str) -> Result<()> {
    // adjacency: from → [(to, cost, via ifname)]
    let mut edges: BTreeMap<&str, Vec<(&str, u32, String)>> = BTreeMap::new();
    for m in &fabric.members {
        let offset = if m.kind == MemberKind::Leaf {
            fabric.leaf_cost_offset
        } else {
            0
        };
        let rows: Vec<ClassRow> = class_rows_of(fabric, m)
            .into_iter()
            .filter(|r| r.zone == zone)
            .collect();
        let universal: Vec<FallbackRow> = fallback_rows_of(fabric, m)
            .into_iter()
            .filter(|r| r.zone == zone)
            .collect();
        for other in &fabric.members {
            if other.name == m.name {
                continue;
            }
            let their: BTreeSet<u8> = class_rows_of(fabric, other)
                .into_iter()
                .filter(|r| r.zone == zone)
                .map(|r| r.seg)
                .collect();
            for r in &rows {
                if their.contains(&r.seg) {
                    edges.entry(&m.name).or_default().push((
                        &other.name,
                        r.ospf_cost + offset,
                        r.ifname.clone(),
                    ));
                }
            }
            // A universal segment is one broadcast domain over every wire, so any two members
            // that both have one in this zone are adjacent on it.
            // No "does the peer have wires?" guard: a member with no wires is unrepresentable
            // (the parser requires at least one), so every member with a universal segment in
            // this zone is adjacent on it.
            for r in &universal {
                edges.entry(&m.name).or_default().push((
                    &other.name,
                    r.ospf_cost + offset,
                    r.ifname.clone(),
                ));
            }
        }
    }
    for src in &fabric.members {
        // Dijkstra with shortest-path COUNTS; a count above one is an equal-cost pair.
        let mut dist: BTreeMap<&str, u32> = BTreeMap::new();
        let mut count: BTreeMap<&str, u32> = BTreeMap::new();
        let mut via: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let mut done: BTreeSet<&str> = BTreeSet::new();
        dist.insert(&src.name, 0);
        count.insert(&src.name, 1);
        while let Some((&node, &d)) = dist
            .iter()
            .filter(|(n, _)| !done.contains(**n))
            .min_by_key(|(n, d)| (**d, **n))
        {
            done.insert(node);
            // A leaf never transits: it is a destination, never a waypoint.
            if node != src.name.as_str()
                && fabric
                    .member(node)
                    .map(|m| m.kind == MemberKind::Leaf)
                    .unwrap_or(false)
            {
                continue;
            }
            for (to, cost, ifname) in edges.get(node).into_iter().flatten() {
                if done.contains(to) {
                    continue;
                }
                let nd = d + cost;
                let cur = dist.get(to).copied();
                let paths = count.get(node).copied().unwrap_or(0);
                match cur {
                    Some(c) if c < nd => {}
                    Some(c) if c == nd => {
                        *count.entry(to).or_insert(0) += paths;
                        via.entry(to).or_default().push(format!("{node}:{ifname}"));
                    }
                    _ => {
                        dist.insert(to, nd);
                        count.insert(to, paths);
                        via.insert(to, vec![format!("{node}:{ifname}")]);
                    }
                }
            }
        }
        for (dst, n) in &count {
            if *dst != src.name.as_str() && *n > 1 {
                return Err(Error::config(format!(
                    "zone {zone}: {} reaches {dst} over {n} distinct paths of equal cost {} \
                     (last hops: {}). OSPF installs both and the kernel prunes a dead ECMP \
                     nexthop with no route event, so a failure there is invisible. Change one \
                     of the zone's wire orders (WIRE_PREF) so the paths differ",
                    src.name,
                    dist.get(dst).copied().unwrap_or(0),
                    via.get(dst).map(|v| v.join(", ")).unwrap_or_default()
                )));
            }
        }
    }
    Ok(())
}

/// Every member's wire order for every zone, one line each: what `cfab gen prefs` prints.
pub fn render_prefs(fabric: &Fabric) -> String {
    let mut out = String::new();
    for m in &fabric.members {
        for p in prefs_of(fabric, m) {
            out.push_str(&format!("{} {}\n", m.name, p.render()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;

    fn fabric() -> Fabric {
        Fabric::from_raw(&RawConfig::parse(&conf_text()).unwrap()).unwrap()
    }

    fn conf_text() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
            .unwrap()
    }

    fn edited(edit: impl Fn(&mut String)) -> Fabric {
        let mut t = conf_text();
        edit(&mut t);
        Fabric::from_raw(&RawConfig::parse(&t).unwrap()).unwrap()
    }

    fn err_of(edit: impl Fn(&mut String)) -> String {
        let mut t = conf_text();
        edit(&mut t);
        Fabric::from_raw(&RawConfig::parse(&t).unwrap())
            .unwrap_err()
            .to_string()
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

    /// The default producer (spec §4 option (c)) on the reference declaration: rank 0 is the
    /// zone's declared primary domain, then speed descending with MEMBER_TABLE order on a tie.
    #[test]
    fn the_derived_order_is_primary_then_speed() {
        let f = fabric();
        let p = prefs_of(&f, f.member("pve1-tb").unwrap());
        let got: Vec<(&str, Vec<&str>, &str)> = p
            .iter()
            .map(|x| {
                (
                    x.zone.as_str(),
                    x.order.iter().map(String::as_str).collect(),
                    x.source.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("storage", vec!["eth9", "eth1", "eth0"], "derived"),
                ("cluster", vec!["eth1", "eth9", "eth0"], "derived"),
                // eth9 (5000) outranks eth1 (1000) as mgmt's first backup — the v0 hand-picked
                // costs put eth1 there. See the G1 equivalence test.
                ("mgmt", vec!["eth0", "eth9", "eth1"], "derived"),
            ]
        );
    }

    #[test]
    fn the_ladder_is_ten_then_hundreds() {
        assert_eq!(ladder_cost(0), 10);
        assert_eq!(ladder_cost(1), 100);
        assert_eq!(ladder_cost(2), 200);
        // Two hops over rank-0 wires still beat one rank-1 hop: the whole point of the ladder.
        assert!(ladder_cost(0) * 2 < ladder_cost(1));
    }

    #[test]
    fn a_wire_pref_row_replaces_the_whole_order_and_is_marked() {
        let f = edited(|t| t.push_str("\nWIRE_PREF=\"\npve1-tb storage eth1 eth9 eth0\n\"\n"));
        let p = prefs_of(&f, f.member("pve1-tb").unwrap());
        let storage = p.iter().find(|x| x.zone == "storage").unwrap();
        assert_eq!(storage.order, vec!["eth1", "eth9", "eth0"]);
        assert_eq!(storage.source, PrefSource::Override);
        assert_eq!(storage.render(), "storage: eth1 eth9 eth0 (override)");
        // ...and the costs follow the override, so the bond re-homes with it.
        let rows = class_rows_of(&f, f.member("pve1-tb").unwrap());
        let cost = |ifname: &str| rows.iter().find(|r| r.ifname == ifname).unwrap().ospf_cost;
        assert_eq!(cost("cfab-st-bk"), 10, "eth1 is rank 0 now");
        assert_eq!(cost("cfab-st"), 100);
        assert_eq!(cost("cfab-st-b2"), 200);
        assert_eq!(
            home_wire(&f, f.member("pve1-tb").unwrap(), "storage"),
            Some("eth1".to_string())
        );
        // ...and only this member's order moved.
        assert_eq!(
            prefs_of(&f, f.member("pve2-tb").unwrap())
                .into_iter()
                .find(|x| x.zone == "storage")
                .unwrap()
                .order,
            vec!["eth9", "eth1", "eth0"]
        );
    }

    #[test]
    fn the_universal_cost_is_the_longest_path_plus_one_step() {
        let f = fabric();
        // storage's domain segments cost 10 + 100 + 200 = 310 on every member.
        assert_eq!(universal_cost(&f, "storage"), 410);
        assert_eq!(universal_cost(&f, "cluster"), 410);
        assert_eq!(universal_cost(&f, "mgmt"), 410);
        let v = View::new(&f, "pve1-tb").unwrap();
        assert!(v.fallback_rows().iter().all(|r| r.ospf_cost == 410));
    }

    #[test]
    fn a_universal_cost_at_or_above_the_leaf_offset_is_refused() {
        let err = err_of(|t| *t = t.replace("LEAF_COST_OFFSET=30000", "LEAF_COST_OFFSET=400"));
        assert!(err.contains("is not below LEAF_COST_OFFSET"), "{err}");
        assert!(err.contains("raise LEAF_COST_OFFSET"), "{err}");
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
        // A domain leg is a plain sub-interface: no bond, no slaves.
        assert!(rows[0].slaves.is_empty());
        assert!(!rows[0].migrates());
        let leaf = View::new(&f, "pve3-tb").unwrap();
        assert!(leaf.gw_rows().is_empty());
    }

    /// The same declaration with the ingress on scope `any`.
    fn fabric_with_a_migrating_gw() -> Fabric {
        edited(|t| *t = t.replace("c:249:", "any:249:"))
    }

    #[test]
    fn a_gw_scope_of_any_fans_out_into_a_bond() {
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
                ("cfab-gw249-a", "eth9"),
                ("cfab-gw249-b", "eth1"),
                ("cfab-gw249-c", "eth0"),
            ]
        );
        assert!(View::new(&f, "pve3-tb").unwrap().gw_rows().is_empty());
    }

    #[test]
    fn a_migrating_gw_slave_name_fits_ifnamsiz() {
        let f = fabric_with_a_migrating_gw();
        for m in &f.members {
            for s in gw_rows_of(&f, m).iter().flat_map(|r| &r.slaves) {
                assert!(s.ifname.len() <= 15, "{}", s.ifname);
            }
        }
    }

    #[test]
    fn owned_forwarding_carries_a_migrating_gw_bond_and_its_slaves() {
        let f = fabric_with_a_migrating_gw();
        let v = View::new(&f, "pve1-tb").unwrap();
        let owned = v.owned_forwarding();
        let get = |n: &str| owned.iter().find(|(i, _)| i == n).map(|(_, t)| *t);
        assert_eq!(get("cfab-gw249"), Some(true));
        for s in ["cfab-gw249-a", "cfab-gw249-b", "cfab-gw249-c"] {
            assert_eq!(get(s), Some(false), "{s}");
            assert!(v.owns_if(s), "{s}");
        }
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
                "cfab-cl-fb-a",
                "cfab-cl-fb-b",
                "cfab-cl-fb-c",
                "cfab-id199",
                "cfab-id199-peer",
                "cfab-id249",
                "cfab-id249-peer",
                "cfab-id99",
                "cfab-id99-peer",
                "cfab-mg-fb-a",
                "cfab-mg-fb-b",
                "cfab-mg-fb-c",
                "cfab-st-fb-a",
                "cfab-st-fb-b",
                "cfab-st-fb-c",
                "eth0",
                "eth1",
                "eth9"
            ]
        );
        assert!(host.owns_if("eth9") && host.owns_if("cfab-anything"));
        assert!(!host.owns_if("docker0") && !host.owns_if("vmbr0"));
        let leaf = View::new(&f, "pve3-tb").unwrap();
        assert!(leaf.owned_forwarding().iter().all(|(_, x)| !*x));
        assert!(!leaf.owned_forwarding().is_empty());
    }

    /// The admin plane is every wire on a host (James 2026-09-06): the untagged path of each
    /// NIC is a lifeline, so all of them are guarded, none of them transits, and each gets its
    /// own ADMIN_FLOOR band. A leaf has none of ours.
    #[test]
    fn admin_ifs_are_every_wire_on_a_host_and_none_on_a_leaf() {
        let f = fabric();
        assert_eq!(
            View::new(&f, "pve1-tb").unwrap().admin_ifs(),
            vec!["eth9", "eth1", "eth0"]
        );
        assert!(View::new(&f, "pve1-tb").unwrap().is_admin_if("eth1"));
        assert!(!View::new(&f, "pve1-tb").unwrap().is_admin_if("cfab-st"));
        assert!(View::new(&f, "pve3-tb").unwrap().admin_ifs().is_empty());
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
            assert_eq!(rows.len(), 3, "{name}: one universal row per zone");
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
                        format!("{ifname}-a"),
                        format!("{ifname}-b"),
                        format!("{ifname}-c")
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
    fn wires_and_segments_of_never_see_the_universal_bond_or_its_slaves() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(v.wires(), vec!["eth0", "eth1", "eth9"]);
        assert!(!v.wires().iter().any(|w| w.contains("-fb")));
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

    // ---- G2: shapes the reference declaration does not have -------------------------

    /// A conf built from the example by replacing whole table blocks, so these fabrics stay
    /// readable next to the reference one and keep every unrelated key.
    fn conf_with(blocks: &[(&str, &str)]) -> String {
        let mut t = conf_text();
        for (key, body) in blocks {
            let head = format!("{key}=\"");
            let start = t
                .find(&head)
                .unwrap_or_else(|| panic!("no {key} in the example conf"));
            let end = t[start + head.len()..]
                .find('"')
                .expect("unterminated value")
                + start
                + head.len();
            t.replace_range(start..=end, &format!("{key}=\"{body}\""));
        }
        t
    }

    fn from_blocks(blocks: &[(&str, &str)]) -> Result<Fabric> {
        Fabric::from_raw(&RawConfig::parse(&conf_with(blocks)).unwrap())
    }

    fn order_of(f: &Fabric, member: &str, zone: &str) -> Vec<String> {
        prefs_of(f, f.member(member).unwrap())
            .into_iter()
            .find(|p| p.zone == zone)
            .unwrap()
            .order
    }

    /// A member with ONE wire is not a special case: it is rank 0 in every zone (the zone's
    /// primary domain when it happens to be there, the only candidate otherwise), so every
    /// segment it carries costs 10 and it still gets the universal bond — over one slave.
    #[test]
    fn a_one_wire_member_ranks_that_wire_first_in_every_zone() {
        let f = edited(|t| {
            *t = t
                .replace(
                    "pve1-tb 1 host eth9@a:5000 eth1@b:1000 eth0@c:1000",
                    "pve1-tb 1 host eth9@a:5000",
                )
                .replace(
                    "USB_NICS=\"pve1-tb:eth9 pve2-tb:eth9\"",
                    "USB_NICS=\"pve2-tb:eth9\"",
                );
        });
        let m = f.member("pve1-tb").unwrap();
        for zone in ["storage", "cluster", "mgmt"] {
            assert_eq!(order_of(&f, "pve1-tb", zone), vec!["eth9"], "{zone}");
        }
        let rows: Vec<(String, u32)> = class_rows_of(&f, m)
            .into_iter()
            .map(|r| (r.ifname, r.ospf_cost))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("cfab-st".to_string(), 10),
                ("cfab-cl-bk".to_string(), 10),
                ("cfab-mg-b2".to_string(), 10),
            ],
            "one wire = rank 0 everywhere, including the zones it is only a backup domain for"
        );
        let fb = fallback_rows_of(&f, m);
        assert_eq!(fb.len(), 3);
        for r in &fb {
            assert_eq!(
                r.slaves
                    .iter()
                    .map(|s| s.ifname.clone())
                    .collect::<Vec<_>>(),
                vec![format!("{}-a", r.ifname)],
                "a one-wire member still gets the bond, over its single wire"
            );
            assert_eq!(r.home, "eth9");
        }
    }

    /// Four wires on four domains: rank 0 is the zone's primary domain and the other three
    /// follow by DECLARED speed descending, so the ladder runs 10/100/200/300.
    #[test]
    fn a_four_wire_member_ranks_primary_then_speed_across_four_domains() {
        let f = from_blocks(&[
            ("DOMAINS", "a b c d"),
            (
                "MEMBER_TABLE",
                "
pve1-tb 1 host eth9@a:5000 eth1@b:1000 eth0@c:1000 eth2@d:2500
pve2-tb 2 host eth9@a:5000 eth1@b:1000 eth0@c:1000 eth2@d:2500
pve3-tb 3 leaf eth9@a:10000 eth1@b:1000 eth0@c:1000
",
            ),
            (
                "SEGMENT_TABLE",
                "
cfab-st     a   storage 1 100
cfab-st-bk  b   storage 2 101
cfab-st-b2  c   storage 3 102
cfab-st-b3  d   storage 4 103
cfab-cl     b   cluster 1 200
cfab-cl-bk  a   cluster 2 201
cfab-cl-b2  c   cluster 3 202
cfab-cl-b3  d   cluster 4 203
cfab-mg     c   mgmt    1 250
cfab-mg-bk  b   mgmt    2 251
cfab-mg-b2  a   mgmt    3 252
cfab-mg-b3  d   mgmt    4 253
cfab-st-fb  any storage 9 300
cfab-cl-fb  any cluster 9 301
cfab-mg-fb  any mgmt    9 302
",
            ),
        ])
        .unwrap();
        assert_eq!(
            order_of(&f, "pve1-tb", "storage"),
            vec!["eth9", "eth2", "eth1", "eth0"],
            "primary a, then 2500, then the two 1000s in MEMBER_TABLE order"
        );
        assert_eq!(
            order_of(&f, "pve1-tb", "cluster"),
            vec!["eth1", "eth9", "eth2", "eth0"]
        );
        assert_eq!(
            order_of(&f, "pve1-tb", "mgmt"),
            vec!["eth0", "eth9", "eth2", "eth1"]
        );
        let costs: Vec<(String, u32)> = class_rows_of(&f, f.member("pve1-tb").unwrap())
            .into_iter()
            .filter(|r| r.zone == "storage")
            .map(|r| (r.wire, r.ospf_cost))
            .collect();
        assert_eq!(
            costs,
            vec![
                ("eth9".to_string(), 10),
                ("eth1".to_string(), 200),
                ("eth0".to_string(), 300),
                ("eth2".to_string(), 100),
            ],
            "the ladder is rank-indexed, not table-indexed"
        );
        // The leaf has no wire on d, so it simply has no row there.
        assert!(
            class_rows_of(&f, f.member("pve3-tb").unwrap())
                .iter()
                .all(|r| r.ifname != "cfab-st-b3")
        );
    }

    /// A 4-member fabric where two members share no domain: h1 and h4 reach each other only
    /// through h2 or h3, and those two transits are indistinguishable, so the SPF would ECMP
    /// across them. Distinct INTERFACE costs do not imply distinct PATH costs — this is the
    /// check that catches it at validate time.
    const DISJOINT_MEMBERS: &str = "
h1 1 host eth0@a:1000
h2 2 host eth0@a:1000 eth1@b:1000
h3 3 host eth0@a:1000 eth1@b:1000
h4 4 host eth0@b:1000
";
    const ONE_ZONE_SEGMENTS: &str = "
cfab-st     a   storage 1 100
cfab-st-bk  b   storage 2 101
cfab-st-fb  any storage 9 300
";

    fn one_zone_blocks(domains: &str, members: &str, segments: &str) -> Vec<(String, String)> {
        vec![
            ("DOMAINS".to_string(), domains.to_string()),
            ("MEMBER_TABLE".to_string(), members.to_string()),
            (
                "ZONE_TABLE".to_string(),
                "\nstorage  99 0 cs0 2000 2 4 a -\n".to_string(),
            ),
            ("SEGMENT_TABLE".to_string(), segments.to_string()),
            ("FORWARD_ALLOW".to_string(), "storage>storage".to_string()),
            ("USB_NICS".to_string(), String::new()),
        ]
    }

    fn one_zone_fabric(domains: &str, members: &str, segments: &str) -> Result<Fabric> {
        let owned = one_zone_blocks(domains, members, segments);
        let blocks: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        from_blocks(&blocks)
    }

    #[test]
    fn two_equal_cost_transits_between_domain_disjoint_members_are_refused() {
        let err = one_zone_fabric("a b", DISJOINT_MEMBERS, ONE_ZONE_SEGMENTS)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("storage") && err.contains("h1") && err.contains("h4"),
            "the error must name the zone and both ends: {err}"
        );
        assert!(
            err.contains("h2") && err.contains("h3"),
            "and the two indistinguishable transits: {err}"
        );
    }

    /// The same fabric is fine once the two transits are distinguishable. Cost is a function
    /// of RANK, not of speed, so the fix is the one the error names: a WIRE_PREF row that
    /// re-ranks one transit's wires.
    #[test]
    fn the_same_fabric_passes_once_a_wire_pref_distinguishes_the_transits() {
        let owned = one_zone_blocks("a b", DISJOINT_MEMBERS, ONE_ZONE_SEGMENTS);
        let blocks: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let text = format!(
            "{}\nWIRE_PREF=\"\nh3 storage eth1 eth0\n\"\n",
            conf_with(&blocks)
        );
        let f = Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap();
        assert_eq!(order_of(&f, "h3", "storage"), vec!["eth1", "eth0"]);
        assert_eq!(order_of(&f, "h2", "storage"), vec!["eth0", "eth1"]);
    }

    /// The rank-0 check: a host whose cheapest wire for a zone is alone on its domain while
    /// another of its wires does reach a peer. Every path out then costs more than the
    /// one-hop backup, which is never what the operator meant.
    #[test]
    fn a_rank_zero_wire_alone_on_its_domain_is_refused_when_another_wire_reaches_a_peer() {
        let members = "
h1 1 host eth2@d:1000 eth0@a:1000
h2 2 host eth0@a:1000 eth1@b:1000
h3 3 host eth0@a:1000 eth1@b:1000
";
        let segments = "
cfab-st     a   storage 1 100
cfab-st-bk  b   storage 2 101
cfab-st-b3  d   storage 4 103
cfab-st-fb  any storage 9 300
";
        let owned = one_zone_blocks("a b d", members, segments);
        let mut blocks: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let zone = "\nstorage  99 0 cs0 2000 2 4 d -\n";
        for b in &mut blocks {
            if b.0 == "ZONE_TABLE" {
                b.1 = zone;
            }
        }
        let err = from_blocks(&blocks).unwrap_err().to_string();
        assert!(
            err.contains("h1") && err.contains("eth2") && err.contains("domain d"),
            "name the member, the rank-0 wire and its lonely domain: {err}"
        );
        assert!(
            err.contains("eth0") && err.contains("WIRE_PREF"),
            "and the wire that does reach a peer, plus the remedy: {err}"
        );
    }

    /// The same lonely domain is NOT an error when no wire of that member reaches anyone:
    /// that member is domain-disjoint and the universal bond is exactly what serves it.
    #[test]
    fn a_member_alone_on_every_domain_is_not_a_rank_zero_error() {
        let members = "
h1 1 host eth2@d:1000
h2 2 host eth0@a:1000 eth1@b:1000
h3 3 host eth0@a:1000 eth1@b:1000
";
        let segments = "
cfab-st     a   storage 1 100
cfab-st-bk  b   storage 2 101
cfab-st-b3  d   storage 4 103
cfab-st-fb  any storage 9 300
";
        let f = one_zone_fabric("a b d", members, segments).unwrap();
        assert_eq!(order_of(&f, "h1", "storage"), vec!["eth2"]);
    }

    #[test]
    fn gen_prefs_renders_every_member_and_zone() {
        let f = fabric();
        let out = render_prefs(&f);
        assert_eq!(out.lines().count(), 9);
        assert!(
            out.contains("pve1-tb storage: eth9 eth1 eth0 (derived)"),
            "{out}"
        );
        assert!(
            out.contains("pve3-tb mgmt: eth0 eth9 eth1 (derived)"),
            "{out}"
        );
    }
}
