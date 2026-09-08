//! The typed fabric — the model `fabric.toml` is turned into.
//!
//! `decl` parses the file into a struct tree; this module resolves that tree into the typed
//! model everything downstream reads (`Fabric::from_decl`), and `Fabric::validate` enforces
//! every invariant the shape alone cannot: unique member names, node ids, segment vids and
//! interface names, one segment per zone x domain, known zones and known domains everywhere
//! either is named, at most one wire per member per domain, a member with at least one wire,
//! complete per-zone preference overrides, and ingress gateways that collide with neither a
//! segment vid nor any member's leg address.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::decl::Declaration;
use crate::error::{Error, Result};

/// A physical switch domain: an opaque DECLARED token, so a typo in a wire's or a segment's
/// domain is an error and not a phantom domain. One letter — the bond-port suffix
/// `-<domain>` must fit inside IFNAMSIZ (see `MAX_BOND_IFNAME`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct DomainId(String);

/// The widest a domain token may be. One character, and `MAX_BOND_IFNAME` is derived from it:
/// widen this and every bond-leg name budget follows automatically.
pub const MAX_DOMAIN_TOKEN: usize = 1;

impl DomainId {
    pub fn parse(s: &str) -> Result<DomainId> {
        if s.len() != MAX_DOMAIN_TOKEN || !s.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(Error::config(format!(
                "domain '{s}' is not a switch-domain token (one ASCII letter, e.g. a)"
            )));
        }
        Ok(DomainId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a segment (or an ingress leg) lives: on one switch domain, or on every wire the
/// member has. `Universal` is a SCOPE, not a domain: exactly the old `island any` fallback row,
/// fanned out by the derive layer into an active-backup bond over the member's wires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SegScope {
    Domain(DomainId),
    /// Not a physical switch domain: "every wire this member has".
    Universal,
}

impl SegScope {
    pub fn parse(s: &str) -> Result<SegScope> {
        if s == "any" {
            return Ok(SegScope::Universal);
        }
        Ok(SegScope::Domain(DomainId::parse(s)?))
    }

    pub fn domain(&self) -> Option<&DomainId> {
        match self {
            SegScope::Domain(d) => Some(d),
            SegScope::Universal => None,
        }
    }

    pub fn is_universal(&self) -> bool {
        matches!(self, SegScope::Universal)
    }
}

impl fmt::Display for SegScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SegScope::Domain(d) => f.write_str(d.as_str()),
            SegScope::Universal => f.write_str("any"),
        }
    }
}

/// Membership taxonomy. A closed set, so `kind = "router"` fails at parse naming host|leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum MemberKind {
    /// Transits between zones, shapes, carries every domain it has wires on.
    Host,
    /// Own identity + OSPF/BFD, stub-router, never transits, no shaping; its
    /// untagged/externally-managed L3 is never touched (the NAS).
    Leaf,
}

/// A member's physical NIC, the switch domain it is plugged into, and its DECLARED link speed
/// (Mb/s). One wire is pinned to exactly ONE domain: a single NIC into a single switch IS one
/// domain, and the "one wire, several domains" trunk is deliberately not modelled (spec §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Wire {
    pub name: String,
    pub domain: DomainId,
    pub speed_mbps: u32,
    /// The declared `ethtool -K` words for this NIC, validated at load, applied on bringup and
    /// restored by `down`. `None` = cfab does not touch this NIC's features at all.
    pub driver_features: Option<String>,
}

/// The widest ifname a bond leg (a universal segment, or a migrating ingress leg) may carry.
/// Its ports are named `<ifname>-<domain>`: a separator plus a domain token inside IFNAMSIZ 15.
pub const MAX_BOND_IFNAME: usize = 15 - 1 - MAX_DOMAIN_TOKEN;

/// Does this bond-leg name leave room for the `-<domain>` suffix its ports need? One
/// predicate for both legs, so the rule cannot drift between them.
fn bond_ifname_too_long(ifname: &str) -> bool {
    ifname.len() > MAX_BOND_IFNAME
}

/// One `[[member]]` row.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    /// Node id: the host octet of every address this member holds (identity 10.<id>.0.<node>).
    pub node: u8,
    pub kind: MemberKind,
    /// Every wire this member has, in declaration order (the tie-break for equal speeds).
    ///
    /// The admin plane is not a column: on a host the UNTAGGED path of every one of these
    /// wires is the admin plane (the SSH lifeline that works with the routing stack stopped),
    /// so every wire gets the nft admin treatment and its own `[admin] floor_mbps` band. A leaf owns no
    /// L3 of ours on any wire.
    pub wires: Vec<Wire>,
    /// This member's addresses on `[[workload]]` interfaces it carries. A leaf carries none
    /// (`validate` refuses one that does).
    pub workloads: Vec<MemberWorkload>,
}

impl Member {
    /// This member's wire on `domain`, if it has one. At most one by construction: two wires on
    /// one domain are refused at parse (`validate`).
    pub fn wire_on(&self, domain: &DomainId) -> Option<&Wire> {
        self.wires.iter().find(|w| w.domain == *domain)
    }

    pub fn wire_named(&self, name: &str) -> Option<&Wire> {
        self.wires.iter().find(|w| w.name == name)
    }
}

/// DSCP class selectors the fabric uses. A closed set on purpose: the shaper must know each
/// value's tos byte, and each value needs measured switch-queue behavior behind it — extend
/// this enum, with both, when a new band appears. A value outside it fails at parse, naming
/// the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Dscp {
    Cs0,
    Cs2,
    Cs6,
}

impl Dscp {
    pub fn as_str(self) -> &'static str {
        match self {
            Dscp::Cs0 => "cs0",
            Dscp::Cs2 => "cs2",
            Dscp::Cs6 => "cs6",
        }
    }

    /// IP tos byte (DSCP<<2), as the shaper's flower filters match it.
    pub fn tos(self) -> &'static str {
        match self {
            Dscp::Cs0 => "0x00",
            Dscp::Cs2 => "0x40",
            Dscp::Cs6 => "0xc0",
        }
    }
}

impl fmt::Display for Dscp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the OUTSIDE enters a zone: a router-owned VLAN, distinct from every fabric segment,
/// so the router never holds an address inside a segment and never sees the fabric's IGP.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ZoneGw {
    pub scope: SegScope,
    pub vid: u16,
    /// The router's address; the subnet is its /24 (the only length the design supports).
    pub router: String,
}

impl ZoneGw {
    /// `a.b.c` of the router's /24.
    pub fn subnet_prefix(&self) -> &str {
        self.router
            .rsplit_once('.')
            .map(|(p, _)| p)
            .unwrap_or(&self.router)
    }

    /// This node's address on the ingress leg (the router's /24, host octet = node).
    pub fn leg_cidr(&self, node: u8) -> String {
        format!("{}.{node}/24", self.subnet_prefix())
    }

    /// The router's host octet. Infallible: `resolve_gw` proved the address is four u8
    /// octets before this type existed, and nothing else constructs a `ZoneGw`.
    pub fn router_octet(&self) -> u8 {
        self.router
            .rsplit_once('.')
            .and_then(|(_, o)| o.parse().ok())
            .unwrap_or_else(|| {
                panic!(
                    "gw router '{}' is not an IPv4 address, which resolve_gw refuses",
                    self.router
                )
            })
    }
}

/// A traffic class and the segments that carry it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Zone {
    pub name: String,
    /// The zone's number: OSPF instance, identity netdev cfab-id<id>, block 10.<id>.0.0/16.
    /// NOT a VLAN id (segments carry those).
    pub id: u8,
    /// 802.1p for the zone's traffic (sub-if egress-qos-map 0:pcp).
    pub pcp: u8,
    /// The plane a DSCP-trusting switch queues the zone's traffic on.
    pub dscp: Dscp,
    /// MINIMUM Mb/s guarantee for the zone's HTB band.
    pub floor_mbps: u32,
    /// HTB prio band (0 = control … 2 = bulk).
    pub band: u32,
    /// Quantum ratio within a shared band.
    pub weight: u32,
    /// The switch domain whose segment is this zone's rank-0 (primary) wire on every member
    /// that has a wire there. The one part of preference that IS physical-layout policy, so it
    /// is declared globally and not derived; the backup order below it is derived from speed.
    pub primary: DomainId,
    /// Ingress, or None = the outside never enters this zone.
    pub gw: Option<ZoneGw>,
}

impl Zone {
    /// `10.<id>` — the zone's identity/segment block prefix.
    pub fn block(&self) -> String {
        format!("10.{}", self.id)
    }
}

/// One a zone's `segments` row: zone `zone` on scope `scope`, addressed 10.<id>.<seg>.<node>/24,
/// tagged `vid`. A segment carries no role and no cost: both are derived (spec §4).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Segment {
    pub ifname: String,
    pub scope: SegScope,
    pub zone: String,
    pub seg: u8,
    pub vid: u16,
}

/// One a member's `prefs` row: this member's complete wire order for this zone, replacing the derived
/// one. Complete or an error — an override is never blended with the default.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WirePref {
    pub member: String,
    pub zone: String,
    pub order: Vec<String>,
}

/// Whether a workload's VLAN stays switch-local (phase 1) or becomes a routed per-host prefix
/// (phase 2, not built yet). `span = "host"` is accepted by the schema and refused at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Span {
    Switch,
    Host,
}

/// An IPv4 network: address + prefix length, with the host bits cleared. `parse` refuses a
/// string whose address is not already aligned to its own mask (e.g. `192.168.20.5/24`) with
/// the same message a missing `/len` gets — both are "not a valid prefix", not two things.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Ipv4Prefix {
    pub net: Ipv4Addr,
    pub len: u8,
}

impl Ipv4Prefix {
    fn mask(len: u8) -> u32 {
        if len == 0 { 0 } else { u32::MAX << (32 - len) }
    }

    pub fn parse(s: &str) -> std::result::Result<Ipv4Prefix, String> {
        let bad = || {
            format!("prefix '{s}' is not an IPv4 prefix with a length (example: 192.168.20.0/24)")
        };
        let (addr, len) = s.split_once('/').ok_or_else(bad)?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| bad())?;
        let len: u8 = len.parse().map_err(|_| bad())?;
        if len > 32 {
            return Err(bad());
        }
        let raw = u32::from(addr);
        let net = raw & Self::mask(len);
        if net != raw {
            return Err(bad());
        }
        Ok(Ipv4Prefix {
            net: Ipv4Addr::from(net),
            len,
        })
    }

    pub fn contains(&self, a: Ipv4Addr) -> bool {
        (u32::from(a) & Self::mask(self.len)) == u32::from(self.net)
    }

    /// The network address plus one — the lowest usable host in the prefix.
    pub fn first_host(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.net).saturating_add(1))
    }

    /// The broadcast address: every host bit set.
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.net) | !Self::mask(self.len))
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.len)
    }
}

/// One `[[workload]]` row, typed (spec §4): a VM workload VLAN, its anycast gateway, and the
/// zones it may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Workload {
    pub name: String,
    pub ifname: String,
    pub prefix: Ipv4Prefix,
    /// The anycast gateway every host answers (bare address; the prefix's mask applies).
    pub gw: Ipv4Addr,
    /// The VLAN's existing default router, inside DHCP option 121 (RULED, spec §10 call 14).
    pub router: Ipv4Addr,
    /// Zones this workload may reach; validated against the declared zones.
    pub allow: Vec<String>,
    /// Phase 1: always `Switch` (`span = "host"` is refused at load).
    pub span: Span,
}

impl Workload {
    /// `gw` with the prefix's mask, e.g. `192.168.20.254/24`.
    pub fn gw_cidr(&self) -> String {
        format!("{}/{}", self.gw, self.prefix.len)
    }
}

/// One member's address on a `[[workload]]` interface it carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberWorkload {
    pub name: String,
    pub address: Ipv4Addr,
    pub len: u8,
}

impl MemberWorkload {
    pub fn address_cidr(&self) -> String {
        format!("{}/{}", self.address, self.len)
    }
}

/// The whole declaration, typed. Everything the deployed runtime needs and nothing it computes.
///
/// `PartialEq` is the derived, ORDER-SENSITIVE comparison: `[[member]]` / `[[zone]]` / segment
/// row order feeds the derived wire preferences and leg naming, so reordering rows IS a
/// different fabric. Only TOML key order inside a table, comments and whitespace are invisible.
/// The supervisor's reload decision (`classify_reload`) relies on exactly this.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Fabric {
    /// The declared switch domains, in declaration order.
    pub domains: Vec<DomainId>,
    pub members: Vec<Member>,
    pub zones: Vec<Zone>,
    pub segments: Vec<Segment>,
    pub wire_prefs: Vec<WirePref>,
    pub leaf_cost_offset: u32,
    pub host_forward: bool,
    /// Allowed forward pairs (from, to); unlisted = dropped by policy, counted.
    pub forward_allow: Vec<(String, String)>,
    pub admin_floor_mbps: u32,
    pub admin_band: u32,
    pub pcp_ctrl: u8,
    pub dscp_mark: bool,
    pub bfd_rx_ms: u32,
    pub bfd_tx_ms: u32,
    pub bfd_mult: u32,
    /// UDP port for single-hop BFD (RFC 5881: 3784). A port is an external contract — every
    /// member and every peer must agree — so it is a declared key, not a derived threshold.
    pub bfd_port: u16,
    pub ospf_hello: u32,
    pub ospf_dead: u32,
    pub bgp_as: u32,
    pub bgp_keepalive_s: u32,
    pub bgp_hold_s: u32,
    pub bgp_connect_s: u32,
    /// Runtime state dir written by `up`, read by `status` and the daemons (`[runtime] run_dir`).
    pub run_dir: String,
    pub dns_domain: String,
    /// `[[workload]]` rows, in declaration order.
    pub workloads: Vec<Workload>,
}

/// RFC 5881's single-hop port, as `[bfd] port` defaults to it.
pub const BFD_PORT_DEFAULT: u16 = crate::decl::BFD_PORT;

/// The lowest port the engine may be told to bind: it drops privileges before opening its
/// BFD socket, so anything below 1024 would fail at start instead of here.
const MIN_BFD_PORT: u16 = 1024;

/// A zone's ingress row, typed. The router is declared WITH its prefix (`.../24`, the only
/// length the design supports) and stored without it, because every derived address is built
/// from the /24 it names.
fn resolve_gw(zone: &str, g: &crate::decl::GwDecl) -> Result<ZoneGw> {
    let bad = || {
        Error::config(format!(
            "zone {zone}: gw router '{}' (expected an IPv4 address with /24, e.g. \
             192.168.249.254/24)",
            g.router
        ))
    };
    let (router, len) = g.router.split_once('/').ok_or_else(bad)?;
    if len != "24" {
        return Err(bad());
    }
    if router.split('.').count() != 4 || router.split('.').any(|o| o.parse::<u8>().is_err()) {
        return Err(bad());
    }
    Ok(ZoneGw {
        scope: SegScope::parse(&g.domain)
            .map_err(|e| Error::context(format!("zone {zone}: gw "), e))?,
        vid: g.vid,
        router: router.to_string(),
    })
}

/// A member's own address on a `[[workload]]` interface: `a.b.c.d/len`, a HOST address (not
/// masked to its network — unlike `Ipv4Prefix`, whose whole point is that it IS the network).
fn parse_ipv4_with_len(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, len) = s.split_once('/')?;
    let addr: Ipv4Addr = addr.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    if len > 32 {
        return None;
    }
    Some((addr, len))
}

/// One `[[workload]]` row, typed. `prefix`/`gw`/`router` malformed-value messages are named
/// here so `from_decl` reads as one gate per row; cross-row and cross-table meaning (zone
/// collisions, which member carries it) is `Fabric::validate`'s job.
fn resolve_workload(w: &crate::decl::WorkloadDecl) -> Result<Workload> {
    let prefix = Ipv4Prefix::parse(&w.prefix)
        .map_err(|e| Error::config(format!("workload {}: {e}", w.name)))?;
    let gw: Ipv4Addr = w.gw.parse().map_err(|_| {
        Error::config(format!(
            "workload {}: gw '{}' must be a bare IPv4 address (the prefix's mask is applied)",
            w.name, w.gw
        ))
    })?;
    let router: Ipv4Addr = w.router.parse().map_err(|_| {
        Error::config(format!(
            "workload {}: router '{}' must be a bare IPv4 address (the VLAN's existing default \
             router)",
            w.name, w.router
        ))
    })?;
    let span = match w.span.as_deref() {
        None | Some("switch") => Span::Switch,
        Some("host") => {
            return Err(Error::config(format!(
                "workload {}: span = \"host\" is phase 2 and not built yet (omit it, or span = \
                 \"switch\")",
                w.name
            )));
        }
        Some(s) => {
            return Err(Error::config(format!(
                "workload {}: span '{s}' is not one of switch, host",
                w.name
            )));
        }
    };
    Ok(Workload {
        name: w.name.clone(),
        ifname: w.ifname.clone(),
        prefix,
        gw,
        router,
        allow: w.allow.clone(),
        span,
    })
}

impl Fabric {
    /// Resolve a parsed declaration into the typed model, then validate it. The declaration's
    /// SHAPE was already proven by serde; everything here is meaning.
    pub fn from_decl(d: &Declaration) -> Result<Fabric> {
        let domains = d
            .domains
            .keys()
            .map(|t| DomainId::parse(t))
            .collect::<Result<Vec<_>>>()?;
        let mut members = Vec::new();
        let mut wire_prefs = Vec::new();
        for m in &d.members {
            let mut wires = Vec::new();
            for w in &m.wires {
                let ctx = || format!("member {}: wire {}: ", m.name, w.nic);
                let domain = DomainId::parse(&w.domain).map_err(|e| Error::context(ctx(), e))?;
                // The retired `usb` flag: refuse by name with the replacement, rather than let
                // `deny_unknown_fields` say "unknown field `usb`" and leave the operator
                // guessing what the mitigation became.
                if w.usb.is_some() {
                    return Err(Error::config(format!(
                        "{}'usb' is gone; declare driver_features = \"sg off tso off gso off\" \
                         instead (the words go to `ethtool -K <nic>` as written)",
                        ctx()
                    )));
                }
                if let Some(spec) = &w.driver_features {
                    crate::driver_features::parse(spec).map_err(|e| Error::context(ctx(), e))?;
                }
                wires.push(Wire {
                    name: w.nic.clone(),
                    domain,
                    speed_mbps: w.speed_mbps,
                    driver_features: w.driver_features.clone(),
                });
            }
            // A zone appears at most once per member (a TOML table has one key per name), so
            // the only completeness question left is the one `check_wire_prefs` asks.
            for (zone, order) in &m.prefs {
                wire_prefs.push(WirePref {
                    member: m.name.clone(),
                    zone: zone.clone(),
                    order: order.clone(),
                });
            }
            let mut workloads = Vec::new();
            for mw in &m.workloads {
                let (address, len) = parse_ipv4_with_len(&mw.address).ok_or_else(|| {
                    Error::config(format!(
                        "member {}: workload {}: address '{}' is not an IPv4 address with a length",
                        m.name, mw.name, mw.address
                    ))
                })?;
                workloads.push(MemberWorkload {
                    name: mw.name.clone(),
                    address,
                    len,
                });
            }
            members.push(Member {
                name: m.name.clone(),
                node: m.node,
                kind: m.kind,
                wires,
                workloads,
            });
        }
        let mut zones = Vec::new();
        let mut segments = Vec::new();
        for z in &d.zones {
            // Declaration order inside a zone, zones in declaration order: the order every
            // derived per-member row list inherits.
            for s in &z.segments {
                let domain = DomainId::parse(&s.domain).map_err(|e| {
                    Error::context(format!("zone {}: segment {}: ", z.name, s.ifname), e)
                })?;
                segments.push(Segment {
                    ifname: s.ifname.clone(),
                    scope: SegScope::Domain(domain),
                    zone: z.name.clone(),
                    seg: s.seg,
                    vid: s.vid,
                });
            }
            if let Some(u) = &z.universal {
                segments.push(Segment {
                    ifname: u.ifname.clone(),
                    scope: SegScope::Universal,
                    zone: z.name.clone(),
                    seg: u.seg,
                    vid: u.vid,
                });
            }
            let gw = match &z.gw {
                Some(g) => Some(resolve_gw(&z.name, g)?),
                None => None,
            };
            zones.push(Zone {
                name: z.name.clone(),
                id: z.id,
                pcp: z.pcp,
                dscp: z.dscp,
                floor_mbps: z.floor_mbps,
                band: z.band,
                weight: z.weight,
                primary: DomainId::parse(&z.primary)
                    .map_err(|e| Error::context(format!("zone {}: primary ", z.name), e))?,
                gw,
            });
        }
        let workloads = d
            .workload
            .iter()
            .map(resolve_workload)
            .collect::<Result<Vec<_>>>()?;
        let forward_allow = d
            .forward
            .allow
            .iter()
            .map(|pair| {
                pair.split_once('>')
                    .map(|(f, t)| (f.to_string(), t.to_string()))
                    .ok_or_else(|| {
                        Error::config(format!("[forward] allow '{pair}' (expected \"from>to\")"))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let admin = d.admin.clone().unwrap_or_default();
        let marking = d.marking.clone().unwrap_or_default();
        let cost = d.cost.clone().unwrap_or_default();
        let bfd = d.bfd.clone().unwrap_or_default();
        let ospf = d.ospf.clone().unwrap_or_default();
        let bgp = d.bgp.clone().unwrap_or_default();
        let runtime = d.runtime.clone().unwrap_or_default();
        // 7 is representable on the wire but SO_PRIORITY 7 needs CAP_NET_ADMIN, which the
        // engine drops before it opens its sockets; the failure there is a logged raise and a
        // silently down interface, so the declaration refuses it here instead.
        if marking.pcp_ctrl > 6 {
            return Err(Error::config(format!(
                "[marking] pcp_ctrl = {} is outside 0..6 (7 needs CAP_NET_ADMIN on the \
                 engine's control sockets)",
                marking.pcp_ctrl
            )));
        }
        if bfd.port < MIN_BFD_PORT {
            return Err(Error::config(format!(
                "[bfd] port = {} is outside {MIN_BFD_PORT}..65535",
                bfd.port
            )));
        }
        let fabric = Fabric {
            domains,
            members,
            zones,
            segments,
            wire_prefs,
            leaf_cost_offset: cost.leaf_offset,
            host_forward: d.forward.enabled,
            forward_allow,
            admin_floor_mbps: admin.floor_mbps,
            admin_band: admin.band,
            pcp_ctrl: marking.pcp_ctrl,
            dscp_mark: marking.set_dscp,
            bfd_rx_ms: bfd.rx_ms,
            bfd_tx_ms: bfd.tx_ms,
            bfd_mult: bfd.mult,
            bfd_port: bfd.port,
            ospf_hello: ospf.hello_s,
            ospf_dead: ospf.dead_s,
            bgp_as: bgp.asn,
            bgp_keepalive_s: bgp.keepalive_s,
            bgp_hold_s: bgp.hold_s,
            bgp_connect_s: bgp.connect_s,
            run_dir: runtime.run_dir,
            dns_domain: d.dns_domain.clone(),
            workloads,
        };
        fabric.validate()?;
        Ok(fabric)
    }

    /// Declaration consistency, checked for the whole fabric — not just the running member —
    /// so one member's `check` catches a collision that would only bite another.
    pub fn validate(&self) -> Result<()> {
        fn dup<I: Iterator<Item = String>>(mut items: I) -> Option<String> {
            let mut seen = BTreeSet::new();
            items.find(|i| !seen.insert(i.clone()))
        }
        // ---- domains first: nothing below may index by a domain that was never declared ----
        if self.domains.is_empty() {
            return Err(Error::config(
                "[domains] is empty (declare one token per physical switch domain, e.g. a = \"the 10G \
                 switch\")"
                    .to_string(),
            ));
        }
        let declared: BTreeSet<&DomainId> = self.domains.iter().collect();
        for m in &self.members {
            // Representable in the file (`wires = []`) and meaningless in the fabric: a member
            // with no wire has no segment, no admin plane and no bond to fan out. Refused here
            // so every derivation downstream may assume at least one wire.
            if m.wires.is_empty() {
                return Err(Error::config(format!(
                    "member {}: declares no wires (a member needs at least one \
                     wire = {{ nic, domain, speed_mbps }})",
                    m.name
                )));
            }
            for w in &m.wires {
                if !declared.contains(&w.domain) {
                    return Err(Error::config(format!(
                        "member {}: wire {} on domain {} is not in [domains] ({})",
                        m.name,
                        w.name,
                        w.domain,
                        self.domains_list()
                    )));
                }
            }
            // Refused, not merely unbuilt: a domain has exactly one segment per zone, addressed
            // 10.<id>.<seg>.<node>/24, so two wires in one broadcast domain would hold two
            // addresses of one /24 on one node — ARP-ambiguous.
            let mut seen: BTreeSet<&DomainId> = BTreeSet::new();
            for w in &m.wires {
                if !seen.insert(&w.domain) {
                    return Err(Error::config(format!(
                        "member {}: two wires on domain {} ({}). The model cannot express \
                         it: a domain has one segment per zone, addressed 10.<id>.<seg>.<node>/24, \
                         so two wires in one broadcast domain would hold two addresses of one /24 \
                         on one node — ARP-ambiguous. Put the wires in different domains. The \
                         other coherent shape is one bond over both NICs declared as a single \
                         wire, which cfab does not build yet",
                        m.name,
                        w.domain,
                        m.wires
                            .iter()
                            .filter(|x| x.domain == w.domain)
                            .map(|x| x.name.as_str())
                            .collect::<Vec<_>>()
                            .join(" "),
                    )));
                }
            }
        }
        for s in &self.segments {
            if let Some(d) = s.scope.domain()
                && !declared.contains(d)
            {
                return Err(Error::config(format!(
                    "segment {}: domain {d} is not in [domains] ({})",
                    s.ifname,
                    self.domains_list()
                )));
            }
        }
        for z in &self.zones {
            if !declared.contains(&z.primary) {
                return Err(Error::config(format!(
                    "zone {}: primary domain {} is not in [domains] ({})",
                    z.name,
                    z.primary,
                    self.domains_list()
                )));
            }
            if let Some(gw) = &z.gw
                && let Some(d) = gw.scope.domain()
                && !declared.contains(d)
            {
                return Err(Error::config(format!(
                    "zone {}: gw domain {d} is not in [domains] ({})",
                    z.name,
                    self.domains_list()
                )));
            }
        }
        // The other direction of the two-directional check: a declared domain nobody wires into
        // is a typo or a switch that left the fabric, and every segment on it is dead weight.
        for d in &self.domains {
            if !self.members.iter().any(|m| m.wire_on(d).is_some()) {
                return Err(Error::config(format!(
                    "[domains] declares {d} but no member has a wire on it (drop the token, or \
                     give a member a wire on domain {d})"
                )));
            }
        }
        // ---- segments ----
        let st = &self.segments;
        if let Some(d) = dup(st.iter().map(|r| r.vid.to_string())) {
            return Err(Error::config(format!(
                "vid {d} used by two segments (one VLAN id per segment)"
            )));
        }
        if let Some(d) = dup(st.iter().map(|r| format!("{}:{}", r.zone, r.seg))) {
            return Err(Error::config(format!("segment {d} declared twice")));
        }
        if let Some(d) = dup(st.iter().map(|r| format!("{}:{}", r.zone, r.scope))) {
            return Err(Error::config(format!(
                "zone:domain {d} declared twice (a zone has one segment per domain, and one \
                 universal segment)"
            )));
        }
        if let Some(d) = dup(st.iter().map(|r| r.ifname.clone())) {
            return Err(Error::config(format!("segment ifname {d} declared twice")));
        }
        for r in st {
            self.zone(&r.zone)?;
        }
        for r in st.iter().filter(|r| r.scope.is_universal()) {
            if bond_ifname_too_long(&r.ifname) {
                return Err(Error::config(format!(
                    "zone {}: the universal leg's ifname must be \
                     {MAX_BOND_IFNAME} characters or fewer (ports are named <ifname>-<domain>, \
                     IFNAMSIZ 15)",
                    r.ifname
                )));
            }
        }
        // ---- zones ----
        if let Some(d) = dup(self.zones.iter().map(|z| z.id.to_string())) {
            return Err(Error::config(format!("zone id {d} used twice")));
        }
        for z in &self.zones {
            if z.id < 1 {
                return Err(Error::config(format!(
                    "zone id {} is not a valid block octet (1-254)",
                    z.id
                )));
            }
            // The rank-0 wire of every member is the wire on this domain, so a primary domain
            // with no segment in this zone leaves the whole zone with no rank 0 at all.
            if !st
                .iter()
                .any(|r| r.zone == z.name && r.scope == SegScope::Domain(z.primary.clone()))
            {
                return Err(Error::config(format!(
                    "zone {}: primary domain {} has no segment (the zone's rank-0 wire is the \
                     wire on its primary domain)",
                    z.name, z.primary
                )));
            }
        }
        // ---- members ----
        if let Some(d) = dup(self.members.iter().map(|m| m.name.clone())) {
            return Err(Error::config(format!("member {d} declared twice")));
        }
        if let Some(d) = dup(self.members.iter().map(|m| m.node.to_string())) {
            return Err(Error::config(format!("node id {d} used twice")));
        }
        // ---- wire preference overrides ----
        self.check_wire_prefs()?;
        // ---- the rest, unchanged ----
        for (from, to) in &self.forward_allow {
            for z in [from, to] {
                if self.zones.iter().all(|zz| zz.name != *z) {
                    return Err(Error::config(format!(
                        "[forward] allow '{from}>{to}': unknown zone '{z}'"
                    )));
                }
            }
        }
        // ---- workloads ----
        let mut seen = BTreeSet::new();
        for wl in &self.workloads {
            if self.zone(&wl.name).is_ok() {
                return Err(Error::config(format!(
                    "workload {}: name is also a zone (workload and zone names share one \
                     vocabulary)",
                    wl.name
                )));
            }
            if !seen.insert(wl.name.clone()) {
                return Err(Error::config(format!(
                    "workload {}: declared twice",
                    wl.name
                )));
            }
            // An ifname cfab already creates or owns by declaration: a declared wire, a
            // declared segment/universal sub-if, or a zone's generated ingress/identity leg.
            let collides = self
                .members
                .iter()
                .any(|m| m.wires.iter().any(|w| w.name == wl.ifname))
                || self.segments.iter().any(|s| s.ifname == wl.ifname)
                || self.zones.iter().any(|z| {
                    wl.ifname == format!("cfab-gw{}", z.id)
                        || wl.ifname == format!("cfab-id{}", z.id)
                        || wl.ifname == format!("cfab-id{}-peer", z.id)
                });
            if collides {
                return Err(Error::config(format!(
                    "workload {}: ifname '{}' collides with an interface cfab creates",
                    wl.name, wl.ifname
                )));
            }
            if !wl.prefix.contains(wl.gw) {
                return Err(Error::config(format!(
                    "workload {}: gw {} is outside prefix {}",
                    wl.name, wl.gw, wl.prefix
                )));
            }
            if wl.gw == wl.prefix.net || wl.gw == wl.prefix.broadcast() {
                return Err(Error::config(format!(
                    "workload {}: gw {} is the network or broadcast address of {}",
                    wl.name, wl.gw, wl.prefix
                )));
            }
            if !wl.prefix.contains(wl.router) {
                return Err(Error::config(format!(
                    "workload {}: router {} is outside prefix {}",
                    wl.name, wl.router, wl.prefix
                )));
            }
            if wl.router == wl.prefix.net || wl.router == wl.prefix.broadcast() {
                return Err(Error::config(format!(
                    "workload {}: router {} is the network or broadcast address of {}",
                    wl.name, wl.router, wl.prefix
                )));
            }
            if wl.allow.is_empty() {
                return Err(Error::config(format!(
                    "workload {}: allow is empty; a workload must reach at least one zone",
                    wl.name
                )));
            }
            if !self.host_forward {
                return Err(Error::config(format!(
                    "workload {}: allow is non-empty but [forward] enabled = false; enable \
                     forwarding or remove allow",
                    wl.name
                )));
            }
            for z in &wl.allow {
                if self.zone(z).is_err() {
                    let zones = self
                        .zones
                        .iter()
                        .map(|z| z.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(Error::config(format!(
                        "workload {}: allow '{}': unknown zone (zones: {})",
                        wl.name, z, zones
                    )));
                }
            }
            if !self
                .members
                .iter()
                .any(|m| m.workloads.iter().any(|w| w.name == wl.name))
            {
                return Err(Error::config(format!(
                    "workload {}: no member carries it (add workloads = [{{ name = \"{}\", \
                     address = \"<host address>/{}\" }}] to a member)",
                    wl.name, wl.name, wl.prefix.len
                )));
            }
        }
        for m in &self.members {
            let mut seen_member_workload = BTreeSet::new();
            for mw in &m.workloads {
                if !seen_member_workload.insert(mw.name.clone()) {
                    return Err(Error::config(format!(
                        "member {}: workload {} is declared twice",
                        m.name, mw.name
                    )));
                }
                let Some(wl) = self.workload(&mw.name) else {
                    let names = self
                        .workloads
                        .iter()
                        .map(|w| w.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(Error::config(format!(
                        "member {}: workload '{}' is not a declared [[workload]] (workloads: {})",
                        m.name, mw.name, names
                    )));
                };
                if m.kind == MemberKind::Leaf {
                    return Err(Error::config(format!(
                        "member {}: workload {}: a leaf carries no workload (kind = leaf)",
                        m.name, wl.name
                    )));
                }
                if !wl.prefix.contains(mw.address) {
                    return Err(Error::config(format!(
                        "member {}: workload {}: address {} is outside prefix {}",
                        m.name,
                        wl.name,
                        mw.address_cidr(),
                        wl.prefix
                    )));
                }
                if mw.len != wl.prefix.len {
                    return Err(Error::config(format!(
                        "member {}: workload {}: address {} must carry the prefix's mask /{}",
                        m.name,
                        wl.name,
                        mw.address_cidr(),
                        wl.prefix.len
                    )));
                }
                if mw.address == wl.gw {
                    return Err(Error::config(format!(
                        "member {}: workload {}: address {} is the gateway {}",
                        m.name,
                        wl.name,
                        mw.address_cidr(),
                        wl.gw
                    )));
                }
                if mw.address == wl.prefix.net || mw.address == wl.prefix.broadcast() {
                    return Err(Error::config(format!(
                        "member {}: workload {}: address {} is the network or broadcast \
                         address of {}",
                        m.name,
                        wl.name,
                        mw.address_cidr(),
                        wl.prefix
                    )));
                }
            }
        }
        for z in &self.zones {
            let Some(gw) = &z.gw else { continue };
            // scope `any` = a migrating ingress leg: a bond over one tagged sub-interface
            // per wire, named like a universal segment's ports, so the derived bond name must
            // leave room for the `-<domain>` suffix.
            if gw.scope.is_universal() && bond_ifname_too_long(&format!("cfab-gw{}", z.id)) {
                return Err(Error::config(format!(
                    "zone {}: ingress bond cfab-gw{} must be {MAX_BOND_IFNAME} \
                     characters or fewer (ports are named <ifname>-<domain>, IFNAMSIZ 15)",
                    z.name, z.id
                )));
            }
            if st.iter().any(|r| r.vid == gw.vid) {
                return Err(Error::config(format!(
                    "zone {} ingress vid {} is also a segment vid",
                    z.name, gw.vid
                )));
            }
            let octet = gw.router_octet();
            for m in &self.members {
                // Only a host with a wire on the gw domain carries the leg — but a node id
                // equal to the router octet is a landmine for any future wire, so check all.
                if m.node == octet {
                    return Err(Error::config(format!(
                        "zone {} router {} collides with node {} ({})'s leg address",
                        z.name, gw.router, m.node, m.name
                    )));
                }
            }
        }
        // Everything above is declaration-local. The last gate is what the DERIVATION produces:
        // the universal segment's cost, and the two path properties of spec §4.
        crate::derive::validate_derived(self)
    }

    fn domains_list(&self) -> String {
        self.domains
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A a member's `prefs` row replaces the whole derived order, so it must BE the whole order: every
    /// candidate wire of that (member, zone) exactly once. A partial list is an error, never
    /// blended with the default.
    fn check_wire_prefs(&self) -> Result<()> {
        for p in &self.wire_prefs {
            // The member exists by construction (a prefs table is declared INSIDE its member)
            // and holds each zone at most once (one key per TOML table); the ZONE, however, is
            // a name the operator typed.
            let m = self.member(&p.member).unwrap_or_else(|e| {
                panic!("prefs for a member that is not in the declaration: {e}")
            });
            self.zone(&p.zone).map_err(|e| {
                Error::context(format!("member {} prefs {}: ", p.member, p.zone), e)
            })?;
            for w in &p.order {
                if m.wire_named(w).is_none() {
                    return Err(Error::config(format!(
                        "member {} prefs {}: '{w}' is not one of {}'s wires",
                        p.member, p.zone, p.member
                    )));
                }
            }
            let want: BTreeSet<&str> = self
                .candidate_wires(m, &p.zone)
                .into_iter()
                .map(|w| w.name.as_str())
                .collect();
            let got: BTreeSet<&str> = p.order.iter().map(String::as_str).collect();
            if got.len() != p.order.len() {
                return Err(Error::config(format!(
                    "member {} prefs {}: a wire is listed twice",
                    p.member, p.zone
                )));
            }
            if got != want {
                return Err(Error::config(format!(
                    "member {} prefs {}: an override is the COMPLETE order, never blended with the \
                     derived one — list exactly [{}], got [{}]",
                    p.member,
                    p.zone,
                    want.iter().copied().collect::<Vec<_>>().join(" "),
                    p.order.join(" ")
                )));
            }
        }
        Ok(())
    }

    /// The wires of `member` that can carry `zone`: the wires whose domain has a segment in
    /// that zone, in `[[member]]` order. The candidate set the derived order ranks and an
    /// override must reproduce completely. A universal segment is a bond over every wire, not
    /// a per-wire preference, so it is not a candidate.
    pub fn candidate_wires<'a>(&self, member: &'a Member, zone: &str) -> Vec<&'a Wire> {
        member
            .wires
            .iter()
            .filter(|w| {
                self.segments
                    .iter()
                    .any(|s| s.zone == zone && s.scope == SegScope::Domain(w.domain.clone()))
            })
            .collect()
    }

    pub fn member(&self, name: &str) -> Result<&Member> {
        self.members.iter().find(|m| m.name == name).ok_or_else(|| {
            let names: Vec<&str> = self.members.iter().map(|m| m.name.as_str()).collect();
            Error::config(format!(
                "'{name}' is not a declared member (members: {})",
                names.join(" ")
            ))
        })
    }

    pub fn zone(&self, name: &str) -> Result<&Zone> {
        self.zones.iter().find(|z| z.name == name).ok_or_else(|| {
            let names: Vec<&str> = self.zones.iter().map(|z| z.name.as_str()).collect();
            Error::config(format!(
                "'{name}' is not a declared zone (zones: {})",
                names.join(" ")
            ))
        })
    }

    /// The declared override for one (member, zone), if any.
    pub fn wire_pref(&self, member: &str, zone: &str) -> Option<&WirePref> {
        self.wire_prefs
            .iter()
            .find(|p| p.member == member && p.zone == zone)
    }

    /// The declared `[[workload]]` row of this name, if any.
    pub fn workload(&self, name: &str) -> Option<&Workload> {
        self.workloads.iter().find(|w| w.name == name)
    }

    /// The smallest set of prefixes covering every declared zone block, for DHCP option 121.
    /// STUB for gate A: every zone block, sorted, with no merging of adjacent `/16`s — the
    /// non-merging case this stub covers stays true once Task 4b (`emit::workload::aggregate`)
    /// replaces this body with the real merge.
    pub fn aggregate(&self) -> Vec<String> {
        let mut ids: Vec<u8> = self.zones.iter().map(|z| z.id).collect();
        ids.sort_unstable();
        ids.into_iter()
            .map(|id| format!("10.{id}.0.0/16"))
            .collect()
    }
}

/// Every member's wires, keyed by name — the map several derivations want and none should
/// rebuild.
pub fn wires_by_member(fabric: &Fabric) -> BTreeMap<&str, &[Wire]> {
    fabric
        .members
        .iter()
        .map(|m| (m.name.as_str(), m.wires.as_slice()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::Declaration;

    /// The example declaration shipped with the crate: a real, live-proven 3-member fabric.
    fn real_decl() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
            .expect("examples/fabric.toml")
    }

    /// The example with one edit — the whole gate, parse and validation, as `cfab` runs it.
    fn parse_fabric(mut edit: impl FnMut(&mut String)) -> Result<Fabric> {
        let mut text = real_decl();
        edit(&mut text);
        Fabric::from_decl(&Declaration::parse(&text)?)
    }

    fn a() -> DomainId {
        DomainId::parse("a").unwrap()
    }

    #[test]
    fn resolves_the_real_declaration() {
        let f = parse_fabric(|_| {}).unwrap();
        assert_eq!(f.members.len(), 3);
        assert_eq!(f.zones.len(), 3);
        assert_eq!(
            f.domains,
            vec![
                a(),
                DomainId::parse("b").unwrap(),
                DomainId::parse("c").unwrap()
            ]
        );
        // 9 domain segments + 3 universal legs (one per zone).
        assert_eq!(f.segments.len(), 12);
        // Declaration order: a zone's segments, then its universal leg, zone by zone.
        assert_eq!(
            f.segments
                .iter()
                .map(|s| s.ifname.as_str())
                .collect::<Vec<_>>(),
            vec![
                "cfab-st",
                "cfab-st-bk",
                "cfab-st-b2",
                "cfab-st-fb",
                "cfab-cl",
                "cfab-cl-bk",
                "cfab-cl-b2",
                "cfab-cl-fb",
                "cfab-mg",
                "cfab-mg-bk",
                "cfab-mg-b2",
                "cfab-mg-fb",
            ]
        );
        assert_eq!(f.zone("mgmt").unwrap().id, 249);
        assert_eq!(f.zone("storage").unwrap().primary, a());
        let gw = f.zone("mgmt").unwrap().gw.as_ref().unwrap();
        assert_eq!(gw.router, "192.168.249.254");
        assert_eq!(gw.vid, 249);
        assert_eq!(gw.scope, SegScope::Universal);
        assert_eq!(gw.leg_cidr(2), "192.168.249.2/24");
        assert!(f.zone("storage").unwrap().gw.is_none());
        let universal = f
            .segments
            .iter()
            .find(|r| r.ifname == "cfab-st-fb")
            .unwrap();
        assert!(universal.scope.is_universal());
        assert_eq!(universal.zone, "storage");
        assert_eq!(f.member("pve3-tb").unwrap().kind, MemberKind::Leaf);
        assert_eq!(
            f.member("pve1-tb").unwrap().wire_on(&a()).unwrap().name,
            "eth9"
        );
        assert_eq!(
            f.member("pve1-tb")
                .unwrap()
                .wire_on(&a())
                .unwrap()
                .speed_mbps,
            5000
        );
        assert_eq!(f.dns_domain, "fabric.example");
        assert_eq!(f.run_dir, "/run/cfab");
        assert!(f.host_forward);
        assert_eq!(f.forward_allow.len(), 3);
    }

    /// A `driver_features` string reaches the model on the wire that declared it, and only
    /// there — it is per-NIC, not a member-wide or fabric-wide list.
    #[test]
    fn driver_features_land_on_the_wire_that_declared_them() {
        let f = parse_fabric(|t| {
            *t = t.replace(
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },",
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000, driver_features = \"sg \
                 off tso off\" },",
            )
        })
        .unwrap();
        assert_eq!(
            f.member("pve1-tb").unwrap().wires[0]
                .driver_features
                .as_deref(),
            Some("sg off tso off")
        );
        assert_eq!(f.member("pve1-tb").unwrap().wires[1].driver_features, None);
        assert_eq!(f.member("pve3-tb").unwrap().wires[0].driver_features, None);
    }

    /// The retired `usb` key fails LOUD at load, naming the wire and the replacement — not
    /// `deny_unknown_fields`' "unknown field `usb`", which says nothing about what to write
    /// instead.
    #[test]
    fn the_retired_usb_key_is_refused_by_name_with_the_remedy() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },",
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000, usb = true },",
            )
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "fabric.toml: member pve1-tb: wire eth9: 'usb' is gone; declare driver_features = \
             \"sg off tso off gso off\" instead (the words go to `ethtool -K <nic>` as written)"
        );
    }

    /// `usb = false` is the same retired key: refused, not quietly accepted as "no mitigation".
    #[test]
    fn usb_false_is_refused_too() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "{ nic = \"eth1\", domain = \"b\", speed_mbps = 1000 },",
                "{ nic = \"eth1\", domain = \"b\", speed_mbps = 1000, usb = false },",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("wire eth1: 'usb' is gone"), "{err}");
    }

    /// A malformed `driver_features` string is a DECLARATION error (`cfab check`), not a
    /// surprise from ethtool half way through a bringup. The message names the member and
    /// the wire, like every other wire error.
    #[test]
    fn a_malformed_driver_features_string_is_refused_at_load() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },",
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000, driver_features = \"sg \
                 off tso\" },",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("member pve1-tb: wire eth9: "), "{err}");
        assert!(err.contains("3 words"), "{err}");
        assert!(err.contains("<feature> on|off pairs"), "{err}");
    }

    #[test]
    fn bfd_port_defaults_and_is_range_checked() {
        // The shipped declaration states it; a declaration that omits it gets RFC 5881's port.
        assert_eq!(parse_fabric(|_| {}).unwrap().bfd_port, 3784);
        let f = parse_fabric(|t| *t = t.replace("port = 3784\n", "")).unwrap();
        assert_eq!(f.bfd_port, BFD_PORT_DEFAULT);
        assert_eq!(
            parse_fabric(|t| *t = t.replace("port = 3784", "port = 3785"))
                .unwrap()
                .bfd_port,
            3785
        );
        for (bad, want) in [
            ("port = 1023", "[bfd] port = 1023 is outside 1024..65535"),
            ("port = 0", "[bfd] port = 0 is outside 1024..65535"),
            // Outside u16 or not a number: the parser refuses the VALUE, naming it.
            ("port = 70000", "70000"),
            ("port = \"bfd\"", "bfd"),
        ] {
            let err = parse_fabric(|t| *t = t.replace("port = 3784", bad))
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{bad}: {err}");
        }
    }

    #[test]
    fn pcp_ctrl_is_range_checked() {
        assert_eq!(parse_fabric(|_| {}).unwrap().pcp_ctrl, 6);
        assert_eq!(
            parse_fabric(|t| *t = t.replace("pcp_ctrl = 6", "pcp_ctrl = 5"))
                .unwrap()
                .pcp_ctrl,
            5
        );
        for (bad, want) in [
            (
                "pcp_ctrl = 7",
                "[marking] pcp_ctrl = 7 is outside 0..6 (7 needs CAP_NET_ADMIN on the engine's \
                 control sockets)",
            ),
            ("pcp_ctrl = 8", "pcp_ctrl = 8 is outside 0..6"),
            ("pcp_ctrl = 255", "pcp_ctrl = 255 is outside 0..6"),
            ("pcp_ctrl = 256", "256"),
            ("pcp_ctrl = \"six\"", "six"),
        ] {
            let err = parse_fabric(|t| *t = t.replace("pcp_ctrl = 6", bad))
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{bad}: {err}");
        }
    }

    #[test]
    fn duplicate_vid_fails() {
        let err = parse_fabric(|t| *t = t.replace("seg = 2, vid = 101", "seg = 2, vid = 100"))
            .unwrap_err();
        assert!(
            err.to_string().contains("vid 100 used by two segments"),
            "{err}"
        );
    }

    #[test]
    fn gw_vid_colliding_with_segment_vid_fails() {
        let err =
            parse_fabric(|t| *t = t.replace("vid = 249, router", "vid = 250, router")).unwrap_err();
        assert!(
            err.to_string()
                .contains("ingress vid 250 is also a segment vid"),
            "{err}"
        );
    }

    #[test]
    fn router_octet_colliding_with_a_node_fails() {
        let err =
            parse_fabric(|t| *t = t.replace("192.168.249.254/24", "192.168.249.3/24")).unwrap_err();
        assert!(err.to_string().contains("collides with node 3"), "{err}");
    }

    #[test]
    fn unknown_forward_allow_zone_fails() {
        let err = parse_fabric(|t| *t = t.replace("\"storage>storage\"", "\"public>storage\""))
            .unwrap_err();
        assert!(err.to_string().contains("unknown zone 'public'"), "{err}");
    }

    #[test]
    fn a_forward_pair_without_a_direction_fails() {
        let err = parse_fabric(|t| *t = t.replace("\"storage>storage\"", "\"storage\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("[forward] allow 'storage'"), "{err}");
    }

    #[test]
    fn gw_prefix_other_than_24_fails() {
        let err = parse_fabric(|t| *t = t.replace("192.168.249.254/24", "192.168.249.254/25"))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("expected an IPv4 address with /24"),
            "{err}"
        );
    }

    #[test]
    fn a_gw_router_without_a_prefix_fails() {
        let err =
            parse_fabric(|t| *t = t.replace("192.168.249.254/24", "192.168.249.254")).unwrap_err();
        assert!(
            err.to_string()
                .contains("expected an IPv4 address with /24"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_node_id_fails() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "name = \"pve2-tb\"\nnode = 2",
                "name = \"pve2-tb\"\nnode = 1",
            )
        })
        .unwrap_err();
        assert!(err.to_string().contains("node id 1 used twice"), "{err}");
    }

    #[test]
    fn duplicate_member_name_fails() {
        let err = parse_fabric(|t| *t = t.replace("name = \"pve2-tb\"", "name = \"pve1-tb\""))
            .unwrap_err();
        assert!(
            err.to_string().contains("member pve1-tb declared twice"),
            "{err}"
        );
    }

    #[test]
    fn unknown_member_error_lists_members() {
        let f = parse_fabric(|_| {}).unwrap();
        let err = f.member("nope").unwrap_err();
        assert!(
            err.to_string().contains("members: pve1-tb pve2-tb pve3-tb"),
            "{err}"
        );
    }

    /// Representable in TOML (`wires = []`), meaningless in a fabric — and every derivation
    /// downstream assumes a member has at least one wire.
    #[test]
    fn a_member_with_no_wires_is_refused() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "wires = [\n  { nic = \"eth9\", domain = \"a\", speed_mbps = 10000 },\n  \
                 { nic = \"eth1\", domain = \"b\", speed_mbps = 1000 },\n  \
                 { nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]",
                "wires = []",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("member pve3-tb: declares no wires"), "{err}");
    }

    #[test]
    fn scope_parses_any_and_letters() {
        assert_eq!(SegScope::parse("any").unwrap(), SegScope::Universal);
        assert_eq!(SegScope::parse("a").unwrap(), SegScope::Domain(a()));
        assert_eq!(SegScope::Universal.to_string(), "any");
        assert_eq!(SegScope::Domain(a()).to_string(), "a");
        assert!(SegScope::parse("st").is_err());
    }

    #[test]
    fn a_domain_token_is_one_letter() {
        assert!(DomainId::parse("a").is_ok());
        assert!(DomainId::parse("Z").is_ok());
        for bad in ["", "ab", "1", "-", "a1"] {
            assert!(DomainId::parse(bad).is_err(), "{bad}");
        }
        // ...and a declaration naming a two-character token says which wire holds it.
        let err = parse_fabric(|t| {
            *t = t.replace(
                "{ nic = \"eth1\", domain = \"b\"",
                "{ nic = \"eth1\", domain = \"bb\"",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("member pve1-tb: wire eth1:"), "{err}");
        assert!(err.contains("is not a switch-domain token"), "{err}");
    }

    #[test]
    fn universal_ifname_over_the_budget_fails() {
        let err =
            parse_fabric(|t| *t = t.replace("\"cfab-st-fb\"", "\"cfab-storage-fb\"")).unwrap_err();
        assert!(
            err.to_string().contains("must be 13 characters or fewer"),
            "{err}"
        );
    }

    /// The port-name budget, at the predicate: a bond leg's ports are `<ifname>-<domain>`,
    /// so with one-letter tokens 13 characters fit IFNAMSIZ and 14 do not.
    #[test]
    fn bond_ifname_longer_than_the_budget_is_refused() {
        assert_eq!(MAX_BOND_IFNAME, 13);
        assert!(!bond_ifname_too_long("cfab-st-fb"));
        assert!(!bond_ifname_too_long("1234567890123"));
        assert!(bond_ifname_too_long("12345678901234"));
    }

    /// ...and no zone declaration can reach it today: a zone id is a u8, so the widest
    /// derived ingress bond is `cfab-gw255` (10) and its widest port `cfab-gw255-a` (12).
    #[test]
    fn every_zone_id_yields_an_ingress_bond_name_that_fits() {
        for id in u8::MIN..=u8::MAX {
            let ifname = format!("cfab-gw{id}");
            assert!(!bond_ifname_too_long(&ifname), "{ifname}");
            assert!(format!("{ifname}-a").len() <= 15, "{ifname}");
        }
    }

    /// The ingress leg migrates, so `any` is a legal gw scope — and it is the example's own.
    #[test]
    fn gw_scope_any_is_accepted() {
        let f = parse_fabric(|_| {}).unwrap();
        assert!(
            f.zone("mgmt")
                .unwrap()
                .gw
                .as_ref()
                .unwrap()
                .scope
                .is_universal()
        );
    }

    /// Pinning the leg to one physical domain stays legal: the scope is a choice, not a
    /// migration path with an opt-out.
    #[test]
    fn gw_scope_of_one_domain_is_accepted() {
        let f = parse_fabric(|t| *t = crate::decl::fixtures::with_a_domain_gw(t)).unwrap();
        assert_eq!(
            f.zone("mgmt").unwrap().gw.as_ref().unwrap().scope,
            SegScope::Domain(DomainId::parse("c").unwrap())
        );
    }

    // ---- domains: the two-directional check ------------------------------------------------

    #[test]
    fn an_undeclared_wire_domain_is_refused() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "{ nic = \"eth1\", domain = \"b\", speed_mbps = 1000 },\n  { nic = \"eth0\", \
                 domain = \"c\", speed_mbps = 1000 },\n]\n# Optional",
                "{ nic = \"eth1\", domain = \"d\", speed_mbps = 1000 },\n  { nic = \"eth0\", \
                 domain = \"c\", speed_mbps = 1000 },\n]\n# Optional",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("is not in [domains] (a b c)"), "{err}");
    }

    #[test]
    fn an_undeclared_segment_domain_is_refused() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "{ ifname = \"cfab-st-b2\", domain = \"c\"",
                "{ ifname = \"cfab-st-b2\", domain = \"d\"",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("segment cfab-st-b2: domain d is not in [domains]"),
            "{err}"
        );
    }

    #[test]
    fn a_declared_domain_nobody_wires_into_is_refused() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "c = \"1G admin switch\"",
                "c = \"1G admin switch\"\nd = \"a switch nobody is plugged into\"",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("[domains] declares d but no member has a wire on it"),
            "{err}"
        );
    }

    #[test]
    fn a_zone_primary_domain_without_a_segment_is_refused() {
        // Trips ONLY this check: domain d is declared and wired (so the two-directional domain
        // check is satisfied) but carries no segment, and storage names it as its primary.
        let err = parse_fabric(|t| {
            *t = t
                .replace(
                    "c = \"1G admin switch\"",
                    "c = \"1G admin switch\"\nd = \"a fourth switch\"",
                )
                .replace(
                    "{ nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]\n# Optional",
                    "{ nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n  { nic = \"eth2\", \
                     domain = \"d\", speed_mbps = 1000 },\n]\n# Optional",
                )
                .replace("weight = 4\nprimary = \"a\"", "weight = 4\nprimary = \"d\"");
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("zone storage") && err.contains("primary domain d"),
            "the error must name the zone and its primary domain: {err}"
        );
        assert!(err.contains("has no segment"), "{err}");
    }

    #[test]
    fn two_wires_on_one_domain_are_refused_with_the_reason() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },\n  { nic = \
                 \"eth1\", domain = \"b\", speed_mbps = 1000 },\n  { nic = \"eth0\", domain = \
                 \"c\", speed_mbps = 1000 },\n]\n# Optional",
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },\n  { nic = \
                 \"eth8\", domain = \"a\", speed_mbps = 5000 },\n  { nic = \"eth1\", domain = \
                 \"b\", speed_mbps = 1000 },\n  { nic = \"eth0\", domain = \"c\", speed_mbps = \
                 1000 },\n]\n# Optional",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("two wires on domain a (eth9 eth8)"), "{err}");
        assert!(err.contains("ARP-ambiguous"), "{err}");
        assert!(err.contains("Put the wires in different domains"), "{err}");
        assert!(
            err.contains(
                "one bond over both NICs declared as a single wire, which cfab does not \
                          build yet"
            ),
            "the second remedy is a separate sentence, and says it is not built: {err}"
        );
        assert!(
            !err.contains("SECOND segment"),
            "the second-segment clause was wrong (it does not fix this row): {err}"
        );
    }

    // ---- per-zone preference overrides ------------------------------------------------------

    /// The commented-out override in the example, uncommented: the whole order for one zone.
    fn with_pref(pref: &str) -> String {
        real_decl().replace(
            "# prefs = { storage = [\"eth1\", \"eth9\", \"eth0\"] }",
            pref,
        )
    }

    #[test]
    fn a_complete_pref_override_parses() {
        let text = with_pref("prefs = { storage = [\"eth1\", \"eth9\", \"eth0\"] }");
        let f = Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap();
        let p = f.wire_pref("pve1-tb", "storage").unwrap();
        assert_eq!(p.order, vec!["eth1", "eth9", "eth0"]);
    }

    #[test]
    fn a_partial_pref_override_is_refused() {
        let text = with_pref("prefs = { storage = [\"eth1\", \"eth9\"] }");
        let err = Fabric::from_decl(&Declaration::parse(&text).unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("COMPLETE order"), "{err}");
    }

    #[test]
    fn a_pref_naming_an_unknown_wire_is_refused() {
        let text = with_pref("prefs = { storage = [\"eth1\", \"eth9\", \"eth5\"] }");
        let err = Fabric::from_decl(&Declaration::parse(&text).unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("'eth5' is not one of pve1-tb's wires"),
            "{err}"
        );
    }

    #[test]
    fn a_pref_for_an_unknown_zone_is_refused() {
        let text = with_pref("prefs = { backup = [\"eth1\", \"eth9\", \"eth0\"] }");
        let err = Fabric::from_decl(&Declaration::parse(&text).unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("member pve1-tb prefs backup"), "{err}");
    }

    #[test]
    fn a_pref_listing_a_wire_twice_is_refused() {
        let text = with_pref("prefs = { storage = [\"eth1\", \"eth1\", \"eth9\"] }");
        let err = Fabric::from_decl(&Declaration::parse(&text).unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("a wire is listed twice"), "{err}");
    }

    // ---- workloads ---------------------------------------------------------------------------

    /// The workload fixture with one text edit, through the whole gate (parse + validate).
    fn wl_fabric_edit(edit: impl FnOnce(String) -> String) -> Result<Fabric> {
        let text = edit(crate::decl::fixtures::with_workload(
            &crate::decl::fixtures::example(),
        ));
        Fabric::from_decl(&Declaration::parse(&text)?)
    }
    fn wl_err(edit: impl FnOnce(String) -> String) -> String {
        wl_fabric_edit(edit).unwrap_err().to_string()
    }

    #[test]
    fn a_workload_row_becomes_a_model_workload_with_the_prefix_mask_on_gw() {
        let f = wl_fabric_edit(|t| t).unwrap();
        let wl = f.workload("vms").unwrap();
        assert_eq!(wl.prefix.to_string(), "192.168.20.0/24");
        assert_eq!(wl.gw_cidr(), "192.168.20.254/24");
        assert_eq!(wl.router.to_string(), "192.168.20.1");
        assert_eq!(wl.span, Span::Switch);
        assert_eq!(
            f.member("pve1-tb").unwrap().workloads[0].address_cidr(),
            "192.168.20.2/24"
        );
        assert!(f.member("pve3-tb").unwrap().workloads.is_empty());
    }

    #[test]
    fn check_refuses_a_gw_outside_the_prefix() {
        let e = wl_err(|t| t.replace("gw = \"192.168.20.254\"", "gw = \"192.168.30.254\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: gw 192.168.30.254 is outside prefix 192.168.20.0/24"
        );
    }

    #[test]
    fn check_refuses_a_gw_that_is_the_network_or_broadcast_address() {
        let e = wl_err(|t| t.replace("gw = \"192.168.20.254\"", "gw = \"192.168.20.0\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: gw 192.168.20.0 is the network or broadcast address of \
             192.168.20.0/24"
        );
        let e = wl_err(|t| t.replace("gw = \"192.168.20.254\"", "gw = \"192.168.20.255\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: gw 192.168.20.255 is the network or broadcast address \
             of 192.168.20.0/24"
        );
    }

    #[test]
    fn check_refuses_a_router_outside_the_prefix_or_malformed() {
        let e = wl_err(|t| t.replace("router = \"192.168.20.1\"", "router = \"192.168.30.1\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: router 192.168.30.1 is outside prefix 192.168.20.0/24"
        );
        let e = wl_err(|t| t.replace("router = \"192.168.20.1\"", "router = \"192.168.20.1/24\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: router '192.168.20.1/24' must be a bare IPv4 address \
             (the VLAN's existing default router)"
        );
    }

    #[test]
    fn check_refuses_a_router_that_is_the_network_or_broadcast_address() {
        let e = wl_err(|t| t.replace("router = \"192.168.20.1\"", "router = \"192.168.20.0\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: router 192.168.20.0 is the network or broadcast \
             address of 192.168.20.0/24"
        );
        let e = wl_err(|t| t.replace("router = \"192.168.20.1\"", "router = \"192.168.20.255\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: router 192.168.20.255 is the network or broadcast \
             address of 192.168.20.0/24"
        );
    }

    #[test]
    fn check_refuses_a_workload_ifname_colliding_with_an_interface_cfab_creates() {
        let e = wl_err(|t| t.replace("ifname = \"primary.3\"", "ifname = \"eth9\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: ifname 'eth9' collides with an interface cfab creates"
        );
        let e = wl_err(|t| t.replace("ifname = \"primary.3\"", "ifname = \"cfab-st\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: ifname 'cfab-st' collides with an interface cfab \
             creates"
        );
        let e = wl_err(|t| t.replace("ifname = \"primary.3\"", "ifname = \"cfab-gw249\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: ifname 'cfab-gw249' collides with an interface cfab \
             creates"
        );
    }

    #[test]
    fn check_refuses_workload_allow_empty() {
        let e = wl_err(|t| t.replace("allow = [\"storage\"]", "allow = []"));
        assert_eq!(
            e,
            "fabric.toml: workload vms: allow is empty; a workload must reach at least one zone"
        );
    }

    #[test]
    fn check_refuses_workload_allow_when_forwarding_is_disabled() {
        let e = wl_err(|t| t.replace("enabled = true", "enabled = false"));
        assert_eq!(
            e,
            "fabric.toml: workload vms: allow is non-empty but [forward] enabled = false; \
             enable forwarding or remove allow"
        );
    }

    #[test]
    fn check_refuses_a_member_address_outside_the_prefix() {
        let e = wl_err(|t| {
            t.replace(
                "address = \"192.168.20.2/24\"",
                "address = \"192.168.30.2/24\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve1-tb: workload vms: address 192.168.30.2/24 is outside \
             prefix 192.168.20.0/24"
        );
    }

    #[test]
    fn check_refuses_a_member_address_without_the_prefix_mask() {
        let e = wl_err(|t| {
            t.replace(
                "address = \"192.168.20.2/24\"",
                "address = \"192.168.20.2/32\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve1-tb: workload vms: address 192.168.20.2/32 must carry the \
             prefix's mask /24"
        );
    }

    #[test]
    fn check_refuses_a_member_address_that_is_the_gateway() {
        let e = wl_err(|t| {
            t.replace(
                "address = \"192.168.20.2/24\"",
                "address = \"192.168.20.254/24\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve1-tb: workload vms: address 192.168.20.254/24 is the \
             gateway 192.168.20.254"
        );
    }

    #[test]
    fn check_refuses_a_member_address_that_is_the_network_or_broadcast_address() {
        let e = wl_err(|t| {
            t.replace(
                "address = \"192.168.20.2/24\"",
                "address = \"192.168.20.0/24\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve1-tb: workload vms: address 192.168.20.0/24 is the network \
             or broadcast address of 192.168.20.0/24"
        );
        let e = wl_err(|t| {
            t.replace(
                "address = \"192.168.20.2/24\"",
                "address = \"192.168.20.255/24\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve1-tb: workload vms: address 192.168.20.255/24 is the \
             network or broadcast address of 192.168.20.0/24"
        );
    }

    #[test]
    fn check_refuses_an_allow_naming_an_unknown_zone() {
        let e = wl_err(|t| t.replace("allow = [\"storage\"]", "allow = [\"storage\", \"backup\"]"));
        assert_eq!(
            e,
            "fabric.toml: workload vms: allow 'backup': unknown zone (zones: storage, cluster, \
             mgmt)"
        );
    }

    #[test]
    fn check_refuses_a_workload_no_member_carries() {
        let e = wl_err(|t| {
            t.lines()
                .filter(|l| !l.starts_with("workloads = ["))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        });
        assert_eq!(
            e,
            "fabric.toml: workload vms: no member carries it (add workloads = [{ name = \
             \"vms\", address = \"<host address>/24\" }] to a member)"
        );
    }

    #[test]
    fn check_refuses_a_member_workload_naming_an_unknown_row() {
        let e = wl_err(|t| {
            t.replace(
                "{ name = \"vms\", address = \"192.168.20.2/24\" }",
                "{ name = \"nope\", address = \"192.168.20.2/24\" }",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve1-tb: workload 'nope' is not a declared [[workload]] \
             (workloads: vms)"
        );
    }

    #[test]
    fn check_refuses_a_member_workload_declared_twice() {
        let e = wl_err(|t| {
            t.replace(
                "workloads = [{ name = \"vms\", address = \"192.168.20.2/24\" }]",
                "workloads = [{ name = \"vms\", address = \"192.168.20.2/24\" }, { name = \
                 \"vms\", address = \"192.168.20.5/24\" }]",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve1-tb: workload vms is declared twice"
        );
    }

    #[test]
    fn check_refuses_a_leaf_carrying_a_workload() {
        let e = wl_err(|t| {
            crate::decl::fixtures::with_prefs(
                &t,
                "pve3-tb",
                "workloads = [{ name = \"vms\", address = \"192.168.20.4/24\" }]",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve3-tb: workload vms: a leaf carries no workload (kind = leaf)"
        );
    }

    #[test]
    fn check_refuses_span_host_in_phase_1() {
        let e = wl_err(|t| {
            t.replace(
                "gw = \"192.168.20.254\"",
                "gw = \"192.168.20.254\"\nspan = \"host\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: workload vms: span = \"host\" is phase 2 and not built yet (omit it, \
             or span = \"switch\")"
        );
    }

    #[test]
    fn check_refuses_an_unknown_span_value() {
        let e = wl_err(|t| {
            t.replace(
                "gw = \"192.168.20.254\"",
                "gw = \"192.168.20.254\"\nspan = \"Switch\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: workload vms: span 'Switch' is not one of switch, host"
        );
    }

    #[test]
    fn check_refuses_a_member_address_without_a_length() {
        let e = wl_err(|t| {
            t.replace(
                "address = \"192.168.20.2/24\"",
                "address = \"192.168.20.2\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: member pve1-tb: workload vms: address '192.168.20.2' is not an IPv4 \
             address with a length"
        );
    }

    #[test]
    fn check_refuses_a_workload_named_like_a_zone_or_declared_twice() {
        let e = wl_err(|t| {
            t.replace(
                "[[workload]]\nname = \"vms\"",
                "[[workload]]\nname = \"storage\"",
            )
        });
        assert_eq!(
            e,
            "fabric.toml: workload storage: name is also a zone (workload and zone names share \
             one vocabulary)"
        );
        let e = wl_err(|t| format!("{t}{}", crate::decl::fixtures::WORKLOAD_BLOCK));
        assert_eq!(e, "fabric.toml: workload vms: declared twice");
    }

    #[test]
    fn check_refuses_malformed_prefix_and_gw() {
        let e = wl_err(|t| t.replace("prefix = \"192.168.20.0/24\"", "prefix = \"192.168.20.0\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: prefix '192.168.20.0' is not an IPv4 prefix with a \
             length (example: 192.168.20.0/24)"
        );
        let e = wl_err(|t| t.replace("gw = \"192.168.20.254\"", "gw = \"192.168.20.254/24\""));
        assert_eq!(
            e,
            "fabric.toml: workload vms: gw '192.168.20.254/24' must be a bare IPv4 address (the \
             prefix's mask is applied)"
        );
    }

    #[test]
    fn the_aggregate_covers_every_declared_zone_block() {
        let f = wl_fabric_edit(|t| t).unwrap();
        assert_eq!(
            f.aggregate(),
            vec!["10.99.0.0/16", "10.199.0.0/16", "10.249.0.0/16"]
        );
    }

    #[test]
    fn first_host_and_broadcast_are_the_prefixs_edges() {
        let p = Ipv4Prefix::parse("192.168.20.0/24").unwrap();
        assert_eq!(p.first_host(), Ipv4Addr::new(192, 168, 20, 1));
        assert_eq!(p.broadcast(), Ipv4Addr::new(192, 168, 20, 255));
        let host_prefix = Ipv4Prefix::parse("255.255.255.255/32").unwrap();
        assert_eq!(
            host_prefix.first_host(),
            Ipv4Addr::new(255, 255, 255, 255),
            "saturates instead of wrapping at the top of the address space"
        );
    }
}
