//! The typed fabric declaration — the data model behind `fabric.conf`.
//!
//! Four tables declare the fabric (DOMAINS, MEMBER_TABLE, ZONE_TABLE, SEGMENT_TABLE) plus the
//! optional WIRE_PREF override; everything else is generated from them. This module types every
//! field, and `Fabric::validate` enforces the declaration invariants: unique member names, node
//! ids, segment vids and interface names, one segment per zone × domain, known zones and known
//! domains everywhere either is named, at most one wire per member per domain, complete
//! WIRE_PREF overrides, and ingress gateways that collide with neither a segment vid nor any member's leg address.
//! `cfab schema` emits this model as JSON Schema (schemars).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use schemars::JsonSchema;
use serde::Serialize;

use crate::config::RawConfig;
use crate::error::{Error, Result};

/// A physical switch domain: an opaque DECLARED token, so a typo in a wire's or a segment's
/// domain is an error and not a phantom domain. One letter — the bond-slave suffix
/// `-<domain>` must fit inside IFNAMSIZ (see `MAX_BOND_IFNAME`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
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

/// Membership taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MemberKind {
    /// Transits between zones, shapes, carries every domain it has wires on.
    Host,
    /// Own identity + OSPF/BFD, stub-router, never transits, no shaping; its
    /// untagged/externally-managed L3 is never touched (the NAS).
    Leaf,
}

impl MemberKind {
    pub fn parse(s: &str) -> Result<MemberKind> {
        match s {
            "host" => Ok(MemberKind::Host),
            "leaf" => Ok(MemberKind::Leaf),
            other => Err(Error::config(format!(
                "MEMBER_TABLE kind '{other}' (expected host|leaf)"
            ))),
        }
    }
}

/// A member's physical NIC, the switch domain it is plugged into, and its DECLARED link speed
/// (Mb/s). One wire is pinned to exactly ONE domain: a single NIC into a single switch IS one
/// domain, and the "one wire, several domains" trunk is deliberately not modelled (spec §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Wire {
    pub name: String,
    pub domain: DomainId,
    pub speed_mbit: u32,
}

/// The widest ifname a bond leg (a universal segment, or a migrating ingress leg) may carry.
/// Its slaves are named `<ifname>-<domain>`: a separator plus a domain token inside IFNAMSIZ 15.
pub const MAX_BOND_IFNAME: usize = 15 - 1 - MAX_DOMAIN_TOKEN;

/// Does this bond-leg name leave room for the `-<domain>` suffix its slaves need? One
/// predicate for both legs, so the rule cannot drift between them.
fn bond_ifname_too_long(ifname: &str) -> bool {
    ifname.len() > MAX_BOND_IFNAME
}

/// One MEMBER_TABLE row.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Member {
    pub name: String,
    /// Node id: the host octet of every address this member holds (identity 10.<id>.0.<node>).
    pub node: u8,
    pub kind: MemberKind,
    /// Every wire this member has, in declaration order (the tie-break for equal speeds).
    ///
    /// The admin plane is not a column: on a host the UNTAGGED path of every one of these
    /// wires is the admin plane (the SSH lifeline that works with the routing stack stopped),
    /// so every wire gets the nft admin treatment and its own ADMIN_FLOOR band. A leaf owns no
    /// L3 of ours on any wire.
    pub wires: Vec<Wire>,
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
/// here, with both, when a new band appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Dscp {
    Cs0,
    Cs2,
    Cs6,
}

impl Dscp {
    pub fn parse(s: &str) -> Result<Dscp> {
        match s {
            "cs0" => Ok(Dscp::Cs0),
            "cs2" => Ok(Dscp::Cs2),
            "cs6" => Ok(Dscp::Cs6),
            other => Err(Error::config(format!(
                "unknown dscp '{other}' (cs0|cs2|cs6 — extend the Dscp model with its tos byte \
                 and switch-queue evidence)"
            ))),
        }
    }

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
#[derive(Debug, Clone, Serialize, JsonSchema)]
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

    pub fn router_octet(&self) -> Result<u8> {
        self.router
            .rsplit_once('.')
            .and_then(|(_, o)| o.parse().ok())
            .ok_or_else(|| {
                Error::config(format!(
                    "gw router '{}' is not an IPv4 address",
                    self.router
                ))
            })
    }
}

/// One ZONE_TABLE row: a traffic class.
#[derive(Debug, Clone, Serialize, JsonSchema)]
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
    pub floor_mbit: u32,
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

/// One SEGMENT_TABLE row: zone `zone` on scope `scope`, addressed 10.<id>.<seg>.<node>/24,
/// tagged `vid`. A segment carries no role and no cost: both are derived (spec §4).
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Segment {
    pub ifname: String,
    pub scope: SegScope,
    pub zone: String,
    pub seg: u8,
    pub vid: u16,
}

/// One WIRE_PREF row: this member's complete wire order for this zone, replacing the derived
/// one. Complete or an error — an override is never blended with the default.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct WirePref {
    pub member: String,
    pub zone: String,
    pub order: Vec<String>,
}

/// The whole declaration, typed. Everything the deployed runtime needs and nothing it computes.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Fabric {
    pub fabric_mode: String,
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
    pub admin_floor_mbit: u32,
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
    /// `(member, dev)` pairs from USB_NICS: USB NICs that get offload safe mode on `up`.
    pub usb_nics: Vec<(String, String)>,
    /// Runtime state dir written by `up`, read by `status` and the daemons (CFAB_RUN).
    pub run_dir: String,
    pub fabric_domain: String,
}

/// Every key the model consumes from fabric.conf (for unknown-literal-key warnings).
pub const CONSUMED_KEYS: &[&str] = &[
    "FABRIC_MODE",
    "DOMAINS",
    "MEMBER_TABLE",
    "FABRIC_DOMAIN",
    "ZONE_TABLE",
    "SEGMENT_TABLE",
    "WIRE_PREF",
    "LEAF_COST_OFFSET",
    "HOST_FORWARD",
    "ADMIN_FLOOR",
    "ADMIN_BAND",
    "FORWARD_ALLOW",
    "PCP_CTRL",
    "DSCP_MARK",
    "BFD_RX_MS",
    "BFD_TX_MS",
    "BFD_MULT",
    "BFD_PORT",
    "OSPF_HELLO",
    "OSPF_DEAD",
    "BGP_AS",
    "BGP_KEEPALIVE_S",
    "BGP_HOLD_S",
    "BGP_CONNECT_S",
    "USB_NICS",
    "CFAB_RUN",
];

/// Keys the v0 declaration had and v1 does not. Pre-release there is no compatibility shim: an
/// old file fails at parse with an error that names the new layout, rather than falling through
/// to the generic unknown-key warning and silently generating a fabric nobody declared.
const REMOVED_KEYS: &[(&str, &str)] = &[(
    "CLASS_TABLE",
    "CLASS_TABLE was replaced by SEGMENT_TABLE (rows are segments, and \"class\" is a zone \
     word). New layout: `ifname domain|any zone seg vid` — the role and ospf-cost columns are \
     gone, both are derived from ZONE_TABLE's `primary` column and the per-member wire order",
)];

fn parse_num<T: std::str::FromStr>(raw: &RawConfig, key: &str) -> Result<T> {
    let v = raw.require(key)?;
    v.parse()
        .map_err(|_| Error::config(format!("{key}='{v}' is not a valid number")))
}

/// RFC 5881's single-hop port: what every BFD implementation binds unless told otherwise.
pub const BFD_PORT_DEFAULT: u16 = 3784;

/// An optional port key: absent = the default, present = a registered/dynamic port. Ports below
/// 1024 are refused (the engine drops privileges to bind nothing else there) and 0 is not a port.
fn parse_port(raw: &RawConfig, key: &str, default: u16) -> Result<u16> {
    let Some(v) = raw.get(key) else {
        return Ok(default);
    };
    let port: u16 = v
        .parse()
        .map_err(|_| Error::config(format!("{key}='{v}' is not a valid port")))?;
    if !(1024..=65535).contains(&port) {
        return Err(Error::config(format!(
            "{key}={port} is outside 1024..65535"
        )));
    }
    Ok(port)
}

/// An 802.1p priority: a 3-bit field. Refused loudly here rather than at the socket, where
/// the engine sets it as SO_PRIORITY on its control sockets and a rejected value would take
/// the engine down at start.
fn parse_pcp(raw: &RawConfig, key: &str) -> Result<u8> {
    let pcp: u8 = parse_num(raw, key)?;
    // 7 is representable on the wire but SO_PRIORITY 7 needs CAP_NET_ADMIN, which the engine drops
    // before it opens its sockets; the failure there is a logged raise and a silently down
    // interface, so the declaration refuses it here instead.
    if pcp > 6 {
        return Err(Error::config(format!(
            "{key}={pcp} is outside 0..6 (7 needs CAP_NET_ADMIN on the engine's control sockets)"
        )));
    }
    Ok(pcp)
}

fn parse_bool01(raw: &RawConfig, key: &str) -> Result<bool> {
    match raw.require(key)? {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(Error::config(format!("{key}='{other}' (expected 0|1)"))),
    }
}

impl Fabric {
    pub fn from_raw(raw: &RawConfig) -> Result<Fabric> {
        for (key, why) in REMOVED_KEYS {
            if raw.get(key).is_some() {
                return Err(Error::config((*why).to_string()));
            }
        }
        let domains = parse_domains(raw.require("DOMAINS")?)?;
        let members = parse_member_table(raw.require("MEMBER_TABLE")?)?;
        let zones = parse_zone_table(raw.require("ZONE_TABLE")?)?;
        let segments = parse_segment_table(raw.require("SEGMENT_TABLE")?)?;
        let wire_prefs = match raw.get("WIRE_PREF") {
            Some(text) => parse_wire_pref(text)?,
            None => Vec::new(),
        };
        let forward_allow = raw
            .require("FORWARD_ALLOW")?
            .split_whitespace()
            .map(|pair| {
                pair.split_once('>')
                    .map(|(f, t)| (f.to_string(), t.to_string()))
                    .ok_or_else(|| {
                        Error::config(format!("FORWARD_ALLOW '{pair}' (expected from>to)"))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let fabric = Fabric {
            fabric_mode: raw.require("FABRIC_MODE")?.to_string(),
            domains,
            members,
            zones,
            segments,
            wire_prefs,
            leaf_cost_offset: parse_num(raw, "LEAF_COST_OFFSET")?,
            host_forward: parse_bool01(raw, "HOST_FORWARD")?,
            forward_allow,
            admin_floor_mbit: parse_num(raw, "ADMIN_FLOOR")?,
            admin_band: parse_num(raw, "ADMIN_BAND")?,
            pcp_ctrl: parse_pcp(raw, "PCP_CTRL")?,
            dscp_mark: parse_bool01(raw, "DSCP_MARK")?,
            bfd_rx_ms: parse_num(raw, "BFD_RX_MS")?,
            bfd_tx_ms: parse_num(raw, "BFD_TX_MS")?,
            bfd_mult: parse_num(raw, "BFD_MULT")?,
            bfd_port: parse_port(raw, "BFD_PORT", BFD_PORT_DEFAULT)?,
            ospf_hello: parse_num(raw, "OSPF_HELLO")?,
            ospf_dead: parse_num(raw, "OSPF_DEAD")?,
            bgp_as: parse_num(raw, "BGP_AS")?,
            bgp_keepalive_s: parse_num(raw, "BGP_KEEPALIVE_S")?,
            bgp_hold_s: parse_num(raw, "BGP_HOLD_S")?,
            bgp_connect_s: parse_num(raw, "BGP_CONNECT_S")?,
            usb_nics: raw
                .require("USB_NICS")?
                .split_whitespace()
                .map(|entry| {
                    entry
                        .split_once(':')
                        .filter(|(m, d)| !m.is_empty() && !d.is_empty())
                        .map(|(m, d)| (m.to_string(), d.to_string()))
                        .ok_or_else(|| {
                            Error::config(format!("USB_NICS entry '{entry}' is not member:dev"))
                        })
                })
                .collect::<Result<Vec<_>>>()?,
            run_dir: raw.require("CFAB_RUN")?.to_string(),
            fabric_domain: raw.require("FABRIC_DOMAIN")?.to_string(),
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
                "DOMAINS is empty (declare one token per physical switch domain, e.g. \
                 DOMAINS=\"a b c\")"
                    .to_string(),
            ));
        }
        if let Some(d) = dup(self.domains.iter().map(|d| d.to_string())) {
            return Err(Error::config(format!("DOMAINS token {d} declared twice")));
        }
        let declared: BTreeSet<&DomainId> = self.domains.iter().collect();
        for m in &self.members {
            for w in &m.wires {
                if !declared.contains(&w.domain) {
                    return Err(Error::config(format!(
                        "MEMBER_TABLE {}: wire {}@{} names a domain that is not in DOMAINS ({})",
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
                        "MEMBER_TABLE {}: two wires on domain {} ({}). The model cannot express \
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
                    "SEGMENT_TABLE {}: domain {d} is not in DOMAINS ({})",
                    s.ifname,
                    self.domains_list()
                )));
            }
        }
        for z in &self.zones {
            if !declared.contains(&z.primary) {
                return Err(Error::config(format!(
                    "ZONE_TABLE {}: primary domain {} is not in DOMAINS ({})",
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
                    "ZONE_TABLE {}: gw domain {d} is not in DOMAINS ({})",
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
                    "DOMAINS declares {d} but no member has a wire on it (drop the token, or \
                     give a member a wire@{d}:<speed>)"
                )));
            }
        }
        // ---- segments ----
        let st = &self.segments;
        if let Some(d) = dup(st.iter().map(|r| r.vid.to_string())) {
            return Err(Error::config(format!(
                "SEGMENT_TABLE vid {d} used by two segments (one VLAN id per segment)"
            )));
        }
        if let Some(d) = dup(st.iter().map(|r| format!("{}:{}", r.zone, r.seg))) {
            return Err(Error::config(format!(
                "SEGMENT_TABLE segment {d} declared twice"
            )));
        }
        if let Some(d) = dup(st.iter().map(|r| format!("{}:{}", r.zone, r.scope))) {
            return Err(Error::config(format!(
                "SEGMENT_TABLE zone:domain {d} declared twice (a zone has one segment per \
                 domain, and one universal segment)"
            )));
        }
        if let Some(d) = dup(st.iter().map(|r| r.ifname.clone())) {
            return Err(Error::config(format!(
                "SEGMENT_TABLE ifname {d} declared twice"
            )));
        }
        for r in st {
            self.zone(&r.zone)?;
        }
        for r in st.iter().filter(|r| r.scope.is_universal()) {
            if bond_ifname_too_long(&r.ifname) {
                return Err(Error::config(format!(
                    "SEGMENT_TABLE {}: a universal (any) segment's ifname must be \
                     {MAX_BOND_IFNAME} characters or fewer (slaves are named <ifname>-<domain>, \
                     IFNAMSIZ 15)",
                    r.ifname
                )));
            }
        }
        // ---- zones ----
        if let Some(d) = dup(self.zones.iter().map(|z| z.id.to_string())) {
            return Err(Error::config(format!("ZONE_TABLE id {d} used twice")));
        }
        for z in &self.zones {
            if z.id < 1 {
                return Err(Error::config(format!(
                    "ZONE_TABLE id {} is not a valid block octet (1-254)",
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
                    "ZONE_TABLE {}: primary domain {} has no segment in SEGMENT_TABLE (the \
                     zone's rank-0 wire is the wire on its primary domain)",
                    z.name, z.primary
                )));
            }
        }
        // ---- members ----
        if let Some(d) = dup(self.members.iter().map(|m| m.name.clone())) {
            return Err(Error::config(format!(
                "MEMBER_TABLE member {d} declared twice"
            )));
        }
        if let Some(d) = dup(self.members.iter().map(|m| m.node.to_string())) {
            return Err(Error::config(format!(
                "MEMBER_TABLE node id {d} used twice"
            )));
        }
        // ---- wire preference overrides ----
        self.check_wire_prefs()?;
        // ---- the rest, unchanged ----
        for (from, to) in &self.forward_allow {
            for z in [from, to] {
                if self.zones.iter().all(|zz| zz.name != *z) {
                    return Err(Error::config(format!(
                        "FORWARD_ALLOW '{from}>{to}': unknown zone '{z}'"
                    )));
                }
            }
        }
        for (m, dev) in &self.usb_nics {
            let member = self
                .members
                .iter()
                .find(|mm| mm.name == *m)
                .ok_or_else(|| Error::config(format!("USB_NICS names unknown member '{m}'")))?;
            if member.wire_named(dev).is_none() {
                return Err(Error::config(format!(
                    "USB_NICS {m}:{dev}: '{dev}' is not one of {m}'s wires"
                )));
            }
        }
        for z in &self.zones {
            let Some(gw) = &z.gw else { continue };
            // scope `any` = a migrating ingress leg: a bond over one tagged sub-interface
            // per wire, named like a universal segment's slaves, so the derived bond name must
            // leave room for the `-<domain>` suffix.
            if gw.scope.is_universal() && bond_ifname_too_long(&format!("cfab-gw{}", z.id)) {
                return Err(Error::config(format!(
                    "ZONE_TABLE {}: ingress bond cfab-gw{} must be {MAX_BOND_IFNAME} \
                     characters or fewer (slaves are named <ifname>-<domain>, IFNAMSIZ 15)",
                    z.name, z.id
                )));
            }
            if st.iter().any(|r| r.vid == gw.vid) {
                return Err(Error::config(format!(
                    "ZONE_TABLE {} ingress vid {} is also a segment vid",
                    z.name, gw.vid
                )));
            }
            let octet = gw.router_octet()?;
            for m in &self.members {
                // Only a host with a wire on the gw domain carries the leg — but a node id
                // equal to the router octet is a landmine for any future wire, so check all.
                if m.node == octet {
                    return Err(Error::config(format!(
                        "ZONE_TABLE {} router {} collides with node {} ({})'s leg address",
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

    /// A WIRE_PREF row replaces the whole derived order, so it must BE the whole order: every
    /// candidate wire of that (member, zone) exactly once. A partial list is an error, never
    /// blended with the default.
    fn check_wire_prefs(&self) -> Result<()> {
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for p in &self.wire_prefs {
            let m = self
                .member(&p.member)
                .map_err(|e| Error::config(format!("WIRE_PREF {} {}: {e}", p.member, p.zone)))?;
            self.zone(&p.zone)
                .map_err(|e| Error::config(format!("WIRE_PREF {} {}: {e}", p.member, p.zone)))?;
            if !seen.insert((p.member.clone(), p.zone.clone())) {
                return Err(Error::config(format!(
                    "WIRE_PREF {} {} declared twice",
                    p.member, p.zone
                )));
            }
            for w in &p.order {
                if m.wire_named(w).is_none() {
                    return Err(Error::config(format!(
                        "WIRE_PREF {} {}: '{w}' is not one of {}'s wires",
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
                    "WIRE_PREF {} {}: a wire is listed twice",
                    p.member, p.zone
                )));
            }
            if got != want {
                return Err(Error::config(format!(
                    "WIRE_PREF {} {}: an override is the COMPLETE order, never blended with the \
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
    /// that zone, in MEMBER_TABLE order. The candidate set the derived order ranks and an
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
                "'{name}' is not in MEMBER_TABLE (members: {})",
                names.join(" ")
            ))
        })
    }

    pub fn zone(&self, name: &str) -> Result<&Zone> {
        self.zones.iter().find(|z| z.name == name).ok_or_else(|| {
            let names: Vec<&str> = self.zones.iter().map(|z| z.name.as_str()).collect();
            Error::config(format!(
                "'{name}' is not in ZONE_TABLE (zones: {})",
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
}

/// Non-empty, non-comment rows of a table, split into fields. Row ARITY is each parser's own
/// business: a row with the wrong number of columns is an error that names the layout, never a
/// silently dropped row (which is how an old-format file used to become a half-empty fabric).
fn table_rows(text: &str) -> Vec<Vec<&str>> {
    text.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| !f.is_empty() && !f[0].starts_with('#'))
        .collect()
}

fn parse_domains(text: &str) -> Result<Vec<DomainId>> {
    text.split_whitespace().map(DomainId::parse).collect()
}

/// `name@domain:speed`. Three distinct errors, because the three mistakes have three different
/// remedies: a v0 `name:speed` wire (no domain), a wire with no speed, and a malformed token.
fn parse_wire(member: &str, spec: &str) -> Result<Wire> {
    let bad_shape = || {
        Error::config(format!(
            "MEMBER_TABLE {member}: wire '{spec}' is malformed (expected name@domain:speed, \
             e.g. eth9@a:5000)"
        ))
    };
    let Some((name, rest)) = spec.split_once('@') else {
        return Err(Error::config(format!(
            "MEMBER_TABLE {member}: wire '{spec}' has no switch domain (expected \
             name@domain:speed, e.g. eth9@a:5000). A v1 wire is pinned to exactly one declared \
             domain; the v0 `name:speed` form named an island position instead"
        )));
    };
    let Some((domain, speed)) = rest.split_once(':') else {
        return Err(Error::config(format!(
            "MEMBER_TABLE {member}: wire '{spec}' has no link speed (expected \
             name@domain:speed, e.g. eth9@a:5000; the speed is DECLARED in Mb/s and only \
             cross-checked against ethtool)"
        )));
    };
    if name.is_empty() || rest.contains('@') || speed.contains(':') {
        return Err(bad_shape());
    }
    Ok(Wire {
        name: name.to_string(),
        domain: DomainId::parse(domain).map_err(|_| bad_shape())?,
        speed_mbit: speed.parse().map_err(|_| bad_shape())?,
    })
}

fn parse_member_table(text: &str) -> Result<Vec<Member>> {
    table_rows(text)
        .into_iter()
        .map(|f| {
            if f.len() < 4 {
                return Err(Error::config(format!(
                    "MEMBER_TABLE {}: {} columns (expected at least 4: member node kind \
                     wire@domain:speed …)",
                    f[0],
                    f.len()
                )));
            }
            // The v0 row was `member node kind st:speed cl:speed mg:speed`: three fixed island
            // slots. Named here rather than left to the wire parser's "no domain" error,
            // because the upgrade has a REGRESSION worth stating: v0 accepted the same NIC in
            // all three slots (a 1-NIC host trunking every segment), and v1 pins a wire to ONE
            // domain — such a member now carries one domain's segments and reaches the rest
            // over the universal segment.
            if f[3..].iter().any(|s| s.contains(':') && !s.contains('@')) {
                return Err(Error::config(format!(
                    "MEMBER_TABLE {}: '{}' looks like a v0 island wire. The v1 row is `member \
                     node kind wire@domain:speed …`: the three fixed st/cl/mg slots became a \
                     wire SET, each wire pinned to one declared DOMAINS token. REGRESSION to \
                     check while upgrading: a v0 member naming the SAME NIC in all three slots \
                     was trunking every segment over one wire; in v1 one wire is one domain, so \
                     that member carries only that domain's segments and reaches the rest over \
                     the universal segment",
                    f[0],
                    f[3..]
                        .iter()
                        .find(|s| s.contains(':') && !s.contains('@'))
                        .expect("just matched"),
                )));
            }
            let kind = MemberKind::parse(f[2])?;
            let wires = f[3..]
                .iter()
                .map(|spec| parse_wire(f[0], spec))
                .collect::<Result<Vec<_>>>()?;
            Ok(Member {
                name: f[0].to_string(),
                node: f[1].parse().map_err(|_| {
                    Error::config(format!(
                        "MEMBER_TABLE {}: node '{}' is not a number",
                        f[0], f[1]
                    ))
                })?,
                kind,
                wires,
            })
        })
        .collect()
}

fn parse_zone_table(text: &str) -> Result<Vec<Zone>> {
    table_rows(text)
        .into_iter()
        .map(|f| {
            if f.len() != 9 {
                return Err(Error::config(format!(
                    "ZONE_TABLE {}: {} columns (expected 9: zone id pcp dscp floor band weight \
                     primary gw). `primary` is new in v1: the switch domain carrying this zone's \
                     rank-0 wire on every member, which is where the per-interface OSPF costs \
                     come from now that SEGMENT_TABLE declares none",
                    f[0],
                    f.len()
                )));
            }
            let num = |i: usize, what: &str| -> Result<u32> {
                f[i].parse().map_err(|_| {
                    Error::config(format!(
                        "ZONE_TABLE {}: {what} '{}' is not a number",
                        f[0], f[i]
                    ))
                })
            };
            let gw = if f[8] == "-" {
                None
            } else {
                let parts: Vec<&str> = f[8].split(':').collect();
                let bad = || {
                    Error::config(format!(
                        "ZONE_TABLE {} gw '{}' (expected domain:vid:router/24, any:vid:router/24 \
                         or -)",
                        f[0], f[8]
                    ))
                };
                if parts.len() != 3 {
                    return Err(bad());
                }
                let (router, len) = parts[2].split_once('/').ok_or_else(bad)?;
                if len != "24" {
                    return Err(bad());
                }
                if router.split('.').count() != 4
                    || router.split('.').any(|o| o.parse::<u8>().is_err())
                {
                    return Err(bad());
                }
                Some(ZoneGw {
                    scope: SegScope::parse(parts[0]).map_err(|_| bad())?,
                    vid: parts[1].parse().map_err(|_| bad())?,
                    router: router.to_string(),
                })
            };
            Ok(Zone {
                name: f[0].to_string(),
                id: f[1].parse().map_err(|_| {
                    Error::config(format!(
                        "ZONE_TABLE {}: id {} is not a valid block octet (1-254)",
                        f[0], f[1]
                    ))
                })?,
                pcp: num(2, "pcp")? as u8,
                dscp: Dscp::parse(f[3])?,
                floor_mbit: num(4, "floor")?,
                band: num(5, "band")?,
                weight: num(6, "weight")?,
                primary: DomainId::parse(f[7])
                    .map_err(|e| Error::config(format!("ZONE_TABLE {}: primary {e}", f[0])))?,
                gw,
            })
        })
        .collect()
}

fn parse_segment_table(text: &str) -> Result<Vec<Segment>> {
    table_rows(text)
        .into_iter()
        .map(|f| {
            if f.len() != 5 {
                return Err(Error::config(format!(
                    "SEGMENT_TABLE {}: {} columns (expected 5: ifname domain|any zone seg vid). \
                     The v0 role and ospf-cost columns are gone: a segment's role is its scope \
                     ('any' = universal) and its cost is derived from ZONE_TABLE's primary \
                     domain and the per-member wire order",
                    f[0],
                    f.len()
                )));
            }
            let num = |i: usize, what: &str| -> Result<u32> {
                f[i].parse().map_err(|_| {
                    Error::config(format!(
                        "SEGMENT_TABLE {}: {what} '{}' is not a number",
                        f[0], f[i]
                    ))
                })
            };
            Ok(Segment {
                ifname: f[0].to_string(),
                scope: SegScope::parse(f[1])
                    .map_err(|e| Error::config(format!("SEGMENT_TABLE {}: {e}", f[0])))?,
                zone: f[2].to_string(),
                seg: num(3, "seg")? as u8,
                vid: num(4, "vid")? as u16,
            })
        })
        .collect()
}

fn parse_wire_pref(text: &str) -> Result<Vec<WirePref>> {
    table_rows(text)
        .into_iter()
        .map(|f| {
            if f.len() < 3 {
                return Err(Error::config(format!(
                    "WIRE_PREF {}: {} columns (expected at least 3: member zone wire …)",
                    f[0],
                    f.len()
                )));
            }
            Ok(WirePref {
                member: f[0].to_string(),
                zone: f[1].to_string(),
                order: f[2..].iter().map(|s| s.to_string()).collect(),
            })
        })
        .collect()
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
    use crate::config::RawConfig;

    fn real_conf() -> String {
        // The example declaration shipped with the crate: a real, live-proven 3-member fabric.
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
            .expect("examples/fabric.conf")
    }

    fn parse_fabric(mut edit: impl FnMut(&mut String)) -> Result<Fabric> {
        let mut text = real_conf();
        edit(&mut text);
        Fabric::from_raw(&RawConfig::parse(&text).unwrap())
    }

    fn a() -> DomainId {
        DomainId::parse("a").unwrap()
    }

    #[test]
    fn parses_the_real_declaration() {
        let raw = RawConfig::parse(&real_conf()).unwrap();
        let f = Fabric::from_raw(&raw).unwrap();
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
        // 9 domain segments + 3 universal rows (one per zone).
        assert_eq!(f.segments.len(), 12);
        assert_eq!(f.zone("mgmt").unwrap().id, 249);
        assert_eq!(f.zone("storage").unwrap().primary, a());
        let gw = f.zone("mgmt").unwrap().gw.as_ref().unwrap();
        assert_eq!(gw.router, "192.168.249.254");
        assert_eq!(gw.vid, 249);
        assert_eq!(gw.scope, SegScope::Domain(DomainId::parse("c").unwrap()));
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
                .speed_mbit,
            5000
        );
        // No literal key in the real file is unknown to the model.
        assert_eq!(raw.unconsumed(CONSUMED_KEYS), Vec::<&str>::new());
    }

    #[test]
    fn bfd_port_defaults_and_is_range_checked() {
        // The shipped declaration states it; a declaration that omits it gets RFC 5881's port.
        assert_eq!(parse_fabric(|_| {}).unwrap().bfd_port, 3784);
        let f = parse_fabric(|t| *t = t.replace("BFD_PORT=3784\n", "")).unwrap();
        assert_eq!(f.bfd_port, BFD_PORT_DEFAULT);
        assert_eq!(
            parse_fabric(|t| *t = t.replace("BFD_PORT=3784", "BFD_PORT=3785"))
                .unwrap()
                .bfd_port,
            3785
        );
        for (bad, want) in [
            ("BFD_PORT=1023", "BFD_PORT=1023 is outside 1024..65535"),
            ("BFD_PORT=0", "BFD_PORT=0 is outside 1024..65535"),
            ("BFD_PORT=70000", "BFD_PORT='70000' is not a valid port"),
            ("BFD_PORT=bfd", "BFD_PORT='bfd' is not a valid port"),
        ] {
            let err = parse_fabric(|t| *t = t.replace("BFD_PORT=3784", bad))
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{bad}: {err}");
        }
    }

    #[test]
    fn pcp_ctrl_is_range_checked() {
        assert_eq!(parse_fabric(|_| {}).unwrap().pcp_ctrl, 6);
        assert_eq!(
            parse_fabric(|t| *t = t.replace("PCP_CTRL=6", "PCP_CTRL=5"))
                .unwrap()
                .pcp_ctrl,
            5
        );
        for (bad, want) in [
            (
                "PCP_CTRL=7",
                "PCP_CTRL=7 is outside 0..6 (7 needs CAP_NET_ADMIN on the engine's control sockets)",
            ),
            ("PCP_CTRL=8", "PCP_CTRL=8 is outside 0..6"),
            ("PCP_CTRL=255", "PCP_CTRL=255 is outside 0..6"),
            ("PCP_CTRL=256", "PCP_CTRL='256' is not a valid number"),
            ("PCP_CTRL=six", "PCP_CTRL='six' is not a valid number"),
        ] {
            let err = parse_fabric(|t| *t = t.replace("PCP_CTRL=6", bad))
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{bad}: {err}");
        }
    }

    #[test]
    fn usb_nics_entry_without_dev_fails() {
        let err = parse_fabric(|t| *t = t.replace("pve1-tb:eth9", "pve1-tb")).unwrap_err();
        assert!(
            err.to_string().contains("'pve1-tb' is not member:dev"),
            "{err}"
        );
    }

    #[test]
    fn usb_nics_unknown_member_fails() {
        let err = parse_fabric(|t| *t = t.replace("pve1-tb:eth9", "pve9-tb:eth9")).unwrap_err();
        assert!(
            err.to_string().contains("unknown member 'pve9-tb'"),
            "{err}"
        );
    }

    #[test]
    fn usb_nics_non_wire_dev_fails() {
        let err = parse_fabric(|t| *t = t.replace("pve1-tb:eth9", "pve1-tb:eth5")).unwrap_err();
        assert!(
            err.to_string()
                .contains("'eth5' is not one of pve1-tb's wires"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_vid_fails() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "cfab-st-bk  b   storage 2 101",
                "cfab-st-bk  b   storage 2 100",
            )
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("vid 100 used by two segments"),
            "{err}"
        );
    }

    #[test]
    fn gw_vid_colliding_with_segment_vid_fails() {
        let err = parse_fabric(|t| *t = t.replace("c:249:", "c:250:")).unwrap_err();
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
        let err = parse_fabric(|t| {
            *t = t.replace(
                "FORWARD_ALLOW=\"storage>storage",
                "FORWARD_ALLOW=\"public>storage",
            )
        })
        .unwrap_err();
        assert!(err.to_string().contains("unknown zone 'public'"), "{err}");
    }

    #[test]
    fn gw_prefix_other_than_24_fails() {
        let err = parse_fabric(|t| *t = t.replace("192.168.249.254/24", "192.168.249.254/25"))
            .unwrap_err();
        assert!(
            err.to_string().contains("expected domain:vid:router/24"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_node_id_fails() {
        let err = parse_fabric(|t| *t = t.replace("pve2-tb 2 host", "pve2-tb 1 host")).unwrap_err();
        assert!(err.to_string().contains("node id 1 used twice"), "{err}");
    }

    #[test]
    fn unknown_member_error_lists_members() {
        let raw = RawConfig::parse(&real_conf()).unwrap();
        let f = Fabric::from_raw(&raw).unwrap();
        let err = f.member("nope").unwrap_err();
        assert!(
            err.to_string().contains("members: pve1-tb pve2-tb pve3-tb"),
            "{err}"
        );
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
    }

    #[test]
    fn universal_ifname_over_the_budget_fails() {
        let err = parse_fabric(|t| {
            *t = t.replace("cfab-st-fb  any storage", "cfab-storage-fb any storage")
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("must be 13 characters or fewer"),
            "{err}"
        );
    }

    /// The slave-name budget, at the predicate: a bond leg's slaves are `<ifname>-<domain>`,
    /// so with one-letter tokens 13 characters fit IFNAMSIZ and 14 do not.
    #[test]
    fn bond_ifname_longer_than_the_budget_is_refused() {
        assert_eq!(MAX_BOND_IFNAME, 13);
        assert!(!bond_ifname_too_long("cfab-st-fb"));
        assert!(!bond_ifname_too_long("1234567890123"));
        assert!(bond_ifname_too_long("12345678901234"));
    }

    /// ...and no ZONE_TABLE declaration can reach it today: a zone id is a u8, so the widest
    /// derived ingress bond is `cfab-gw255` (10) and its widest slave `cfab-gw255-a` (12).
    #[test]
    fn every_zone_id_yields_an_ingress_bond_name_that_fits() {
        for id in u8::MIN..=u8::MAX {
            let ifname = format!("cfab-gw{id}");
            assert!(!bond_ifname_too_long(&ifname), "{ifname}");
            assert!(format!("{ifname}-a").len() <= 15, "{ifname}");
        }
    }

    /// The ingress leg migrates, so `any` is a legal gw scope.
    #[test]
    fn gw_scope_any_is_accepted() {
        let f = parse_fabric(|t| *t = t.replace("c:249:", "any:249:")).unwrap();
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

    #[test]
    fn schema_still_emits() {
        let schema = schemars::schema_for!(Fabric);
        let json = serde_json::to_string(&schema).expect("schema serializes");
        assert!(json.contains("universal"), "{json}");
        assert!(json.contains("speed_mbit"), "{json}");
    }

    // ---- v0 declarations fail loud, naming the v1 layout ------------------------------------

    #[test]
    fn a_v0_class_table_key_names_segment_table() {
        let err = parse_fabric(|t| *t = t.replace("SEGMENT_TABLE=", "CLASS_TABLE=")).unwrap_err();
        assert!(
            err.to_string()
                .contains("CLASS_TABLE was replaced by SEGMENT_TABLE"),
            "{err}"
        );
    }

    #[test]
    fn a_v0_member_row_names_the_new_layout_and_the_trunk_regression() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "pve1-tb 1 host eth9@a:5000 eth1@b:1000 eth0@c:1000",
                "pve1-tb 1 host eth9:5000 eth1:1000 eth0:1000",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("looks like a v0 island wire"), "{err}");
        assert!(err.contains("wire@domain:speed"), "{err}");
        assert!(err.contains("REGRESSION"), "{err}");
    }

    #[test]
    fn a_v0_zone_row_names_the_primary_column() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "storage  99 0 cs0 2000 2 4 a -",
                "storage  99 0 cs0 2000 2 4 -",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("8 columns (expected 9"), "{err}");
        assert!(err.contains("primary gw"), "{err}");
    }

    #[test]
    fn a_v0_segment_row_names_the_dropped_role_and_cost_columns() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "cfab-st     a   storage 1 100",
                "cfab-st     a   storage 1 100 primary 10",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("7 columns (expected 5"), "{err}");
        assert!(err.contains("role and ospf-cost columns are gone"), "{err}");
    }

    // ---- name@domain:speed: three mistakes, three errors ------------------------------------

    /// A bare name reaches the "no domain" error. The v0 `name:speed` spelling does NOT: the
    /// old-format detector above catches it first and says more, which is the point of having
    /// both.
    #[test]
    fn a_wire_without_a_domain_says_so() {
        let err = parse_fabric(|t| {
            *t = t.replace("eth1@b:1000 eth0@c:1000\npve2", "eth1 eth0@c:1000\npve2")
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("has no switch domain"), "{err}");
        let v0 = parse_fabric(|t| {
            *t = t.replace(
                "eth1@b:1000 eth0@c:1000\npve2",
                "eth1:1000 eth0@c:1000\npve2",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(v0.contains("looks like a v0 island wire"), "{v0}");
    }

    #[test]
    fn a_wire_without_a_speed_says_so() {
        let err = parse_fabric(|t| {
            *t = t.replace("eth1@b:1000 eth0@c:1000\npve2", "eth1@b eth0@c:1000\npve2")
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("has no link speed"), "{err}");
    }

    #[test]
    fn a_malformed_wire_says_so() {
        for bad in ["eth1@bb:1000", "eth1@b:fast", "@b:1000", "eth1@b:1:0"] {
            let err = parse_fabric(|t| {
                *t = t.replace(
                    "eth1@b:1000 eth0@c:1000\npve2",
                    &format!("{bad} eth0@c:1000\npve2"),
                )
            })
            .unwrap_err()
            .to_string();
            assert!(err.contains("is malformed"), "{bad}: {err}");
        }
    }

    // ---- the new refusals -------------------------------------------------------------------

    #[test]
    fn two_wires_on_one_domain_are_refused_with_the_reason() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "pve1-tb 1 host eth9@a:5000 eth1@b:1000 eth0@c:1000",
                "pve1-tb 1 host eth9@a:5000 eth8@a:5000 eth1@b:1000 eth0@c:1000",
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

    #[test]
    fn an_undeclared_wire_domain_is_refused() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "eth1@b:1000 eth0@c:1000\npve2",
                "eth1@d:1000 eth0@c:1000\npve2",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("not in DOMAINS (a b c)"), "{err}");
    }

    #[test]
    fn a_declared_domain_nobody_wires_into_is_refused() {
        let err = parse_fabric(|t| *t = t.replace("DOMAINS=\"a b c\"", "DOMAINS=\"a b c d\""))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("DOMAINS declares d but no member has a wire on it"),
            "{err}"
        );
    }

    #[test]
    fn a_zone_primary_domain_without_a_segment_is_refused() {
        // Trips ONLY this check: domain d is declared and wired (so the two-directional domain
        // check is satisfied) but carries no segment, and storage names it as its primary.
        let err = parse_fabric(|t| {
            *t = t
                .replace("DOMAINS=\"a b c\"", "DOMAINS=\"a b c d\"")
                .replace(
                    "pve1-tb 1 host eth9@a:5000 eth1@b:1000 eth0@c:1000",
                    "pve1-tb 1 host eth9@a:5000 eth1@b:1000 eth0@c:1000 eth2@d:1000",
                )
                .replace(
                    "storage  99 0 cs0 2000 2 4 a -",
                    "storage  99 0 cs0 2000 2 4 d -",
                );
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("ZONE_TABLE storage") && err.contains("primary domain d"),
            "the error must name the zone and its primary domain: {err}"
        );
        assert!(err.contains("no segment in SEGMENT_TABLE"), "{err}");
    }

    // ---- WIRE_PREF --------------------------------------------------------------------------

    #[test]
    fn a_complete_wire_pref_override_parses() {
        let f =
            parse_fabric(|t| t.push_str("\nWIRE_PREF=\"\npve1-tb storage eth1 eth9 eth0\n\"\n"))
                .unwrap();
        let p = f.wire_pref("pve1-tb", "storage").unwrap();
        assert_eq!(p.order, vec!["eth1", "eth9", "eth0"]);
    }

    #[test]
    fn a_partial_wire_pref_override_is_refused() {
        let err = parse_fabric(|t| t.push_str("\nWIRE_PREF=\"\npve1-tb storage eth1 eth9\n\"\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("COMPLETE order"), "{err}");
    }

    #[test]
    fn a_wire_pref_naming_an_unknown_wire_is_refused() {
        let err =
            parse_fabric(|t| t.push_str("\nWIRE_PREF=\"\npve1-tb storage eth1 eth9 eth5\n\"\n"))
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("'eth5' is not one of pve1-tb's wires"),
            "{err}"
        );
    }

    #[test]
    fn a_wire_pref_for_an_unknown_member_or_zone_is_refused() {
        let err =
            parse_fabric(|t| t.push_str("\nWIRE_PREF=\"\npve9-tb storage eth1 eth9 eth0\n\"\n"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("WIRE_PREF pve9-tb storage"), "{err}");
        let err =
            parse_fabric(|t| t.push_str("\nWIRE_PREF=\"\npve1-tb backup eth1 eth9 eth0\n\"\n"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("WIRE_PREF pve1-tb backup"), "{err}");
    }

    #[test]
    fn the_same_wire_pref_row_twice_is_refused() {
        let err = parse_fabric(|t| {
            t.push_str(
                "\nWIRE_PREF=\"\npve1-tb storage eth1 eth9 eth0\npve1-tb storage eth9 eth1 eth0\n\"\n",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("declared twice"), "{err}");
    }

    /// A table row with the wrong column count used to be dropped SILENTLY (`table_rows`
    /// filtered on an exact arity), which turned a typo into a half-declared fabric.
    #[test]
    fn a_short_member_row_is_an_error_not_a_dropped_row() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "pve2-tb 2 host eth9@a:5000 eth1@b:1000 eth0@c:1000",
                "pve2-tb 2 host",
            )
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("3 columns (expected at least 4"), "{err}");
    }
}
