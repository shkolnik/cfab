//! The typed fabric declaration — the data model behind `fabric.conf`.
//!
//! Three tables declare the fabric (MEMBER_TABLE, ZONE_TABLE, CLASS_TABLE); everything else is
//! generated from them. This module types every field, and `Fabric::validate` enforces the
//! declaration invariants: unique member names, node ids, segment vids and interface names, one
//! segment per zone × island, known zones everywhere a zone is named, and ingress gateways that
//! collide with neither a segment vid nor any member's leg address.
//! `cfab schema` emits this model as JSON Schema (schemars).

use std::collections::BTreeSet;
use std::fmt;

use schemars::JsonSchema;
use serde::Serialize;

use crate::config::RawConfig;
use crate::error::{Error, Result};

/// The three switch domains, named by the zone whose PRIMARY segment they carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Island {
    /// The storage island.
    St,
    /// The cluster island.
    Cl,
    /// The management island; a host's wire here also carries its untagged admin path.
    Mg,
    /// Not a physical switch domain: "every island this member has a wire on". Only a
    /// fallback segment (`Role::Fallback`) is declared on it; `Member::wire` always returns
    /// `None` for it (a fallback leg is a bond over every wire, resolved in the derive layer,
    /// never a single indexed wire).
    Any,
}

impl Island {
    pub fn parse(s: &str) -> Result<Island> {
        match s {
            "st" => Ok(Island::St),
            "cl" => Ok(Island::Cl),
            "mg" => Ok(Island::Mg),
            "any" => Ok(Island::Any),
            other => Err(Error::config(format!(
                "unknown island '{other}' (st|cl|mg|any)"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Island::St => "st",
            Island::Cl => "cl",
            Island::Mg => "mg",
            Island::Any => "any",
        }
    }
}

impl fmt::Display for Island {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Membership taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MemberKind {
    /// Transits between zones, shapes, carries every island it has wires on.
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

/// A member's physical NIC on one island + its DECLARED link speed (Mb/s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Wire {
    pub name: String,
    pub speed_mbit: u32,
}

/// The widest ifname a bond leg (a fallback segment, or a migrating ingress leg) may carry.
/// Its slaves are named `<ifname>-<island>`: three characters of suffix inside IFNAMSIZ 15.
pub const MAX_BOND_IFNAME: usize = 12;

/// Does this bond-leg name leave room for the `-<island>` suffix its slaves need? One
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
    /// Wire per island, in st/cl/mg order; None = no wire on that island ("-").
    pub wires: [Option<Wire>; 3],
}

impl Member {
    pub fn wire(&self, island: Island) -> Option<&Wire> {
        match island {
            Island::St | Island::Cl | Island::Mg => self.wires[island as usize].as_ref(),
            // A fallback leg is a bond over every wire this member has, not one indexed
            // wire — resolved by the derive layer, never here.
            Island::Any => None,
        }
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
    pub island: Island,
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
    /// Ingress, or None = the outside never enters this zone.
    pub gw: Option<ZoneGw>,
}

impl Zone {
    /// `10.<id>` — the zone's identity/segment block prefix.
    pub fn block(&self) -> String {
        format!("10.{}", self.id)
    }
}

/// primary|backup — a segment's role for its zone on this member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Primary,
    Backup,
    /// A fallback segment: island `any`, one per zone, no BFD, reached only when every
    /// island segment of its zone is gone.
    Fallback,
}

impl Role {
    pub fn parse(s: &str) -> Result<Role> {
        match s {
            "primary" => Ok(Role::Primary),
            "backup" => Ok(Role::Backup),
            "fallback" => Ok(Role::Fallback),
            other => Err(Error::config(format!(
                "CLASS_TABLE role '{other}' (expected primary|backup|fallback)"
            ))),
        }
    }
}

/// One CLASS_TABLE row: zone `zone` on island `island`, addressed 10.<id>.<seg>.<node>/24,
/// tagged `vid` on the island's switch.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Segment {
    pub ifname: String,
    pub island: Island,
    pub zone: String,
    pub seg: u8,
    pub vid: u16,
    pub role: Role,
    pub ospf_cost: u32,
}

/// The whole declaration, typed. Everything the deployed runtime needs and nothing it computes.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Fabric {
    pub fabric_mode: String,
    pub members: Vec<Member>,
    pub zones: Vec<Zone>,
    pub class_table: Vec<Segment>,
    pub leaf_cost_offset: u32,
    pub host_forward: bool,
    /// Allowed forward pairs (from, to); unlisted = dropped by policy, counted.
    pub forward_allow: Vec<(String, String)>,
    pub admin_floor_mbit: u32,
    pub admin_band: u32,
    pub vrrp_gw: bool,
    pub vrrp_vrid: u8,
    pub vrrp_if: String,
    pub vrrp_advert_ms: u32,
    pub pcp_ctrl: u8,
    pub dscp_mark: bool,
    pub dscp_ctrl: Dscp,
    pub bfd_rx_ms: u32,
    pub bfd_tx_ms: u32,
    pub bfd_mult: u32,
    pub ospf_hello: u32,
    pub ospf_dead: u32,
    pub bgp_as: u32,
    pub bgp_keepalive_s: u32,
    pub bgp_hold_s: u32,
    pub bgp_connect_s: u32,
    /// `(member, dev)` pairs from USB_NICS: USB NICs that get offload safe mode on `up`.
    pub usb_nics: Vec<(String, String)>,
    /// Runtime state dir written by `up`, read by `verify` and the daemons (CFAB_RUN).
    pub run_dir: String,
    pub fabric_domain: String,
}

/// Every key the model consumes from fabric.conf (for unknown-literal-key warnings).
pub const CONSUMED_KEYS: &[&str] = &[
    "FABRIC_MODE",
    "MEMBER_TABLE",
    "FABRIC_DOMAIN",
    "ZONE_TABLE",
    "CLASS_TABLE",
    "LEAF_COST_OFFSET",
    "HOST_FORWARD",
    "ADMIN_FLOOR",
    "ADMIN_BAND",
    "FORWARD_ALLOW",
    "VRRP_GW",
    "VRRP_VRID",
    "VRRP_ADVERT_MS",
    "VRRP_IF",
    "PCP_CTRL",
    "DSCP_MARK",
    "DSCP_CTRL",
    "BFD_RX_MS",
    "BFD_TX_MS",
    "BFD_MULT",
    "OSPF_HELLO",
    "OSPF_DEAD",
    "BGP_AS",
    "BGP_KEEPALIVE_S",
    "BGP_HOLD_S",
    "BGP_CONNECT_S",
    "USB_NICS",
    "CFAB_RUN",
];

fn parse_num<T: std::str::FromStr>(raw: &RawConfig, key: &str) -> Result<T> {
    let v = raw.require(key)?;
    v.parse()
        .map_err(|_| Error::config(format!("{key}='{v}' is not a valid number")))
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
        let members = parse_member_table(raw.require("MEMBER_TABLE")?)?;
        let zones = parse_zone_table(raw.require("ZONE_TABLE")?)?;
        let class_table = parse_class_table(raw.require("CLASS_TABLE")?)?;
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
            members,
            zones,
            class_table,
            leaf_cost_offset: parse_num(raw, "LEAF_COST_OFFSET")?,
            host_forward: parse_bool01(raw, "HOST_FORWARD")?,
            forward_allow,
            admin_floor_mbit: parse_num(raw, "ADMIN_FLOOR")?,
            admin_band: parse_num(raw, "ADMIN_BAND")?,
            vrrp_gw: parse_bool01(raw, "VRRP_GW")?,
            vrrp_vrid: parse_num(raw, "VRRP_VRID")?,
            vrrp_if: raw.require("VRRP_IF")?.to_string(),
            vrrp_advert_ms: parse_num(raw, "VRRP_ADVERT_MS")?,
            pcp_ctrl: parse_num(raw, "PCP_CTRL")?,
            dscp_mark: parse_bool01(raw, "DSCP_MARK")?,
            dscp_ctrl: Dscp::parse(raw.require("DSCP_CTRL")?)?,
            bfd_rx_ms: parse_num(raw, "BFD_RX_MS")?,
            bfd_tx_ms: parse_num(raw, "BFD_TX_MS")?,
            bfd_mult: parse_num(raw, "BFD_MULT")?,
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
        let ct = &self.class_table;
        if let Some(d) = dup(ct.iter().map(|r| r.vid.to_string())) {
            return Err(Error::config(format!(
                "CLASS_TABLE vid {d} used by two segments (one VLAN id per segment)"
            )));
        }
        if let Some(d) = dup(ct.iter().map(|r| format!("{}:{}", r.zone, r.seg))) {
            return Err(Error::config(format!(
                "CLASS_TABLE segment {d} declared twice"
            )));
        }
        if let Some(d) = dup(ct.iter().map(|r| format!("{}:{}", r.zone, r.island))) {
            return Err(Error::config(format!(
                "CLASS_TABLE zone:island {d} declared twice (a zone has one segment per island)"
            )));
        }
        if let Some(d) = dup(ct.iter().map(|r| r.ifname.clone())) {
            return Err(Error::config(format!(
                "CLASS_TABLE ifname {d} declared twice"
            )));
        }
        for r in ct {
            self.zone(&r.zone)?;
        }
        for r in ct {
            if r.island == Island::Any && r.role != Role::Fallback {
                return Err(Error::config(format!(
                    "CLASS_TABLE {}: island 'any' requires role 'fallback' (a fallback segment is \
                     the only segment without an island)",
                    r.ifname
                )));
            }
            if r.role == Role::Fallback && r.island != Island::Any {
                return Err(Error::config(format!(
                    "CLASS_TABLE {}: role 'fallback' requires island 'any' (an island segment \
                     cannot be fallback)",
                    r.ifname
                )));
            }
        }
        for r in ct.iter().filter(|r| r.role == Role::Fallback) {
            if bond_ifname_too_long(&r.ifname) {
                return Err(Error::config(format!(
                    "CLASS_TABLE {}: fallback ifname must be {MAX_BOND_IFNAME} characters or \
                     fewer (slaves are named <ifname>-<island>, IFNAMSIZ 15)",
                    r.ifname
                )));
            }
            let longest_path: u32 = ct
                .iter()
                .filter(|other| other.zone == r.zone && other.role != Role::Fallback)
                .map(|other| other.ospf_cost)
                .sum();
            if r.ospf_cost <= longest_path {
                return Err(Error::config(format!(
                    "CLASS_TABLE {}: fallback cost {} must exceed zone {}'s longest host path \
                     ({longest_path}, the sum of its class-row costs)",
                    r.ifname, r.ospf_cost, r.zone
                )));
            }
            if r.ospf_cost >= self.leaf_cost_offset {
                return Err(Error::config(format!(
                    "CLASS_TABLE {}: fallback cost {} must be below LEAF_COST_OFFSET ({})",
                    r.ifname, r.ospf_cost, self.leaf_cost_offset
                )));
            }
        }
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
        }
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
            if !member.wires.iter().flatten().any(|w| w.name == *dev) {
                return Err(Error::config(format!(
                    "USB_NICS {m}:{dev}: '{dev}' is not one of {m}'s wires"
                )));
            }
        }
        for z in &self.zones {
            let Some(gw) = &z.gw else { continue };
            // island `any` = a migrating ingress leg: a bond over one tagged sub-interface
            // per wire, named like a fallback leg's slaves, so the derived bond name must
            // leave room for the `-<island>` suffix.
            if gw.island == Island::Any && bond_ifname_too_long(&format!("cfab-gw{}", z.id)) {
                return Err(Error::config(format!(
                    "ZONE_TABLE {}: ingress bond cfab-gw{} must be {MAX_BOND_IFNAME} \
                     characters or fewer (slaves are named <ifname>-<island>, IFNAMSIZ 15)",
                    z.name, z.id
                )));
            }
            if ct.iter().any(|r| r.vid == gw.vid) {
                return Err(Error::config(format!(
                    "ZONE_TABLE {} ingress vid {} is also a segment vid",
                    z.name, gw.vid
                )));
            }
            let octet = gw.router_octet()?;
            for m in &self.members {
                // Only a host with a wire on the gw island carries the leg — but a node id
                // equal to the router octet is a landmine for any future wire, so check all.
                if m.node == octet {
                    return Err(Error::config(format!(
                        "ZONE_TABLE {} router {} collides with node {} ({})'s leg address",
                        z.name, gw.router, m.node, m.name
                    )));
                }
            }
        }
        Ok(())
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
}

fn table_rows(text: &str, want_fields: usize) -> Vec<Vec<&str>> {
    text.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.len() == want_fields && !f[0].starts_with('#'))
        .collect()
}

fn parse_member_table(text: &str) -> Result<Vec<Member>> {
    table_rows(text, 6)
        .into_iter()
        .map(|f| {
            let mut wires: [Option<Wire>; 3] = [None, None, None];
            for (i, spec) in f[3..6].iter().enumerate() {
                if spec.split(':').next() == Some("-") {
                    continue; // no wire on this island ("-" or "-:0")
                }
                let (name, speed) = spec.split_once(':').ok_or_else(|| {
                    Error::config(format!(
                        "MEMBER_TABLE {}: wire '{spec}' (expected name:speed)",
                        f[0]
                    ))
                })?;
                wires[i] = Some(Wire {
                    name: name.to_string(),
                    speed_mbit: speed.parse().map_err(|_| {
                        Error::config(format!(
                            "MEMBER_TABLE {}: wire '{spec}' speed is not a number",
                            f[0]
                        ))
                    })?,
                });
            }
            Ok(Member {
                name: f[0].to_string(),
                node: f[1].parse().map_err(|_| {
                    Error::config(format!(
                        "MEMBER_TABLE {}: node '{}' is not a number",
                        f[0], f[1]
                    ))
                })?,
                kind: MemberKind::parse(f[2])?,
                wires,
            })
        })
        .collect()
}

fn parse_zone_table(text: &str) -> Result<Vec<Zone>> {
    table_rows(text, 8)
        .into_iter()
        .map(|f| {
            let num = |i: usize, what: &str| -> Result<u32> {
                f[i].parse().map_err(|_| {
                    Error::config(format!(
                        "ZONE_TABLE {}: {what} '{}' is not a number",
                        f[0], f[i]
                    ))
                })
            };
            let gw = if f[7] == "-" {
                None
            } else {
                let parts: Vec<&str> = f[7].split(':').collect();
                let bad = || {
                    Error::config(format!(
                        "ZONE_TABLE {} gw '{}' (expected island:vid:router/24)",
                        f[0], f[7]
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
                    island: Island::parse(parts[0])?,
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
                gw,
            })
        })
        .collect()
}

fn parse_class_table(text: &str) -> Result<Vec<Segment>> {
    table_rows(text, 7)
        .into_iter()
        .map(|f| {
            let num = |i: usize, what: &str| -> Result<u32> {
                f[i].parse().map_err(|_| {
                    Error::config(format!(
                        "CLASS_TABLE {}: {what} '{}' is not a number",
                        f[0], f[i]
                    ))
                })
            };
            Ok(Segment {
                ifname: f[0].to_string(),
                island: Island::parse(f[1])?,
                zone: f[2].to_string(),
                seg: num(3, "seg")? as u8,
                vid: num(4, "vid")? as u16,
                role: Role::parse(f[5])?,
                ospf_cost: num(6, "ospf-cost")?,
            })
        })
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

    #[test]
    fn parses_the_real_declaration() {
        let raw = RawConfig::parse(&real_conf()).unwrap();
        let f = Fabric::from_raw(&raw).unwrap();
        assert_eq!(f.members.len(), 3);
        assert_eq!(f.zones.len(), 3);
        // 9 class segments + 3 fallback rows (one per zone, island `any`).
        assert_eq!(f.class_table.len(), 12);
        assert_eq!(f.zone("mgmt").unwrap().id, 249);
        let gw = f.zone("mgmt").unwrap().gw.as_ref().unwrap();
        assert_eq!(gw.router, "192.168.249.254");
        assert_eq!(gw.vid, 249);
        assert_eq!(gw.island, Island::Mg);
        assert_eq!(gw.leg_cidr(2), "192.168.249.2/24");
        assert!(f.zone("storage").unwrap().gw.is_none());
        let fallback = f
            .class_table
            .iter()
            .find(|r| r.ifname == "cfab-st-fb")
            .unwrap();
        assert_eq!(fallback.island, Island::Any);
        assert_eq!(fallback.role, Role::Fallback);
        assert_eq!(fallback.zone, "storage");
        assert_eq!(fallback.ospf_cost, 5000);
        assert_eq!(f.member("pve3-tb").unwrap().kind, MemberKind::Leaf);
        assert_eq!(
            f.member("pve1-tb")
                .unwrap()
                .wire(Island::St)
                .unwrap()
                .speed_mbit,
            5000
        );
        // No literal key in the real file is unknown to the model.
        assert_eq!(raw.unconsumed(CONSUMED_KEYS), Vec::<&str>::new());
    }

    fn parse_fabric(mut edit: impl FnMut(&mut String)) -> Result<Fabric> {
        let mut text = real_conf();
        edit(&mut text);
        Fabric::from_raw(&RawConfig::parse(&text).unwrap())
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
                "cfab-st-bk  cl storage 2 101",
                "cfab-st-bk  cl storage 2 100",
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
        let err = parse_fabric(|t| *t = t.replace("mg:249:", "mg:250:")).unwrap_err();
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
            err.to_string().contains("expected island:vid:router/24"),
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
    fn island_parses_any() {
        assert_eq!(Island::parse("any").unwrap(), Island::Any);
        assert_eq!(Island::Any.as_str(), "any");
        assert_eq!(Island::Any.to_string(), "any");
    }

    #[test]
    fn role_parses_fallback() {
        assert_eq!(Role::parse("fallback").unwrap(), Role::Fallback);
    }

    #[test]
    fn wire_of_island_any_is_always_none() {
        let raw = RawConfig::parse(&real_conf()).unwrap();
        let f = Fabric::from_raw(&raw).unwrap();
        for m in &f.members {
            assert!(m.wire(Island::Any).is_none(), "{}", m.name);
        }
    }

    #[test]
    fn island_any_without_role_fallback_fails() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "cfab-st-fb  any storage 9 300 fallback 5000",
                "cfab-st-fb  any storage 9 300 primary 5000",
            )
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("island 'any' requires role 'fallback'"),
            "{err}"
        );
    }

    #[test]
    fn role_fallback_without_island_any_fails() {
        // Flip an ordinary segment's role to `fallback` without changing its island — the
        // opposite-direction check, exercised without colliding with the zone:island
        // uniqueness check (every zone already has a row on every physical island).
        let err = parse_fabric(|t| {
            *t = t.replace(
                "cfab-st-bk  cl storage 2 101 backup  100",
                "cfab-st-bk  cl storage 2 101 fallback  100",
            )
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("role 'fallback' requires island 'any'"),
            "{err}"
        );
    }

    #[test]
    fn fallback_ifname_over_12_chars_fails() {
        let err = parse_fabric(|t| {
            *t = t.replace("cfab-st-fb  any storage", "cfab-storage-fb any storage")
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("fallback ifname must be 12 characters or fewer"),
            "{err}"
        );
    }

    #[test]
    fn fallback_cost_at_or_below_zones_longest_path_fails() {
        // storage's other class rows sum to 10 + 100 + 300 = 410; 400 does not clear it.
        let err = parse_fabric(|t| {
            *t = t.replace(
                "cfab-st-fb  any storage 9 300 fallback 5000",
                "cfab-st-fb  any storage 9 300 fallback 400",
            )
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("fallback cost 400 must exceed zone storage's longest host path (410"),
            "{err}"
        );
    }

    #[test]
    fn fallback_cost_at_or_above_leaf_cost_offset_fails() {
        let err = parse_fabric(|t| {
            *t = t.replace(
                "cfab-cl-fb  any cluster 9 301 fallback 5000",
                "cfab-cl-fb  any cluster 9 301 fallback 30000",
            )
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("fallback cost 30000 must be below LEAF_COST_OFFSET (30000)"),
            "{err}"
        );
    }

    /// Task 9: the ingress leg migrates, so `any` is a legal gw island. (Task 1 shipped a
    /// temporary refusal here because `gw_rows_of` had no fan-out; this replaces it.)
    #[test]
    fn gw_island_any_is_accepted() {
        let f = parse_fabric(|t| *t = t.replace("mg:249:", "any:249:")).unwrap();
        assert_eq!(
            f.zone("mgmt").unwrap().gw.as_ref().unwrap().island,
            Island::Any
        );
    }

    /// The slave-name guard, at the predicate: a bond leg's slaves are `<ifname>-<island>`,
    /// so 12 characters fit IFNAMSIZ and 13 do not.
    #[test]
    fn bond_ifname_longer_than_twelve_is_refused() {
        assert!(!bond_ifname_too_long("cfab-st-fb"));
        assert!(!bond_ifname_too_long("123456789012"));
        assert!(bond_ifname_too_long("1234567890123"));
    }

    /// ...and no ZONE_TABLE declaration can reach it today: a zone id is a u8, so the widest
    /// derived ingress bond is `cfab-gw255` (10) and its widest slave `cfab-gw255-mg` (13).
    /// The check guards the name SCHEME, not the declaration; this test is what would go red
    /// if the scheme ever grew.
    #[test]
    fn every_zone_id_yields_an_ingress_bond_name_that_fits() {
        for id in u8::MIN..=u8::MAX {
            let ifname = format!("cfab-gw{id}");
            assert!(!bond_ifname_too_long(&ifname), "{ifname}");
            assert!(format!("{ifname}-mg").len() <= 15, "{ifname}");
        }
    }

    #[test]
    fn schema_still_emits_with_fallback() {
        let schema = schemars::schema_for!(Fabric);
        let json = serde_json::to_string(&schema).expect("schema serializes");
        assert!(json.contains("\"fallback\""), "{json}");
        assert!(json.contains("\"any\""), "{json}");
    }
}
