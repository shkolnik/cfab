//! The declaration file `fabric.toml`, as a serde struct tree.
//!
//! This is the INPUT schema: named fields, closed sets as enums, `deny_unknown_fields`
//! everywhere. A key that is not in the tree is an error with a line and a column, and a
//! closed-set value that is not in its enum fails at parse naming the allowed set — both
//! things a positional table of whitespace columns could only get wrong silently.
//!
//! Nothing here validates the FABRIC: cross-table meaning (which domains exist, whether a
//! preference order is complete, whether an ingress vid collides with a segment) lives in
//! `model::Fabric::from_decl` and `Fabric::validate`, one gate for every declaration
//! whatever syntax it arrived in. This module's whole job is shape and type.
//!
//! `cfab schema` emits the JSON Schema of THIS tree: the file an operator writes, not the
//! model the binary derives from it.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::{Dscp, MemberKind};

/// The whole declaration. The structural tables (`domains`, `member`, `zone`) and the
/// forwarding posture (`forward`) are required; every other table is a tunable with a
/// measured default and may be omitted.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    /// DNS domain under which identities are named: `<member>.<zone>.<dns_domain>`
    /// (reserved: declared here, not generated yet).
    pub dns_domain: String,
    /// The physical switch domains: token -> what that switch physically is. Declared, not
    /// inferred, so a typo in a wire's or a segment's domain is an error and not a phantom
    /// domain. A `BTreeMap`, so the token order in every error message is deterministic.
    pub domains: BTreeMap<String, String>,
    /// `[[member]]` — who is in the fabric, on which wires.
    #[serde(rename = "member")]
    pub members: Vec<MemberDecl>,
    /// `[[zone]]` — the traffic classes, each with its own segments.
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneDecl>,
    /// `[[workload]]` — a VM workload VLAN and the zones it may reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workload: Vec<WorkloadDecl>,
    /// Required: whether hosts transit between zones, and which pairs may. Not a tunable
    /// with a default — a default would let an omitted table decide the isolation posture.
    pub forward: ForwardDecl,
    #[serde(default)]
    pub admin: Option<AdminDecl>,
    #[serde(default)]
    pub marking: Option<MarkingDecl>,
    #[serde(default)]
    pub cost: Option<CostDecl>,
    #[serde(default)]
    pub bfd: Option<BfdDecl>,
    #[serde(default)]
    pub ospf: Option<OspfDecl>,
    #[serde(default)]
    pub bgp: Option<BgpDecl>,
    #[serde(default)]
    pub runtime: Option<RuntimeDecl>,
}

impl Declaration {
    /// Parse `fabric.toml`. The error is the `toml` crate's own (line, column and the serde
    /// message) behind the `fabric.toml: ` prefix — no custom pretty-printing, so a new field
    /// cannot acquire a worse message than the parser already gives it.
    pub fn parse(text: &str) -> Result<Declaration> {
        toml::from_str(text).map_err(Error::config)
    }
}

/// One `[[member]]`: a fabric member and every wire it has.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberDecl {
    pub name: String,
    /// Node id: the host octet of every address this member holds (identity 10.<id>.0.<node>).
    pub node: u8,
    pub kind: MemberKind,
    /// Every wire, in declaration order: the fan-out order of a universal (fallback) bond,
    /// and the tie-break when two wires declare the same speed.
    pub wires: Vec<WireDecl>,
    /// Per-zone preference OVERRIDE: `zone = [wire, ...]`, the COMPLETE order for that zone
    /// (a partial list is an error, never blended with the derived order). Absent = derived.
    #[serde(default)]
    pub prefs: BTreeMap<String, Vec<String>>,
    /// This member's addresses on `[[workload]]` interfaces it carries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<MemberWorkloadDecl>,
}

/// One wire: a physical NIC, the switch domain it is plugged into, its DECLARED link speed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireDecl {
    pub nic: String,
    /// A `[domains]` token. One wire is pinned to exactly ONE domain.
    pub domain: String,
    /// DECLARED link speed in Mb/s; the observed ethtool speed is only cross-checked
    /// (USB NICs misreport, and a down link reports "Unknown").
    pub speed_mbps: u32,
    /// Optional `ethtool -K <nic>` words, applied on bringup and put back by `down`:
    /// `<feature> on|off` pairs, handed to ethtool VERBATIM. cfab knows no adapter and no
    /// driver — which features a NIC needs is the operator's declaration (`driver_features`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_features: Option<String>,
    /// RETIRED. `usb = true` used to select a hard-coded r8152 offload mitigation; it is gone,
    /// and a declaration that still carries it is refused by name (`model::Fabric::from_decl`)
    /// rather than by `deny_unknown_fields`' generic "unknown field". Kept out of the emitted
    /// schema: it is a tombstone for a good error message, not a key anyone may write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(skip)]
    pub usb: Option<bool>,
}

/// One `[[zone]]`: a traffic class and the segments that carry it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ZoneDecl {
    pub name: String,
    /// The zone's number: OSPF instance, identity netdev cfab-id<id>, block 10.<id>.0.0/16.
    /// NOT a VLAN id — segments carry those.
    pub id: u8,
    /// 802.1p priority for the zone's traffic (sub-interface egress-qos-map 0:pcp).
    pub pcp: u8,
    /// The plane a DSCP-trusting switch queues the zone's traffic on.
    pub dscp: Dscp,
    /// MINIMUM Mb/s guarantee for the zone's HTB band.
    pub floor_mbps: u32,
    /// HTB prio band (0 = control … 2 = bulk).
    pub band: u32,
    /// Quantum ratio within a shared band.
    pub weight: u32,
    /// The domain whose segment is this zone's rank-0 (primary) wire on every member that
    /// has a wire there — the one part of path preference that IS physical-layout policy.
    pub primary: String,
    pub segments: Vec<SegmentDecl>,
    /// The fallback leg (scope "any"): an active-backup bond over the member's own wires,
    /// no BFD. Omit it for a fallback-free zone.
    #[serde(default)]
    pub universal: Option<UniversalDecl>,
    /// Where the OUTSIDE enters this zone. Omit = the outside never enters it.
    #[serde(default)]
    pub gw: Option<GwDecl>,
}

/// One segment of a zone: zone x domain, addressed 10.<id>.<seg>.<node>/24, tagged `vid`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SegmentDecl {
    pub ifname: String,
    /// A `[domains]` token: the switch domain this segment lives on.
    pub domain: String,
    pub seg: u8,
    pub vid: u16,
}

/// A zone's universal (fallback) leg: like a segment, but on every wire the member has.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UniversalDecl {
    pub ifname: String,
    pub seg: u8,
    pub vid: u16,
}

/// A zone's ingress: a router-owned VLAN, distinct from every fabric segment.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GwDecl {
    /// A `[domains]` token, or "any" to make the leg migrate between wires.
    pub domain: String,
    pub vid: u16,
    /// The router's address with its prefix, e.g. `192.168.249.254/24` (/24 is the only
    /// length the design supports).
    pub router: String,
}

/// One VM workload VLAN (spec §4). `span` is phase 2; phase 1 accepts only its absence or "switch".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadDecl {
    pub name: String,
    pub ifname: String,
    pub prefix: String,
    pub gw: String,
    /// The VLAN's existing default router, listed inside DHCP option 121 (a client with 121
    /// ignores option 3). RULED (spec §10 call 14): declared, like any static IP configuration.
    pub router: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberWorkloadDecl {
    pub name: String,
    pub address: String,
}

/// `[forward]` — the isolation posture. Required.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForwardDecl {
    /// true = hosts forward between the zones listed in `allow`, under a generated
    /// default-deny nft policy; false = hosts route only for themselves.
    pub enabled: bool,
    /// Allowed forward pairs `"from>to"`; an unlisted pair is dropped by the policy, and
    /// counted.
    pub allow: Vec<String>,
}

pub const ADMIN_FLOOR_MBPS: u32 = 100;
pub const ADMIN_BAND: u32 = 1;

/// `[admin]` — the untagged admin band every host wire carries.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminDecl {
    #[serde(default = "default_admin_floor")]
    pub floor_mbps: u32,
    #[serde(default = "default_admin_band")]
    pub band: u32,
}

fn default_admin_floor() -> u32 {
    ADMIN_FLOOR_MBPS
}
fn default_admin_band() -> u32 {
    ADMIN_BAND
}

impl Default for AdminDecl {
    fn default() -> Self {
        AdminDecl {
            floor_mbps: ADMIN_FLOOR_MBPS,
            band: ADMIN_BAND,
        }
    }
}

pub const PCP_CTRL: u8 = 6;
pub const SET_DSCP: bool = true;

/// `[marking]` — the CONTROL marks (a zone's own pcp/dscp live in its `[[zone]]` table).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MarkingDecl {
    /// 802.1p priority the engine sets on its own OSPF/BFD sockets: control above every
    /// zone below it, so a switch gives it its own high queue.
    #[serde(default = "default_pcp_ctrl")]
    pub pcp_ctrl: u8,
    /// The DSCP overlay: `false` rolls the fabric back to PCP-only marking. Named
    /// `set_dscp`, not `dscp`, because a zone's `dscp` is a class and this is a switch.
    #[serde(default = "default_set_dscp")]
    pub set_dscp: bool,
}

fn default_pcp_ctrl() -> u8 {
    PCP_CTRL
}
fn default_set_dscp() -> bool {
    SET_DSCP
}

impl Default for MarkingDecl {
    fn default() -> Self {
        MarkingDecl {
            pcp_ctrl: PCP_CTRL,
            set_dscp: SET_DSCP,
        }
    }
}

pub const LEAF_OFFSET: u32 = 30000;

/// `[cost]` — the OSPF cost constants that are not derived.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CostDecl {
    /// A leaf never transits: its interfaces are advertised this far above any host path.
    #[serde(default = "default_leaf_offset")]
    pub leaf_offset: u32,
}

fn default_leaf_offset() -> u32 {
    LEAF_OFFSET
}

impl Default for CostDecl {
    fn default() -> Self {
        CostDecl {
            leaf_offset: LEAF_OFFSET,
        }
    }
}

pub const BFD_RX_MS: u32 = 250;
pub const BFD_TX_MS: u32 = 250;
pub const BFD_MULT: u32 = 3;
/// RFC 5881's single-hop port: what every BFD implementation binds unless told otherwise.
pub const BFD_PORT: u16 = 3784;

/// `[bfd]` — detect time is roughly `rx_ms x mult`. Loosen before tightening: measured LAN
/// jitter under saturating load can false-flap a 300 ms detect.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BfdDecl {
    #[serde(default = "default_bfd_rx")]
    pub rx_ms: u32,
    #[serde(default = "default_bfd_tx")]
    pub tx_ms: u32,
    #[serde(default = "default_bfd_mult")]
    pub mult: u32,
    /// A fabric-wide contract, not a per-host knob: both ends of a session must agree.
    #[serde(default = "default_bfd_port")]
    pub port: u16,
}

fn default_bfd_rx() -> u32 {
    BFD_RX_MS
}
fn default_bfd_tx() -> u32 {
    BFD_TX_MS
}
fn default_bfd_mult() -> u32 {
    BFD_MULT
}
fn default_bfd_port() -> u16 {
    BFD_PORT
}

impl Default for BfdDecl {
    fn default() -> Self {
        BfdDecl {
            rx_ms: BFD_RX_MS,
            tx_ms: BFD_TX_MS,
            mult: BFD_MULT,
            port: BFD_PORT,
        }
    }
}

pub const OSPF_HELLO_S: u32 = 1;
pub const OSPF_DEAD_S: u32 = 3;

/// `[ospf]` — the slow fallback behind BFD.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OspfDecl {
    #[serde(default = "default_ospf_hello")]
    pub hello_s: u32,
    #[serde(default = "default_ospf_dead")]
    pub dead_s: u32,
}

fn default_ospf_hello() -> u32 {
    OSPF_HELLO_S
}
fn default_ospf_dead() -> u32 {
    OSPF_DEAD_S
}

impl Default for OspfDecl {
    fn default() -> Self {
        OspfDecl {
            hello_s: OSPF_HELLO_S,
            dead_s: OSPF_DEAD_S,
        }
    }
}

pub const BGP_ASN: u32 = 65000;
pub const BGP_KEEPALIVE_S: u32 = 1;
pub const BGP_HOLD_S: u32 = 3;
pub const BGP_CONNECT_S: u32 = 3;

/// `[bgp]` — the ingress session to the router (only zones with a `gw` use it).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BgpDecl {
    #[serde(default = "default_bgp_asn")]
    pub asn: u32,
    #[serde(default = "default_bgp_keepalive")]
    pub keepalive_s: u32,
    #[serde(default = "default_bgp_hold")]
    pub hold_s: u32,
    /// FRR's default 120 s makes a returned wire re-peer slowly.
    #[serde(default = "default_bgp_connect")]
    pub connect_s: u32,
}

fn default_bgp_asn() -> u32 {
    BGP_ASN
}
fn default_bgp_keepalive() -> u32 {
    BGP_KEEPALIVE_S
}
fn default_bgp_hold() -> u32 {
    BGP_HOLD_S
}
fn default_bgp_connect() -> u32 {
    BGP_CONNECT_S
}

impl Default for BgpDecl {
    fn default() -> Self {
        BgpDecl {
            asn: BGP_ASN,
            keepalive_s: BGP_KEEPALIVE_S,
            hold_s: BGP_HOLD_S,
            connect_s: BGP_CONNECT_S,
        }
    }
}

pub const RUN_DIR: &str = "/run/cfab";

/// `[runtime]` — the state directory `up` writes and the daemons read.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDecl {
    #[serde(default = "default_run_dir")]
    pub run_dir: String,
}

fn default_run_dir() -> String {
    RUN_DIR.to_string()
}

impl Default for RuntimeDecl {
    fn default() -> Self {
        RuntimeDecl {
            run_dir: RUN_DIR.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
            .expect("examples/fabric.toml")
    }

    #[test]
    fn the_example_declaration_parses() {
        let d = Declaration::parse(&example()).expect("the example parses");
        assert_eq!(d.dns_domain, "fabric.example");
        assert_eq!(
            d.domains.keys().collect::<Vec<_>>(),
            vec!["a", "b", "c"],
            "tokens in deterministic order"
        );
        assert_eq!(d.members.len(), 3);
        assert_eq!(d.zones.len(), 3);
        assert_eq!(d.members[0].wires[0].nic, "eth9");
        assert_eq!(d.members[0].wires[0].speed_mbps, 5000);
        assert!(
            d.members[0].wires[0].driver_features.is_none(),
            "the example declares no driver_features on a live wire"
        );
        assert!(
            d.members
                .iter()
                .flat_map(|m| &m.wires)
                .all(|w| w.usb.is_none()),
            "the retired `usb` key is absent from the example"
        );
        assert!(d.members[0].prefs.is_empty(), "no override in the example");
        assert_eq!(d.zones[0].segments.len(), 3);
        assert_eq!(d.zones[0].universal.as_ref().unwrap().vid, 300);
        assert!(d.zones[0].gw.is_none());
        assert_eq!(d.zones[2].gw.as_ref().unwrap().domain, "any");
        assert!(d.forward.enabled);
    }

    /// An unknown key is an ERROR (not a warning), and the message says where it is.
    #[test]
    fn an_unknown_key_fails_with_its_line_and_column() {
        let text = example().replace("dns_domain =", "dns_dmoain =");
        let err = Declaration::parse(&text).unwrap_err().to_string();
        assert!(err.contains("fabric.toml: "), "{err}");
        assert!(err.contains("dns_dmoain"), "{err}");
        assert!(
            err.contains("line 3"),
            "the position is in the error: {err}"
        );
        assert!(err.contains("column"), "{err}");
    }

    #[test]
    fn an_unknown_key_inside_a_table_fails_too() {
        let text = example().replace("speed_mbps = 5000", "speed = 5000");
        let err = Declaration::parse(&text).unwrap_err().to_string();
        assert!(err.contains("speed"), "{err}");
    }

    /// A closed set fails at parse naming what is allowed.
    #[test]
    fn a_bad_dscp_names_the_allowed_set() {
        let text = example().replace("dscp = \"cs0\"", "dscp = \"cs1\"");
        let err = Declaration::parse(&text).unwrap_err().to_string();
        assert!(err.contains("cs1"), "{err}");
        for allowed in ["cs0", "cs2", "cs6"] {
            assert!(err.contains(allowed), "{allowed} missing from: {err}");
        }
    }

    #[test]
    fn a_bad_kind_names_the_allowed_set() {
        let text = example().replace("kind = \"leaf\"", "kind = \"router\"");
        let err = Declaration::parse(&text).unwrap_err().to_string();
        assert!(err.contains("router"), "{err}");
        assert!(err.contains("host") && err.contains("leaf"), "{err}");
    }

    /// The four blocks of the smallest legal declaration, so a test can leave one out.
    const MINIMAL_BLOCKS: [(&str, &str); 5] = [
        ("dns_domain", "dns_domain = \"x.example\"\n"),
        ("domains", "[domains]\na = \"the only switch\"\n"),
        (
            "member",
            "[[member]]\nname = \"m1\"\nnode = 1\nkind = \"host\"\n\
             wires = [{ nic = \"eth0\", domain = \"a\", speed_mbps = 1000 }]\n",
        ),
        (
            "zone",
            "[[zone]]\nname = \"z\"\nid = 9\npcp = 0\ndscp = \"cs0\"\nfloor_mbps = 10\n\
             band = 0\nweight = 1\nprimary = \"a\"\n\
             segments = [{ ifname = \"cfab-z\", domain = \"a\", seg = 1, vid = 10 }]\n",
        ),
        ("forward", "[forward]\nenabled = false\nallow = []\n"),
    ];

    pub(crate) fn minimal(without: &str) -> String {
        MINIMAL_BLOCKS
            .iter()
            .filter(|(name, _)| *name != without)
            .map(|(_, text)| *text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A required table is required: no default fabric appears when one is missing.
    #[test]
    fn a_missing_required_table_fails() {
        Declaration::parse(&minimal("")).expect("the minimal declaration parses");
        for (name, _) in MINIMAL_BLOCKS {
            let err = Declaration::parse(&minimal(name)).unwrap_err().to_string();
            assert!(
                err.contains("missing field") && err.contains(name),
                "without {name}: {err}"
            );
        }
    }

    /// The tunable tables are optional; omitting one takes the documented default.
    #[test]
    fn every_tunable_table_may_be_omitted() {
        let d = Declaration::parse(&example()).unwrap();
        assert_eq!(d.bfd.as_ref().unwrap().port, BFD_PORT);
        let stripped = strip_tunables(&example());
        let d = Declaration::parse(&stripped).expect("the tunables are optional");
        assert!(d.admin.is_none());
        assert!(d.bfd.is_none());
        assert_eq!(AdminDecl::default().floor_mbps, ADMIN_FLOOR_MBPS);
        assert_eq!(BfdDecl::default().port, BFD_PORT);
        assert_eq!(MarkingDecl::default().pcp_ctrl, PCP_CTRL);
        assert_eq!(RuntimeDecl::default().run_dir, RUN_DIR);
    }

    /// ...and a PRESENT tunable table may state only the field it changes.
    #[test]
    fn a_present_tunable_table_may_state_one_field() {
        let text = strip_tunables(&example()) + "\n[bfd]\nmult = 5\n";
        let d = Declaration::parse(&text).unwrap();
        let bfd = d.bfd.unwrap();
        assert_eq!(bfd.mult, 5);
        assert_eq!(bfd.rx_ms, BFD_RX_MS);
        assert_eq!(bfd.port, BFD_PORT);
    }

    /// Everything from `[admin]` to the end of the file is a tunable table; `[forward]`
    /// above it is required and stays.
    pub(crate) fn strip_tunables(text: &str) -> String {
        let cut = text.find("[admin]").expect("the tunables start at [admin]");
        text[..cut].to_string()
    }

    /// Parse -> serialize -> parse is a fixed point: every field the file states survives
    /// the struct tree, so `cfab schema` describes the file cfab actually reads.
    #[test]
    fn the_example_round_trips_through_the_struct_tree() {
        let once = Declaration::parse(&example()).unwrap();
        let text = toml::to_string(&once).expect("the declaration serializes");
        let twice = Declaration::parse(&text).expect("the serialized form parses");
        assert_eq!(
            toml::to_string(&twice).unwrap(),
            text,
            "the struct tree is not a fixed point"
        );
    }

    /// `cfab schema` emits the INPUT schema: the required tables are required, the tunables
    /// are not, and an unknown key is refused by the schema exactly as the parser refuses it.
    #[test]
    fn the_schema_describes_the_declaration() {
        let schema = schemars::schema_for!(Declaration);
        let json = serde_json::to_value(&schema).unwrap();
        let required: Vec<&str> = json["required"]
            .as_array()
            .expect("required")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for want in ["dns_domain", "domains", "member", "zone", "forward"] {
            assert!(required.contains(&want), "{want} must be required: {json}");
        }
        for tunable in ["admin", "marking", "cost", "bfd", "ospf", "bgp", "runtime"] {
            assert!(
                !required.contains(&tunable),
                "{tunable} is a tunable with defaults: {json}"
            );
            assert!(
                json["properties"][tunable] != serde_json::Value::Null,
                "{tunable} must still be in the schema"
            );
        }
        assert_eq!(json["additionalProperties"], serde_json::json!(false));
        // ...and every property the example states is described.
        let props = json["properties"].as_object().expect("properties");
        for key in [
            "dns_domain",
            "domains",
            "member",
            "zone",
            "forward",
            "workload",
        ] {
            assert!(props.contains_key(key), "{key}");
        }
    }

    #[test]
    fn a_workload_row_and_member_workloads_parse() {
        let d = Declaration::parse(&fixtures::with_workload(&fixtures::example())).unwrap();
        let wl = &d.workload[0];
        assert_eq!(
            (
                wl.name.as_str(),
                wl.ifname.as_str(),
                wl.prefix.as_str(),
                wl.gw.as_str(),
                wl.router.as_str()
            ),
            (
                "vms",
                "primary.3",
                "192.168.20.0/24",
                "192.168.20.254",
                "192.168.20.1"
            )
        );
        assert_eq!(wl.allow, vec!["storage".to_string()]);
        assert_eq!(wl.span, None);
        let m = d.members.iter().find(|m| m.name == "pve1-tb").unwrap();
        assert_eq!(m.workloads[0].name, "vms");
        assert_eq!(m.workloads[0].address, "192.168.20.2/24");
        assert!(
            d.members
                .iter()
                .find(|m| m.name == "pve3-tb")
                .unwrap()
                .workloads
                .is_empty()
        );
    }

    #[test]
    fn span_is_accepted_by_the_schema() {
        let text = fixtures::with_workload(&fixtures::example()).replace(
            "gw = \"192.168.20.254\"",
            "gw = \"192.168.20.254\"\nspan = \"switch\"",
        );
        let d = Declaration::parse(&text).unwrap();
        assert_eq!(d.workload[0].span.as_deref(), Some("switch"));
    }

    #[test]
    fn a_workload_row_rejects_unknown_keys() {
        let text = fixtures::with_workload(&fixtures::example()).replace(
            "gw = \"192.168.20.254\"",
            "gw = \"192.168.20.254\"\nvid = 3",
        );
        let err = Declaration::parse(&text).unwrap_err().to_string();
        assert!(err.contains("unknown field `vid`"), "{err}");
    }

    /// The retired shell format is not a declaration: it fails at parse, loudly.
    #[test]
    fn a_v0_shell_format_file_is_refused_at_parse() {
        let err = Declaration::parse("FABRIC_MODE=tagged\nDOMAINS=\"a b c\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("fabric.toml: "), "{err}");
    }
}

/// Declaration fixtures shared by the unit tests of every module: the shipped example, and
/// the few edits tests make to it. Centralized so a change to the file's shape breaks one
/// helper instead of thirty string literals.
/// Not `#[cfg(test)]`: the gate B golden (`tests/workload_golden.rs`) is an integration test and
/// so links the crate as an external library, where a test-gated module does not exist. These are
/// three string builders and a `read_to_string` of `examples/fabric.toml` resolved at call time,
/// so the shipped binary gains nothing but the code.
#[doc(hidden)]
pub mod fixtures {
    /// The example declaration shipped with the crate.
    pub fn example() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
            .expect("examples/fabric.toml")
    }

    /// `"eth9@a:5000 eth0@c:1000"` -> the inline wire tables. A TEST shorthand for writing
    /// wire sets compactly; the file format itself has no such spelling.
    pub fn wires(spec: &str) -> String {
        spec.split_whitespace()
            .map(|w| {
                let (nic, rest) = w.split_once('@').expect("nic@domain:speed");
                let (domain, speed) = rest.split_once(':').expect("nic@domain:speed");
                format!("{{ nic = \"{nic}\", domain = \"{domain}\", speed_mbps = {speed} }}")
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The example with the ingress leg pinned to ONE physical domain. It ships on scope
    /// `any` — the migrating leg — so every test of the pinned shape edits it here, and the
    /// assert means a change to the example's gw line cannot leave a caller silently testing
    /// the shipped scope instead of the one it names.
    pub fn with_a_domain_gw(text: &str) -> String {
        let needle = "gw = { domain = \"any\"";
        assert!(
            text.contains(needle),
            "the example's gw is no longer on scope `any`"
        );
        text.replace(needle, "gw = { domain = \"c\"")
    }

    /// Replace one member's whole wire set (and, with it, any `driver_features` those wires
    /// carried).
    pub fn with_wires(text: &str, member: &str, spec: &str) -> String {
        let at = text
            .find(&format!("name = \"{member}\""))
            .unwrap_or_else(|| panic!("no member {member} in the declaration"));
        let start = at + text[at..].find("wires = [").expect("a wires array");
        let end = start + text[start..].find("]\n").expect("the wires array ends") + 2;
        format!(
            "{}wires = [{}]\n{}",
            &text[..start],
            wires(spec),
            &text[end..]
        )
    }

    /// A whole `[[member]]` block.
    pub fn member(name: &str, node: u8, kind: &str, wire_spec: &str) -> String {
        format!(
            "[[member]]\nname = \"{name}\"\nnode = {node}\nkind = \"{kind}\"\nwires = [{}]\n\n",
            wires(wire_spec)
        )
    }

    /// One segment table entry, from the test shorthand `ifname@domain:seg:vid`.
    fn segment(spec: &str) -> String {
        let (ifname, rest) = spec.split_once('@').expect("ifname@domain:seg:vid");
        let mut parts = rest.split(':');
        let (domain, seg, vid) = (
            parts.next().expect("domain"),
            parts.next().expect("seg"),
            parts.next().expect("vid"),
        );
        format!("{{ ifname = \"{ifname}\", domain = \"{domain}\", seg = {seg}, vid = {vid} }}")
    }

    /// A whole `[[zone]]` block: `segment_spec` is a space-separated list of
    /// `ifname@domain:seg:vid`, `universal` is `ifname:seg:vid`.
    pub fn zone(
        name: &str,
        id: u8,
        primary: &str,
        segment_spec: &str,
        universal: Option<&str>,
        gw: Option<&str>,
    ) -> String {
        let segs: Vec<String> = segment_spec.split_whitespace().map(segment).collect();
        let mut out = format!(
            "[[zone]]\nname = \"{name}\"\nid = {id}\npcp = 0\ndscp = \"cs0\"\n\
             floor_mbps = 2000\nband = 2\nweight = 4\nprimary = \"{primary}\"\n\
             segments = [{}]\n",
            segs.join(", ")
        );
        if let Some(u) = universal {
            let mut p = u.split(':');
            out.push_str(&format!(
                "universal = {{ ifname = \"{}\", seg = {}, vid = {} }}\n",
                p.next().expect("ifname"),
                p.next().expect("seg"),
                p.next().expect("vid")
            ));
        }
        if let Some(g) = gw {
            let (domain, rest) = g.split_once(':').expect("domain:vid:router/24");
            let (vid, router) = rest.split_once(':').expect("domain:vid:router/24");
            out.push_str(&format!(
                "gw = {{ domain = \"{domain}\", vid = {vid}, router = \"{router}\" }}\n"
            ));
        }
        out.push('\n');
        out
    }

    /// A whole declaration from parts: domains, member blocks, zone blocks.
    pub fn declaration(domains: &[&str], members: &str, zones: &str, allow: &str) -> String {
        let doms: String = domains
            .iter()
            .map(|d| format!("{d} = \"switch {d}\"\n"))
            .collect();
        format!(
            "dns_domain = \"x.example\"\n\n[domains]\n{doms}\n{members}{zones}\
             [forward]\nenabled = true\nallow = [{allow}]\n"
        )
    }

    /// Insert a `prefs = { ... }` line into one member's block.
    pub fn with_prefs(text: &str, member: &str, prefs: &str) -> String {
        let at = text
            .find(&format!("name = \"{member}\""))
            .unwrap_or_else(|| panic!("no member {member} in the declaration"));
        let start = at + text[at..].find("wires = [").expect("a wires array");
        let end = start + text[start..].find("]\n").expect("the wires array ends") + 2;
        format!("{}{prefs}\n{}", &text[..end], &text[end..])
    }

    /// The example with its member blocks replaced wholesale (its zones untouched).
    pub fn with_members(text: &str, members: &str) -> String {
        let start = text.find("[[member]]").expect("the member blocks");
        let end = text.find("# ---- ZONES").expect("the zones section");
        format!(
            "{}{}\n\n{}",
            &text[..start],
            members.trim_end(),
            &text[end..]
        )
    }

    /// The `[[workload]]` block the tests share (`vms` on `primary.3`), appended as a top-level
    /// array table, and the member rows on the two hosts (inserted after their `wires` arrays).
    pub const WORKLOAD_BLOCK: &str = "\n[[workload]]\nname = \"vms\"\nifname = \"primary.3\"\nprefix = \"192.168.20.0/24\"\ngw = \"192.168.20.254\"\nrouter = \"192.168.20.1\"\nallow = [\"storage\"]\n";

    /// `WORKLOAD_BLOCK` allowed into a second zone (`mgmt`, alongside `storage`): the fixture
    /// that exercises "one sibling / passive OSPF entry / forward-policy pair per allowed zone",
    /// not just the single-zone case `WORKLOAD_BLOCK` covers.
    pub const MULTI_ZONE_ALLOW_WORKLOAD_BLOCK: &str = "\n[[workload]]\nname = \"vms\"\nifname = \"primary.3\"\nprefix = \"192.168.20.0/24\"\ngw = \"192.168.20.254\"\nrouter = \"192.168.20.1\"\nallow = [\"storage\", \"mgmt\"]\n";

    fn with_workload_block(text: &str, block: &str) -> String {
        let t = with_prefs(
            text,
            "pve1-tb",
            "workloads = [{ name = \"vms\", address = \"192.168.20.2/24\" }]",
        );
        let t = with_prefs(
            &t,
            "pve2-tb",
            "workloads = [{ name = \"vms\", address = \"192.168.20.3/24\" }]",
        );
        format!("{t}{block}")
    }

    pub fn with_workload(text: &str) -> String {
        with_workload_block(text, WORKLOAD_BLOCK)
    }

    /// The `with_workload` fixture with `allow = ["storage"]` instead of one zone.
    pub fn with_multi_zone_allow_workload(text: &str) -> String {
        with_workload_block(text, MULTI_ZONE_ALLOW_WORKLOAD_BLOCK)
    }

    /// The example with every zone's universal (fallback) leg removed.
    pub fn without_universal_legs(text: &str) -> String {
        text.lines()
            .filter(|l| !l.starts_with("universal = "))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }
}
