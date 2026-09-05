//! The routing engine's configuration tree for this member — a pure generator, testable and
//! diffable without a live host. libyang's JSON encoding of ietf-interfaces + ietf-routing +
//! ietf-ospf: one OSPFv2 instance per zone with the segment interfaces (OSPF+BFD) and the
//! passive identity/ingress interfaces, plus the bare interface list the OSPF interface
//! leafrefs require (name + type only: `ip` stays the sole writer of link state and addresses).

use serde_json::{Map, Value, json};

use crate::derive::{GwRow, View};
use crate::error::{Error, Result};
use crate::model::MemberKind;

/// Base of the engine's private kernel route-protocol range: `201 = ospf, 202 = static,
/// 203 = bgp`, so `down`'s sweep and the startup purge touch nothing another stack installed.
pub const PROTO_BASE: u8 = 201;

/// cfab's own kernel route-protocol id, for the routes cfab installs itself (the per-zone
/// return-path default, task E2.2). Deliberately OUTSIDE the engine's purged range
/// `PROTO_BASE..=PROTO_BASE + 3` (201..204), so neither the engine's startup purge nor `down`'s
/// sweep — both of which delete by that range — removes a route cfab owns from under itself.
pub const CFAB_PROTO: u8 = 205;

/// RFC 8405 SPF back-off, in milliseconds (`ietf-ospf` units), overriding the model defaults of
/// 5000/10000. Those defaults protect a large IGP's CPU from repeated SPF over hundreds of nodes;
/// a fabric of three routers and nine segments computes an SPF in microseconds. Measured cost of
/// the defaults on the testbed: a second topology event inside the hold-down window took 5.106 s
/// against 0.156 s for the first, and every event — a link returning, a peer restarting, a USB NIC
/// bouncing — re-arms the window. Availability-first says be fast when the fabric is being tested.
/// `long-delay` is what a second event pays once `time-to-learn` (500 ms) has passed. FRR's
/// equivalent (`spf-timers` holdtime, `lib/libospf.h`) starts at 50 ms and only ramps under
/// sustained churn; 1000 ms here was measured as 0.9 s of a 1.85 s second-event outage, 100 ms
/// leaves 0.93 s, all of it BFD detection plus MinLSInterval. The fixed value cannot ramp the way
/// FRR's does; at this scale an SPF every 100 ms under a flap storm is still noise.
const SPF_LONG_DELAY_MS: u32 = 100;
const SPF_HOLD_DOWN_MS: u32 = 3000;

/// What a transit link's OSPF cost is generated at. A leaf is always offset (it cannot
/// transit); a host is offset only while its forward policy has failed closed, so that no
/// peer keeps choosing it as transit while its own forwarding is off (spec §12 (b)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitCost {
    /// The cost the declaration asks for.
    Declared,
    /// The declared cost plus `LEAF_COST_OFFSET`: reachable, never chosen as a path through.
    LeafOffset,
}

impl TransitCost {
    /// The wire word, in the `transit-cost` request and in the engine's reply. One spelling.
    pub fn word(self) -> &'static str {
        match self {
            TransitCost::Declared => "normal",
            TransitCost::LeafOffset => "leaf",
        }
    }
}

pub fn generate(view: &View) -> Result<Value> {
    generate_at(view, TransitCost::Declared)
}

pub fn generate_at(view: &View, transit: TransitCost) -> Result<Value> {
    let f = view.fabric;
    let class_rows = view.class_rows();
    let fallback_rows = view.fallback_rows();
    let gw_rows = view.gw_rows();

    // Every interface any instance names, in class-row → fallback-bond → identity →
    // ingress-leg order.
    let mut if_names: Vec<String> = Vec::new();
    let mut add_if = |name: String| {
        if !if_names.contains(&name) {
            if_names.push(name);
        }
    };
    for r in &class_rows {
        add_if(r.ifname.clone());
    }
    // The fallback bond is an interface like any other here: holo needs only its name, and the
    // slaves under it are L2, never in the tree.
    for r in &fallback_rows {
        add_if(r.ifname.clone());
    }
    for z in &f.zones {
        add_if(View::identity_if(z));
    }
    for r in &gw_rows {
        add_if(r.ifname.clone());
    }
    let interfaces: Vec<Value> = if_names
        .iter()
        .map(|n| json!({ "name": n, "type": "iana-if-type:ethernetCsmacd" }))
        .collect();

    let mut protocols: Vec<Value> = Vec::new();
    for z in &f.zones {
        let mut ospf_ifs: Vec<Value> = Vec::new();
        // Segments: a leaf's transit links carry cost + LEAF_COST_OFFSET (never a transit).
        for r in class_rows.iter().filter(|r| r.zone == z.name) {
            let cost = link_cost(view, transit, r.ospf_cost);
            // ietf-bfd intervals are microseconds; fabric.conf declares milliseconds.
            ospf_ifs.push(json!({
                "name": r.ifname,
                "interface-type": "broadcast",
                "hello-interval": f.ospf_hello,
                "dead-interval": f.ospf_dead,
                "cost": cost,
                "bfd": {
                    "enabled": true,
                    "local-multiplier": f.bfd_mult,
                    "desired-min-tx-interval": f.bfd_tx_ms * 1000,
                    "required-min-rx-interval": f.bfd_rx_ms * 1000,
                },
            }));
        }
        // The fallback bond: an adjacency interface like a segment, but with NO bfd key at all.
        // The fallback path exists only when the fabric is already degraded and its active slave
        // migrates between wires in ~50 ms; a session would only re-establish per migration.
        // OSPF's dead interval is its detector, as it is for the ingress leg.
        for r in fallback_rows.iter().filter(|r| r.zone == z.name) {
            let cost = link_cost(view, transit, r.ospf_cost);
            ospf_ifs.push(json!({
                "name": r.ifname,
                "interface-type": "broadcast",
                "hello-interval": f.ospf_hello,
                "dead-interval": f.ospf_dead,
                "cost": cost,
            }));
        }
        // The identity, then the ingress leg (the router's /24 reaches the peers; no
        // adjacency — the router is not in the IGP).
        ospf_ifs.push(json!({ "name": View::identity_if(z), "passive": true }));
        for r in gw_rows.iter().filter(|r| r.zone == z.name) {
            ospf_ifs.push(json!({ "name": r.ifname, "passive": true }));
        }
        protocols.push(json!({
            "type": "ietf-ospf:ospfv2",
            "name": z.name,
            "ietf-ospf:ospf": {
                "explicit-router-id": view.identity_addr(z),
                "spf-control": { "ietf-spf-delay": {
                    "long-delay": SPF_LONG_DELAY_MS,
                    "hold-down": SPF_HOLD_DOWN_MS,
                } },
                "areas": { "area": [ {
                    "area-id": "0.0.0.0",
                    "interfaces": { "interface": ospf_ifs },
                } ] },
            },
        }));
    }

    let mut tree = Map::new();
    tree.insert(
        "ietf-interfaces:interfaces".into(),
        json!({ "interface": interfaces }),
    );
    if let Some((routing_policy, bgp)) = ingress_bgp(view, &gw_rows)? {
        protocols.push(bgp);
        tree.insert("ietf-routing-policy:routing-policy".into(), routing_policy);
    }
    tree.insert(
        "ietf-routing:routing".into(),
        json!({ "control-plane-protocols": { "control-plane-protocol": protocols } }),
    );
    Ok(Value::Object(tree))
}

/// The identity prefix set of a gw zone. Routing-policy names live in one flat, fabric-wide
/// namespace, so every generated name is `cfab-`-prefixed, like the nft tables.
fn id_set(zone: &str) -> String {
    format!("cfab-{zone}-id")
}

fn import_policy(zone: &str) -> String {
    format!("cfab-{zone}-import")
}

fn export_policy(zone: &str) -> String {
    format!("cfab-{zone}-export")
}

/// The iBGP ingress: one BGP instance for the member, one neighbor per gw row, and the
/// routing policy both ends of it name. Returns the `(routing-policy, control-plane-protocol)`
/// pair, or `None` when this member carries no ingress leg — a leaf, or a fabric that declares
/// no `gw`, emits neither.
///
/// Every policy name this tree references is defined in the same tree: holo resolves a
/// neighbor's policy names with `shared.policies.get(name).unwrap()`
/// (`holo-bgp/src/ibus/rx.rs`), so a dangling name is a panic in the engine, not a warning.
fn ingress_bgp(view: &View, gw_rows: &[GwRow]) -> Result<Option<(Value, Value)>> {
    let f = view.fabric;
    let Some(first) = gw_rows.first() else {
        return Ok(None);
    };

    let mut prefix_sets: Vec<Value> = Vec::new();
    let mut policies: Vec<Value> = Vec::new();
    let mut import_policies: Vec<Value> = Vec::new();
    let mut neighbors: Vec<Value> = Vec::new();
    let mut networks: Vec<Value> = Vec::new();

    for r in gw_rows {
        let z = f.zone(&r.zone)?;
        let gw = z.gw.as_ref().ok_or_else(|| {
            Error::config(format!("zone {} carries an ingress leg but no gw", z.name))
        })?;

        // The identity /32s of the zone and nothing else. Matching is
        // `contains(ip) && len >= lower && len <= upper` (`holo-utils/src/policy.rs`), so the
        // block's own /24 (len 24) and every segment /24 outside it are excluded — the filter
        // that keeps `redistribute direct`'s route for every address on the host (vmbr0,
        // docker0, the admin /24, every VM bridge) off the router.
        prefix_sets.push(json!({
            "name": id_set(&z.name),
            "mode": "ipv4",
            "prefixes": { "prefix-list": [ {
                "ip-prefix": format!("{}.0.0/24", z.block()),
                "mask-length-lower": 32,
                "mask-length-upper": 32,
            } ] },
        }));
        // Import: `set-med igp` carries the OSPF cost of a redistributed identity into MED, so
        // the router prefers the identity's owner (MED 0) over a transit. It works only here —
        // the export stage sees the interned attributes alone.
        policies.push(json!({
            "name": import_policy(&z.name),
            "statements": { "statement": [ {
                "name": "1",
                "conditions": { "match-prefix-set": { "prefix-set": id_set(&z.name) } },
                "actions": {
                    "policy-result": "accept-route",
                    "ietf-bgp-policy:bgp-actions": { "set-med": "igp" },
                },
            } ] },
        }));
        // Export: the OSPF next hop of a redistributed identity is a segment address the
        // router cannot resolve, so the leg address replaces it. The prefix set repeats the
        // import filter as defense in depth.
        policies.push(json!({
            "name": export_policy(&z.name),
            "statements": { "statement": [ {
                "name": "1",
                "conditions": { "match-prefix-set": { "prefix-set": id_set(&z.name) } },
                "actions": {
                    "policy-result": "accept-route",
                    "ietf-bgp-policy:bgp-actions": { "set-next-hop": "self" },
                },
            } ] },
        }));
        import_policies.push(Value::String(import_policy(&z.name)));
        // The owner's own identity /32 has no connected DIRECT route (holo marks a
        // non-loopback /32 UNNUMBERED), so `redistribute direct` never originates it and the
        // router only ever learns it via transit at MED = OSPF cost. `network` originates it
        // directly with MED 0, so the router prefers the owner over any transit re-advertising
        // the same /32.
        networks.push(Value::String(format!("{}/32", view.identity_addr(z))));

        let leg = gw.leg_cidr(view.node());
        let local = leg.split('/').next().unwrap_or(&leg).to_string();
        // No `passive-mode`: it defaults to false, and this fork refuses the commit outright if
        // it is true while the instance runs under `BgpListenPolicy::NoListener`. No neighbor
        // import policy either — holo's `default-import-policy` is already `reject-route`, so a
        // deny-all would be a second spelling of the rule and one more name to keep in sync.
        neighbors.push(json!({
            "remote-address": gw.router,
            "peer-as": f.bgp_as,
            "timers": {
                "connect-retry-interval": f.bgp_connect_s,
                "hold-time": f.bgp_hold_s,
                "keepalive": f.bgp_keepalive_s,
            },
            "transport": { "local-address": local },
            "afi-safis": { "afi-safi": [ {
                "name": "iana-bgp-types:ipv4-unicast",
                // The IPv4-unicast multiprotocol capability is sent only when the
                // NEIGHBOR-level leaf is true (`holo-bgp/src/neighbor.rs`); the global one is
                // read nowhere.
                "enabled": true,
                // holo's `default-export-policy` is `reject-route`, and an afi-safi
                // `apply-policy` SHADOWS the instance-level one rather than merging with it
                // (`holo-bgp/src/events.rs`) — so the export policy is attached here, at the
                // afi-safi, or the session sits Established advertising nothing.
                "apply-policy": { "export-policy": [ export_policy(&z.name) ] },
            } ] },
        }));
    }

    // The BGP router-id. `/routing/router-id` is deviated `not-supported` in holo, so
    // per-instance is the only place it can go; the first gw zone in ZONE_TABLE order owns it.
    let identifier = view.identity_addr(f.zone(&first.zone)?);
    let bgp = json!({
        "type": "ietf-bgp:bgp",
        // One instance per member spanning every gw zone, so a zone name would be wrong the
        // moment a second zone declares a gw.
        "name": "cfab",
        "ietf-bgp:bgp": {
            "global": {
                "as": f.bgp_as,
                "identifier": identifier,
                "afi-safis": { "afi-safi": [ {
                    "name": "iana-bgp-types:ipv4-unicast",
                    // Redistributed routes run the GLOBAL afi-safi's apply-policy, and holo's
                    // `default-import-policy` is `reject-route`: without this attachment every
                    // redistributed route is dropped with the session Established, PfxSnt 0,
                    // and no error anywhere.
                    "apply-policy": { "import-policy": import_policies },
                    "ipv4-unicast": {
                        "holo-bgp:redistribution": [
                            { "type": "ietf-routing:direct" },
                            { "type": "ietf-ospf:ospfv2" },
                        ],
                        "holo-bgp:network": networks,
                    },
                } ] },
            },
            "neighbors": { "neighbor": neighbors },
        },
    });

    let routing_policy = json!({
        "defined-sets": { "prefix-sets": { "prefix-set": prefix_sets } },
        "policy-definitions": { "policy-definition": policies },
    });
    Ok(Some((routing_policy, bgp)))
}

/// The one place the leaf offset is added. A leaf is offset by what it is; a host is offset
/// only when it is asked to be — the two callers of `generate_at`.
fn link_cost(view: &View, transit: TransitCost, declared: u32) -> u32 {
    if view.kind() == MemberKind::Leaf || transit == TransitCost::LeafOffset {
        declared + view.fabric.leaf_cost_offset
    } else {
        declared
    }
}

/// Source pinning, one rule per zone in ZONE_TABLE order: a route inside the zone's `/16`
/// block is installed with this member's identity as its preferred source, so identities are
/// the addresses on the wire (the embedded engine's stand-in for FRR's `set src` route-map).
pub fn prefsrc_rules(view: &View) -> Vec<(String, String)> {
    view.fabric
        .zones
        .iter()
        .map(|z| (format!("{}.0.0/16", z.block()), view.identity_addr(z)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::model::Fabric;
    use serde_json::Value;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// cfab's own route-protocol id must sit outside the engine's swept range (or the sweep
    /// deletes cfab's own default from under it) and must not collide with a well-known id.
    #[test]
    fn cfab_proto_is_outside_the_swept_range_and_not_well_known() {
        use crate::commands::engine_ctl::PROTO_RANGE;
        assert!(
            !PROTO_RANGE.contains(&CFAB_PROTO),
            "CFAB_PROTO {CFAB_PROTO} is inside the engine's swept range {PROTO_RANGE:?}"
        );
        // The numeric ids in this host's /usr/share/iproute2/rt_protos (checked 2026-09-05):
        // kernel 2, boot 3, static 4, gated 8, ra 9, mrt 10, zebra 11, bird 12, dnrouted 13,
        // xorp 14, ntk 15, dhcp 16, keepalived 18, babel 42, ovn 84, openr 99, bgp 186,
        // isis 187, ospf 188, rip 189, eigrp 192. cfab-return (205) is none of them.
        const WELL_KNOWN: [u8; 21] = [
            2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 42, 84, 99, 186, 187, 188, 189, 192,
        ];
        assert!(
            !WELL_KNOWN.contains(&CFAB_PROTO),
            "CFAB_PROTO {CFAB_PROTO} collides with a well-known rt_protos id"
        );
    }

    fn tree(member: &str) -> Value {
        let f = fabric();
        let v = View::new(&f, member).unwrap();
        generate(&v).unwrap()
    }

    fn instances(t: &Value) -> &Vec<Value> {
        t["ietf-routing:routing"]["control-plane-protocols"]["control-plane-protocol"]
            .as_array()
            .unwrap()
    }

    /// The per-zone OSPF instances; the member's one BGP instance is appended after them.
    fn ospf_instances(t: &Value) -> Vec<&Value> {
        instances(t)
            .iter()
            .filter(|p| p["type"] == "ietf-ospf:ospfv2")
            .collect()
    }

    fn instance<'a>(t: &'a Value, name: &str) -> &'a Value {
        instances(t)
            .iter()
            .find(|p| p["name"] == name)
            .unwrap_or_else(|| panic!("no instance {name}"))
    }

    fn ospf_ifs(inst: &Value) -> &Vec<Value> {
        let areas = inst["ietf-ospf:ospf"]["areas"]["area"].as_array().unwrap();
        assert_eq!(areas.len(), 1);
        assert_eq!(areas[0]["area-id"], "0.0.0.0");
        areas[0]["interfaces"]["interface"].as_array().unwrap()
    }

    fn ospf_if<'a>(inst: &'a Value, name: &str) -> &'a Value {
        ospf_ifs(inst)
            .iter()
            .find(|i| i["name"] == name)
            .unwrap_or_else(|| panic!("no interface {name} in instance"))
    }

    fn if_names(t: &Value) -> Vec<String> {
        t["ietf-interfaces:interfaces"]["interface"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn host_tree_has_three_ospf_instances_and_bfd_in_microseconds() {
        let t = tree("pve1-tb");
        let names: Vec<&str> = ospf_instances(&t)
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["storage", "cluster", "mgmt"]);
        let mgmt = instance(&t, "mgmt");
        assert_eq!(mgmt["ietf-ospf:ospf"]["explicit-router-id"], "10.249.0.1");

        let mg = ospf_if(mgmt, "cfab-mg");
        assert_eq!(mg["interface-type"], "broadcast");
        assert_eq!(mg["cost"], 10);
        assert_eq!(mg["hello-interval"], 1);
        assert_eq!(mg["dead-interval"], 3);
        assert_eq!(mg["bfd"]["enabled"], true);
        assert_eq!(mg["bfd"]["local-multiplier"], 3);
        assert_eq!(mg["bfd"]["desired-min-tx-interval"], 250_000);
        assert_eq!(mg["bfd"]["required-min-rx-interval"], 250_000);

        for passive in ["cfab-id249", "cfab-gw249"] {
            let p = ospf_if(mgmt, passive);
            assert_eq!(p["passive"], true, "{passive}");
            assert!(p.get("cost").is_none(), "{passive} carries a cost");
            assert!(p.get("bfd").is_none(), "{passive} carries bfd");
        }

        let ifs = if_names(&t);
        assert!(ifs.contains(&"cfab-gw249".to_string()));
        let mut sorted = ifs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ifs.len(),
            "duplicate interface entry: {ifs:?}"
        );
        // Every interface named in any OSPF instance has an ietf-interfaces entry (leafref).
        for inst in ospf_instances(&t) {
            for i in ospf_ifs(inst) {
                let n = i["name"].as_str().unwrap();
                assert!(ifs.contains(&n.to_string()), "{n} missing from interfaces");
            }
        }
        for e in t["ietf-interfaces:interfaces"]["interface"]
            .as_array()
            .unwrap()
        {
            let keys: Vec<&String> = e.as_object().unwrap().keys().collect();
            assert_eq!(keys, ["name", "type"], "{e}");
            assert_eq!(e["type"], "iana-if-type:ethernetCsmacd");
            assert!(e["name"].as_str().unwrap().starts_with("cfab-"));
        }
    }

    #[test]
    fn every_instance_sets_the_spf_backoff() {
        for member in ["pve1-tb", "pve3-tb"] {
            let t = tree(member);
            for inst in ospf_instances(&t) {
                let d = &inst["ietf-ospf:ospf"]["spf-control"]["ietf-spf-delay"];
                let name = &inst["name"];
                assert_eq!(d["long-delay"], 100, "{member} {name}");
                assert_eq!(d["hold-down"], 3000, "{member} {name}");
                // The rest of the algorithm stays on the model's defaults.
                for dflt in ["initial-delay", "short-delay", "time-to-learn"] {
                    assert!(d.get(dflt).is_none(), "{member} {name} pins {dflt}");
                }
            }
        }
    }

    /// Spec §12 (b): a fail-closed transit host advertises every transit link at the declared
    /// cost + LEAF_COST_OFFSET, so no peer keeps choosing it as a path through — and back at
    /// the declared cost when the policy is restored. Asserted on the candidate the engine
    /// commits, which is the only thing the peers ever see.
    #[test]
    fn a_fail_closed_host_advertises_transit_links_at_the_leaf_offset() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let normal = generate_at(&v, TransitCost::Declared).unwrap();
        let offset = generate_at(&v, TransitCost::LeafOffset).unwrap();
        assert_eq!(
            normal,
            generate(&v).unwrap(),
            "Declared is what `up` commits"
        );
        for (zone, ifn, declared) in [
            ("storage", "cfab-st", 10),
            ("storage", "cfab-st-bk", 100),
            ("cluster", "cfab-cl", 10),
            ("mgmt", "cfab-mg", 10),
            // The fallback bond is a transit link too: offset with the rest.
            ("storage", "cfab-st-fb", 5000),
        ] {
            assert_eq!(ospf_if(instance(&normal, zone), ifn)["cost"], declared);
            assert_eq!(
                ospf_if(instance(&offset, zone), ifn)["cost"],
                declared + 30000,
                "{zone} {ifn}"
            );
        }
        // Only the costs move: the identity, the ingress leg, BFD, the timers, everything
        // else must be byte-identical, or this is a reconfiguration and not a re-advertisement.
        let strip = |t: &Value| {
            let s = serde_json::to_string(t).unwrap();
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(at) = rest.find("\"cost\":") {
                out.push_str(&rest[..at]);
                out.push_str("\"cost\":X");
                rest = &rest[at + 7..];
                rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
            }
            out.push_str(rest);
            out
        };
        assert_eq!(strip(&normal), strip(&offset));
    }

    /// A leaf cannot transit and is already offset by what it is: asking it to fail closed
    /// changes nothing it advertises.
    #[test]
    fn a_leaf_is_unaffected_by_the_transit_cost_request() {
        let f = fabric();
        let v = View::new(&f, "pve3-tb").unwrap();
        assert_eq!(
            generate_at(&v, TransitCost::Declared).unwrap(),
            generate_at(&v, TransitCost::LeafOffset).unwrap()
        );
    }

    #[test]
    fn leaf_offsets_costs_no_gw_leg() {
        let t = tree("pve3-tb");
        assert_eq!(ospf_instances(&t).len(), 3);
        let st = ospf_if(instance(&t, "storage"), "cfab-st");
        assert_eq!(st["cost"], 30010);
        let s = serde_json::to_string(&t).unwrap();
        assert!(!s.contains("cfab-gw"), "leaf carries an ingress leg: {s}");
    }

    /// The fallback bond is an adjacency interface with a cost and no BFD, sitting between the
    /// segments and the passive identity. `"bfd": {"enabled": false}` would not do: the key
    /// must be absent, so holo never builds a session for it.
    #[test]
    fn fallback_interface_carries_a_cost_and_no_bfd_after_the_segments() {
        for (member, cost) in [("pve1-tb", 5000), ("pve3-tb", 35000)] {
            let t = tree(member);
            for (zone, bond) in [
                ("storage", "cfab-st-fb"),
                ("cluster", "cfab-cl-fb"),
                ("mgmt", "cfab-mg-fb"),
            ] {
                let inst = instance(&t, zone);
                let r = ospf_if(inst, bond);
                assert_eq!(r["interface-type"], "broadcast", "{member} {bond}");
                assert_eq!(r["hello-interval"], 1, "{member} {bond}");
                assert_eq!(r["dead-interval"], 3, "{member} {bond}");
                assert_eq!(r["cost"], cost, "{member} {bond}");
                assert!(
                    r.as_object().unwrap().get("bfd").is_none(),
                    "{member} {bond} carries a bfd key: {r}"
                );
                assert!(r.get("passive").is_none(), "{member} {bond} is passive");

                // Position: after every segment of the zone, before the passive identity.
                let names: Vec<&str> = ospf_ifs(inst)
                    .iter()
                    .map(|i| i["name"].as_str().unwrap())
                    .collect();
                let at = names.iter().position(|n| *n == bond).unwrap();
                let id = names.iter().position(|n| n.starts_with("cfab-id")).unwrap();
                assert!(at < id, "{member} {zone}: {names:?}");
                for (i, n) in names.iter().enumerate() {
                    if n.ends_with("-fb") || n.starts_with("cfab-id") || n.starts_with("cfab-gw") {
                        continue;
                    }
                    assert!(
                        i < at,
                        "{member} {zone}: segment {n} after the bond: {names:?}"
                    );
                }
            }
            // The bond is in the interface list; its slaves are L2 and never in the tree.
            let ifs = if_names(&t);
            for bond in ["cfab-st-fb", "cfab-cl-fb", "cfab-mg-fb"] {
                assert!(ifs.contains(&bond.to_string()), "{member}: {ifs:?}");
            }
            let s = serde_json::to_string(&t).unwrap();
            for slave in ["cfab-st-fb-st", "cfab-st-fb-cl", "cfab-st-fb-mg"] {
                assert!(!s.contains(slave), "{member} carries slave {slave}");
            }
        }
    }

    /// The whole engine-tree delta of the fallback segment, stated as a count: three interface
    /// entries, and one OSPF interface in each of the three zones.
    #[test]
    fn fallback_adds_exactly_three_interfaces_and_one_ospf_if_per_zone() {
        for member in ["pve1-tb", "pve2-tb", "pve3-tb"] {
            let t = tree(member);
            let names = if_names(&t);
            let fallback: Vec<&String> = names.iter().filter(|n| n.ends_with("-fb")).collect();
            assert_eq!(fallback.len(), 3, "{member}: {fallback:?}");
            for inst in ospf_instances(&t) {
                let n = ospf_ifs(inst)
                    .iter()
                    .filter(|i| i["name"].as_str().unwrap().ends_with("-fb"))
                    .count();
                assert_eq!(n, 1, "{member} {}", inst["name"]);
            }
        }
    }

    #[test]
    fn prefsrc_rules_one_per_zone() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let want: Vec<(String, String)> = [
            ("10.99.0.0/16", "10.99.0.1"),
            ("10.199.0.0/16", "10.199.0.1"),
            ("10.249.0.0/16", "10.249.0.1"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(prefsrc_rules(&v), want);
    }

    fn fixture() -> Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/engine-bgp.json"
        ))
        .unwrap();
        serde_json::from_str(&text).unwrap()
    }

    /// The one BGP instance of the emitted tree, or `None` when the member emits none.
    fn bgp_instance(t: &Value) -> Option<&Value> {
        instances(t).iter().find(|p| p["type"] == "ietf-bgp:bgp")
    }

    /// The same fabric with a second gw zone, so every per-zone name and every per-zone filter
    /// is exercised against a neighbor that must not see it.
    fn fabric_with_two_gw_zones() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace(
                    "cluster 199 6 cs6  200 0 1 -",
                    "cluster 199 6 cs6  200 0 1 cl:199:192.168.199.254/24",
                );
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// The same fabric with no ingress at all.
    fn fabric_without_a_gw() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace(
                    "mgmt    249 2 cs2  100 1 1 mg:249:192.168.249.254/24",
                    "mgmt    249 2 cs2  100 1 1 -",
                );
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// Every string value under `key`, anywhere in the tree.
    fn collect(v: &Value, key: &str, out: &mut Vec<String>) {
        if let Some(m) = v.as_object() {
            for (k, val) in m {
                if k == key {
                    if let Some(s) = val.as_str() {
                        out.push(s.to_string());
                    } else if let Some(a) = val.as_array() {
                        out.extend(a.iter().filter_map(|e| e.as_str()).map(str::to_string));
                    }
                }
                collect(val, key, out);
            }
        } else if let Some(a) = v.as_array() {
            for e in a {
                collect(e, key, out);
            }
        }
    }

    fn names_at(t: &Value, path: &[&str]) -> Vec<String> {
        let mut v = &t["ietf-routing-policy:routing-policy"];
        for p in path {
            v = &v[p];
        }
        v.as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn bgp_subtree_matches_the_golden_fixture() {
        let t = tree("pve1-tb");
        let want = fixture();
        assert_eq!(
            t["ietf-routing-policy:routing-policy"],
            want["ietf-routing-policy:routing-policy"]
        );
        assert_eq!(bgp_instance(&t).unwrap(), &want["bgp-instance"]);
        // The BGP instance is appended after the per-zone OSPF instances.
        let names: Vec<&str> = instances(&t)
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["storage", "cluster", "mgmt", "cfab"]);
    }

    /// A leaf never peers (it never transits), so it emits no BGP instance and no policy tree
    /// at all — not an empty one.
    #[test]
    fn a_leaf_emits_no_bgp_and_no_routing_policy() {
        let t = tree("pve3-tb");
        assert!(bgp_instance(&t).is_none());
        assert!(t.get("ietf-routing-policy:routing-policy").is_none());
        assert_eq!(instances(&t).len(), 3);
    }

    /// A host in a fabric that declares no ingress emits neither key either: the BGP subtree
    /// keys off the gw rows, not off the member kind.
    #[test]
    fn a_host_with_no_gw_row_emits_no_bgp_and_no_routing_policy() {
        let f = fabric_without_a_gw();
        let v = View::new(&f, "pve1-tb").unwrap();
        assert!(v.gw_rows().is_empty());
        let t = generate(&v).unwrap();
        assert!(bgp_instance(&t).is_none());
        assert!(t.get("ietf-routing-policy:routing-policy").is_none());
    }

    /// INVARIANT: holo resolves policy names with `.unwrap()` and panics on a name the tree does
    /// not define. Every reference anywhere in the emitted tree must resolve.
    #[test]
    fn every_policy_and_prefix_set_reference_is_defined() {
        for f in [fabric(), fabric_with_two_gw_zones()] {
            for member in ["pve1-tb", "pve2-tb", "pve3-tb"] {
                let v = View::new(&f, member).unwrap();
                let t = generate(&v).unwrap();
                if t.get("ietf-routing-policy:routing-policy").is_none() {
                    let s = serde_json::to_string(&t).unwrap();
                    assert!(!s.contains("policy"), "{member} references a policy: {s}");
                    continue;
                }
                let policies = names_at(&t, &["policy-definitions", "policy-definition"]);
                let sets = names_at(&t, &["defined-sets", "prefix-sets", "prefix-set"]);
                let mut refs = Vec::new();
                collect(&t, "import-policy", &mut refs);
                collect(&t, "export-policy", &mut refs);
                assert!(!refs.is_empty(), "{member}");
                for r in &refs {
                    assert!(policies.contains(r), "{member}: {r} not in {policies:?}");
                }
                let mut set_refs = Vec::new();
                collect(&t, "prefix-set", &mut set_refs);
                assert!(!set_refs.is_empty(), "{member}");
                for r in &set_refs {
                    assert!(sets.contains(r), "{member}: {r} not in {sets:?}");
                }
            }
        }
    }

    /// holo's default import policy is `reject-route` and it applies to REDISTRIBUTED routes:
    /// without a global afi-safi import policy every redistributed route is dropped with the
    /// session Established and no error anywhere.
    #[test]
    fn redistribution_always_carries_a_global_import_policy() {
        for f in [fabric(), fabric_with_two_gw_zones()] {
            for member in ["pve1-tb", "pve2-tb"] {
                let v = View::new(&f, member).unwrap();
                let t = generate(&v).unwrap();
                let gw_zones: Vec<String> = v.gw_rows().into_iter().map(|r| r.zone).collect();
                let global = &bgp_instance(&t).unwrap()["ietf-bgp:bgp"]["global"];
                for afi in global["afi-safis"]["afi-safi"].as_array().unwrap() {
                    let redist = &afi["ipv4-unicast"]["holo-bgp:redistribution"];
                    assert!(redist.is_array(), "{member}");
                    let imports = afi["apply-policy"]["import-policy"].as_array().unwrap();
                    let want: Vec<Value> = gw_zones
                        .iter()
                        .map(|z| Value::String(format!("cfab-{z}-import")))
                        .collect();
                    assert_eq!(imports, &want, "{member}");
                }
            }
        }
    }

    /// The owner's own identity /32 is originated via `holo-bgp:network`, one per gw zone, in
    /// gw-row order — the fix for the defect where redistribution never carries it (holo flags
    /// a non-loopback /32 UNNUMBERED, so there is no connected DIRECT route for it).
    #[test]
    fn network_carries_this_members_own_identity_per_gw_zone() {
        for f in [fabric(), fabric_with_two_gw_zones()] {
            for member in ["pve1-tb", "pve2-tb"] {
                let v = View::new(&f, member).unwrap();
                let t = generate(&v).unwrap();
                let want: Vec<Value> = v
                    .gw_rows()
                    .iter()
                    .map(|r| {
                        let z = f.zone(&r.zone).unwrap();
                        Value::String(format!("{}/32", v.identity_addr(z)))
                    })
                    .collect();
                let global = &bgp_instance(&t).unwrap()["ietf-bgp:bgp"]["global"];
                for afi in global["afi-safis"]["afi-safi"].as_array().unwrap() {
                    let network = afi["ipv4-unicast"]["holo-bgp:network"].as_array().unwrap();
                    assert_eq!(network, &want, "{member}");
                }
            }
        }
    }

    /// One prefix set per gw zone, and no zone's identity block reaches another zone's policies:
    /// a leak here would advertise cluster identities to the mgmt router.
    #[test]
    fn a_zones_policies_name_only_its_own_identity_block() {
        let f = fabric_with_two_gw_zones();
        let v = View::new(&f, "pve1-tb").unwrap();
        let t = generate(&v).unwrap();
        let pol = &t["ietf-routing-policy:routing-policy"];
        assert_eq!(
            names_at(&t, &["defined-sets", "prefix-sets", "prefix-set"]),
            ["cfab-cluster-id", "cfab-mgmt-id"]
        );
        assert_eq!(
            names_at(&t, &["policy-definitions", "policy-definition"]),
            [
                "cfab-cluster-import",
                "cfab-cluster-export",
                "cfab-mgmt-import",
                "cfab-mgmt-export"
            ]
        );
        for (set, block) in [
            ("cfab-cluster-id", "10.199.0.0/24"),
            ("cfab-mgmt-id", "10.249.0.0/24"),
        ] {
            let s = pol["defined-sets"]["prefix-sets"]["prefix-set"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == set)
                .unwrap();
            let list = s["prefixes"]["prefix-list"].as_array().unwrap();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0]["ip-prefix"], block);
            assert_eq!(list[0]["mask-length-lower"], 32);
            assert_eq!(list[0]["mask-length-upper"], 32);
        }
        for p in pol["policy-definitions"]["policy-definition"]
            .as_array()
            .unwrap()
        {
            let name = p["name"].as_str().unwrap();
            let zone = name.split('-').nth(1).unwrap();
            let mut sets = Vec::new();
            collect(p, "prefix-set", &mut sets);
            assert_eq!(sets, [format!("cfab-{zone}-id")], "{name}");
        }
        // Each neighbor exports only its own zone's policy.
        for (zone, router) in [("cluster", "192.168.199.254"), ("mgmt", "192.168.249.254")] {
            let n = bgp_instance(&t).unwrap()["ietf-bgp:bgp"]["neighbors"]["neighbor"]
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["remote-address"] == router)
                .unwrap();
            let afi = &n["afi-safis"]["afi-safi"][0];
            assert_eq!(afi["enabled"], true, "{zone}");
            assert_eq!(
                afi["apply-policy"]["export-policy"],
                json!([format!("cfab-{zone}-export")])
            );
            assert!(afi["apply-policy"].get("import-policy").is_none(), "{zone}");
        }
    }

    /// `passive-mode` true is refused outright by the fork when the instance runs under
    /// `BgpListenPolicy::NoListener`, and false is a second spelling of the default.
    #[test]
    fn no_passive_mode_anywhere() {
        for f in [fabric(), fabric_with_two_gw_zones()] {
            for member in ["pve1-tb", "pve2-tb", "pve3-tb"] {
                let v = View::new(&f, member).unwrap();
                let s = serde_json::to_string(&generate(&v).unwrap()).unwrap();
                assert!(!s.contains("passive-mode"), "{member}: {s}");
            }
        }
    }

    #[test]
    fn tree_is_deterministic() {
        let a = serde_json::to_string_pretty(&tree("pve1-tb")).unwrap();
        let b = serde_json::to_string_pretty(&tree("pve1-tb")).unwrap();
        assert_eq!(a, b);
    }
}
