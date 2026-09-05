//! The routing engine's configuration tree for this member — a pure generator, testable and
//! diffable without a live host. libyang's JSON encoding of ietf-interfaces + ietf-routing +
//! ietf-ospf: one OSPFv2 instance per zone with the segment interfaces (OSPF+BFD) and the
//! passive identity/ingress interfaces, plus the bare interface list the OSPF interface
//! leafrefs require (name + type only: `ip` stays the sole writer of link state and addresses).

use serde_json::{Map, Value, json};

use crate::derive::View;
use crate::error::Result;
use crate::model::MemberKind;

/// Base of the engine's private kernel route-protocol range: `201 = ospf, 202 = static,
/// 203 = bgp`, so `down`'s sweep and the startup purge touch nothing another stack installed.
pub const PROTO_BASE: u8 = 201;

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
    tree.insert(
        "ietf-routing:routing".into(),
        json!({ "control-plane-protocols": { "control-plane-protocol": protocols } }),
    );
    Ok(Value::Object(tree))
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
    fn host_tree_has_three_instances_and_bfd_in_microseconds() {
        let t = tree("pve1-tb");
        let names: Vec<&str> = instances(&t)
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["storage", "cluster", "mgmt"]);
        for p in instances(&t) {
            assert_eq!(p["type"], "ietf-ospf:ospfv2");
        }
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
        for inst in instances(&t) {
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
            for inst in instances(&t) {
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
        assert_eq!(instances(&t).len(), 3);
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
            for inst in instances(&t) {
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

    #[test]
    fn tree_is_deterministic() {
        let a = serde_json::to_string_pretty(&tree("pve1-tb")).unwrap();
        let b = serde_json::to_string_pretty(&tree("pve1-tb")).unwrap();
        assert_eq!(a, b);
    }
}
