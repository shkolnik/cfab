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

pub fn generate(view: &View) -> Result<Value> {
    let f = view.fabric;
    let class_rows = view.class_rows();
    let gw_rows = view.gw_rows();

    // Every interface any instance names, in class-row → identity → ingress-leg order.
    let mut if_names: Vec<String> = Vec::new();
    let mut add_if = |name: String| {
        if !if_names.contains(&name) {
            if_names.push(name);
        }
    };
    for r in &class_rows {
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
            let cost = if view.kind() == MemberKind::Leaf {
                r.ospf_cost + f.leaf_cost_offset
            } else {
                r.ospf_cost
            };
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
    fn leaf_offsets_costs_no_gw_leg() {
        let t = tree("pve3-tb");
        assert_eq!(instances(&t).len(), 3);
        let st = ospf_if(instance(&t, "storage"), "cfab-st");
        assert_eq!(st["cost"], 30010);
        let s = serde_json::to_string(&t).unwrap();
        assert!(!s.contains("cfab-gw"), "leaf carries an ingress leg: {s}");
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
