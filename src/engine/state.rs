//! The engine's state document (spec §6): the one JSON object `status` and `up` read over
//! `engine.sock`, distilled from the providers' merged operational tree plus this member's
//! own configuration tree (cost/passive are config facts holo does not echo into state).

use serde_json::{Map, Value, json};

const OSPFV2: &str = "ietf-ospf:ospfv2";
const BFDV1: &str = "ietf-bfd-types:bfdv1";

/// Build the document. `cfg` is `emit::engine::generate`'s tree (cost/passive per OSPF
/// interface); `state_trees` are the providers' operational trees as libyang printed them.
pub fn document(ready: bool, cfg: &Value, state_trees: &[Value]) -> Value {
    let mut ospf = Map::new();
    let mut bfd = Vec::new();
    for tree in state_trees {
        for proto in protocols(tree) {
            match proto["type"].as_str() {
                Some(OSPFV2) => {
                    if let Some(name) = proto["name"].as_str() {
                        ospf.insert(
                            name.to_string(),
                            ospf_instance(proto, cfg_instance(cfg, name)),
                        );
                    }
                }
                Some(BFDV1) => bfd.extend(bfd_sessions(proto)),
                Some(_) | None => {}
            }
        }
    }
    json!({
        "ready": ready,
        "ospf": Value::Object(ospf),
        "bfd": bfd,
        "bgp": [],
    })
}

fn protocols(tree: &Value) -> impl Iterator<Item = &Value> {
    tree["ietf-routing:routing"]["control-plane-protocols"]["control-plane-protocol"]
        .as_array()
        .into_iter()
        .flatten()
}

fn cfg_instance<'a>(cfg: &'a Value, name: &str) -> Option<&'a Value> {
    protocols(cfg).find(|p| p["type"] == OSPFV2 && p["name"] == name)
}

fn list<'a>(v: &'a Value, container: &str, entry: &str) -> impl Iterator<Item = &'a Value> {
    v[container][entry].as_array().into_iter().flatten()
}

/// `module:name` → `name`; libyang prefixes an identity/enum value only when its module
/// differs from the node's.
fn local_name(v: &Value) -> Option<&str> {
    v.as_str().map(|s| s.rsplit(':').next().unwrap_or(s))
}

fn ospf_instance(proto: &Value, cfg: Option<&Value>) -> Value {
    let ospf = &proto["ietf-ospf:ospf"];
    let router_id = ospf["router-id"].clone();
    let cfg_ifs: Vec<&Value> = cfg
        .map(|c| {
            list(&c["ietf-ospf:ospf"], "areas", "area")
                .flat_map(|a| list(a, "interfaces", "interface"))
                .collect()
        })
        .unwrap_or_default();

    let mut interfaces = Map::new();
    let mut self_lsa_links = Vec::new();
    for area in list(ospf, "areas", "area") {
        for i in list(area, "interfaces", "interface") {
            let Some(name) = i["name"].as_str() else {
                continue;
            };
            let c = cfg_ifs.iter().find(|c| c["name"] == name);
            let neighbors: Vec<Value> = list(i, "neighbors", "neighbor")
                .map(|n| {
                    json!({
                        "router_id": n["neighbor-router-id"],
                        "addr": n["address"],
                        "state": n["state"],
                    })
                })
                .collect();
            interfaces.insert(
                name.to_string(),
                json!({
                    "state": i["state"],
                    "cost": c.map(|c| c["cost"].clone()).unwrap_or(Value::Null),
                    "passive": c.map(|c| c["passive"] == true).unwrap_or(false),
                    "neighbors": neighbors,
                }),
            );
        }
        for t in list(area, "database", "area-scope-lsa-type") {
            for lsa in list(t, "area-scope-lsas", "area-scope-lsa") {
                let hdr = &lsa["ospfv2"]["header"];
                if local_name(&hdr["type"]) != Some("ospfv2-router-lsa")
                    || hdr["adv-router"] != router_id
                {
                    continue;
                }
                for link in list(&lsa["ospfv2"]["body"]["router"], "links", "link") {
                    let metric = list(link, "topologies", "topology")
                        .next()
                        .map(|t| t["metric"].clone())
                        .unwrap_or(Value::Null);
                    self_lsa_links.push(json!({
                        "if": link["link-data"],
                        "link_id": link["link-id"],
                        "type": local_name(&link["type"]),
                        "metric": metric,
                    }));
                }
            }
        }
    }
    json!({
        "router_id": router_id,
        "interfaces": Value::Object(interfaces),
        "self_lsa_links": self_lsa_links,
    })
}

fn bfd_sessions(proto: &Value) -> Vec<Value> {
    list(
        &proto["ietf-bfd:bfd"]["ietf-bfd-ip-sh:ip-sh"],
        "sessions",
        "session",
    )
    .map(|s| {
        let run = &s["session-running"];
        let state = local_name(&run["local-state"]).map(|st| match st {
            "adminDown" => "admin-down".to_string(),
            other => other.to_ascii_lowercase(),
        });
        json!({
            "local": s["source-addr"],
            "peer": s["dest-addr"],
            "if": s["interface"],
            "state": state,
            "rx_us": run["negotiated-rx-interval"],
            "tx_us": run["negotiated-tx-interval"],
            "mult": s["remote-multiplier"],
        })
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Operational tree in the shape holo prints (OSPF part cut from
    /// holo-ospf/tests/conformance/ospfv2/topologies/topo1-1/rt1/output/northbound-state.json,
    /// renamed onto cfab's mgmt zone; BFD part written from ietf-bfd-ip-sh@2022-09-22 +
    /// ietf-bfd-types with the leaves holo-bfd's state.rs emits).
    fn state() -> Value {
        serde_json::from_str(r#"{
            "ietf-routing:routing": { "control-plane-protocols": { "control-plane-protocol": [
                { "type": "ietf-ospf:ospfv2", "name": "mgmt", "ietf-ospf:ospf": {
                    "router-id": "10.249.0.1",
                    "areas": { "area": [ { "area-id": "0.0.0.0",
                        "interfaces": { "interface": [
                            { "name": "cfab-mg", "state": "dr", "neighbors": { "neighbor": [
                                { "neighbor-router-id": "10.249.0.2", "address": "10.249.1.2",
                                  "state": "full", "statistics": { "nbr-retrans-qlen": 0 } } ] } },
                            { "name": "cfab-id249", "state": "loopback" }
                        ] },
                        "database": { "area-scope-lsa-type": [
                            { "lsa-type": 1, "area-scope-lsas": { "area-scope-lsa": [
                                { "lsa-id": "10.249.0.1", "adv-router": "10.249.0.1", "ospfv2": {
                                    "header": { "type": "ospfv2-router-lsa", "adv-router": "10.249.0.1" },
                                    "body": { "router": { "links": { "link": [
                                        { "link-id": "10.249.1.2", "link-data": "10.249.1.1",
                                          "type": "transit-network-link",
                                          "topologies": { "topology": [ { "mt-id": 0, "metric": 10 } ] } },
                                        { "link-id": "10.249.0.1", "link-data": "255.255.255.255",
                                          "type": "stub-network-link",
                                          "topologies": { "topology": [ { "mt-id": 0, "metric": 0 } ] } }
                                    ] } } } } },
                                { "lsa-id": "10.249.0.2", "adv-router": "10.249.0.2", "ospfv2": {
                                    "header": { "type": "ospfv2-router-lsa", "adv-router": "10.249.0.2" },
                                    "body": { "router": { "links": { "link": [
                                        { "link-id": "10.249.1.2", "link-data": "10.249.1.2",
                                          "type": "transit-network-link",
                                          "topologies": { "topology": [ { "mt-id": 0, "metric": 10 } ] } }
                                    ] } } } } }
                            ] } },
                            { "lsa-type": 2, "area-scope-lsas": { "area-scope-lsa": [
                                { "lsa-id": "10.249.1.2", "adv-router": "10.249.0.1", "ospfv2": {
                                    "header": { "type": "ospfv2-network-lsa", "adv-router": "10.249.0.1" },
                                    "body": { "network": { "network-mask": "255.255.255.0" } } } }
                            ] } }
                        ] }
                    } ] }
                } },
                { "type": "ietf-bfd-types:bfdv1", "name": "main", "ietf-bfd:bfd": {
                    "ietf-bfd-ip-sh:ip-sh": { "sessions": { "session": [
                        { "interface": "cfab-mg", "dest-addr": "10.249.1.2",
                          "path-type": "ietf-bfd-types:path-ip-sh", "ip-encapsulation": true,
                          "local-discriminator": 1, "remote-discriminator": 7, "remote-multiplier": 3,
                          "session-running": { "session-index": 1, "local-state": "up",
                              "remote-state": "up", "negotiated-tx-interval": 250000,
                              "negotiated-rx-interval": 250000, "detection-time": 750000 } },
                        { "interface": "cfab-st", "dest-addr": "10.99.1.2",
                          "local-discriminator": 2,
                          "session-running": { "local-state": "adminDown" } }
                    ] } }
                } }
            ] } }
        }"#).unwrap()
    }

    fn cfg() -> Value {
        json!({
            "ietf-interfaces:interfaces": { "interface": [ { "name": "cfab-mg", "type": "iana-if-type:ethernetCsmacd" } ] },
            "ietf-routing:routing": { "control-plane-protocols": { "control-plane-protocol": [
                { "type": "ietf-ospf:ospfv2", "name": "mgmt", "ietf-ospf:ospf": {
                    "explicit-router-id": "10.249.0.1",
                    "areas": { "area": [ { "area-id": "0.0.0.0", "interfaces": { "interface": [
                        { "name": "cfab-mg", "cost": 10, "bfd": { "enabled": true } },
                        { "name": "cfab-id249", "passive": true }
                    ] } } ] }
                } }
            ] } }
        })
    }

    #[test]
    fn ospf_instance_router_id_interfaces_neighbors_and_self_links() {
        let d = document(true, &cfg(), &[state()]);
        assert_eq!(d["ready"], true);
        let mgmt = &d["ospf"]["mgmt"];
        assert_eq!(mgmt["router_id"], "10.249.0.1");
        let mg = &mgmt["interfaces"]["cfab-mg"];
        assert_eq!(mg["state"], "dr");
        assert_eq!(mg["cost"], 10);
        assert_eq!(mg["passive"], false);
        assert_eq!(
            mg["neighbors"],
            json!([{ "router_id": "10.249.0.2", "addr": "10.249.1.2", "state": "full" }])
        );
        let id = &mgmt["interfaces"]["cfab-id249"];
        assert_eq!(id["state"], "loopback");
        assert_eq!(id["passive"], true);
        assert_eq!(id["cost"], Value::Null);
        assert_eq!(id["neighbors"], json!([]));
        // Only this router's router-LSA links, never the neighbor's.
        assert_eq!(
            mgmt["self_lsa_links"],
            json!([
                { "if": "10.249.1.1", "link_id": "10.249.1.2", "type": "transit-network-link", "metric": 10 },
                { "if": "255.255.255.255", "link_id": "10.249.0.1", "type": "stub-network-link", "metric": 0 }
            ])
        );
    }

    #[test]
    fn bfd_sessions_with_state_normalized() {
        let d = document(true, &cfg(), &[state()]);
        let bfd = d["bfd"].as_array().unwrap();
        assert_eq!(bfd.len(), 2);
        assert_eq!(
            bfd[0],
            json!({ "local": null, "peer": "10.249.1.2", "if": "cfab-mg", "state": "up",
                    "rx_us": 250000, "tx_us": 250000, "mult": 3 })
        );
        assert_eq!(bfd[1]["state"], "admin-down");
        assert_eq!(bfd[1]["peer"], "10.99.1.2");
        assert_eq!(d["bgp"], json!([]));
    }

    #[test]
    fn empty_state_is_empty_document() {
        let d = document(false, &cfg(), &[json!({})]);
        assert_eq!(d["ready"], false);
        assert_eq!(d["ospf"], json!({}));
        assert_eq!(d["bfd"], json!([]));
        let d = document(true, &cfg(), &[]);
        assert_eq!(d["ospf"], json!({}));
    }

    #[test]
    fn identity_values_accept_a_module_prefix() {
        let mut s = state();
        let lsa = &mut s["ietf-routing:routing"]["control-plane-protocols"]["control-plane-protocol"]
            [0]["ietf-ospf:ospf"]["areas"]["area"][0]["database"]["area-scope-lsa-type"][0]["area-scope-lsas"]
            ["area-scope-lsa"][0]["ospfv2"];
        lsa["header"]["type"] = json!("ietf-ospf:ospfv2-router-lsa");
        lsa["body"]["router"]["links"]["link"][0]["type"] = json!("ietf-ospf:transit-network-link");
        let d = document(true, &cfg(), &[s]);
        let links = d["ospf"]["mgmt"]["self_lsa_links"].as_array().unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0]["type"], "transit-network-link");
    }
}
