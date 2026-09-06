//! G1 — semantic equivalence between the v0 declaration (cfab `main` `3ae8213`, 0.3.2) and the
//! v1 one this spike replaces it with.
//!
//! The oracle is `tests/fixtures/model-v0/`, captured from `3ae8213`'s own binary BEFORE any
//! model change (see that commit for the exact commands). C4 of the spec review makes byte
//! identity impossible by construction (every bond slave is renamed), so this compares the
//! SEMANTICS and enumerates every textual difference that is allowed. Anything else fails with
//! a readable diff.
//!
//! ALLOWED DIFFS, exhaustive:
//!   1. OSPF cost VALUES — the derived ladder (rank 0 -> 10, rank r -> 100·r) replaces the
//!      hand-picked numbers. The rank ORDER must survive; see the mgmt exception below.
//!   2. The universal (fallback) segment's cost — 5000 declared -> 410 derived (a zone's
//!      longest host path plus one ladder step), +30000 on the leaf.
//!   3. Bond-slave names — `<ifname>-<island>` -> `<ifname>-<domain>`, st->a, cl->b, mg->c.
//!   4. The nft admin set — one nominated NIC -> every wire of a host (James 2026-09-06: the
//!      untagged path of EVERY host wire is the admin plane). Not a model-v1 consequence; the
//!      same ruling that removed the admin-wire column.
//!   5. The mgmt zone's preference ORDER on every member — see
//!      `the_mgmt_backup_order_is_the_one_real_behavior_change`. This one is a genuine
//!      behavior change, NOT a cosmetic diff, and it contradicts spec §4's claim that option
//!      (c) "derives EXACTLY today's order for every (member, zone)". It is pinned here so it
//!      cannot change silently while James rules on it.

use std::collections::BTreeMap;

use cfab::decl::Declaration;
use cfab::derive::{View, class_rows_of, fallback_rows_of, prefs_of};
use cfab::model::Fabric;
use serde_json::Value;

const MEMBERS: [&str; 3] = ["pve1-tb", "pve2-tb", "pve3-tb"];

/// island token -> domain token, the whole of allowed diff 3.
const RENAME: [(&str, &str); 3] = [("st", "a"), ("cl", "b"), ("mg", "c")];

fn fabric() -> Fabric {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
            .expect("examples/fabric.toml");
    Fabric::from_decl(&Declaration::parse(&text).unwrap()).expect("the v1 example parses")
}

fn fixture(member: &str, file: &str) -> String {
    let p = format!(
        "{}/tests/fixtures/model-v0/{member}/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

/// A line-by-line diff, so a failure says WHICH line moved rather than dumping two blobs.
fn diff(label: &str, want: &str, got: &str) -> Option<String> {
    if want == got {
        return None;
    }
    let mut out = format!("{label}:\n");
    let (w, g): (Vec<&str>, Vec<&str>) = (want.lines().collect(), got.lines().collect());
    for i in 0..w.len().max(g.len()) {
        let (a, b) = (
            w.get(i).copied().unwrap_or(""),
            g.get(i).copied().unwrap_or(""),
        );
        if a != b {
            out.push_str(&format!("  line {}:\n    v0: {a}\n    v1: {b}\n", i + 1));
        }
    }
    Some(out)
}

/// The zone -> ordered (ifname, cost) list an engine tree carries, for the three fabric zones.
fn ospf_costs(tree: &Value) -> BTreeMap<String, Vec<(String, u64)>> {
    let mut out = BTreeMap::new();
    let cps = tree["ietf-routing:routing"]["control-plane-protocols"]["control-plane-protocol"]
        .as_array()
        .expect("control-plane-protocol list");
    for cp in cps {
        let Some(ospf) = cp.get("ietf-ospf:ospf") else {
            continue;
        };
        let ifs = ospf["areas"]["area"][0]["interfaces"]["interface"]
            .as_array()
            .expect("interface list");
        out.insert(
            cp["name"].as_str().expect("instance name").to_string(),
            ifs.iter()
                .filter_map(|i| Some((i["name"].as_str()?.to_string(), i.get("cost")?.as_u64()?)))
                .collect(),
        );
    }
    out
}

/// The v0 declaration at `3ae8213`, transcribed — the two fields no generated artifact prints
/// (a segment's vid, and the island whose wire carries it):
///
/// ```text
/// `[[member]]` (all three members, st/cl/mg): eth9 eth1 eth0
/// a zone's `segments`:  ifname      island zone    seg vid  role     cost
///               cfab-st     st     storage 1   100  primary  10
///               cfab-st-bk  cl     storage 2   101  backup   100
///               cfab-st-b2  mg     storage 3   102  backup   300
///               cfab-cl     cl     cluster 1   200  primary  10
///               cfab-cl-bk  st     cluster 2   201  backup   200
///               cfab-cl-b2  mg     cluster 3   202  backup   300
///               cfab-mg     mg     mgmt    1   250  primary  10
///               cfab-mg-bk  cl     mgmt    2   251  backup   100
///               cfab-mg-b2  st     mgmt    3   252  backup   200
///               cfab-st-fb  any    storage 9   300  fallback 5000
///               cfab-cl-fb  any    cluster 9   301  fallback 5000
///               cfab-mg-fb  any    mgmt    9   302  fallback 5000
/// ```
const V0_SEGMENTS: [(&str, &str, &str, u8, u16, &str); 12] = [
    // ifname, island, zone, seg, vid, wire (the same on all three members)
    ("cfab-st", "st", "storage", 1, 100, "eth9"),
    ("cfab-st-bk", "cl", "storage", 2, 101, "eth1"),
    ("cfab-st-b2", "mg", "storage", 3, 102, "eth0"),
    ("cfab-cl", "cl", "cluster", 1, 200, "eth1"),
    ("cfab-cl-bk", "st", "cluster", 2, 201, "eth9"),
    ("cfab-cl-b2", "mg", "cluster", 3, 202, "eth0"),
    ("cfab-mg", "mg", "mgmt", 1, 250, "eth0"),
    ("cfab-mg-bk", "cl", "mgmt", 2, 251, "eth1"),
    ("cfab-mg-b2", "st", "mgmt", 3, 252, "eth9"),
    ("cfab-st-fb", "any", "storage", 9, 300, ""),
    ("cfab-cl-fb", "any", "cluster", 9, 301, ""),
    ("cfab-mg-fb", "any", "mgmt", 9, 302, ""),
];

/// The load-bearing tuple set of G1: every member must carry the same
/// (zone, seg, vid, wire, ifname) rows it carried under v0.
#[test]
fn every_member_carries_the_same_zone_seg_vid_wire_ifname_tuples() {
    let f = fabric();
    for member in MEMBERS {
        let m = f.member(member).unwrap();
        let got: Vec<(String, u8, u16, String, String)> = class_rows_of(&f, m)
            .into_iter()
            .map(|r| (r.zone, r.seg, r.vid, r.wire, r.ifname))
            .collect();
        let want: Vec<(String, u8, u16, String, String)> = V0_SEGMENTS
            .iter()
            .filter(|(_, island, ..)| *island != "any")
            .map(|(ifname, _, zone, seg, vid, wire)| {
                (
                    zone.to_string(),
                    *seg,
                    *vid,
                    wire.to_string(),
                    ifname.to_string(),
                )
            })
            .collect();
        assert_eq!(got, want, "{member}");
        // ...and the universal rows, which have no single wire.
        let uni: Vec<(String, u8, u16)> = fallback_rows_of(&f, m)
            .into_iter()
            .map(|r| (r.zone, r.seg, r.vid))
            .collect();
        let want_uni: Vec<(String, u8, u16)> = V0_SEGMENTS
            .iter()
            .filter(|(_, island, ..)| *island == "any")
            .map(|(_, _, zone, seg, vid, _)| (zone.to_string(), *seg, *vid))
            .collect();
        assert_eq!(uni, want_uni, "{member} universal segments");
    }
}

/// The engine tree is identical except for cost values, and every cost that moved kept its
/// RANK inside its zone — with mgmt's documented exception. A structural change anywhere else
/// (an interface added, removed or reordered; a BFD block; a timer) fails here.
#[test]
fn the_engine_tree_differs_from_v0_only_in_cost_values() {
    let f = fabric();
    for member in MEMBERS {
        let v = View::new(&f, member).unwrap();
        let mut got = cfab::emit::engine::generate(&v).unwrap();
        let mut want: Value = serde_json::from_str(&fixture(member, "gen-engine.json")).unwrap();
        let (got_costs, want_costs) = (ospf_costs(&got), ospf_costs(&want));
        assert_eq!(
            want_costs.keys().collect::<Vec<_>>(),
            got_costs.keys().collect::<Vec<_>>(),
            "{member}: OSPF instances"
        );
        for (zone, w) in &want_costs {
            let g = &got_costs[zone];
            assert_eq!(
                w.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                g.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                "{member} {zone}: interface list"
            );
            // Rank order inside the zone: the ordinal each interface's cost holds.
            let rank = |v: &Vec<(String, u64)>| {
                let mut sorted: Vec<u64> = v.iter().map(|(_, c)| *c).collect();
                sorted.sort_unstable();
                v.iter()
                    .map(|(n, c)| {
                        (
                            n.clone(),
                            sorted.iter().position(|s| s == c).expect("own cost"),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            if zone == "mgmt" {
                continue; // allowed diff 5, pinned by its own test below
            }
            assert_eq!(rank(w), rank(g), "{member} {zone}: preference rank order");
        }
        // Now blank every cost and demand byte identity of everything else.
        blank_costs(&mut got);
        blank_costs(&mut want);
        if let Some(d) = diff(
            &format!("{member}: engine tree outside the cost leaves"),
            &serde_json::to_string_pretty(&want).unwrap(),
            &serde_json::to_string_pretty(&got).unwrap(),
        ) {
            panic!("{d}");
        }
    }
}

fn blank_costs(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if k == "cost" {
                    *val = Value::String("<cost>".into());
                } else {
                    blank_costs(val);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(blank_costs),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// The universal segment's cost: 5000 declared -> 410 derived, +30000 on the leaf.
#[test]
fn the_universal_segment_cost_moved_from_5000_to_the_derived_410() {
    let f = fabric();
    for (member, want) in [("pve1-tb", 410), ("pve2-tb", 410), ("pve3-tb", 30410)] {
        let v = View::new(&f, member).unwrap();
        let tree = cfab::emit::engine::generate(&v).unwrap();
        for (zone, rows) in ospf_costs(&tree) {
            let bond = rows
                .iter()
                .find(|(n, _)| n.ends_with("-fb"))
                .unwrap_or_else(|| panic!("{member} {zone}: no universal segment"));
            assert_eq!(bond.1, want, "{member} {zone} {}", bond.0);
        }
        // ...and v0 really did say 5000 (+30000): the fixture, not folklore.
        let v0: Value = serde_json::from_str(&fixture(member, "gen-engine.json")).unwrap();
        let v0_want = if member == "pve3-tb" { 35000 } else { 5000 };
        for (_, rows) in ospf_costs(&v0) {
            let bond = rows.iter().find(|(n, _)| n.ends_with("-fb")).unwrap();
            assert_eq!(bond.1, v0_want);
        }
    }
}

/// Every member's wire order per zone, against the order the v0 costs implied. storage and
/// cluster reproduce exactly; mgmt does not (allowed diff 5).
#[test]
fn the_preference_order_per_zone_reproduces_v0_except_mgmt() {
    let f = fabric();
    for member in MEMBERS {
        let v0: Value = serde_json::from_str(&fixture(member, "gen-engine.json")).unwrap();
        let v0_costs = ospf_costs(&v0);
        for p in prefs_of(&f, f.member(member).unwrap()) {
            // v0's order: the zone's segments sorted by declared cost, mapped to their wire.
            let mut rows: Vec<(String, u64)> = v0_costs[&p.zone]
                .iter()
                .filter(|(n, _)| !n.ends_with("-fb"))
                .cloned()
                .collect();
            rows.sort_by_key(|(_, c)| *c);
            let want: Vec<&str> = rows
                .iter()
                .map(|(n, _)| {
                    V0_SEGMENTS
                        .iter()
                        .find(|(ifname, ..)| ifname == n)
                        .expect("a v0 segment")
                        .5
                })
                .collect();
            let got: Vec<&str> = p.order.iter().map(String::as_str).collect();
            if p.zone == "mgmt" {
                assert_ne!(got, want, "{member}: mgmt is the documented exception");
                continue;
            }
            assert_eq!(got, want, "{member} {}", p.zone);
        }
    }
}

/// ALLOWED DIFF 5, pinned so it cannot move silently.
///
/// Spec §4 claims option (c) "derives EXACTLY today's order for every (member, zone)". It does
/// not. mgmt's primary is domain `c` (eth0, 1000 Mb/s) on every member, and the two backups are
/// eth9 (5000/10000 Mb/s, domain a) and eth1 (1000 Mb/s, domain b). Speed descending puts eth9
/// first; the v0 declaration hand-picked cfab-mg-bk (eth1) at 100 and cfab-mg-b2 (eth9) at 200,
/// i.e. eth1 first. So mgmt's FIRST BACKUP moves from the 1G cluster switch to the 5G/10G
/// storage NIC on every member.
///
/// That is a real change of failure behavior, not a cosmetic one: after eth0 dies, mgmt lands
/// on the wire that carries storage bulk instead of the wire that carries cluster control. It
/// is reversible with a `prefs` entry on each host. James's call; until then the derived order stands
/// and this test states it.
#[test]
fn the_mgmt_backup_order_is_the_one_real_behavior_change() {
    let f = fabric();
    for member in MEMBERS {
        let p = prefs_of(&f, f.member(member).unwrap())
            .into_iter()
            .find(|p| p.zone == "mgmt")
            .unwrap();
        assert_eq!(p.order, vec!["eth0", "eth9", "eth1"], "{member} derived");
        // v0 was eth0 eth1 eth9 (costs 10 / 100 / 200 on cfab-mg / -bk / -b2).
        let v0: Value = serde_json::from_str(&fixture(member, "gen-engine.json")).unwrap();
        let mgmt = &ospf_costs(&v0)["mgmt"];
        let cost = |n: &str| mgmt.iter().find(|(x, _)| x == n).unwrap().1;
        let base = if member == "pve3-tb" { 30000 } else { 0 };
        assert_eq!(cost("cfab-mg") - base, 10);
        assert_eq!(
            cost("cfab-mg-bk") - base,
            100,
            "v0: eth1 was the first backup"
        );
        assert_eq!(cost("cfab-mg-b2") - base, 200, "v0: eth9 was the second");
    }
    // ...and one `prefs` row per member restores v0's order exactly.
    let mut text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
            .unwrap();
    for member in MEMBERS {
        // Insert the override right after that member's wire array.
        let at = text
            .find(&format!("name = \"{member}\""))
            .expect("the member block");
        let start = at + text[at..].find("wires = [").expect("a wires array");
        let end = start + text[start..].find("]\n").expect("the array ends") + 2;
        text = format!(
            "{}prefs = {{ mgmt = [\"eth0\", \"eth1\", \"eth9\"] }}\n{}",
            &text[..end],
            &text[end..]
        );
    }
    let f = Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap();
    for member in MEMBERS {
        let p = prefs_of(&f, f.member(member).unwrap())
            .into_iter()
            .find(|p| p.zone == "mgmt")
            .unwrap();
        assert_eq!(p.order, vec!["eth0", "eth1", "eth9"], "{member}");
        assert_eq!(p.source.as_str(), "override");
    }
}

/// Slave -> wire mapping and bond home, both unchanged apart from the slave rename.
#[test]
fn slave_names_wires_and_bond_homes_survive_the_rename() {
    let f = fabric();
    let island_of_wire: BTreeMap<&str, &str> =
        [("eth9", "st"), ("eth1", "cl"), ("eth0", "mg")].into();
    for member in MEMBERS {
        let v = View::new(&f, member).unwrap();
        // The v0 slave names, straight out of the fixture's `set cfab` line.
        let policy = fixture(member, "gen-policy.txt");
        let cfab_set = policy
            .lines()
            .find(|l| l.trim_start().starts_with("set cfab {"))
            .expect("the cfab owned set");
        let mut v0_slaves: Vec<String> = cfab_set
            .split('"')
            .filter(|t| t.contains("-fb-"))
            .map(|t| {
                let (base, island) = t.rsplit_once('-').unwrap();
                let d = RENAME
                    .iter()
                    .find(|(i, _)| *i == island)
                    .unwrap_or_else(|| panic!("unknown island suffix in {t}"))
                    .1;
                format!("{base}-{d}")
            })
            .collect();
        v0_slaves.sort();
        let mut got: Vec<String> = v
            .fallback_rows()
            .iter()
            .flat_map(|r| r.slaves.iter().map(|s| s.ifname.clone()))
            .collect();
        got.sort();
        assert_eq!(got, v0_slaves, "{member}: renamed slave set");
        // Each slave still sits on the wire its island named.
        for r in v.fallback_rows() {
            for s in &r.slaves {
                let want = RENAME
                    .iter()
                    .find(|(i, _)| *i == island_of_wire[s.wire.as_str()])
                    .unwrap()
                    .1;
                assert!(
                    s.ifname.ends_with(&format!("-{want}")),
                    "{member}: {} is on {} (island {})",
                    s.ifname,
                    s.wire,
                    island_of_wire[s.wire.as_str()]
                );
            }
            // The bond home: v0 homed a bond on the wire carrying that zone's CHEAPEST
            // segment, so the v0 engine fixture is the oracle.
            let v0: Value = serde_json::from_str(&fixture(member, "gen-engine.json")).unwrap();
            let mut rows: Vec<(String, u64)> = ospf_costs(&v0)[&r.zone]
                .iter()
                .filter(|(n, _)| !n.ends_with("-fb"))
                .cloned()
                .collect();
            rows.sort_by_key(|(_, c)| *c);
            let home = V0_SEGMENTS
                .iter()
                .find(|(ifname, ..)| *ifname == rows[0].0)
                .expect("a v0 segment")
                .5;
            assert_eq!(r.home, home, "{member} {}: bond home", r.zone);
            // The v0 SHAPER printed the same wire for the default/bulk zone; cross-check the
            // one zone where it is visible, so the oracle above is not the only witness.
            if r.zone == "storage" {
                assert!(
                    fixture(member, &format!("gen-shape-{home}.txt"))
                        .contains(&format!("storage effective-primary on {home}")),
                    "{member}: v0 shaper disagrees about storage's home wire"
                );
            }
        }
    }
}

/// The nft forward policy is byte-identical to v0 once the two enumerated transforms are
/// applied: the slave rename, and the admin set widening to every wire of a host. Any other
/// character difference fails with the line.
#[test]
fn the_forward_policy_differs_only_by_the_slave_rename_and_the_admin_set() {
    let f = fabric();
    for member in MEMBERS {
        let v = View::new(&f, member).unwrap();
        let got = cfab::emit::policy::generate(&v).unwrap();
        let mut want = fixture(member, "gen-policy.txt");
        for (island, domain) in RENAME {
            want = want.replace(&format!("-fb-{island}\""), &format!("-fb-{domain}\""));
        }
        // Allowed diff 4: v0 nominated one NIC, v1 fences every wire of a host.
        want = want.replace(
            "set admin { type ifname; elements = { \"eth0\" } }",
            "set admin { type ifname; elements = { \"eth9\",\"eth1\",\"eth0\" } }",
        );
        // The set is emitted sorted; the rename reorders three names inside it.
        let sort_set = |s: &str| {
            s.lines()
                .map(|l| {
                    if !l.trim_start().starts_with("set cfab {") {
                        return l.to_string();
                    }
                    let (head, rest) = l.split_once('{').unwrap();
                    let (_, rest) = rest.split_once('{').unwrap();
                    let inner = rest.rsplit_once('}').unwrap().0.rsplit_once('}').unwrap().0;
                    let mut names: Vec<&str> = inner.split(',').map(str::trim).collect();
                    names.sort_unstable();
                    format!(
                        "{head}{{ type ifname; elements = {{ {} }} }}",
                        names.join(",")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        if let Some(d) = diff(
            &format!("{member}: nft forward policy"),
            &sort_set(&want),
            &sort_set(&got),
        ) {
            panic!("{d}");
        }
    }
}

/// The marking table and the iptables-legacy ceiling are byte-identical to v0: no rename, no
/// cost, no admin set reaches them.
#[test]
fn the_marking_and_ceiling_artifacts_are_byte_identical_to_v0() {
    let f = fabric();
    for member in MEMBERS {
        let v = View::new(&f, member).unwrap();
        for (file, got) in [
            ("gen-mark.txt", cfab::emit::mark::generate(&v).unwrap()),
            (
                "gen-mark-iptables-legacy.txt",
                cfab::emit::ceiling_ipt::generate(&v).unwrap(),
            ),
        ] {
            if let Some(d) = diff(&format!("{member}: {file}"), &fixture(member, file), &got) {
                panic!("{d}");
            }
        }
    }
}
