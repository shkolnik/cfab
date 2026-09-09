//! Gate B acceptance: one golden per member with every workload-related rendering.
//!
//! Six emitters answer for the `with_workload` fixture in one artifact — `check`, the return-path
//! rules, the forward policy, the mark table, the engine config, the bridge ARP guard and the
//! DHCP option 121 snippet — rendered verbatim for a host that carries the workload (`pve1-tb`)
//! and for the leaf that does not (`pve3-tb`). A change to any one of them shows up here as a
//! diff to read, which is the point: the fixture files are the reviewed record of what phase 1
//! puts on a member.
//!
//! On a mismatch the test writes `<fixture>.actual` and fails, telling the reader to read that
//! file line by line before copying it into place (the apply-argv pattern used elsewhere in this
//! suite). Never copy it unread.

use cfab::commands::check;
use cfab::commands::common::return_path_rules;
use cfab::decl::{Declaration, fixtures};
use cfab::derive::View;
use cfab::emit::{engine, mark, policy, workload};
use cfab::model::Fabric;
use cfab::workload::uplink::Uplink;

/// The uplink `emit::workload::bridge_table` is fed here. Identification itself reads sysfs and
/// is covered by `workload::uplink`'s own tests; this golden pins the RENDERED table, so the
/// uplink is stated rather than probed.
fn fixture_uplink() -> Uplink {
    Uplink {
        bridge: "primary".into(),
        vid: 3,
        ports: vec!["eth0".into()],
    }
}

fn render(member: &str) -> String {
    let decl = Declaration::parse(&fixtures::with_workload(&fixtures::example()))
        .expect("the with_workload fixture parses");
    let f = Fabric::from_decl(&decl).expect("the with_workload fixture loads");
    let v = View::new(&f, member).expect("the member is in the fixture");

    let mut out = String::new();
    let mut section = |name: &str, body: String| {
        out.push_str(&format!("== {name} ==\n{body}\n"));
    };

    section("check", check::report(&f, &v));
    section(
        "rules",
        return_path_rules(&v)
            .iter()
            .map(|r| format!("pref {} {}", r.pref, r.add.join(" ")))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    section("policy", policy::generate(&v).expect("policy generates"));
    section("mark", mark::generate(&v).expect("mark generates"));
    section(
        "engine",
        serde_json::to_string_pretty(&engine::generate(&v).expect("engine generates"))
            .expect("the engine config serializes"),
    );
    let guards: Vec<(std::net::Ipv4Addr, Uplink)> = v
        .workload_rows()
        .iter()
        .map(|r| (r.wl.gw, fixture_uplink()))
        .collect();
    section(
        "bridge",
        if guards.is_empty() {
            String::new()
        } else {
            workload::bridge_table(&guards)
        },
    );
    section(
        "dhcp",
        f.workloads
            .iter()
            .map(|w| workload::dhcp_option_121(w.prefix, &f.aggregate(), w.gw, w.router))
            .collect::<String>(),
    );
    out
}

fn golden(member: &str) {
    let path = format!("tests/fixtures/workload-golden-{member}.txt");
    let got = render(member);
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    if got != want {
        std::fs::write(format!("{path}.actual"), &got).expect("the .actual file is writable");
        panic!("{path} differs; read {path}.actual line by line, then copy it into place");
    }
}

#[test]
fn the_host_workload_rendering_is_pinned() {
    golden("pve1-tb");
}

#[test]
fn the_leaf_workload_rendering_is_pinned() {
    golden("pve3-tb");
}
