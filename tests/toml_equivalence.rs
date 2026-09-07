//! Gate G0-toml (spec §11.3): the TOML declaration produces exactly what the shell one did.
//!
//! The oracle is `tests/fixtures/model-v1-2eaf191/`, captured from THIS worktree's binary at
//! `2eaf191` — the last commit before the format switch — for every member and every
//! subcommand that reads the declaration. `examples/fabric.toml` must reproduce it byte for
//! byte, stdout and stderr.
//!
//! TWO transforms are applied, and they are the whole of the allowed difference:
//!   1. The summary line of `check` (and every error) names the declaration file, which is now
//!      `fabric.toml` (§11.2 rule 5).
//!   2. `gen engine` now filters LEAF identities out of every gw zone's BGP policy — the
//!      `cfab-<zone>-leaf` prefix set and the `reject-route` statement naming it. A leaf carries
//!      no ingress leg and cannot answer a packet sent to its fabric identity, so its identity
//!      is never offered to the router (James 2026-09-06: unsupported by design). The capture
//!      predates that, so the filter is SUBTRACTED from the new output and everything else in
//!      the tree stays compared. Its own shape is pinned by `emit::engine`'s tests.
//!
//! The fixture is left verbatim because it is a CAPTURE — evidence of what the old binary
//! printed, not a file to keep in sync.
//!
//! `schema.json` is deliberately not compared: `cfab schema` now emits the DECLARATION
//! schema instead of the internal model's (§11.2 rule 6), which is a wanted change, not a
//! regression.

use std::path::PathBuf;
use std::process::Command;

use cfab::decl::Declaration;
use cfab::model::Fabric;
use serde_json::Value;

const MEMBERS: [&str; 3] = ["pve1-tb", "pve2-tb", "pve3-tb"];
const WIRES: [&str; 3] = ["eth9", "eth1", "eth0"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn example() -> String {
    std::fs::read_to_string(root().join("examples/fabric.toml")).expect("examples/fabric.toml")
}

/// Every (fixture file, argv) the capture recorded, in capture order.
fn artifacts() -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = vec![
        ("check.txt", vec!["check"]),
        ("gen-policy.txt", vec!["gen", "policy"]),
        ("gen-mark.txt", vec!["gen", "mark"]),
        (
            "gen-mark-iptables-legacy.txt",
            vec!["gen", "mark", "--backend", "iptables-legacy"],
        ),
        ("gen-engine.json", vec!["gen", "engine"]),
        ("gen-prefs.txt", vec!["gen", "prefs"]),
    ]
    .into_iter()
    .map(|(f, a)| (f.to_string(), a.iter().map(|s| s.to_string()).collect()))
    .collect();
    for dev in WIRES {
        for (suffix, extra) in [
            ("", vec![]),
            ("-tc", vec!["--tc"]),
            ("-expect", vec!["--expect"]),
        ] {
            let mut argv = vec!["gen".to_string(), "shape".to_string(), dev.to_string()];
            argv.extend(extra.iter().map(|s| s.to_string()));
            out.push((format!("gen-shape-{dev}{suffix}.txt"), argv));
        }
    }
    out
}

/// Run the built binary against a declaration file, as the capture did.
fn run(config: &std::path::Path, member: &str, argv: &[String]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cfab"))
        .arg("--config")
        .arg(config)
        .arg("--host")
        .arg(member)
        .args(argv)
        .output()
        .expect("the cfab binary runs");
    assert!(
        out.status.success(),
        "{member} {argv:?}: exit {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
        String::from_utf8(out.stderr).expect("utf-8 stderr"),
    )
}

fn fixture(member: &str, file: &str) -> String {
    let p = root()
        .join("tests/fixtures/model-v1-2eaf191")
        .join(member)
        .join(file);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The captured stderr for an artifact — absent file = the capture recorded none.
fn fixture_err(member: &str, file: &str) -> String {
    let base = file.rsplit_once('.').expect("an extension").0;
    let p = root()
        .join("tests/fixtures/model-v1-2eaf191")
        .join(member)
        .join(format!("{base}.err"));
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Enumerated transform 1: the declaration's name.
fn renamed(fixture: &str) -> String {
    fixture.replace("fabric.conf", "fabric.toml")
}

/// Enumerated transform 2: subtract the leaf-identity filter from `gen engine`'s output, so
/// every other node of the tree stays under byte comparison. A no-op on any other artifact,
/// and a no-op on a member that emits no policy tree.
fn without_leaf_filter(file: &str, stdout: &str) -> String {
    if file != "gen-engine.json" {
        return stdout.to_string();
    }
    let mut t: Value = serde_json::from_str(stdout).expect("gen engine emits JSON");
    let Some(pol) = t.get_mut("ietf-routing-policy:routing-policy") else {
        return stdout.to_string();
    };
    if let Some(sets) = pol["defined-sets"]["prefix-sets"]["prefix-set"].as_array_mut() {
        sets.retain(|s| !s["name"].as_str().unwrap().ends_with("-leaf"));
    }
    for p in pol["policy-definitions"]["policy-definition"]
        .as_array_mut()
        .into_iter()
        .flatten()
    {
        if let Some(stmts) = p["statements"]["statement"].as_array_mut() {
            stmts.retain(|s| {
                !(s["conditions"]["match-prefix-set"]["prefix-set"]
                    .as_str()
                    .is_some_and(|n| n.ends_with("-leaf"))
                    && s["actions"]["policy-result"] == "reject-route")
            });
        }
    }
    let trailing = &stdout[stdout.trim_end().len()..];
    format!("{}{trailing}", serde_json::to_string_pretty(&t).unwrap())
}

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
            out.push_str(&format!("  line {}:\n    v1: {a}\n    toml: {b}\n", i + 1));
        }
    }
    Some(out)
}

/// G0-toml: every artifact of every member, byte for byte.
#[test]
fn every_artifact_matches_the_shell_format_capture() {
    let config = root().join("examples/fabric.toml");
    for member in MEMBERS {
        for (file, argv) in artifacts() {
            let (stdout, stderr) = run(&config, member, &argv);
            if let Some(d) = diff(
                &format!("{member} {file} (stdout)"),
                &renamed(&fixture(member, &file)),
                &without_leaf_filter(&file, &stdout),
            ) {
                panic!("{d}");
            }
            if let Some(d) = diff(
                &format!("{member} {file} (stderr)"),
                &renamed(&fixture_err(member, &file)),
                &stderr,
            ) {
                panic!("{d}");
            }
        }
    }
}

/// The capture is not empty and it really did name the old file — the transform above is
/// doing something, and a fixture that silently vanished would fail here first.
#[test]
fn the_capture_is_the_shell_formats_own_output() {
    for member in MEMBERS {
        assert!(fixture(member, "check.txt").starts_with("fabric.conf OK: 3 zones"));
        assert!(fixture(member, "gen-engine.json").contains("ietf-ospf:ospf"));
    }
}

/// A declaration with every OPTIONAL table omitted generates exactly what the full example
/// generates: the documented defaults are the values the example states, not a second set of
/// numbers that happen to agree.
#[test]
fn the_minimal_declaration_generates_the_same_artifacts() {
    let cut = example()
        .find("[admin]")
        .expect("the tunable tables start at [admin]");
    let minimal = example()[..cut].to_string();
    assert!(
        minimal.contains("[forward]"),
        "[forward] is required and must survive the strip"
    );
    for table in [
        "[admin]",
        "[marking]",
        "[cost]",
        "[bfd]",
        "[ospf]",
        "[bgp]",
        "[runtime]",
    ] {
        assert!(!minimal.contains(table), "{table} must be stripped");
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fabric.toml");
    std::fs::write(&path, &minimal).unwrap();
    let full = root().join("examples/fabric.toml");
    for member in MEMBERS {
        for (file, argv) in artifacts() {
            let (want, want_err) = run(&full, member, &argv);
            let (got, got_err) = run(&path, member, &argv);
            if let Some(d) = diff(
                &format!("{member} {file} with no tunable tables"),
                &want,
                &got,
            ) {
                panic!("{d}");
            }
            assert_eq!(want_err, got_err, "{member} {file} (stderr)");
        }
    }
}

// ---- the negative gate: one malformed declaration per validation in model.rs ---------------

/// Every check `Fabric::from_decl`/`validate` still makes, each with the declaration that
/// trips it and the words its message must carry. Deleting a check makes its case fail;
/// deleting a CASE fails the count below. Grow both together when a check is added.
const CASES: usize = 30;

fn edited(edits: &[(&str, &str)]) -> String {
    let mut text = example();
    for (from, to) in edits {
        assert!(text.contains(from), "the example has no `{from}`");
        text = text.replace(from, to);
    }
    text
}

fn err_of(text: &str) -> String {
    let d = match Declaration::parse(text) {
        Ok(d) => d,
        Err(e) => return e.to_string(),
    };
    Fabric::from_decl(&d)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "NO ERROR: the declaration validated".to_string())
}

#[test]
fn every_surviving_validation_has_a_declaration_that_trips_it() {
    // A wire's whole set, so a member can be given more or fewer of them.
    let pve1_wires = "wires = [\n  { nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },\n  { nic = \"eth1\", domain = \"b\", speed_mbps = 1000 },\n  { nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]";
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "a domain token that is not one letter",
            edited(&[(
                "domain = \"b\", speed_mbps = 1000 }",
                "domain = \"bb\", speed_mbps = 1000 }",
            )]),
            "is not a switch-domain token",
        ),
        (
            "a gw router without /24",
            edited(&[("192.168.249.254/24", "192.168.249.254/25")]),
            "expected an IPv4 address with /24",
        ),
        (
            "a gw domain that is not a token or `any`",
            edited(&[("gw = { domain = \"c\"", "gw = { domain = \"cc\"")]),
            "zone mgmt: gw domain",
        ),
        (
            "a segment domain that is not one letter",
            edited(&[(
                "{ ifname = \"cfab-st-b2\", domain = \"c\"",
                "{ ifname = \"cfab-st-b2\", domain = \"cc\"",
            )]),
            "zone storage: segment cfab-st-b2",
        ),
        (
            "a zone primary that is not one letter",
            edited(&[(
                "weight = 4\nprimary = \"a\"",
                "weight = 4\nprimary = \"aa\"",
            )]),
            "zone storage: primary",
        ),
        (
            "a forward pair with no direction",
            edited(&[("\"storage>storage\"", "\"storage\"")]),
            "[forward] allow 'storage'",
        ),
        (
            "pcp_ctrl above 6",
            edited(&[("pcp_ctrl = 6", "pcp_ctrl = 7")]),
            "[marking] pcp_ctrl = 7 is outside 0..6",
        ),
        (
            "a privileged bfd port",
            edited(&[("port = 3784", "port = 1023")]),
            "[bfd] port = 1023 is outside 1024..65535",
        ),
        (
            "no domains at all",
            edited(&[(
                "[domains]\na = \"5G/10G storage switch\"\nb = \"1G switch\"\nc = \"1G admin switch\"",
                "[domains]",
            )]),
            "[domains] is empty",
        ),
        (
            "a member with no wires",
            edited(&[(pve1_wires, "wires = []")]),
            "member pve1-tb: declares no wires",
        ),
        (
            "a wire on an undeclared domain",
            edited(&[(
                "{ nic = \"eth1\", domain = \"b\", speed_mbps = 1000 },\n  { nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]\n# USB",
                "{ nic = \"eth1\", domain = \"d\", speed_mbps = 1000 },\n  { nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]\n# USB",
            )]),
            "is not in [domains] (a b c)",
        ),
        (
            "two wires on one domain",
            edited(&[(
                pve1_wires,
                "wires = [\n  { nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },\n  { nic = \"eth8\", domain = \"a\", speed_mbps = 5000 },\n  { nic = \"eth1\", domain = \"b\", speed_mbps = 1000 },\n  { nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]",
            )]),
            "two wires on domain a (eth9 eth8)",
        ),
        (
            "a segment on an undeclared domain",
            edited(&[(
                "{ ifname = \"cfab-st-b2\", domain = \"c\"",
                "{ ifname = \"cfab-st-b2\", domain = \"d\"",
            )]),
            "segment cfab-st-b2: domain d is not in [domains]",
        ),
        (
            "a zone primary on an undeclared domain",
            edited(&[("weight = 4\nprimary = \"a\"", "weight = 4\nprimary = \"d\"")]),
            "zone storage: primary domain d is not in [domains]",
        ),
        (
            "a gw on an undeclared domain",
            edited(&[("gw = { domain = \"c\"", "gw = { domain = \"d\"")]),
            "zone mgmt: gw domain d is not in [domains]",
        ),
        (
            "a declared domain nobody wires into",
            edited(&[(
                "c = \"1G admin switch\"",
                "c = \"1G admin switch\"\nd = \"nobody's switch\"",
            )]),
            "[domains] declares d but no member has a wire on it",
        ),
        (
            "one vid on two segments",
            edited(&[("seg = 2, vid = 101", "seg = 2, vid = 100")]),
            "vid 100 used by two segments",
        ),
        (
            "one (zone, seg) declared twice",
            edited(&[(
                "{ ifname = \"cfab-st-bk\", domain = \"b\", seg = 2, vid = 101 }",
                "{ ifname = \"cfab-st-bk\", domain = \"b\", seg = 1, vid = 101 }",
            )]),
            "segment storage:1 declared twice",
        ),
        (
            "two segments of one zone on one domain",
            edited(&[(
                "{ ifname = \"cfab-st-bk\", domain = \"b\", seg = 2, vid = 101 }",
                "{ ifname = \"cfab-st-bk\", domain = \"a\", seg = 2, vid = 101 }",
            )]),
            "zone:domain storage:a declared twice",
        ),
        (
            "one ifname on two segments",
            edited(&[(
                "{ ifname = \"cfab-st-bk\", domain = \"b\"",
                "{ ifname = \"cfab-st\", domain = \"b\"",
            )]),
            "segment ifname cfab-st declared twice",
        ),
        (
            "a universal leg whose slaves would not fit IFNAMSIZ",
            edited(&[("\"cfab-st-fb\"", "\"cfab-storage-fb\"")]),
            "must be 13 characters or fewer",
        ),
        (
            "two zones with one id",
            edited(&[(
                "name = \"cluster\"\nid = 199",
                "name = \"cluster\"\nid = 99",
            )]),
            "zone id 99 used twice",
        ),
        (
            "a zone id that is not a block octet",
            edited(&[("name = \"cluster\"\nid = 199", "name = \"cluster\"\nid = 0")]),
            "zone id 0 is not a valid block octet",
        ),
        (
            "a primary domain with no segment in the zone",
            edited(&[
                (
                    "c = \"1G admin switch\"",
                    "c = \"1G admin switch\"\nd = \"a fourth switch\"",
                ),
                (
                    "{ nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]\n# USB",
                    "{ nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n  { nic = \"eth2\", domain = \"d\", speed_mbps = 1000 },\n]\n# USB",
                ),
                ("weight = 4\nprimary = \"a\"", "weight = 4\nprimary = \"d\""),
            ]),
            "zone storage: primary domain d has no segment",
        ),
        (
            "a forward pair naming a zone that does not exist",
            edited(&[("\"storage>storage\"", "\"public>storage\"")]),
            "unknown zone 'public'",
        ),
        (
            "an ingress vid that is also a segment vid",
            edited(&[("vid = 249, router", "vid = 250, router")]),
            "ingress vid 250 is also a segment vid",
        ),
        (
            "an ingress router on a node's own address",
            edited(&[("192.168.249.254/24", "192.168.249.3/24")]),
            "collides with node 3",
        ),
        (
            "a prefs order that is not complete",
            edited(&[(
                "# prefs = { storage = [\"eth1\", \"eth9\", \"eth0\"] }",
                "prefs = { storage = [\"eth1\", \"eth9\"] }",
            )]),
            "an override is the COMPLETE order",
        ),
        (
            "a member name declared twice",
            edited(&[("name = \"pve2-tb\"", "name = \"pve1-tb\"")]),
            "member pve1-tb declared twice",
        ),
        (
            "a node id used twice",
            edited(&[("node = 2\n", "node = 1\n")]),
            "node id 1 used twice",
        ),
    ];
    assert_eq!(
        cases.len(),
        CASES,
        "the negative gate lost or gained a case: every validation in model.rs needs one"
    );
    for (name, text, want) in cases {
        let err = err_of(&text);
        assert!(err.contains(want), "{name}: wanted `{want}`, got `{err}`");
    }
}

/// Two prefs checks the table above cannot reach through the shipped example's zone names.
#[test]
fn a_prefs_row_naming_an_unknown_zone_or_wire_is_refused() {
    let unknown_zone = edited(&[(
        "# prefs = { storage = [\"eth1\", \"eth9\", \"eth0\"] }",
        "prefs = { backup = [\"eth1\", \"eth9\", \"eth0\"] }",
    )]);
    assert!(
        err_of(&unknown_zone).contains("member pve1-tb prefs backup"),
        "{}",
        err_of(&unknown_zone)
    );
    let unknown_wire = edited(&[(
        "# prefs = { storage = [\"eth1\", \"eth9\", \"eth0\"] }",
        "prefs = { storage = [\"eth1\", \"eth9\", \"eth5\"] }",
    )]);
    assert!(
        err_of(&unknown_wire).contains("'eth5' is not one of pve1-tb's wires"),
        "{}",
        err_of(&unknown_wire)
    );
    let twice = edited(&[(
        "# prefs = { storage = [\"eth1\", \"eth9\", \"eth0\"] }",
        "prefs = { storage = [\"eth1\", \"eth1\", \"eth9\"] }",
    )]);
    assert!(
        err_of(&twice).contains("a wire is listed twice"),
        "{}",
        err_of(&twice)
    );
}

/// The retired shell format is not a declaration in disguise: it fails in the parser.
#[test]
fn a_shell_format_declaration_is_refused() {
    let err = err_of(
        "FABRIC_MODE=tagged\nDOMAINS=\"a b c\"\nMEMBER_TABLE=\"\npve1-tb 1 host eth9@a:5000\n\"\n",
    );
    assert!(err.starts_with("fabric.toml: "), "{err}");
    assert!(
        !err.contains("NO ERROR"),
        "a KEY=value file must never validate: {err}"
    );
}
