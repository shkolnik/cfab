//! Gate G0-toml (spec §11.3): the TOML declaration produces exactly what the shell one did.
//!
//! The oracle is `tests/fixtures/model-v1-2eaf191/`, captured from THIS worktree's binary at
//! `2eaf191` — the last commit before the format switch — for every member and every
//! subcommand that reads the declaration. `examples/fabric.toml` must reproduce it byte for
//! byte, stdout and stderr.
//!
//! THREE transforms are applied, and they are the whole of the allowed difference:
//!   1. The summary line of `check` (and every error) names the declaration file, which is now
//!      `fabric.toml` (§11.2 rule 5).
//!   2. `gen engine` now filters LEAF identities out of every gw zone's BGP policy — the
//!      `cfab-<zone>-leaf` prefix set and the `reject-route` statement naming it. A leaf carries
//!      no ingress leg and cannot answer a packet sent to its fabric identity, so its identity
//!      is never offered to the router (James 2026-09-06: unsupported by design). The capture
//!      predates that, so the filter is SUBTRACTED from the new output and everything else in
//!      the tree stays compared. Its own shape is pinned by `emit::engine`'s tests.
//!
//!   3. `gen policy`'s `cfab` (owned-interface) set gains the ingress leg's three ports. The
//!      example now puts the gw on scope `any`, so the leg MIGRATES — an active-backup bond
//!      with one tagged sub-interface per wire — and a host owns those netdevs exactly as it
//!      owns a universal segment's ports. The capture predates the scope, so the names are
//!      ADDED to it and every other byte of the policy stays compared.
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
use cfab::derive::View;
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

/// Render one artifact for a named member, through the same library entry points the CLI
/// dispatches to.
///
/// This used to spawn the binary with `--host <member>`. That flag is gone: identity is the
/// kernel hostname and nothing else, so a binary cannot be told to be three different members
/// from one process. Rendering a NAMED row is not an identity claim, though — it is what `gen`
/// has always meant — so the library still does it, and `cfab_prints_exactly_what_the_library_
/// renders` below pins the CLI plumbing this no longer covers.
///
/// One deliberate difference from the CLI: `check` here is the declaration report alone, where
/// the CLI also prints `host_preflight`/`host_warnings` from the REAL machine first. Those were
/// silently empty on the machines this test runs on (no declared bridge exists, so both loops
/// `continue`) — which is to say the old spawning version would have failed here, for reasons
/// having nothing to do with TOML equivalence, on any host that happened to own a bridge with a
/// declared name. Dropping them makes what this test pins independent of the box it runs on.
fn run(config: &std::path::Path, member: &str, argv: &[String]) -> (String, String) {
    let (fabric, _) = cfab::load_fabric_text(config).expect("the declaration loads");
    let view = View::new(&fabric, member).expect("the member is declared");
    render(&fabric, &view, argv)
}

fn render(fabric: &Fabric, view: &View<'_>, argv: &[String]) -> (String, String) {
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    let plain = |s: String| (s, String::new());
    match a.as_slice() {
        ["check"] => plain(cfab::commands::check::report(fabric)),
        ["gen", "policy"] => plain(cfab::emit::policy::generate(view).expect("gen policy")),
        ["gen", "mark"] => plain(cfab::emit::mark::generate(view).expect("gen mark")),
        ["gen", "mark", "--backend", "iptables-legacy"] => {
            plain(cfab::emit::ceiling_ipt::generate(view).expect("gen mark --backend"))
        }
        ["gen", "prefs"] => plain(cfab::derive::render_prefs(fabric)),
        ["gen", "engine"] => plain(cfab::commands::render::engine_json(view).expect("gen engine")),
        ["gen", "shape", dev, rest @ ..] => cfab::commands::render::shape_output(
            view,
            fabric,
            dev,
            rest.contains(&"--tc"),
            rest.contains(&"--expect"),
        )
        .expect("gen shape"),
        other => panic!("argv not mapped to a library call: {other:?}"),
    }
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

/// Enumerated transform 3: add the migrating ingress leg's ports to the captured owned set.
/// A no-op on every other artifact, and on a leaf (which carries no ingress leg at all).
fn with_gw_ports(file: &str, fixture: &str) -> String {
    if file != "gen-policy.txt" {
        return fixture.to_string();
    }
    fixture.replace(
        "\"cfab-gw249\",",
        "\"cfab-gw249\",\"cfab-gw249-a\",\"cfab-gw249-b\",\"cfab-gw249-c\",",
    )
}

/// Enumerated transform 4: `check`'s member lines. The shell era printed exactly one, for the
/// member the run was scoped to:
///
/// ```text
/// this member: pve1-tb (node 1, host); 9 segment sub-ifs on wires [...], ...
/// ```
///
/// The TOML era scopes `check` to nothing — it reports every declared member, so its output is
/// the same on every host and a diff across the cluster proves they hold the same file. The DATA
/// in the line is unchanged, which is what equivalence is about, so this takes the new report
/// back down to the old shape: keep the line for the member under capture, drop the other
/// members', restore the old label. A no-op on every other artifact.
fn one_member_line(file: &str, member: &str, rendered: &str) -> String {
    if file != "check.txt" {
        return rendered.to_string();
    }
    let mine = format!("member {member} (");
    rendered
        .lines()
        .filter(|l| !l.starts_with("member ") || l.starts_with(&mine))
        .map(|l| match l.strip_prefix("member ") {
            Some(rest) => format!("this member: {}\n", rest.replacen("): ", "); ", 1)),
            None => format!("{l}\n"),
        })
        .collect()
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
                &with_gw_ports(&file, &renamed(&fixture(member, &file))),
                &one_member_line(&file, member, &without_leaf_filter(&file, &stdout)),
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

/// What `run` above stopped covering when it left the binary behind: argv parsing, the `Gen`
/// dispatch arms, and the exact bytes `print!`/`eprintln!` put on each stream.
///
/// `check` is the whole file's verdict, and a box that is no member of the fabric still gets it.
///
/// Before this, `check` loaded the declaration, ran the whole validation gate, PASSED it, and
/// then exited nonzero anyway because the kernel hostname matched no `[[member]]` row — an exit
/// status about the operator, dressed as a statement about the file. A laptop, a CI runner or a
/// host renamed out of its row could not read a verdict on a file it holds.
///
/// This runs the real binary against the UNMODIFIED example, whose three rows are `pveN-tb`. It
/// therefore only means anything on a box that is not one of them, which is every box that is
/// not the testbed — so it asserts the premise first rather than passing vacuously.
#[test]
fn check_reports_the_whole_file_on_a_box_that_is_no_member() {
    let me = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("a kernel hostname")
        .trim()
        .to_string();
    if MEMBERS.contains(&me.as_str()) {
        return; // on the testbed itself the premise does not hold; the sibling test covers it
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fabric.toml");
    std::fs::write(&path, example()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_cfab"))
        .arg("--config")
        .arg(&path)
        .arg("check")
        .output()
        .expect("the cfab binary runs");
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    assert!(
        out.status.success(),
        "check must succeed on a valid file whoever runs it: exit {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    // The verdict, and every member's row — not just some member's.
    assert!(stdout.starts_with("fabric.toml OK: "), "{stdout}");
    // `gen prefs` is the other artifact that names no member: it renders every member's wire
    // order and never asks who is running, so it too must work here.
    let prefs = Command::new(env!("CARGO_BIN_EXE_cfab"))
        .arg("--config")
        .arg(&path)
        .args(["gen", "prefs"])
        .output()
        .expect("the cfab binary runs");
    assert!(
        prefs.status.success(),
        "gen prefs must succeed on a valid file whoever runs it: exit {:?}\n{}",
        prefs.status.code(),
        String::from_utf8_lossy(&prefs.stderr)
    );
    let prefs_out = String::from_utf8(prefs.stdout).expect("utf-8 stdout");
    for m in MEMBERS {
        assert!(prefs_out.contains(&format!("{m} storage: ")), "{prefs_out}");
    }
    for m in MEMBERS {
        assert!(stdout.contains(&format!("\nmember {m} (")), "{stdout}");
    }
    // ...and it says what it could not do, rather than reading as a clean bill of health.
    assert!(
        stdout.contains(&format!(
            "this host: {me} is not a declared member of this fabric; host checks skipped\n"
        )),
        "{stdout}"
    );
}

/// Identity is the kernel hostname now, so this does not name a member — it hands the binary a
/// declaration in which THIS box IS a member, by copying the example and renaming one row (the
/// name appears exactly once in the file). Then it asserts the binary's two streams equal what
/// the library renders for the same row of the same file. No override, and the test works on any
/// host under any hostname.
#[test]
fn cfab_prints_exactly_what_the_library_renders() {
    let me = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("a kernel hostname")
        .trim()
        .to_string();
    let renamed_decl = example().replacen(
        &format!("name = \"{}\"", MEMBERS[0]),
        &format!("name = \"{me}\""),
        1,
    );
    assert!(
        renamed_decl.contains(&format!("name = \"{me}\"")),
        "the rename must land: {} appears once in the example",
        MEMBERS[0]
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fabric.toml");
    std::fs::write(&path, &renamed_decl).unwrap();

    for (file, argv) in artifacts() {
        let out = Command::new(env!("CARGO_BIN_EXE_cfab"))
            .arg("--config")
            .arg(&path)
            .args(&argv)
            .output()
            .expect("the cfab binary runs");
        assert!(
            out.status.success(),
            "{file}: exit {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        let (want, want_err) = run(&path, &me, &argv);
        // `check` is the one artifact whose CLI form prints more than the library call: the
        // file's report FIRST, then this host's own line and whatever the live host checks say.
        // So the library's render is a prefix here, and only here; every other artifact is
        // compared whole. (Prefix, not suffix: the host section moved below the report so a
        // host that cannot carry a row can no longer suppress the file's verdict.)
        let got = String::from_utf8(out.stdout).expect("utf-8 stdout");
        if file == "check.txt" {
            assert!(
                got.starts_with(&want),
                "{file}: the binary's report head differs from the library's\n--- want head ---\n{want}\n--- got ---\n{got}"
            );
            // and the host line the library does NOT render is there, naming this box
            assert!(
                got[want.len()..].starts_with(&format!("this host: {me}\n")),
                "{file}: the host line is missing or does not name this box\n--- got ---\n{got}"
            );
        } else if let Some(d) = diff(&format!("{file} (binary vs library)"), &want, &got) {
            panic!("{d}");
        }
        let got_err = String::from_utf8(out.stderr).expect("utf-8 stderr");
        assert_eq!(want_err, got_err, "{file} (stderr)");
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
const CASES: usize = 32;

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
    // pve1's whole wire set, so a member can be given more or fewer of them. Taken from the
    // file rather than spelled out: pve2 declares an IDENTICAL set of wires and `edited`
    // replaces every match, so a hard-coded array would edit both members and the error would
    // name whichever comes first. pve1's array is the only one carrying the NIC-quirks
    // comment, which is what makes this slice unique.
    let ex = example();
    let start = ex.find("wires = [").expect("the example declares wires");
    let end = start + ex[start..].find("\n]").expect("the array ends") + 2;
    let pve1_wires = &ex[start..end];
    assert_eq!(ex.matches(pve1_wires).count(), 1, "pve1's array is unique");
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
            edited(&[("gw = { domain = \"any\"", "gw = { domain = \"cc\"")]),
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
                "{ nic = \"eth1\", domain = \"b\", speed_mbps = 1000 },\n  { nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]\n# Optional",
                "{ nic = \"eth1\", domain = \"d\", speed_mbps = 1000 },\n  { nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]\n# Optional",
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
            edited(&[("gw = { domain = \"any\"", "gw = { domain = \"d\"")]),
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
            "a universal leg whose ports would not fit IFNAMSIZ",
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
                    "{ nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n]\n# Optional",
                    "{ nic = \"eth0\", domain = \"c\", speed_mbps = 1000 },\n  { nic = \"eth2\", domain = \"d\", speed_mbps = 1000 },\n]\n# Optional",
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
        (
            "the retired driver_features wire key",
            edited(&[(
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },",
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000, driver_features = \"gro off\" },",
            )]),
            "'driver_features' is gone",
        ),
        (
            "the retired usb wire key",
            edited(&[(
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000 },",
                "{ nic = \"eth9\", domain = \"a\", speed_mbps = 5000, usb = true },",
            )]),
            "'usb' is gone",
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
