//! NIC feature quirks are set by a host-side udev rule, not by cfab: cfab never sets one again
//! — not at `up`, not at `down`, not on a forwarding-watchdog tick that rebuilds a leg. A grep
//! is the honest proof: the thing asserted is the ABSENCE of a mechanism, and the argv literal
//! `"-K"` (`ethtool -K <nic> ...`) is the one needle every past call site used.
//!
//! Production code only, via `tests/support/mod.rs`'s `#[cfg(test)]`-mod stripper (shared with
//! `no_second_path.rs`): a test naming the retired call to prove the production side never
//! emits it is not itself a false positive.

#[path = "support/mod.rs"]
mod support;

use support::rust_sources;

#[test]
fn no_production_code_path_builds_an_ethtool_dash_capital_k_argv() {
    let mut hits = Vec::new();
    for (path, text) in rust_sources() {
        if text.contains("\"-K\"") {
            hits.push(path);
        }
    }
    assert!(
        hits.is_empty(),
        "ethtool -K survivors (NIC features are the host's business now): {hits:?}"
    );
}

/// The argv-literal needle above misses a call built as one string (`format!("ethtool -K
/// {nic} ...")`) rather than as separate argv elements. Any production line of CODE naming both
/// words together is the same retired mechanism by another spelling; a comment line (like the
/// retirement note on `WireDecl::driver_features`, which names both words in prose) is not a
/// call site and is not scanned.
#[test]
fn no_production_line_names_ethtool_and_dash_capital_k_together() {
    let mut hits = Vec::new();
    for (path, text) in rust_sources() {
        for (n, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if line.contains("ethtool") && line.contains("-K") {
                hits.push(format!("{path}:{}", n + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "ethtool -K survivors (NIC features are the host's business now): {hits:?}"
    );
}

/// Teeth for the stripper itself: a truncate-at-first-`#[cfg(test)]` implementation blinds this
/// whole guard to any production code that follows a tests module. Both files below have real
/// production items after theirs, so their presence in the scanned text is the proof the
/// stripper is skipping only the gated module and not swallowing what comes after it.
#[test]
fn the_stripper_keeps_production_code_that_follows_a_tests_module() {
    let sources = rust_sources();
    let workload = sources
        .iter()
        .find(|(p, _)| p == "src/emit/workload.rs")
        .map(|(_, t)| t.as_str())
        .expect("src/emit/workload.rs is scanned");
    assert!(
        workload.contains("fn bridge_table"),
        "bridge_table follows workload.rs's tests module and must stay in the scanned text"
    );
    let decl = sources
        .iter()
        .find(|(p, _)| p == "src/decl.rs")
        .map(|(_, t)| t.as_str())
        .expect("src/decl.rs is scanned");
    assert!(
        decl.contains("mod fixtures"),
        "fixtures follows decl.rs's tests module and must stay in the scanned text"
    );
}
