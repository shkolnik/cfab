//! NIC feature quirks are set by a host-side udev rule, not by cfab: cfab never sets one again
//! — not at `up`, not at `down`, not on a forwarding-watchdog tick that rebuilds a leg. A grep
//! is the honest proof: the thing asserted is the ABSENCE of a mechanism, and the argv literal
//! `"-K"` (`ethtool -K <nic> ...`) is the one needle every past call site used.
//!
//! Production code only: each source is truncated at its first `#[cfg(test)]` line before the
//! grep, exactly like `no_second_path.rs`, so a test naming the retired call to prove the
//! production side never emits it is not itself a false positive.

use std::path::Path;

fn rust_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                out.push((display(&path), production_only(&text)));
            }
        }
    }
    out
}

fn display(path: &Path) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Everything up to (not including) the first line that contains `#[cfg(test)]`.
fn production_only(text: &str) -> String {
    let mut kept = String::new();
    for line in text.lines() {
        if line.contains("#[cfg(test)]") {
            break;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    kept
}

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
