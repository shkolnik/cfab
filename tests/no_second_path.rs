//! Spec §16 invariants 3 and 10: there is ONE way to bring the fabric up (the supervisor
//! `cfab run` spawns and supervises its children directly) and ONE code path for systemd and
//! no-systemd. No transient unit, no detached spawn, no `if systemd { .. } else { .. }` branch
//! survives anywhere in production.
//!
//! A grep is the honest test: the thing asserted is the ABSENCE of a mechanism, which a compile
//! error would only catch through a caller. The needles are the mechanisms invariants 3 and 10
//! forbid — a transient-unit spawn (`systemd-run`), a detached spawn (`spawn_detached`/`setsid`),
//! a systemd-presence branch (`/run/systemd/system`) — plus the dead per-component unit/timer
//! names, spelled with their `.service`/`.timer` suffix so they cannot collide with live strings
//! (the running supervisor unit is `cfab.service`; the watchdog's live syslog tag is bare
//! `cfab-fwd-watchdog`, which has no `.timer`).
//!
//! Production code only: each source is truncated at its first `#[cfg(test)]` line before the
//! grep, so a test that names a forbidden mechanism to prove the production side never emits it
//! (e.g. `apply_starts_no_daemon_and_names_no_unit`) is not itself a false positive.

use std::path::Path;

/// Every `.rs` under `src/`, as `(display path, production text)` — the text truncated at the
/// first line that opens a `#[cfg(test)]` module (tests live in a bottom `mod tests` here).
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
fn no_transient_units_no_detached_spawn_no_systemd_branch() {
    const NEEDLES: [&str; 8] = [
        "systemd-run",
        "spawn_detached",
        "setsid",
        "/run/systemd/system",
        "cfab-engine.service",
        "cfab-shape.service",
        "cfab-conf-sync.service",
        "cfab-fwd-watchdog.timer",
    ];
    let mut hits = Vec::new();
    for (path, text) in rust_sources() {
        for needle in NEEDLES {
            if text.contains(needle) {
                hits.push(format!("{path} still names {needle}"));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "second-path survivors:\n{}",
        hits.join("\n")
    );
}
