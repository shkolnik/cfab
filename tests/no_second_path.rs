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
//! Production code only, via `tests/support/mod.rs`'s `#[cfg(test)]`-mod stripper (shared with
//! `no_ethtool_dash_k.rs`): a test that names a forbidden mechanism to prove the production side
//! never emits it (e.g. `apply_starts_no_daemon_and_names_no_unit`) is not itself a false
//! positive.

#[path = "support/mod.rs"]
mod support;

use support::rust_sources;

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
