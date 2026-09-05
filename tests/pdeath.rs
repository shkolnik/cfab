//! Parent-death behavior of a supervised child, end to end against the real `cfab` binary.
//!
//! These live in an integration test on purpose: unit tests inside the library get no
//! `CARGO_BIN_EXE_cfab`, and — measured on this machine 2026-09-05 — `cargo test` does not
//! uplift `target/debug/cfab` at all unless the crate has an integration-test target. Reaching
//! for the binary by path from a unit test silently reads whatever was built last, so the
//! tests below would pass or fail against stale code.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cfab::supervisor::child::{Spawned, spawn};

const CFAB: &str = env!("CARGO_BIN_EXE_cfab");

/// Alive means "has a /proc entry that is not a zombie". `kill(pid, 0)` cannot tell the two
/// apart, and a grandchild we cannot wait for stays reapable until its new parent gets to it.
fn is_alive(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => match s.rsplit_once(") ") {
            Some((_, rest)) => !rest.starts_with('Z'),
            None => false,
        },
        Err(_) => false,
    }
}

fn dies_within(pid: u32, limit: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if !is_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    !is_alive(pid)
}

fn read_pidfile(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("no pid in {}", path.display()))
}

/// Run a `sh` script to completion. The middle process of every parent-death test is a shell,
/// so the grandchild's parent is a process we can kill without killing the test.
fn run_sh(script: &str) {
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .status()
        .unwrap();
}

fn kill9(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status();
}

/// The child arms its own PDEATHSIG (`pre_exec` is unsafe and the crate forbids unsafe).
/// Proof it works end to end: a grandchild whose parent is SIGKILLed dies on its own.
#[tokio::test]
async fn a_supervised_child_dies_when_its_supervisor_is_sigkilled() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("gc.pid");
    run_sh(&format!(
        "CFAB_SUPERVISOR_PID=$$ {CFAB} __pdeath-selftest {pf} &\n\
         n=0; while [ ! -f {pf} ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n+1)); done\n\
         kill -9 $$",
        pf = pidfile.display()
    ));
    let gc = read_pidfile(&pidfile);
    let died = dies_within(gc, Duration::from_secs(5));
    if !died {
        kill9(gc);
    }
    assert!(died, "grandchild {gc} outlived its SIGKILLed supervisor");
}

/// CORRECTION 1. Standalone use must arm NOTHING. `scripts/engine-oracle.sh` runs
/// `cfab engine` under `setsid -f`, whose intermediate parent exits at once; an unconditional
/// set_pdeathsig would SIGTERM the engine the instant it started.
#[tokio::test]
async fn an_unsupervised_child_survives_its_parents_exit() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("gc.pid");
    run_sh(&format!(
        "{CFAB} __pdeath-selftest {pf} &\n\
         n=0; while [ ! -f {pf} ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n+1)); done\n\
         exit 0",
        pf = pidfile.display()
    ));
    let gc = read_pidfile(&pidfile);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let alive = is_alive(gc);
    kill9(gc);
    assert!(
        alive,
        "an unsupervised child must survive its launcher exiting"
    );
}

/// The mismatch is the child's own exit code and it is 5, not 4: 4 is the supervisor's
/// "instance lock already held", and one spelling per condition is the rule.
#[test]
fn a_supervised_verb_whose_supervisor_vanished_exits_5() {
    let st = std::process::Command::new(CFAB)
        .arg("__pdeath-selftest")
        .env("CFAB_SUPERVISOR_PID", u32::MAX.to_string())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(5));
}

fn spawn_selftest_child(pidfile: &Path) -> Spawned {
    spawn(
        "engine",
        &[
            PathBuf::from(CFAB).to_string_lossy().into_owned(),
            "__pdeath-selftest".into(),
            pidfile.to_string_lossy().into_owned(),
        ],
        std::process::id(),
    )
    .unwrap()
}

/// CORRECTION 2. PDEATHSIG follows the parent THREAD (prctl(2)), and tokio reaps idle
/// blocking-pool threads — so this test exists to show the hazard the spawn-site invariant
/// exists for, not to be fixed by making the child tolerate it.
#[tokio::test(flavor = "multi_thread")]
async fn spawning_a_child_from_spawn_blocking_kills_it_when_that_thread_retires() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("gc.pid");
    let pf = pidfile.clone();
    // The whole `Spawned` comes back and is held: dropping it would kill the child by
    // `kill_on_drop`, and the test would then pass for the wrong reason.
    let held = tokio::task::spawn_blocking(move || spawn_selftest_child(&pf))
        .await
        .unwrap();
    let pid = held.pid;
    assert!(
        dies_within(pid, Duration::from_secs(90)),
        "if this ever stops reproducing, the invariant still stands: spawn on the main thread"
    );
}
