//! `cfab conf-sync` — the cluster config-sync daemon (runs as cfab-conf-sync.service on every
//! clustered member; started by `up` only when the pmxcfs probe reports clustered). Watches
//! `/etc/pve/cfab/gen` on a 1 s stat-poll; on a new generation it validates the published
//! fabric.conf with the full typed gate, applies it by re-execing this binary's own `up`
//! (one source of truth — the daemon never reimplements bringup), verifies, then runs the
//! peer-witness protocol: write an ack file, wait for at least one ack from a DIFFERENT
//! member, and REVERT to the previous conf when no witness appears. The pmxcfs channel's own
//! failure is the revert signal: a severed member cannot write or see acks, so it cannot keep
//! a conf nobody witnessed — fail-safe by construction.
//!
//! Local cache chain: `/etc/cfab/fabric.conf` (last-known-good, the apply target) and
//! `/etc/cfab/fabric.conf.prev` (revert target). Daemon state lives in the declaration's
//! run_dir: `conf-sync-attempted` / `conf-sync-committed`, each one decimal generation.
//! `attempted` is written BEFORE any apply (crash-safe ordering) and a generation is never
//! re-attempted — a reverted or refused generation stays refused until the next publish.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::cluster::{Pmxcfs, format_gen, parse_gen};
use crate::error::{Error, Result};
use crate::sys::Sys;

/// Poll interval for the gen counter and for ack files.
pub const TICK: Duration = Duration::from_secs(1);
/// Witness window: 1 s ack polls before a lone applier reverts.
pub const WITNESS_POLLS: u32 = 60;
/// Passed to the re-exec'd `verify`.
pub const VERIFY_TIMEOUT_SECS: u64 = 30;

/// What one tick did — the loop body's whole outcome, so every ordering is unit-testable.
#[derive(Debug, PartialEq, Eq)]
pub enum Tick {
    /// Advisory fast-path: not quorate, gen reads may be stale — do nothing.
    NotQuorate,
    /// Nothing new (gen == committed).
    Idle,
    /// gen > committed but already attempted and not committed: refused or reverted earlier;
    /// never retried (a revert must not loop).
    AlreadyAttempted(u64),
    /// gen < committed — someone rewound the counter; ignored (logged once per value).
    GenRegression { generation: u64, committed: u64 },
    /// The published conf failed the gate (unreadable or invalid) — never applied.
    Refused { generation: u64, reason: String },
    /// Applied (or byte-identical, `applied: false`) and committed.
    Committed {
        generation: u64,
        applied: bool,
        witness: String,
    },
    /// Applied but not witnessed (or verify/ack failed) — previous conf restored.
    Reverted { generation: u64, reason: String },
}

pub struct ConfSync {
    pmx: Pmxcfs,
    exe: String,
    member: String,
    local_conf: PathBuf,
    run_dir: PathBuf,
    attempted: u64,
    committed: u64,
    regression_logged: Option<u64>,
}

impl ConfSync {
    pub fn new(
        pmx: Pmxcfs,
        exe: impl Into<String>,
        member: impl Into<String>,
        local_conf: impl Into<PathBuf>,
        run_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        let run_dir = run_dir.into();
        let attempted = read_state(&run_dir.join("conf-sync-attempted"))?;
        let committed = read_state(&run_dir.join("conf-sync-committed"))?;
        Ok(ConfSync {
            pmx,
            exe: exe.into(),
            member: member.into(),
            local_conf: local_conf.into(),
            run_dir,
            attempted,
            committed,
            regression_logged: None,
        })
    }

    fn prev_path(&self) -> PathBuf {
        let mut name = self.local_conf.as_os_str().to_owned();
        name.push(".prev");
        PathBuf::from(name)
    }

    fn set_attempted(&mut self, generation: u64) -> Result<()> {
        write_state(&self.run_dir.join("conf-sync-attempted"), generation)?;
        self.attempted = generation;
        Ok(())
    }

    fn set_committed(&mut self, generation: u64) -> Result<()> {
        write_state(&self.run_dir.join("conf-sync-committed"), generation)?;
        self.committed = generation;
        Ok(())
    }

    /// One loop iteration. Cheap checks first (quorum, gen); the expensive path only on a new
    /// generation. Errors are transient faults (pmxcfs unreadable mid-restart …): the caller
    /// logs and keeps ticking.
    pub fn tick(&mut self, sys: &mut dyn Sys) -> Result<Tick> {
        if !self.pmx.quorate()? {
            return Ok(Tick::NotQuorate);
        }
        let generation = self.pmx.read_gen()?;
        if generation == self.committed {
            return Ok(Tick::Idle);
        }
        if generation < self.committed {
            return Ok(Tick::GenRegression {
                generation,
                committed: self.committed,
            });
        }
        if generation == self.attempted {
            return Ok(Tick::AlreadyAttempted(generation));
        }
        self.handle_new_generation(sys, generation)
    }

    fn handle_new_generation(&mut self, sys: &mut dyn Sys, generation: u64) -> Result<Tick> {
        // Crash-safe ordering: record the attempt BEFORE any apply, so a crash mid-apply can
        // never loop on this generation.
        self.set_attempted(generation)?;

        let published = match std::fs::read_to_string(self.pmx.conf_path()) {
            Ok(t) => t,
            Err(e) => {
                return Ok(Tick::Refused {
                    generation,
                    reason: format!("cannot read {}: {e}", self.pmx.conf_path().display()),
                });
            }
        };
        // The FULL existing gate: parse, type, validate, and resolve this member's view. A
        // published conf that fails any of it is refused loudly and never applied.
        if let Err(e) = validate(&published, &self.member) {
            return Ok(Tick::Refused {
                generation,
                reason: e.to_string(),
            });
        }

        let local = std::fs::read_to_string(&self.local_conf).ok();
        if local.as_deref() == Some(published.as_str()) {
            // Byte-identical: nothing to apply. Ack (exit code 0: the running conf IS this
            // conf) and commit; a failed ack write changes nothing locally, so it does not
            // revert — the witness protocol guards applies, not no-ops.
            let witness = match self.write_ack(generation, 0) {
                Ok(()) => "identical, ack written".to_string(),
                Err(e) => format!("identical; ack write failed ({e}) — committed anyway"),
            };
            self.set_committed(generation)?;
            return Ok(Tick::Committed {
                generation,
                applied: false,
                witness,
            });
        }

        // Apply: cache the revert target, install the published text, re-exec our own `up`.
        if let Some(current) = &local {
            std::fs::write(self.prev_path(), current).map_err(|e| {
                Error::fatal(format!("cannot write {}: {e}", self.prev_path().display()))
            })?;
        }
        std::fs::write(&self.local_conf, &published).map_err(|e| {
            Error::fatal(format!("cannot write {}: {e}", self.local_conf.display()))
        })?;
        let local_conf = self.local_conf.display().to_string();
        let up = sys.run(&[&self.exe, "--config", &local_conf, "up"])?;
        if !up.ok() {
            return self.revert(sys, generation, format!("up exited {}", up.status));
        }
        let timeout = VERIFY_TIMEOUT_SECS.to_string();
        let verify = sys.run(&[
            &self.exe,
            "--config",
            &local_conf,
            "verify",
            "--timeout",
            &timeout,
        ])?;
        // 0 = healthy, 2 = degraded-but-carrying: both count as carrying traffic.
        if verify.status != 0 && verify.status != 2 {
            return self.revert(sys, generation, format!("verify exited {}", verify.status));
        }

        // Witness. The ack write is retried across the whole window, not treated as terminal
        // on first failure: applying a conf restarts FRR, which blips the very routes the
        // coordination channel rides, so pmxcfs is routinely unwritable (EPERM/EACCES) for a
        // few seconds after `up`. A member that stays unable to write its ack for the full
        // window is genuinely severed — that, and only that, is the revert signal.
        let single = self.member_count() == 1;
        let mut acked = false;
        let mut last_ack_err = String::new();
        for _ in 0..WITNESS_POLLS {
            if !acked {
                match self.write_ack(generation, verify.status) {
                    Ok(()) => acked = true,
                    Err(e) => last_ack_err = e.to_string(),
                }
            }
            if acked && single {
                self.set_committed(generation)?;
                return Ok(Tick::Committed {
                    generation,
                    applied: true,
                    witness: "witness skipped: single-member cluster, no peers".to_string(),
                });
            }
            if acked && let Some(peer) = self.peer_ack(generation) {
                self.set_committed(generation)?;
                return Ok(Tick::Committed {
                    generation,
                    applied: true,
                    witness: format!("witnessed by {peer}"),
                });
            }
            sys.sleep(TICK);
        }
        let reason = if acked {
            format!("no peer ack within {WITNESS_POLLS} s")
        } else {
            format!(
                "own ack unwritable for {WITNESS_POLLS} s ({last_ack_err}) — severed or \
                 non-quorate"
            )
        };
        self.revert(sys, generation, reason)
    }

    /// Restore the previous conf and re-exec `up` on it. `attempted` stays at this
    /// generation, so it is never retried; `committed` is unchanged.
    fn revert(&mut self, sys: &mut dyn Sys, generation: u64, reason: String) -> Result<Tick> {
        // Retract our ack first: an ack must not outlive the decision it advertises (a late
        // reader could otherwise commit on our word after we reverted). Best-effort — in the
        // severed case the ack was never written, and the retraction cannot land either.
        match std::fs::remove_file(self.pmx.ack_path(generation, &self.member)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "conf-sync: cannot retract ack for gen {generation}: {e} — peers reject it \
                 as stale after {WITNESS_POLLS} s anyway"
            ),
        }
        let prev = self.prev_path();
        match std::fs::read_to_string(&prev) {
            Ok(text) => {
                std::fs::write(&self.local_conf, text).map_err(|e| {
                    Error::fatal(format!("cannot write {}: {e}", self.local_conf.display()))
                })?;
                let local_conf = self.local_conf.display().to_string();
                let up = sys.run(&[&self.exe, "--config", &local_conf, "up"])?;
                if !up.ok() {
                    eprintln!(
                        "conf-sync: REVERT of gen {generation}: up on the previous conf \
                         exited {} — fabric state needs hands",
                        up.status
                    );
                }
            }
            Err(e) => eprintln!(
                "conf-sync: REVERT of gen {generation}: no revert target ({}: {e}) — \
                 the new conf stays applied, fabric state needs hands",
                prev.display()
            ),
        }
        Ok(Tick::Reverted { generation, reason })
    }

    /// Ack file for this member: one line, member name + verify exit code, written with the
    /// atomic tmp+rename publish (a rename is one totally-ordered cluster message).
    fn write_ack(&self, generation: u64, verify_status: i32) -> Result<()> {
        let dir = self.pmx.acks_dir(generation);
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::fatal(format!("cannot create {}: {e}", dir.display())))?;
        self.pmx.publish(
            &self.pmx.ack_path(generation, &self.member),
            &format!("{} {verify_status}\n", self.member),
        )
    }

    /// First ack from a member that is not us (tmp files from in-flight publishes excluded).
    /// A peer ack is only proof while FRESH (younger than the witness window): an acker that
    /// times out reverts and retracts its ack, but a reader mid-race — or a member that was
    /// frozen and woke late — must not trust an ack whose writer's own window has passed
    /// (live-found: a stale ack let a late member commit a generation its witness had
    /// already reverted). pmxcfs mtimes are writer-set; measured cross-host skew is ~ms.
    fn peer_ack(&self, generation: u64) -> Option<String> {
        let entries = std::fs::read_dir(self.pmx.acks_dir(generation)).ok()?;
        let window = Duration::from_secs(WITNESS_POLLS as u64);
        entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| SystemTime::now().duration_since(t).ok())
                    .is_some_and(|age| age <= window)
            })
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|name| !name.starts_with('.') && *name != self.member)
    }

    /// Declared members, from `.members`. Unreadable or empty counts as "has peers": when in
    /// doubt, require a witness (fail-safe), never skip it.
    fn member_count(&self) -> usize {
        match self.pmx.probe() {
            Ok(Some(m)) if !m.nodelist.is_empty() => m.nodelist.len(),
            _ => 2,
        }
    }

    /// Log a tick's outcome (quiet on the steady states). Kept beside `tick` so tests can
    /// assert outcomes without capturing stdio.
    fn report(&mut self, t: &Tick) {
        match t {
            Tick::NotQuorate | Tick::Idle | Tick::AlreadyAttempted(_) => {}
            Tick::GenRegression {
                generation,
                committed,
            } => {
                if self.regression_logged != Some(*generation) {
                    self.regression_logged = Some(*generation);
                    eprintln!(
                        "conf-sync: gen {generation} is BEHIND committed {committed} — \
                         counter rewound? ignoring until it advances"
                    );
                }
            }
            Tick::Refused { generation, reason } => eprintln!(
                "conf-sync: REFUSED published gen {generation}: {reason} — never applied; \
                 will not retry this generation (publish a fixed conf)"
            ),
            Tick::Committed {
                generation,
                applied,
                witness,
            } => println!(
                "conf-sync: gen {generation} committed ({}; {witness})",
                if *applied { "applied" } else { "no apply" }
            ),
            Tick::Reverted { generation, reason } => eprintln!(
                "conf-sync: REVERTED gen {generation}: {reason} — previous conf restored; \
                 will not retry this generation"
            ),
        }
    }
}

fn validate(text: &str, member: &str) -> Result<()> {
    let raw = crate::config::RawConfig::parse(text)?;
    let fabric = crate::model::Fabric::from_raw(&raw)?;
    crate::derive::View::new(&fabric, member)?;
    Ok(())
}

fn read_state(path: &Path) -> Result<u64> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_gen(&text, path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(Error::fatal(format!("cannot read {}: {e}", path.display()))),
    }
}

fn write_state(path: &Path, generation: u64) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::fatal(format!("cannot create {}: {e}", dir.display())))?;
    }
    std::fs::write(path, format_gen(generation))
        .map_err(|e| Error::fatal(format!("cannot write {}: {e}", path.display())))
}

/// The real daemon: tick every second until SIGTERM/SIGINT, log outcomes, exit cleanly.
pub fn run(sys: &mut dyn Sys, member: &str, run_dir: &str, exe: &str) -> Result<()> {
    let mut cs = ConfSync::new(Pmxcfs::new(), exe, member, "/etc/cfab/fabric.conf", run_dir)?;
    println!(
        "conf-sync: start member={member} attempted={} committed={}",
        cs.attempted, cs.committed
    );
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let f = stop.clone();
        ctrlc::set_handler(move || f.store(true, std::sync::atomic::Ordering::SeqCst))
            .map_err(|e| Error::fatal(format!("cannot install signal handler: {e}")))?;
    }
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        match cs.tick(sys) {
            Ok(t) => cs.report(&t),
            Err(e) => eprintln!("conf-sync: tick failed: {e}"),
        }
        sys.sleep(TICK);
    }
    println!("conf-sync: stopped (signal); local conf untouched");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    const EXE: &str = "/usr/bin/cfab";
    const MEMBER: &str = "pve1-tb";

    const MEMBERS_3: &str = r#"{
      "nodename": "pve1-tb", "version": 7,
      "cluster": {"name": "cfab-test", "version": 3, "nodes": 3, "quorate": 1},
      "nodelist": {
        "pve1-tb": {"id": 1, "online": 1, "ip": "10.249.0.1"},
        "pve2-tb": {"id": 2, "online": 1, "ip": "10.249.0.2"},
        "pve3-tb": {"id": 3, "online": 1, "ip": "10.249.0.3"}
      }
    }"#;

    const MEMBERS_1: &str = r#"{
      "nodename": "pve1-tb", "version": 7,
      "cluster": {"name": "cfab-test", "version": 3, "nodes": 1, "quorate": 1},
      "nodelist": {"pve1-tb": {"id": 1, "online": 1, "ip": "10.249.0.1"}}
    }"#;

    fn valid_conf() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
            .unwrap()
    }

    struct Fixture {
        _pve: tempfile::TempDir,
        _local: tempfile::TempDir,
        cs: ConfSync,
        pmx_root: PathBuf,
        local_conf: PathBuf,
        run_dir: PathBuf,
    }

    /// A pmxcfs stand-in (tempdir), a local /etc/cfab stand-in, and the daemon over them.
    fn fixture(members: &str, published: Option<&str>, generation: u64, local: &str) -> Fixture {
        let pve = tempfile::tempdir().unwrap();
        let local_dir = tempfile::tempdir().unwrap();
        let pmx = Pmxcfs::at(pve.path());
        std::fs::write(pmx.members_path(), members).unwrap();
        std::fs::create_dir_all(pmx.cfab_dir()).unwrap();
        if let Some(text) = published {
            std::fs::write(pmx.conf_path(), text).unwrap();
        }
        std::fs::write(pmx.gen_path(), format_gen(generation)).unwrap();
        let local_conf = local_dir.path().join("fabric.conf");
        std::fs::write(&local_conf, local).unwrap();
        let run_dir = local_dir.path().join("run");
        let cs = ConfSync::new(Pmxcfs::at(pve.path()), EXE, MEMBER, &local_conf, &run_dir).unwrap();
        Fixture {
            pmx_root: pve.path().to_path_buf(),
            _pve: pve,
            _local: local_dir,
            cs,
            local_conf,
            run_dir,
        }
    }

    fn up_argv(f: &Fixture) -> String {
        format!("{EXE} --config {} up", f.local_conf.display())
    }

    fn verify_argv(f: &Fixture) -> String {
        format!(
            "{EXE} --config {} verify --timeout 30",
            f.local_conf.display()
        )
    }

    fn state(f: &Fixture, name: &str) -> Option<String> {
        std::fs::read_to_string(f.run_dir.join(name))
            .ok()
            .map(|s| s.trim().to_string())
    }

    #[test]
    fn new_gen_applies_and_commits_on_peer_ack() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        // The peer's ack is already there when the witness poll starts.
        let pmx = Pmxcfs::at(&f.pmx_root);
        std::fs::create_dir_all(pmx.acks_dir(1)).unwrap();
        std::fs::write(pmx.ack_path(1, "pve2-tb"), "pve2-tb 0\n").unwrap();
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys).unwrap();
        assert_eq!(
            t,
            Tick::Committed {
                generation: 1,
                applied: true,
                witness: "witnessed by pve2-tb".to_string()
            }
        );
        // Exact re-exec argv, in order: up then verify.
        assert_eq!(sys.calls, vec![up_argv(&f), verify_argv(&f)]);
        assert!(sys.slept.is_empty(), "peer ack present: no witness wait");
        // Local cache chain updated; state files persisted.
        assert_eq!(std::fs::read_to_string(&f.local_conf).unwrap(), conf);
        let prev = std::fs::read_to_string(f.cs.prev_path()).unwrap();
        assert_eq!(prev, "OLD\n");
        assert_eq!(state(&f, "conf-sync-attempted").as_deref(), Some("1"));
        assert_eq!(state(&f, "conf-sync-committed").as_deref(), Some("1"));
        // Our own ack was written too.
        assert_eq!(
            std::fs::read_to_string(pmx.ack_path(1, MEMBER)).unwrap(),
            "pve1-tb 0\n"
        );
        // Next tick is quiet.
        assert_eq!(f.cs.tick(&mut sys).unwrap(), Tick::Idle);
    }

    #[test]
    fn witness_timeout_reverts() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys).unwrap();
        assert_eq!(
            t,
            Tick::Reverted {
                generation: 1,
                reason: "no peer ack within 60 s".to_string()
            }
        );
        assert_eq!(sys.slept.len(), 60, "full witness window polled");
        // up (apply), verify, up (revert) — exactly.
        assert_eq!(sys.calls, vec![up_argv(&f), verify_argv(&f), up_argv(&f)]);
        // Previous conf back in place; attempted recorded, committed not.
        assert_eq!(std::fs::read_to_string(&f.local_conf).unwrap(), "OLD\n");
        assert_eq!(state(&f, "conf-sync-attempted").as_deref(), Some("1"));
        assert_eq!(state(&f, "conf-sync-committed"), None);
        // The reverted generation is never re-attempted.
        assert_eq!(f.cs.tick(&mut sys).unwrap(), Tick::AlreadyAttempted(1));
        // The revert retracted our own ack: it must not outlive the decision.
        assert!(!Pmxcfs::at(&f.pmx_root).ack_path(1, MEMBER).exists());
    }

    #[test]
    fn stale_peer_ack_is_not_a_witness() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        // A peer ack older than the witness window: its writer's own window has passed (it
        // reverted, or died); trusting it is how a late member commits a generation its
        // witness abandoned (live-found).
        let pmx = Pmxcfs::at(&f.pmx_root);
        std::fs::create_dir_all(pmx.acks_dir(1)).unwrap();
        let stale = pmx.ack_path(1, "pve2-tb");
        std::fs::write(&stale, "pve2-tb 0\n").unwrap();
        assert!(
            std::process::Command::new("touch")
                .args(["-d", "-120 seconds", "--"])
                .arg(&stale)
                .status()
                .unwrap()
                .success()
        );
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys).unwrap();
        assert_eq!(
            t,
            Tick::Reverted {
                generation: 1,
                reason: "no peer ack within 60 s".to_string()
            }
        );
        assert_eq!(std::fs::read_to_string(&f.local_conf).unwrap(), "OLD\n");
    }

    #[test]
    fn verify_fail_reverts_without_ack() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        let mut sys = MockSys::default().on_fail(
            &[
                EXE,
                "--config",
                &f.local_conf.display().to_string(),
                "verify",
            ],
            1,
            "degraded past carrying",
        );
        let t = f.cs.tick(&mut sys).unwrap();
        assert_eq!(
            t,
            Tick::Reverted {
                generation: 1,
                reason: "verify exited 1".to_string()
            }
        );
        assert_eq!(sys.calls, vec![up_argv(&f), verify_argv(&f), up_argv(&f)]);
        assert_eq!(std::fs::read_to_string(&f.local_conf).unwrap(), "OLD\n");
        // No ack for a conf that failed verify.
        assert!(!Pmxcfs::at(&f.pmx_root).ack_path(1, MEMBER).exists());
    }

    #[test]
    fn verify_degraded_exit_2_still_counts_as_carrying() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        let pmx = Pmxcfs::at(&f.pmx_root);
        std::fs::create_dir_all(pmx.acks_dir(1)).unwrap();
        std::fs::write(pmx.ack_path(1, "pve3-tb"), "pve3-tb 0\n").unwrap();
        let mut sys = MockSys::default().on_fail(
            &[
                EXE,
                "--config",
                &f.local_conf.display().to_string(),
                "verify",
            ],
            2,
            "",
        );
        let t = f.cs.tick(&mut sys).unwrap();
        assert!(
            matches!(
                t,
                Tick::Committed {
                    generation: 1,
                    applied: true,
                    ..
                }
            ),
            "{t:?}"
        );
        // The ack records the degraded exit code.
        assert_eq!(
            std::fs::read_to_string(pmx.ack_path(1, MEMBER)).unwrap(),
            "pve1-tb 2\n"
        );
    }

    #[test]
    fn invalid_published_conf_refused_and_not_retried() {
        let mut f = fixture(MEMBERS_3, Some("NOT_A_KEY==\n"), 1, "OLD\n");
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys).unwrap();
        assert!(matches!(t, Tick::Refused { generation: 1, .. }), "{t:?}");
        // Nothing applied, nothing run, local cache untouched.
        assert!(sys.calls.is_empty());
        assert_eq!(std::fs::read_to_string(&f.local_conf).unwrap(), "OLD\n");
        assert_eq!(state(&f, "conf-sync-attempted").as_deref(), Some("1"));
        // The attempted gate holds: no retry loop on a bad publish.
        assert_eq!(f.cs.tick(&mut sys).unwrap(), Tick::AlreadyAttempted(1));
        assert!(sys.calls.is_empty());
    }

    #[test]
    fn valid_conf_for_wrong_member_is_refused() {
        // Validation runs against THIS member's view: a conf whose MEMBER_TABLE lacks us
        // is refused even though it parses.
        let conf = valid_conf().replace("pve1-tb", "pve9-tb");
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys).unwrap();
        assert!(matches!(t, Tick::Refused { generation: 1, .. }), "{t:?}");
        assert!(sys.calls.is_empty());
    }

    #[test]
    fn identical_conf_acks_without_apply() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 3, &conf);
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys).unwrap();
        assert_eq!(
            t,
            Tick::Committed {
                generation: 3,
                applied: false,
                witness: "identical, ack written".to_string()
            }
        );
        assert!(
            sys.calls.is_empty(),
            "no up/verify re-exec: {:?}",
            sys.calls
        );
        assert!(sys.slept.is_empty(), "no witness wait for a no-op");
        let pmx = Pmxcfs::at(&f.pmx_root);
        assert_eq!(
            std::fs::read_to_string(pmx.ack_path(3, MEMBER)).unwrap(),
            "pve1-tb 0\n"
        );
        assert_eq!(state(&f, "conf-sync-committed").as_deref(), Some("3"));
        assert!(!f.cs.prev_path().exists(), "no apply, no .prev churn");
    }

    #[test]
    fn non_quorate_tick_does_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        std::fs::set_permissions(&f.pmx_root, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys);
        std::fs::set_permissions(&f.pmx_root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(t.unwrap(), Tick::NotQuorate);
        assert!(sys.calls.is_empty());
        assert_eq!(state(&f, "conf-sync-attempted"), None, "gen not even read");
    }

    #[test]
    fn single_member_skips_witness() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_1, Some(&conf), 1, "OLD\n");
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys).unwrap();
        assert_eq!(
            t,
            Tick::Committed {
                generation: 1,
                applied: true,
                witness: "witness skipped: single-member cluster, no peers".to_string()
            }
        );
        assert!(sys.slept.is_empty(), "no witness polling");
        assert_eq!(sys.calls, vec![up_argv(&f), verify_argv(&f)]);
        // The lone member still writes its ack (a joining peer can read history).
        let pmx = Pmxcfs::at(&f.pmx_root);
        assert_eq!(
            std::fs::read_to_string(pmx.ack_path(1, MEMBER)).unwrap(),
            "pve1-tb 0\n"
        );
    }

    #[test]
    fn ack_unwritable_all_window_reverts() {
        use std::os::unix::fs::PermissionsExt;
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        // The severed-node stand-in: the ack dir refuses writes for the WHOLE window (a real
        // severed pmxcfs fails the write with EACCES the same way). A transient failure is
        // retried each poll — only window-long failure reverts.
        let pmx = Pmxcfs::at(&f.pmx_root);
        std::fs::create_dir_all(pmx.acks_dir(1)).unwrap();
        std::fs::set_permissions(pmx.acks_dir(1), std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut sys = MockSys::default();
        let t = f.cs.tick(&mut sys).unwrap();
        std::fs::set_permissions(pmx.acks_dir(1), std::fs::Permissions::from_mode(0o755)).unwrap();
        if let Tick::Reverted {
            generation: 1,
            reason,
        } = &t
        {
            assert!(reason.contains("own ack unwritable"), "{reason}");
        } else {
            panic!("expected Reverted, got {t:?}");
        }
        assert_eq!(std::fs::read_to_string(&f.local_conf).unwrap(), "OLD\n");
        assert_eq!(sys.calls, vec![up_argv(&f), verify_argv(&f), up_argv(&f)]);
        // The whole window was spent retrying, one poll per tick.
        assert_eq!(sys.slept.len(), 60);
    }

    #[test]
    fn ack_transient_failure_recovers_within_window() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        // First ack attempt fails (no acks dir is creatable: a file squats on the path);
        // clearing the obstruction mid-window must let the retry succeed — with a peer ack
        // present, the apply commits instead of reverting.
        let pmx = Pmxcfs::at(&f.pmx_root);
        std::fs::write(pmx.cfab_dir().join("acks"), "squatter").unwrap();
        let mut sys = MockSys::default();
        let pmx_root = f.pmx_root.clone();
        sys.on_sleep = Some(Box::new(move |n| {
            if n == 2 {
                let pmx = Pmxcfs::at(&pmx_root);
                std::fs::remove_file(pmx.cfab_dir().join("acks")).unwrap();
                std::fs::create_dir_all(pmx.acks_dir(1)).unwrap();
                std::fs::write(pmx.ack_path(1, "pve2-tb"), "pve2-tb 0\n").unwrap();
            }
        }));
        let t = f.cs.tick(&mut sys).unwrap();
        if let Tick::Committed {
            generation: 1,
            applied: true,
            witness,
        } = &t
        {
            assert!(witness.contains("pve2-tb"), "{witness}");
        } else {
            panic!("expected Committed, got {t:?}");
        }
        // Own ack landed despite the initial failure.
        assert!(pmx.ack_path(1, MEMBER).exists());
    }

    #[test]
    fn gen_regression_is_ignored() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 3, "OLD\n");
        write_state(&f.run_dir.join("conf-sync-committed"), 5).unwrap();
        let mut f2 = ConfSync::new(
            Pmxcfs::at(&f.pmx_root),
            EXE,
            MEMBER,
            &f.local_conf,
            &f.run_dir,
        )
        .unwrap();
        let mut sys = MockSys::default();
        let t = f2.tick(&mut sys).unwrap();
        assert_eq!(
            t,
            Tick::GenRegression {
                generation: 3,
                committed: 5
            }
        );
        assert!(sys.calls.is_empty());
        assert_eq!(std::fs::read_to_string(&f.local_conf).unwrap(), "OLD\n");
        drop(f2);
        let _ = &mut f;
    }

    #[test]
    fn state_survives_restart() {
        let conf = valid_conf();
        let mut f = fixture(MEMBERS_3, Some(&conf), 1, "OLD\n");
        let mut sys = MockSys::default();
        // Revert path leaves attempted=1 persisted; a restarted daemon must not retry.
        assert!(matches!(
            f.cs.tick(&mut sys).unwrap(),
            Tick::Reverted { generation: 1, .. }
        ));
        let mut restarted = ConfSync::new(
            Pmxcfs::at(&f.pmx_root),
            EXE,
            MEMBER,
            &f.local_conf,
            &f.run_dir,
        )
        .unwrap();
        let mut sys2 = MockSys::default();
        assert_eq!(
            restarted.tick(&mut sys2).unwrap(),
            Tick::AlreadyAttempted(1)
        );
        assert!(sys2.calls.is_empty());
    }
}
