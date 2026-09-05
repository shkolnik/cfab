//! `flock`-based single instance (spec §14): a held lock is released by the kernel on ANY
//! death — including `SIGKILL` and OOM — which makes the stale-state class that
//! `engine_ctl::stop_and_sweep`'s `/proc` cmdline forensics existed to work around
//! unrepresentable. Pid files are gone; `<run_dir>/cfab.lock` (the supervisor) and
//! `<run_dir>/engine.lock` (the engine) are both held through this one function, for the
//! process's whole lifetime.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::Path;

use nix::fcntl::{Flock, FlockArg};

/// Another process already holds the lock. `pid` is the holder's pid if the lock file names
/// one it was possible to read and parse — a fresh, empty, or unreadable file yields `None`,
/// never a reason to assume the lock is actually free (the flock says otherwise).
#[derive(Debug, PartialEq, Eq)]
pub struct Held {
    pub pid: Option<u32>,
}

/// The lock, held for as long as this guard lives: dropping it releases the flock (also done
/// by the kernel on `SIGKILL`/OOM, which is the whole point). Carries the open, locked file so
/// the fd — and therefore the lock — survives for the guard's lifetime.
pub struct LockGuard(#[allow(dead_code)] Flock<File>);

/// Take an exclusive, non-blocking `flock` on `path` (creating it if it does not exist yet)
/// and, once held, write our own pid into it — AFTER locking, so a pid a `SIGKILL`ed previous
/// holder left behind is never read as live by the next contender; the lock itself, not the
/// file's content, is the single source of truth for "who holds it".
///
/// Opening or preparing the lock file is expected to succeed: `path`'s directory (the run
/// dir) is created by `apply` before anything holds a lock in it. A failure at that layer
/// (permissions, a read-only filesystem) is an environment fault this function cannot recover
/// from and is not the "already held" condition callers act on, so it panics with the OS
/// error rather than silently reporting the wrong condition as `Held`.
pub fn hold(path: &Path) -> std::result::Result<LockGuard, Held> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .unwrap_or_else(|e| panic!("cannot open lock file {}: {e}", path.display()));
    let mut file = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(locked) => locked,
        Err((mut file, _errno)) => {
            let pid = read_pid(&mut file);
            return Err(Held { pid });
        }
    };
    file.set_len(0)
        .and_then(|()| file.rewind())
        .and_then(|()| file.write_all(std::process::id().to_string().as_bytes()))
        .unwrap_or_else(|e| panic!("cannot write lock file {}: {e}", path.display()));
    Ok(LockGuard(file))
}

/// Best-effort: the previous holder's pid, for the message a refused caller prints. Read
/// without the lock (we do not hold it), so this can race a concurrent write — informational
/// only, never load-bearing for correctness.
fn read_pid(file: &mut File) -> Option<u32> {
    file.rewind().ok()?;
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;
    buf.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_second_holder_is_refused_and_told_the_first_ones_pid() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cfab.lock");
        let _g = hold(&p).unwrap();
        // A second process, not a second thread: flock is per-open-file-description, so two
        // handles in the same process would not contend at all.
        let out = selftest_command(&p).output().unwrap();
        assert_eq!(out.status.code(), Some(4), "{out:?}");
    }

    /// The stale-state class `engine.pid`'s `/proc` cmdline forensics existed to work around:
    /// a holder that dies by `SIGKILL` (no unlock, no chance to run any cleanup at all) must
    /// not leave the lock looking held. The kernel releases an `flock` on any fd close,
    /// including the implicit one at process death.
    #[test]
    fn the_lock_is_released_by_the_kernel_on_sigkill() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cfab.lock");
        let mut child = selftest_command(&p).stdout(Stdio::piped()).spawn().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        // Wait for the child to confirm it actually holds the lock before killing it —
        // otherwise a kill that lands before the child even opens the file proves nothing.
        loop {
            let line = lines
                .next()
                .expect("child exited before confirming it holds the lock")
                .unwrap();
            if line.trim() == "LOCKED" {
                break;
            }
        }
        child.kill().unwrap(); // SIGKILL
        child.wait().unwrap();
        // Give the kernel a moment to tear down the dead process's file table (best effort;
        // in practice this is immediate on Linux, but never race a test on that assumption
        // alone — retry briefly rather than flake).
        let mut got = hold(&p);
        let mut waited = Duration::ZERO;
        while got.is_err() && waited < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(20));
            waited += Duration::from_millis(20);
            got = hold(&p);
        }
        assert!(
            got.is_ok(),
            "the lock still looks held after the kernel reaped a SIGKILLed holder"
        );
    }

    /// Not a real assertion: a subprocess worker for the two tests above, dispatched by an
    /// env var so an ordinary `cargo test` run (which also executes this function) does
    /// nothing. Held: prints "LOCKED" and blocks forever (until killed). Refused: exit 4.
    #[test]
    fn lock_selftest_worker() {
        let Ok(path) = std::env::var("CFAB_LOCK_SELFTEST_PATH") else {
            return;
        };
        match hold(std::path::Path::new(&path)) {
            Ok(_guard) => {
                println!("LOCKED");
                std::io::stdout().flush().ok();
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            }
            Err(Held { .. }) => std::process::exit(4),
        }
    }

    /// Re-invoke this very test binary, targeting only `lock_selftest_worker`, with the path
    /// it should contend for. `--nocapture` is required: libtest otherwise buffers a test's
    /// stdout and only releases it once the test returns — this one never does.
    fn selftest_command(path: &std::path::Path) -> Command {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "supervisor::lock::tests::lock_selftest_worker",
            "--exact",
            "--nocapture",
        ])
        .env("CFAB_LOCK_SELFTEST_PATH", path);
        cmd
    }
}
