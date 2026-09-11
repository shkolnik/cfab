//! The flush actor's writer boundary (gate C spec §4.4, plan §4 task 3a): a `Send`-boxed trait
//! that still forks `ip`, reproducing `Sys::run`'s `Output`-shaped return (`sys.rs:134-144`)
//! and adding the one thing it lacks. It does NOT go through `Sys`: `Sys::run` takes
//! `&mut self` and lives on the command loop, which is the entire reason the flush actor
//! (task 3b) is its own task rather than another command-loop arm. Reading the kernel is the
//! same capability as writing to it (spec §4.2.2: the actor reads through the same boxed
//! trait it writes with), so this trait is not named for the write alone, and its one method
//! serves both.
//!
//! `Command::output()`/`wait_with_output` blocks with no way to time it out in place, so the
//! real implementation spawns, drains both pipes on their own threads (a child that fills a
//! pipe buffer before exiting must not be able to wedge the wait loop below), polls for exit
//! against a deadline, and kills the child on expiry. `WRITE_DEADLINE` bounds EVERY child the
//! actor spawns through this trait, the pre-drain kernel read included — a wedged
//! `ip -j neigh show` is the same host-wide stall a wedged write is, since there is one actor
//! for the whole host.
//!
//! No locale control and no stderr parsing here or anywhere downstream of it: the classifier
//! (task 3b) decides solely on exit status and on whether a read entry carries an `lladdr`, so
//! `LC_ALL=C`, an `/usr/bin/env` argv prefix, and a match against `RTNETLINK answers: File
//! exists` buy nothing and are not reintroduced (spec §10, r14: deleted along with
//! EEXIST-as-success).

use std::io::Read;
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::sys::Output;
use crate::workload::relay::mac_str;

/// ~2000x the measured 1.0 ms neighbor write (spec §2), far outside any normal variance and
/// well inside `SWEEP` = 15 s (plan §1): a wedged `ip` costs the actor at most one queue
/// position, never the host's DHCP forwarding. Derived from the write itself, not from
/// `SWEEP` (spec §10, r13: r9's derivation had gone stale against `SWEEP`'s dead 60 s lean).
/// New code, not a flag — never exposed as a runtime knob.
pub const WRITE_DEADLINE: Duration = Duration::from_secs(2);

/// How often the deadline loop polls `try_wait()`. Coarse enough to cost nothing at
/// `WRITE_DEADLINE`'s scale, fine enough that the kill lands within a few polls of the
/// deadline rather than a whole extra interval late.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The two verbs the classifier (task 3b, spec §4.1.1) chooses between: `Add` when the kernel
/// holds no entry for the address at all (create-only — the enforcement point inside the
/// read-to-write window), `Replace` when it holds one with no `lladdr`
/// (FAILED/INCOMPLETE/a NOARP entry with no real MAC). cfab never issues a third verb, and
/// never collapses these two (spec §10; six rounds re-found the same defect from doing so).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteVerb {
    Add,
    Replace,
}

impl WriteVerb {
    fn ip_verb(self) -> &'static str {
        match self {
            WriteVerb::Add => "add",
            WriteVerb::Replace => "replace",
        }
    }
}

/// Build the argv for one neighbor write. `nud stale` is not optional (spec §2, measured on
/// pve1-tb): an entry created with no `nud` argument is PERMANENT, and the victim's own ARP
/// can never correct it — one word between this design and the hijack it exists to prevent,
/// so it is baked into the builder rather than left for a caller to remember to append.
pub fn write_argv(verb: WriteVerb, addr: Ipv4Addr, mac: [u8; 6], leg: &str) -> Vec<String> {
    vec![
        "ip".to_string(),
        "neigh".to_string(),
        verb.ip_verb().to_string(),
        addr.to_string(),
        "lladdr".to_string(),
        mac_str(mac),
        "dev".to_string(),
        leg.to_string(),
        "nud".to_string(),
        "stale".to_string(),
    ]
}

/// What the flush actor forks through, for both its kernel read and its writes: `Send`
/// because the actor is its own task (task 3b), never the command loop that owns `Sys`.
/// Keeping this a trait — rather than calling `std::process::Command` inline in the actor —
/// is what makes the whole write path mockable, which the test strategy depends on, and what
/// makes a later netlink implementation (spec §4.4, deferred) a second impl of this trait
/// rather than a redesign.
pub trait NeighborIo: Send {
    /// Run `argv` to completion or `WRITE_DEADLINE`, whichever comes first. A timeout is
    /// reported as `Err`, the same shape as "could not exec at all": a real timeout kills the
    /// child, and no exit status can represent that the answer never came.
    fn run(&mut self, argv: &[&str]) -> Result<Output>;
}

/// The real implementation: forks `argv[0]`, drains stdout/stderr fully on their own threads,
/// waits with a deadline, and kills the child on expiry. Never touches locale or stderr text —
/// the returned `Output` carries the real exit status untouched (spec §10: "no string match on
/// stderr, ever again").
pub struct ForkNeighborIo {
    deadline: Duration,
}

impl Default for ForkNeighborIo {
    fn default() -> Self {
        ForkNeighborIo {
            deadline: WRITE_DEADLINE,
        }
    }
}

impl ForkNeighborIo {
    /// Production always runs at `WRITE_DEADLINE`; only a test shrinks it, so a suite proving
    /// the kill fires does not cost 2 s of wall time per test. `WRITE_DEADLINE` itself is not a
    /// runtime knob, so this constructor does not exist outside `cfg(test)`.
    #[cfg(test)]
    fn with_deadline(deadline: Duration) -> Self {
        ForkNeighborIo { deadline }
    }
}

impl NeighborIo for ForkNeighborIo {
    fn run(&mut self, argv: &[&str]) -> Result<Output> {
        run_with_deadline(argv, self.deadline)
    }
}

/// Spawn, drain, wait-with-deadline, kill-on-expiry — the shape `Command::output()` cannot
/// give us, because `wait_with_output` blocks with no way to bound it in place.
fn run_with_deadline(argv: &[&str], deadline: Duration) -> Result<Output> {
    if argv.is_empty() {
        return Err(Error::fatal("cannot exec: empty argv"));
    }
    // Its own process group, so the deadline below can kill the whole tree. MEASURED on this
    // tree: killing only the direct child leaves a grandchild holding the pipe write ends, and
    // the drain threads' `read_to_end` then blocks until that grandchild exits on its own — a
    // 200 ms deadline took 60 s. `ip` forks no grandchild, but a deadline that holds only for
    // well-behaved children is not a bound on the actor, and the actor's whole fork budget is
    // derived from one.
    let mut child = Command::new(argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| Error::fatal(format!("cannot exec {}: {e}", argv[0])))?;
    let pgid = nix::unistd::Pid::from_raw(child.id() as i32);

    // Drained on their own threads, never in the poll loop below: a child that writes enough
    // to fill a pipe buffer before exiting would otherwise block forever on a write() nobody
    // is reading, wedging this write behind it regardless of the deadline below.
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if started.elapsed() >= deadline {
                    break None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => return Err(Error::fatal(format!("cannot wait for {}: {e}", argv[0]))),
        }
    };

    match status {
        Some(status) => {
            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();
            Ok(Output {
                status: status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            })
        }
        // The child never told us anything, so no exit status can represent this: `Err`, the
        // same shape as "could not exec at all", not a scripted nonzero `Output`.
        None => {
            // The GROUP, not the child: see the spawn above.
            let _ = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL);
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            Err(Error::fatal(format!(
                "{}: timed out after {deadline:?}, killed",
                argv[0]
            )))
        }
    }
}

/// The scriptable `NeighborIo` the flush actor's tests drive. One mock covers every case the
/// actor has: what the kernel holds, a write that fails, a read that never returns, and the
/// fork counting the token bucket's whole guarantee is stated in — because each of those is
/// just a different answer to "what did this argv do?".
#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::{Arc, Mutex};

    type Answer = dyn FnMut(&[&str], usize) -> Result<Output> + Send;

    pub struct MockNeighborIo {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        answer: Box<Answer>,
    }

    impl MockNeighborIo {
        /// `answer` is handed the argv and the 1-based number of *this kind* of call so far
        /// (reads and writes counted separately), which is how a test scripts "the first write
        /// fails" without matching on text.
        pub fn new(answer: impl FnMut(&[&str], usize) -> Result<Output> + Send + 'static) -> Self {
            MockNeighborIo {
                calls: Arc::new(Mutex::new(Vec::new())),
                answer: Box::new(answer),
            }
        }

        /// The common case: every read returns `kernel`, every write succeeds.
        pub fn kernel(kernel: &str) -> Self {
            let kernel = kernel.to_string();
            Self::new(move |argv, _| {
                Ok(Output {
                    status: 0,
                    stdout: if argv.contains(&"show") {
                        kernel.clone()
                    } else {
                        String::new()
                    },
                    stderr: String::new(),
                })
            })
        }

        /// Every argv this io was asked to run, in order. Shared, so a test can read it while
        /// the actor still owns the io.
        pub fn calls(&self) -> Arc<Mutex<Vec<Vec<String>>>> {
            self.calls.clone()
        }
    }

    impl NeighborIo for MockNeighborIo {
        fn run(&mut self, argv: &[&str]) -> Result<Output> {
            let is_read = argv.contains(&"show");
            let nth = {
                let mut c = self.calls.lock().unwrap();
                c.push(argv.iter().map(|s| s.to_string()).collect());
                c.iter()
                    .filter(|p| p.iter().any(|w| w == "show") == is_read)
                    .count()
            };
            (self.answer)(argv, nth)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- T6b: `nud stale` is on every write argv, both verbs -----------------------------

    /// **T6b.** Asserting the argv rather than the effect is deliberate (plan §4 task 3a): the
    /// harm is a PERMANENT entry the victim's own ARP can never correct, which is invisible to
    /// a mock kernel and only measurable against a real one (spec §2).
    ///
    /// Regression: drop the `"nud", "stale"` pair from `write_argv`.
    #[test]
    fn write_argv_always_carries_nud_stale() {
        let addr: Ipv4Addr = "192.168.20.150".parse().unwrap();
        let mac = [0x4e, 0x48, 0xe9, 0x89, 0x2e, 0xe5];
        for verb in [WriteVerb::Add, WriteVerb::Replace] {
            let argv = write_argv(verb, addr, mac, "cfab-work-vms");
            assert!(
                argv.windows(2).any(|w| w == ["nud", "stale"]),
                "{verb:?} argv missing nud stale: {argv:?}"
            );
        }
    }

    /// The verb itself must not collapse (spec §10: six rounds re-found this defect once
    /// `add`/`replace` were merged into one code path).
    #[test]
    fn write_argv_verb_is_not_collapsed() {
        let addr: Ipv4Addr = "192.168.20.150".parse().unwrap();
        let mac = [0x4e, 0x48, 0xe9, 0x89, 0x2e, 0xe5];
        assert!(write_argv(WriteVerb::Add, addr, mac, "leg0").contains(&"add".to_string()));
        assert!(write_argv(WriteVerb::Replace, addr, mac, "leg0").contains(&"replace".to_string()));
    }

    // ---- T6c: any non-zero exit is a failure, no stderr classification --------------------

    /// **T6c.** A real child exiting non-zero with `RTNETLINK answers: File exists` on stderr
    /// (the exact text every earlier round matched to turn EEXIST into success) must come back
    /// with its real, unaltered exit status.
    ///
    /// Regression: after building `Output`, special-case
    /// `stderr.contains("RTNETLINK answers: File exists")` to force `status = 0`.
    #[test]
    fn any_nonzero_exit_is_a_failure_no_stderr_classification() {
        let mut io = ForkNeighborIo::default();
        let out = io
            .run(&[
                "sh",
                "-c",
                "echo 'RTNETLINK answers: File exists' 1>&2; exit 2",
            ])
            .expect("the child ran and exited; only a spawn/timeout failure is Err");
        assert_eq!(out.status, 2);
        assert!(!out.ok());
        assert!(out.stderr.contains("File exists"));
    }

    /// A clean exit is still success — the companion case, so `ok()` is proven both ways.
    #[test]
    fn a_zero_exit_is_success() {
        let mut io = ForkNeighborIo::default();
        let out = io.run(&["sh", "-c", "exit 0"]).unwrap();
        assert!(out.ok());
    }

    /// **T-DEADLINE, grandchild half.** `sh -c 'sleep 60'` — no `exec`, so `sh` FORKS and the
    /// grandchild inherits the pipe write ends. Killing only `sh` leaves those ends open and the
    /// drain threads' `read_to_end` blocks until the grandchild exits on its own: MEASURED at
    /// 60.0 s against a 200 ms deadline before this was fixed. The child is spawned into its own
    /// process group and the whole group is killed, so the pipes close and the deadline holds.
    ///
    /// `ip` forks no grandchild, so this is not a live path today — but `WRITE_DEADLINE` is what
    /// bounds every fork the actor makes, and the fork budget `MIN_LEASE` is derived from
    /// assumes that bound is real rather than conditional on the callee's behavior.
    #[test]
    fn write_deadline_kills_a_grandchild_holding_the_pipes() {
        let deadline = Duration::from_millis(200);
        let mut io = ForkNeighborIo::with_deadline(deadline);
        let started = Instant::now();
        let r = io.run(&["sh", "-c", "sleep 60"]);
        let elapsed = started.elapsed();
        assert!(r.is_err(), "a killed child is Err, got {r:?}");
        assert!(
            elapsed < deadline * 10,
            "the deadline must bound the CALL, not just signal the direct child: {elapsed:?}"
        );
    }

    // ---- T-DEADLINE (write half): a child that never returns is killed ---------------------

    /// **T-DEADLINE, write half.** `sh -c 'exec sleep 60'` never exits on its own; a
    /// `Command::output()` with no deadline would block for the full 60 s (or forever, on a
    /// truly wedged `ip`). The real deadline here is shrunk so the suite stays fast — production
    /// always runs at `WRITE_DEADLINE` = 2 s.
    ///
    /// Regression: replace `run_with_deadline`'s poll loop with a bare
    /// `child.wait_with_output()` and watch this test take 60 s and then fail (or hang the
    /// suite outright on a command that never exits at all).
    #[test]
    fn write_deadline_kills_a_child_that_never_returns() {
        let mut io = ForkNeighborIo::with_deadline(Duration::from_millis(100));
        let started = Instant::now();
        let result = io.run(&["sh", "-c", "exec sleep 60"]);
        let elapsed = started.elapsed();
        assert!(result.is_err(), "expected a timeout Err, got {result:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "deadline did not bound the wait: {elapsed:?}"
        );
    }

    /// The deadline must not fire early on a fast, well-behaved child.
    #[test]
    fn write_deadline_does_not_fire_on_a_fast_child() {
        let mut io = ForkNeighborIo::with_deadline(Duration::from_millis(500));
        let out = io.run(&["sh", "-c", "exit 0"]).unwrap();
        assert!(out.ok());
    }

    // ---- exec failure is still Err, distinct from a timeout --------------------------------

    #[test]
    fn a_missing_binary_is_err_not_a_timeout() {
        let mut io = ForkNeighborIo::default();
        let result = io.run(&["cfab-writer-test-binary-that-does-not-exist"]);
        assert!(result.is_err());
    }
}
