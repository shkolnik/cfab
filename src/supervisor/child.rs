//! One supervised child process: the state machine, pure.
//!
//! No I/O, no tokio, no `Sys` — every transition is decided from arguments, so the machine is
//! provable without a process. The spawn side lives in the same file but stays out of here.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Fixed restart delay. No exponential growth, no cap, no give-up: a crash loop must stay
/// visible in `components` and in `status` rather than being smoothed away (spec §4).
pub const BACKOFF: Duration = Duration::from_secs(2);

/// Ring size and per-line cap of each child's captured output (spec §3).
const LOG_LINES: usize = 200;
const LOG_LINE_MAX: usize = 2048;

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Starting,
    Running,
    Restarting,
    Stopped,
}

impl State {
    /// The one spelling of each state, as `components` and `status` print it.
    pub fn as_str(self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Running => "running",
            State::Restarting => "restarting",
            State::Stopped => "stopped",
        }
    }
}

/// How a child last died: `exit <code>`, `signal <NAME>` or `unknown`, plus the elapsed
/// seconds since it happened (monotonic, never a wall-clock timestamp). This is the
/// serialized shape only — a `Child` stores the cause and the instant, and `s_ago` is
/// measured when the document is built, never frozen at the moment of death.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExitCause {
    pub cause: String,
    pub s_ago: u64,
}

pub struct Child {
    /// `engine` | `shape-daemon` | `conf-sync`.
    pub name: &'static str,
    pub state: State,
    /// The supervisor's intent. `Stopped` is the only state with `want == false`.
    pub want: bool,
    /// Monotonic since supervisor start; never reset — a counter that resets hides the crash
    /// loop it exists to reveal.
    pub restarts: u64,
    /// Why this child is not wanted here, e.g. "not clustered".
    pub why_stopped: Option<String>,
    pid: Option<u32>,
    started_at: Option<Instant>,
    last_exit: Option<String>,
    exited_at: Option<Instant>,
    log: VecDeque<String>,
}

impl Child {
    pub fn new(name: &'static str) -> Self {
        Child {
            name,
            state: State::Stopped,
            want: false,
            restarts: 0,
            why_stopped: None,
            pid: None,
            started_at: None,
            last_exit: None,
            exited_at: None,
            log: VecDeque::with_capacity(LOG_LINES),
        }
    }

    /// A child this member does not run: listed as `stopped` with the reason, never omitted —
    /// an absent row reads as a bug, a `stopped` row reads as a fact (spec §4).
    pub fn stopped(name: &'static str, why: &str) -> Self {
        let mut c = Child::new(name);
        c.why_stopped = Some(why.to_string());
        c
    }

    /// The process died of `cause` (`exit <code>` / `signal <NAME>` / `unknown`). Records it
    /// against `now` and returns the instant at which it may be respawned — `None` when it is not wanted, which is the only case that is not a fault.
    /// ANY exit restarts a wanted child, clean or not: a daemon that exits 0 while the
    /// supervisor still wants it running is a fault, not a success (spec §4).
    pub fn exited(&mut self, cause: String, now: Instant) -> Option<Instant> {
        self.pid = None;
        self.started_at = None;
        self.last_exit = Some(cause);
        self.exited_at = Some(now);
        if self.want {
            self.state = State::Restarting;
            self.restarts += 1;
            Some(now + BACKOFF)
        } else {
            self.state = State::Stopped;
            None
        }
    }

    /// A new process is running under `pid`. `needs_readiness` is the engine's socket poll:
    /// it stays `starting` until `became_ready`. shape-daemon and conf-sync have no readiness
    /// protocol and are `running` at once.
    pub fn spawned(&mut self, pid: u32, now: Instant, needs_readiness: bool) {
        self.pid = Some(pid);
        self.started_at = Some(now);
        self.want = true;
        self.why_stopped = None;
        self.state = if needs_readiness {
            State::Starting
        } else {
            State::Running
        };
    }

    /// The engine's socket answered `"ready": true`. Ignored unless we are still `starting`:
    /// a late answer must not resurrect a child that has since died.
    pub fn became_ready(&mut self) {
        if self.state == State::Starting {
            self.state = State::Running;
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// How this child last died, aged at `now`. The age is measured here rather than stored,
    /// so a crash from two hours ago never keeps reporting the second it happened.
    pub fn last_exit(&self, now: Instant) -> Option<ExitCause> {
        let (cause, at) = (self.last_exit.as_ref()?, self.exited_at?);
        Some(ExitCause {
            cause: cause.clone(),
            s_ago: now.saturating_duration_since(at).as_secs(),
        })
    }

    /// Seconds since this process started, or `None` when no process is running.
    pub fn uptime_s(&self, now: Instant) -> Option<u64> {
        self.started_at
            .map(|t| now.saturating_duration_since(t).as_secs())
    }

    /// Append one captured output line, truncated to `LOG_LINE_MAX` bytes on a char boundary.
    pub fn push_log(&mut self, line: &str) {
        let mut end = line.len().min(LOG_LINE_MAX);
        while end > 0 && !line.is_char_boundary(end) {
            end -= 1;
        }
        if self.log.len() == LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(line[..end].to_string());
    }

    /// The last `n` captured lines, oldest first.
    pub fn log_tail(&self, n: usize) -> Vec<String> {
        let skip = self.log.len().saturating_sub(n);
        self.log.iter().skip(skip).cloned().collect()
    }
}

/// A live child process and the two pipes its output arrives on.
pub struct Spawned {
    pub pid: u32,
    pub child: tokio::process::Child,
    pub stdout: tokio::process::ChildStdout,
    pub stderr: tokio::process::ChildStderr,
}

/// How the supervisor starts a child. Task 6 supervises against this trait so the whole
/// lifecycle is testable without real processes; `RealSpawner` is the only implementation
/// that forks.
pub trait Spawner {
    fn spawn(
        &mut self,
        name: &'static str,
        argv: &[String],
        supervisor_pid: u32,
    ) -> std::io::Result<Spawned>;
}

pub struct RealSpawner;

impl Spawner for RealSpawner {
    fn spawn(
        &mut self,
        name: &'static str,
        argv: &[String],
        supervisor_pid: u32,
    ) -> std::io::Result<Spawned> {
        spawn(name, argv, supervisor_pid)
    }
}

/// Start one child: both streams piped, `CFAB_SUPERVISOR_PID` set so the child arms its own
/// parent-death signal, and the service manager's notification variables removed so a child
/// that called `sd_notify` cannot talk to OUR service manager (spec §3).
///
/// **Every call site must be the main thread inside the root `block_on` future** — never a
/// `tokio::spawn`ed task, never `spawn_blocking`. `PR_SET_PDEATHSIG` fires when the parent
/// *thread* that forked terminates, not when the parent process does (prctl(2): "the
/// parent-death signal is sent upon subsequent termination of the parent thread"), and
/// tokio retires idle blocking-pool workers — so a child forked off a blocking worker is
/// SIGTERMed for no reason when that worker retires. `block_in_place` on the root future is
/// fine: it keeps running on the same thread. This is an invariant, not a preference (spec
/// §7); `spawning_a_child_from_spawn_blocking_kills_it_when_that_thread_retires` reproduces
/// the hazard.
pub fn spawn(name: &'static str, argv: &[String], supervisor_pid: u32) -> std::io::Result<Spawned> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| std::io::Error::other(format!("{name}: empty argv")))?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("CFAB_SUPERVISOR_PID", supervisor_pid.to_string())
        .env_remove("NOTIFY_SOCKET")
        .env_remove("WATCHDOG_USEC")
        .env_remove("WATCHDOG_PID")
        .kill_on_drop(true)
        .spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| std::io::Error::other(format!("{name}: exited before it had a pid")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other(format!("{name}: no stdout pipe")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other(format!("{name}: no stderr pipe")))?;
    Ok(Spawned {
        pid,
        child,
        stdout,
        stderr,
    })
}

/// Pump one child stream until EOF: every line is re-emitted on our own stderr prefixed
/// `<name>: ` — one journal stream, children tagged, and the same text in a container with
/// no journal — and handed to `sink`, which appends it to that child's ring buffer.
pub async fn tag_lines<R, F>(name: &str, reader: R, mut sink: F)
where
    R: tokio::io::AsyncRead + Unpin,
    F: FnMut(&str),
{
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        eprintln!("{name}: {line}");
        sink(&line);
    }
}

/// Arm this process's parent-death signal, but **only when supervised** (spec §7).
///
/// `None` (no `CFAB_SUPERVISOR_PID` in the environment) does nothing at all — no prctl, no
/// `getppid`: a standalone `cfab engine` must survive its launcher exiting, and
/// `scripts/engine-oracle.sh` runs it under `setsid -f`, whose intermediate parent exits
/// immediately. `Some(p)` arms SIGTERM first and only then compares `getppid()` with `p`, so
/// a supervisor that dies inside the fork window cannot slip between the check and the arm;
/// the mismatch is this child's own exit 5, never the supervisor's 4.
pub fn arm_parent_death(expected_ppid: Option<u32>) -> crate::error::Result<()> {
    let Some(expected) = expected_ppid else {
        return Ok(());
    };
    nix::sys::prctl::set_pdeathsig(Some(nix::sys::signal::Signal::SIGTERM))
        .map_err(|e| crate::error::Error::fatal(format!("cannot arm parent-death signal: {e}")))?;
    let actual = nix::unistd::getppid().as_raw() as u32;
    if actual != expected {
        return Err(crate::error::Error::fatal(format!(
            "the supervisor vanished at spawn (CFAB_SUPERVISOR_PID={expected}, parent is now {actual})"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn any_exit_restarts_while_wanted_and_the_counter_never_resets() {
        let t0 = Instant::now();
        let mut c = Child::new("engine");
        c.spawned(10, t0, true);
        c.became_ready();
        assert_eq!(c.state, State::Running);
        // A CLEAN exit is still a fault while the supervisor wants it running.
        let at = c.exited("exit 0".into(), t0).unwrap();
        assert_eq!(c.state, State::Restarting);
        assert_eq!(at.duration_since(t0), BACKOFF);
        assert_eq!(c.restarts, 1);
        for i in 2..=6 {
            c.spawned(10 + i as u32, t0, true);
            c.exited("signal SIGKILL".into(), t0);
            assert_eq!(c.restarts, i, "the restart counter must never reset");
        }
    }

    /// The document says "how long ago", not "how long ago it was when it happened": a crash
    /// two hours old must never keep reporting the age it had the moment it was recorded.
    #[test]
    fn the_last_exit_age_is_measured_when_it_is_read() {
        let t0 = Instant::now();
        let mut c = Child::new("engine");
        c.spawned(10, t0, false);
        c.exited("signal SIGKILL".into(), t0);
        let e = c
            .last_exit(t0 + std::time::Duration::from_secs(90))
            .unwrap();
        assert_eq!(e.cause, "signal SIGKILL");
        assert_eq!(e.s_ago, 90);
    }

    #[test]
    fn an_unwanted_child_is_not_restarted() {
        let t0 = Instant::now();
        let mut c = Child::new("shape-daemon");
        c.spawned(11, t0, false);
        assert_eq!(
            c.state,
            State::Running,
            "no readiness protocol: running on spawn"
        );
        c.want = false;
        assert!(c.exited("exit 0".into(), t0).is_none());
        assert_eq!(c.state, State::Stopped);
        assert_eq!(c.restarts, 0, "a deliberate stop is not a restart");
    }

    #[test]
    fn an_engine_that_never_becomes_ready_stays_starting() {
        let mut c = Child::new("engine");
        c.spawned(12, Instant::now(), true);
        assert_eq!(c.state, State::Starting);
    }

    #[test]
    fn the_log_ring_keeps_the_last_200_lines_and_truncates_each() {
        let mut c = Child::new("engine");
        for i in 0..250 {
            c.push_log(&format!("line {i}"));
        }
        c.push_log(&"x".repeat(5000));
        let tail = c.log_tail(500);
        assert_eq!(tail.len(), 200);
        assert_eq!(tail[0], "line 51");
        assert_eq!(tail[199].len(), 2048);
    }
}

#[cfg(test)]
mod spawn_tests {
    use super::*;

    #[test]
    fn a_vanished_supervisor_is_its_own_exit_code() {
        // getppid() != expected → Err; main.rs turns it into exit 5, never 4 (the lock's code).
        assert!(arm_parent_death(Some(u32::MAX)).is_err());
        // Disarm: the call above armed PDEATHSIG on this test process too, and the test
        // binary must not be SIGTERMed if cargo's forking thread ever retires.
        nix::sys::prctl::set_pdeathsig(None).unwrap();
    }

    #[test]
    fn no_supervisor_in_the_environment_arms_nothing() {
        assert!(
            arm_parent_death(None).is_ok(),
            "no env var ⇒ no prctl, no getppid check"
        );
    }

    #[tokio::test]
    async fn child_output_is_tagged_and_ringed() {
        let Spawned {
            pid,
            mut child,
            stdout,
            stderr,
        } = spawn(
            "engine",
            &["sh".into(), "-c".into(), "echo hi; echo bad >&2".into()],
            std::process::id(),
        )
        .unwrap();
        assert!(pid > 0);
        let ring = std::sync::Arc::new(std::sync::Mutex::new(Child::new("engine")));
        let (r1, r2) = (ring.clone(), ring.clone());
        let a = tokio::spawn(async move {
            tag_lines("engine", stdout, move |l| r1.lock().unwrap().push_log(l)).await
        });
        let b = tokio::spawn(async move {
            tag_lines("engine", stderr, move |l| r2.lock().unwrap().push_log(l)).await
        });
        a.await.unwrap();
        b.await.unwrap();
        let _ = child.wait().await;
        let tail = ring.lock().unwrap().log_tail(10);
        assert!(
            tail.contains(&"hi".to_string()),
            "stdout line missing: {tail:?}"
        );
        assert!(
            tail.contains(&"bad".to_string()),
            "stderr line missing: {tail:?}"
        );
    }
}
