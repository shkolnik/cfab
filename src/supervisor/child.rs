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
/// seconds since it happened (monotonic, never a wall-clock timestamp).
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
    last_exit: Option<ExitCause>,
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

    /// The process died. Records the cause and returns the instant at which it may be
    /// respawned — `None` when it is not wanted, which is the only case that is not a fault.
    /// ANY exit restarts a wanted child, clean or not: a daemon that exits 0 while the
    /// supervisor still wants it running is a fault, not a success (spec §4).
    pub fn exited(&mut self, cause: ExitCause, now: Instant) -> Option<Instant> {
        self.pid = None;
        self.started_at = None;
        self.last_exit = Some(cause);
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

    pub fn last_exit(&self) -> Option<&ExitCause> {
        self.last_exit.as_ref()
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
        let at = c
            .exited(
                ExitCause {
                    cause: "exit 0".into(),
                    s_ago: 0,
                },
                t0,
            )
            .unwrap();
        assert_eq!(c.state, State::Restarting);
        assert_eq!(at.duration_since(t0), BACKOFF);
        assert_eq!(c.restarts, 1);
        for i in 2..=6 {
            c.spawned(10 + i as u32, t0, true);
            c.exited(
                ExitCause {
                    cause: "signal SIGKILL".into(),
                    s_ago: 0,
                },
                t0,
            );
            assert_eq!(c.restarts, i, "the restart counter must never reset");
        }
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
        assert!(
            c.exited(
                ExitCause {
                    cause: "exit 0".into(),
                    s_ago: 0
                },
                t0
            )
            .is_none()
        );
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
