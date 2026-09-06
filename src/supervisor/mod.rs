//! `cfab run`: one supervising process that applies the fabric and then keeps the fabric's
//! child processes (`cfab engine`, `cfab shape-daemon`, `cfab conf-sync`) running.
//!
//! The lifecycle (spec §6): take the instance lock, apply the fabric, spawn the engine and wait
//! for it to become ready, read the engine back, spawn the shape daemon and conf-sync where
//! their predicates hold, then supervise — restart any child 2 s after it exits while it is
//! wanted, reload on SIGHUP or a `reapply` request, and on SIGTERM/SIGINT tear the fabric
//! down and exit 0.
//!
//! **A reload re-reads the declaration** (James's ruling, 2026-09-06). SIGHUP and the socket
//! `reapply` are one path: read `--config` through `Sys`, derive the `Fabric` it now describes
//! and compare it with the running one (`classify_reload`). The same fabric re-applies in place
//! as before (a repair); a changed, valid one runs the stop sequence and exits `EXIT_RELOAD` so
//! systemd starts a fresh supervisor on it — `apply::run` creates and repairs but never prunes
//! what a declaration stopped declaring, so an in-place switch would leave the old fabric's
//! netdevs, rules and tables resident; anything else (unreadable, invalid, or no longer naming
//! this member) is refused, leaving the running fabric untouched and the reason in
//! `last_apply_error`, where `cfab status` prints it.
//!
//! **The spawn-site invariant (spec §7) is structural, not a preference.** Every
//! `Command::spawn` — the initial spawns, every backoff respawn, and the re-apply's restarts —
//! is executed by the root `block_on` future on the main thread. `PR_SET_PDEATHSIG` fires when
//! the parent *thread* that forked terminates, and tokio retires idle blocking-pool workers, so
//! a child forked off a `spawn_blocking` worker would be SIGTERMed for no reason when that
//! worker retires. Only work that spawns nothing is moved off the main thread with
//! `tokio::spawn`: the per-child stream readers, `Child::wait`, the socket server, the signal
//! forwarders and the watchdog feed. The guard test
//! `every_spawn_happens_on_the_supervisor_main_thread` proves it.

pub mod child;
pub mod lock;
pub mod report;
pub mod sock;

use std::os::unix::process::ExitStatusExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::commands::{apply, engine_ctl, fwd_watchdog, teardown};
use crate::derive::View;
use crate::model::{Fabric, MemberKind};
use crate::sys::{RealSys, Sys};

use child::{BACKOFF, Child, RealSpawner, Spawned, Spawner, tag_lines};
use report::{Component, Components, SupervisorInfo, WatchdogInfo};

/// Clean stop: SIGTERM/SIGINT, teardown completed.
pub const EXIT_OK: u8 = 0;
/// An internal error the supervisor cannot classify.
pub const EXIT_INTERNAL: u8 = 1;
/// The initial apply was refused (spec §10). Terminal: systemd's `RestartPreventExitStatus`
/// carries it, and no child was ever started.
pub const EXIT_APPLY_REFUSED: u8 = 3;
/// Another supervisor already holds `<run_dir>/cfab.lock` (spec §14).
pub const EXIT_LOCK_HELD: u8 = 4;
/// The declaration on disk changed under a reload: the fabric was torn down and this process
/// exits so systemd starts a fresh one on the new file. NOT 5 — that status already means
/// "a supervised child could not arm `PR_SET_PDEATHSIG`" in this same binary, and one number
/// must not carry two meanings. The unit turns it into a restart with
/// `RestartForceExitStatus=6` and `SuccessExitStatus=6`.
pub const EXIT_RELOAD: u8 = 6;

/// The engine's readiness poll — the same values `engine_ctl` uses privately (spec §4/§8): the
/// state socket answers `"ready": true` within `START_WAIT_MS`, retried every `POLL_MS`.
const START_WAIT_MS: u64 = 30_000;
const POLL_MS: u64 = 500;

/// Each child gets this long to exit after its stop SIGTERM before the supervisor SIGKILLs it
/// (spec §13 step 4). `TimeoutStopSec=60` in the unit carries the worst case with margin.
const CHILD_STOP_GRACE: Duration = Duration::from_secs(10);

/// How the supervisor pokes the systemd watchdog. One injectable seam for EVERY feed — the
/// select-loop `feed` arm and the in-reapply feeds — so a test can observe them; production
/// sends `WATCHDOG=1`. It carries no data because the decision of *whether* to feed is made by
/// `should_feed` at each call site, never inside the closure.
type FeedFn = Arc<dyn Fn() + Send + Sync>;

/// A command reaching the main loop: a `reapply` request from the socket (with a reply
/// channel), a SIGHUP re-apply, or a SIGTERM/SIGINT stop. Real Unix signals are forwarded onto
/// this channel by `run`, and the socket server posts `Reapply`, so the loop has exactly one
/// place it learns what to do next — which is also what the tests drive.
pub(crate) enum Cmd {
    /// A `reapply` over `cfab.sock`: the reply carries the apply result back to the (blocked)
    /// socket connection thread, so `reapply` answers only after the re-apply finishes (§9).
    Reapply(std::sync::mpsc::Sender<crate::error::Result<()>>),
    /// SIGHUP: reload, no reply.
    Hangup,
    /// SIGTERM/SIGINT: begin the stop sequence and exit 0.
    Terminate,
}

/// A child's exit, reported by its `wait` task to the main loop.
struct ChildExit {
    name: &'static str,
    cause: String,
}

/// Everything the socket server and the `status` line read, and the main loop writes. Held
/// behind an `Arc<Mutex<_>>`: the main loop locks it briefly to mutate (never across an
/// `await`), the socket server and stream readers lock it briefly to snapshot or append.
pub(crate) struct Shared {
    pid: u32,
    started_at: Instant,
    applying: bool,
    apply_started_at: Option<Instant>,
    applies: u64,
    last_apply_error: Option<String>,
    /// Fixed order: engine, shape-daemon, conf-sync. Every one is always present — a child this
    /// member does not run is `stopped` with a reason, never omitted (spec §4).
    children: Vec<Child>,
    wd_result: String,
    wd_detail: Option<String>,
    wd_last_tick: Option<Instant>,
}

impl Shared {
    fn new(pid: u32) -> Self {
        Shared {
            pid,
            started_at: Instant::now(),
            applying: false,
            apply_started_at: None,
            applies: 0,
            last_apply_error: None,
            children: vec![
                Child::new("engine"),
                Child::new("shape-daemon"),
                Child::new("conf-sync"),
            ],
            wd_result: "ok".to_string(),
            wd_detail: None,
            wd_last_tick: None,
        }
    }

    fn child(&self, name: &str) -> &Child {
        self.children
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no such child: {name}"))
    }

    fn child_mut(&mut self, name: &str) -> &mut Child {
        self.children
            .iter_mut()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no such child: {name}"))
    }

    /// Mark a child this member does not run: `stopped`, `want == false`, with the reason
    /// (spec §4). Never spawned, never omitted from the document.
    fn mark_stopped(&mut self, name: &str, why: &str) {
        let c = self.child_mut(name);
        c.state = child::State::Stopped;
        c.want = false;
        c.why_stopped = Some(why.to_string());
    }

    /// The `components` document (spec §9). Every duration is aged at `now`, never frozen.
    fn components(&self, now: Instant) -> Components {
        Components {
            supervisor: SupervisorInfo {
                pid: self.pid,
                uptime_s: now.saturating_duration_since(self.started_at).as_secs(),
                applying: self.applying,
                applies: self.applies,
                last_apply_error: self.last_apply_error.clone(),
            },
            components: self
                .children
                .iter()
                .map(|c| Component {
                    name: c.name.to_string(),
                    state: c.state,
                    pid: c.pid(),
                    uptime_s: c.uptime_s(now),
                    restarts: c.restarts,
                    last_exit: c.last_exit(now),
                    why: c.why_stopped.clone(),
                })
                .collect(),
            watchdog: WatchdogInfo {
                last_tick_s_ago: self
                    .wd_last_tick
                    .map(|t| now.saturating_duration_since(t).as_secs()),
                result: self.wd_result.clone(),
                detail: self.wd_detail.clone(),
            },
        }
    }

    fn log_tail(&self, name: &str, n: usize) -> Option<Vec<String>> {
        self.children
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.log_tail(n))
    }
}

/// What the `cfab.sock` server reads and how a `reapply` reaches the main loop. The server runs
/// on a spawned task and touches no `Sys` — `reapply` is a synchronous round trip to the main
/// loop (which owns `Sys` and does every apply), so the socket connection blocks until the
/// re-apply finishes, exactly the `reapply` contract (§9).
struct SockSource {
    shared: Arc<Mutex<Shared>>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
}

impl sock::ComponentsSource for SockSource {
    fn snapshot(&self) -> Components {
        self.shared.lock().unwrap().components(Instant::now())
    }
    fn log_tail(&self, name: &str, n: usize) -> Option<Vec<String>> {
        self.shared.lock().unwrap().log_tail(name, n)
    }
    fn reapply(&self) -> crate::error::Result<()> {
        // `UnboundedSender::send` is a synchronous, non-blocking call safe inside the async
        // connection task; the reply is a std channel we then block this one connection on.
        let (tx, rx) = std::sync::mpsc::channel();
        self.cmd_tx
            .send(Cmd::Reapply(tx))
            .map_err(|_| crate::error::Error::fatal("the supervisor is shutting down"))?;
        // The whole re-apply (up to ~35 s) runs before this recv returns; `block_in_place` so
        // this connection-handler task hands its worker back to the runtime instead of pinning
        // it for the duration (same starvation class as the apply itself, spec §3). The
        // synchronous `reapply` contract (§9) is unchanged — we still return only when done.
        tokio::task::block_in_place(|| rx.recv())
            .map_err(|_| crate::error::Error::fatal("the supervisor dropped the reapply request"))?
    }
}

/// Test seams: production passes `Hooks::production()`; the unit tests inject a shared-state
/// handle to observe children, a readiness signal to sequence a driver, and turn the
/// forwarding-watchdog tick and the real `cfab.sock` server off so a test is deterministic.
pub(crate) struct Hooks {
    pub on_ready: Option<tokio::sync::oneshot::Sender<()>>,
    pub run_watchdog: bool,
    pub serve_socket: bool,
    pub shared: Option<Arc<Mutex<Shared>>>,
    /// A test recorder the stop sequence appends its signal/wait/kill markers to, in order, so
    /// a test can assert the stop ordering (spec §13) against a single merged trace shared with
    /// a recording `Sys`. `None` in production — the stop path records nothing.
    pub trace: Option<Arc<Mutex<Vec<String>>>>,
    /// The per-child SIGTERM→SIGKILL grace in the stop sequence. Production is
    /// `CHILD_STOP_GRACE` (10 s); a test shrinks it so the SIGKILL path is exercised without a
    /// real 10 s wait.
    pub stop_grace: Duration,
    /// The watchdog feed seam (see `FeedFn`). Production sends `WATCHDOG=1`; a test installs a
    /// recorder so the in-reapply feeds are observable.
    pub feed: FeedFn,
}

impl Hooks {
    fn production() -> Self {
        Hooks {
            on_ready: None,
            run_watchdog: true,
            serve_socket: true,
            shared: None,
            trace: None,
            stop_grace: CHILD_STOP_GRACE,
            feed: Arc::new(|| {
                let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
            }),
        }
    }
}

/// Feed the watchdog from inside a reapply, at a safe point, iff the apply is still within
/// `should_feed`'s `Applying` tolerance. The select! loop cannot poll its own `feed` arm while
/// `do_reapply` runs — `do_reapply` holds `&mut sys` and runs the handler to completion — so
/// without this the watchdog starves for the whole reapply (apply + up to two ~10 s child
/// restarts), long enough to blow `WatchdogSec=30` and have systemd kill a healthy supervisor.
/// Past the bound we STOP feeding, so a reapply that has itself hung beyond ~63 s still trips
/// `WatchdogSec` — the A3 gap survives (spec §8).
fn feed_during_reapply(feed: &FeedFn, apply_started: Instant) {
    let since_s = apply_started.elapsed().as_secs();
    // The `Applying` arm of `should_feed` ignores the engine state and the read, so the two
    // placeholders below never affect the decision — the one source of truth for the bound.
    if should_feed(
        ApplyState::Applying { since_s },
        child::State::Starting,
        StateRead::Failed,
    ) {
        feed();
    }
}

/// Append one stop-sequence marker to the test trace, if one is installed (spec §13). A no-op
/// in production, where `trace` is `None`.
fn trace_mark(trace: &Option<Arc<Mutex<Vec<String>>>>, s: String) {
    if let Some(t) = trace {
        t.lock().unwrap().push(s);
    }
}

/// The public entry point (`cfab run`): build the multi-thread runtime and drive the whole
/// lifecycle on its `block_on` future — the main thread every child is forked from.
pub fn run(_fabric: &Fabric, view: &View, exe: &str, config: &str) -> crate::error::Result<u8> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            crate::error::Error::fatal(format!("supervisor: cannot build runtime: {e}"))
        })?;
    let code = rt.block_on(async {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Cmd>();
        spawn_signal_forwarders(cmd_tx.clone());
        let mut sys = RealSys;
        let mut spawner = RealSpawner;
        run_with(
            &mut sys,
            view,
            &mut spawner,
            exe,
            config,
            "/etc/pve",
            cmd_tx,
            cmd_rx,
            Hooks::production(),
        )
        .await
    });
    Ok(code)
}

/// Forward SIGHUP → `Hangup`, SIGTERM/SIGINT → `Terminate` onto the command channel. Each
/// listener is a task that only sends on a channel — it spawns nothing, so it never forks a
/// child off a worker thread.
fn spawn_signal_forwarders(tx: mpsc::UnboundedSender<Cmd>) {
    use tokio::signal::unix::{SignalKind, signal};
    let install = |kind: SignalKind, make: fn() -> Cmd| {
        if let Ok(mut s) = signal(kind) {
            let tx = tx.clone();
            tokio::spawn(async move {
                while s.recv().await.is_some() {
                    if tx.send(make()).is_err() {
                        break;
                    }
                }
            });
        }
    };
    install(SignalKind::hangup(), || Cmd::Hangup);
    install(SignalKind::terminate(), || Cmd::Terminate);
    install(SignalKind::interrupt(), || Cmd::Terminate);
}

/// The lifecycle core, testable against `MockSys` and a `Spawner` fake. Returns the process
/// exit code — every outcome (clean stop, apply refused, lock held) is a code, never an `Err`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with(
    sys: &mut dyn Sys,
    view: &View<'_>,
    spawner: &mut dyn Spawner,
    exe: &str,
    config: &str,
    pmxcfs_root: &str,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    hooks: Hooks,
) -> u8 {
    let pid = std::process::id();
    let run_dir = view.fabric.run_dir.clone();
    let sock_path = format!("{run_dir}/{}", crate::engine::SOCK_NAME);
    // Captured before `hooks` is partially moved below.
    let trace = hooks.trace.clone();
    let stop_grace = hooks.stop_grace;
    let feed_fn = hooks.feed.clone();

    // 1. The instance lock, before anything (spec §14). The run dir must exist to hold a lock
    // file in it; `apply` creates it too, but the lock is taken first and no stub stands in.
    if let Err(e) = std::fs::create_dir_all(&run_dir) {
        eprintln!("cfab run: cannot create run dir {run_dir}: {e}");
        return EXIT_INTERNAL;
    }
    let lock_path = std::path::PathBuf::from(&run_dir).join("cfab.lock");
    let _lock = match lock::hold(&lock_path) {
        Ok(g) => g,
        Err(held) => {
            eprintln!(
                "REFUSING: another cfab supervisor holds {} (pid {})",
                lock_path.display(),
                held.pid.map_or("unknown".to_string(), |p| p.to_string())
            );
            return EXIT_LOCK_HELD;
        }
    };

    // 1b. The operator socket, before the apply: a supervisor nobody can talk to must not start
    // a fabric. A path left by a SIGKILLed predecessor is reclaimed (nothing answers on it); a
    // live answer is another supervisor — the same refusal as the lock, by name.
    let cfab_sock = std::path::PathBuf::from(&run_dir).join("cfab.sock");
    let sock_listener = if hooks.serve_socket {
        if crate::sock_frame::answers(&cfab_sock, "components") {
            eprintln!(
                "REFUSING: another cfab supervisor answers on {}",
                cfab_sock.display()
            );
            return EXIT_LOCK_HELD;
        }
        match sock::bind(&cfab_sock) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("cfab run: {e}");
                return EXIT_INTERNAL;
            }
        }
    } else {
        None
    };

    let shared = hooks
        .shared
        .unwrap_or_else(|| Arc::new(Mutex::new(Shared::new(pid))));
    let opts = apply::ApplyOpts {
        pmxcfs_root: pmxcfs_root.to_string(),
    };

    // 2. The initial apply. A refusal is terminal (§10) and has started no child — the whole
    // point of exit 3.
    {
        let mut st = shared.lock().unwrap();
        st.applying = true;
        st.apply_started_at = Some(Instant::now());
    }
    // `block_in_place`: the apply is synchronous `&mut Sys` code that can take ~35 s
    // (`START_WAIT_MS` + `SETTLE_MS`), and it must not pin the runtime thread it runs on — on a
    // single-vCPU host (this project's target) the watchdog feed, the `cfab.sock` accept loop and
    // signal handling all live on that one thread and would stall for the whole apply (spec §3).
    match tokio::task::block_in_place(|| apply::run(sys, view, &opts)) {
        Ok(warnings) => {
            for w in &warnings {
                println!("{w}");
            }
            let mut st = shared.lock().unwrap();
            st.applying = false;
            st.applies += 1;
        }
        Err(e) => {
            eprintln!("{e}");
            return EXIT_APPLY_REFUSED;
        }
    }

    let (exit_tx, mut exit_rx) = mpsc::unbounded_channel::<ChildExit>();
    let mut pending: Vec<(&'static str, Instant)> = Vec::new();

    // 3. The engine, ready and read back. Sweep a previous engine's private-proto routes first
    // (a SIGKILLed supervisor can leave them behind), then spawn.
    let _ = engine_ctl::sweep_routes(sys);
    launch(
        "engine",
        engine_ctl_argv(exe, config, &view.member.name, "engine"),
        pid,
        true,
        spawner,
        &shared,
        &exit_tx,
        &mut pending,
    );
    // `block_in_place` for the same reason as the apply: `wait_ready` blocks up to `START_WAIT_MS`
    // polling the engine socket, and must not pin the runtime thread (spec §3). It precedes
    // `READY=1`, so the stakes are lower than the re-apply case, but the root cause is identical.
    if let Some(doc) = tokio::task::block_in_place(|| wait_ready(sys, &sock_path)) {
        shared.lock().unwrap().child_mut("engine").became_ready();
        if let Err(e) = engine_ctl::readback(view, &doc) {
            // Readback failure is fatal to the *initial* apply (§6/§10): stop the engine we
            // started and refuse. The successful apply's netdevs/sysctls are deliberately LEFT
            // in place (as legacy `up` did — the operator runs `cfab down` after a failed
            // bringup); this is not an oversight. A re-apply's readback would not refuse (§6).
            eprintln!("{e}");
            if let Some(p) = shared.lock().unwrap().child("engine").pid() {
                signal_pid(p, nix::sys::signal::Signal::SIGTERM);
            }
            return EXIT_APPLY_REFUSED;
        }
        match engine_ctl::settled_down_ifs(sys, view, &doc) {
            Ok(down) => {
                let d = apply::describe_down(view, &down);
                if !d.is_empty() {
                    eprintln!(
                        "cfab: warn: ospf interfaces still down after {}s: {} — the fabric is up \
                         on the rest; cfab status grades this degraded",
                        engine_ctl::SETTLE_MS / 1000,
                        d.join(", ")
                    );
                }
            }
            Err(e) => eprintln!("cfab: warn: {e}"),
        }
    } else {
        eprintln!(
            "cfab: engine did not become ready within {}s — it is supervised and will keep \
             restarting; cfab status is the convergence wait",
            START_WAIT_MS / 1000
        );
    }

    // 4. The shape daemon (host members only) and conf-sync (clustered members only). A child
    // whose predicate is false is `stopped` with the reason, never omitted.
    if view.kind() == MemberKind::Host {
        launch(
            "shape-daemon",
            engine_ctl_argv(exe, config, &view.member.name, "shape-daemon"),
            pid,
            false,
            spawner,
            &shared,
            &exit_tx,
            &mut pending,
        );
    } else {
        shared
            .lock()
            .unwrap()
            .mark_stopped("shape-daemon", "not a host");
    }
    let clustered = crate::cluster::Pmxcfs::at(pmxcfs_root)
        .probe()
        .ok()
        .flatten()
        .is_some_and(|m| m.cluster.is_some());
    if clustered {
        launch(
            "conf-sync",
            engine_ctl_argv(exe, config, &view.member.name, "conf-sync"),
            pid,
            false,
            spawner,
            &shared,
            &exit_tx,
            &mut pending,
        );
    } else {
        shared
            .lock()
            .unwrap()
            .mark_stopped("conf-sync", "not clustered");
    }

    // 5. The operator surface: the `cfab.sock` server, on the listener bound at 1b.
    if let Some(listener) = sock_listener {
        let source = Arc::new(SockSource {
            shared: shared.clone(),
            cmd_tx: cmd_tx.clone(),
        });
        tokio::spawn(async move {
            if let Err(e) = sock::serve(source, listener).await {
                tracing::warn!(%e, "cfab.sock server stopped");
            }
        });
    }

    // The watchdog feed (spec §8): only when systemd set WATCHDOG_USEC, so `WatchdogSec` lives
    // in the unit file alone. Absent that, the feed never runs.
    let feed_period = feed_period();

    if let Some(tx) = hooks.on_ready {
        let _ = tx.send(());
    }
    // 6. READY=1 — a no-op with no NOTIFY_SOCKET (the container path).
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);

    // ---- supervise -------------------------------------------------------------
    let mut fwd_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(3),
        Duration::from_secs(3),
    );
    let mut feed_tick = feed_period.map(|p| {
        tokio::time::interval_at(
            tokio::time::Instant::now() + p,
            p.max(Duration::from_millis(1)),
        )
    });
    // Reconcile the engine's readiness on every tick. The initial `wait_ready` above runs once,
    // before this loop; every *respawn* — the crash backoff here and the reapply's
    // `restart_child` alike — puts the engine back into `starting` (spec §4), and nothing else
    // moves it to `running`. Without this a healthy engine the supervisor restarted in place
    // stays labeled `starting` forever (pid stable, fabric converged), which `status` then
    // misreports as a stuck start. Same query and cadence as `wait_ready`.
    let mut ready_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_millis(POLL_MS),
        Duration::from_millis(POLL_MS),
    );

    // Set by a reload that found a changed declaration: the stop sequence below runs unchanged,
    // and the exit status asks systemd for the restart that applies the new file.
    let mut reload = false;

    loop {
        let next_respawn = pending.iter().map(|(_, d)| *d).min();
        let respawn_sleep = async {
            match next_respawn {
                Some(d) => {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        // `feed_tick` is optional; a never-ready future stands in when it is absent.
        let feed = async {
            match feed_tick.as_mut() {
                Some(t) => {
                    t.tick().await;
                }
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            Some(ev) = exit_rx.recv() => {
                let now = Instant::now();
                let respawn = shared.lock().unwrap().child_mut(ev.name).exited(ev.cause.clone(), now);
                eprintln!("{}: exited ({})", ev.name, ev.cause);
                if respawn.is_some() {
                    pending.retain(|(n, _)| *n != ev.name);
                    pending.push((ev.name, now + BACKOFF));
                }
            }
            _ = respawn_sleep, if next_respawn.is_some() => {
                let now = Instant::now();
                let due: Vec<&'static str> =
                    pending.iter().filter(|(_, d)| *d <= now).map(|(n, _)| *n).collect();
                pending.retain(|(_, d)| *d > now);
                for name in due {
                    launch(
                        name,
                        engine_ctl_argv(exe, config, &view.member.name, name),
                        pid,
                        name == "engine",
                        spawner,
                        &shared,
                        &exit_tx,
                        &mut pending,
                    );
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                // SIGHUP and a socket `reapply` are the SAME path (James's ruling, 2026-09-06):
                // re-read the declaration and act on what it says. The only difference is
                // whether anybody is waiting for an answer.
                let reply = match cmd {
                    Cmd::Terminate => break,
                    Cmd::Hangup => None,
                    Cmd::Reapply(tx) => Some(tx),
                };
                match read_reload(&*sys, view, config) {
                    Reload::Identical => {
                        let r = do_reapply(
                            sys, view, &opts, &shared, spawner, exe, config, pid,
                            &exit_tx, &mut exit_rx, &mut pending, &feed_fn,
                        )
                        .await;
                        if let Some(tx) = reply {
                            let _ = tx.send(r);
                        }
                    }
                    Reload::Changed => {
                        eprintln!(
                            "cfab: declaration changed, restarting to apply {config}"
                        );
                        // Answer the requester BEFORE the stop sequence: the restart takes the
                        // socket with it, and a blocked `cfab reapply` must not hang for it.
                        if let Some(tx) = reply {
                            let _ = tx.send(Ok(()));
                        }
                        reload = true;
                        break;
                    }
                    Reload::Invalid(why) => {
                        let e = crate::error::Error::config(format!(
                            "reload refused, keeping the running fabric: {why}"
                        ));
                        shared.lock().unwrap().last_apply_error = Some(e.to_string());
                        eprintln!("cfab: {e}");
                        if let Some(tx) = reply {
                            let _ = tx.send(Err(e));
                        }
                    }
                }
            }
            // Same select!-arm coupling as the reapply above: `watchdog_tick` holds `&mut sys`
            // and runs to completion before the `feed` arm can be polled again. It is NOT fed
            // through here because the forwarding check is short and bounded (a handful of sysctl
            // reads and `ip rule` shows, sub-second) — nowhere near `WatchdogSec` — unlike a
            // reapply, which is why only the reapply gets interior feeds.
            _ = fwd_tick.tick(), if hooks.run_watchdog => {
                watchdog_tick(sys, view, &shared);
            }
            _ = feed => {
                let (apply, engine_state) = {
                    let st = shared.lock().unwrap();
                    let apply = if st.applying {
                        ApplyState::Applying {
                            since_s: st.apply_started_at.map_or(0, |t| t.elapsed().as_secs()),
                        }
                    } else {
                        ApplyState::Idle
                    };
                    (apply, st.child("engine").state)
                };
                // Only a `running` engine's silence withholds the feed, so only then pay the
                // bounded `state\n` read (5 s client timeout); otherwise the read is not consulted.
                let read = if engine_state == child::State::Running {
                    match sys.unix_request(&sock_path, "state\n") {
                        Ok(r) if serde_json::from_str::<serde_json::Value>(&r).is_ok() => {
                            StateRead::Ok
                        }
                        _ => StateRead::Failed,
                    }
                } else {
                    StateRead::Failed
                };
                if should_feed(apply, engine_state, read) {
                    feed_fn();
                }
            }
            // Move a restarted engine out of `starting` once its socket answers ready. Only the
            // `starting` state pays the bounded `state\n` read; a `running`/`stopped`/`restarting`
            // engine is a cheap lock check. `became_ready` is a no-op unless still `starting`, so
            // a late answer never resurrects a child that has since died.
            _ = ready_tick.tick() => {
                let starting =
                    shared.lock().unwrap().child("engine").state == child::State::Starting;
                if starting
                    && let Ok(reply) = sys.unix_request(&sock_path, "state\n")
                    && let Ok(doc) = serde_json::from_str::<serde_json::Value>(&reply)
                    && doc["ready"] == true
                {
                    shared.lock().unwrap().child_mut("engine").became_ready();
                }
            }
        }
    }

    // ---- stop sequence (spec §13) ----------------------------------------------
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
    // 1. No child is wanted any more; refuse further reapplies (the loop is gone).
    {
        let mut st = shared.lock().unwrap();
        for c in &mut st.children {
            c.want = false;
        }
    }
    // 2. Forwarding OFF first — fail closed before anything that can block or be SIGKILLed.
    if let Err(e) = teardown::forwarding_off(sys, view) {
        eprintln!("cfab: warn: forwarding_off during stop: {e}");
    }
    // 3. SIGTERM every child at once (they are independent). The old "conf-sync first" ordering
    // is obsolete: step 1 already set `want = false` and neutered `reapply`, so a conf-sync still
    // breathing here has nothing it can apply.
    let targets: Vec<(&'static str, u32)> = {
        let st = shared.lock().unwrap();
        st.children
            .iter()
            .filter_map(|c| c.pid().map(|p| (c.name, p)))
            .collect()
    };
    for (name, p) in &targets {
        trace_mark(&trace, format!("signal {name} SIGTERM"));
        signal_pid(*p, nix::sys::signal::Signal::SIGTERM);
    }
    // 4. Wait each out ≤ `stop_grace` from the signal, then SIGKILL the survivors.
    trace_mark(&trace, "wait children".to_string());
    let deadline = Instant::now() + stop_grace;
    let mut alive: Vec<&'static str> = targets.iter().map(|(n, _)| *n).collect();
    while !alive.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match tokio::time::timeout(deadline - now, exit_rx.recv()).await {
            Ok(Some(ev)) => {
                shared
                    .lock()
                    .unwrap()
                    .child_mut(ev.name)
                    .exited(ev.cause, Instant::now());
                alive.retain(|n| *n != ev.name);
            }
            _ => break,
        }
    }
    for (n, p) in &targets {
        if alive.contains(n) {
            trace_mark(&trace, format!("signal {n} SIGKILL"));
            signal_pid(*p, nix::sys::signal::Signal::SIGKILL);
        }
    }
    // 5. The rest of the teardown (route sweep, rules, run dir, netdevs, qdiscs).
    match teardown::run(sys, view) {
        Ok(msg) => print!("{msg}"),
        Err(e) => eprintln!("{e}"),
    }
    // 6. Exit 0 — or `EXIT_RELOAD`, which is the same clean stop plus "start me again on the
    // declaration I just read".
    if reload { EXIT_RELOAD } else { EXIT_OK }
}

/// Argv for a supervised child: exactly today's `<exe> --config <config> --host <member>
/// <verb>` (spec §3).
fn engine_ctl_argv(exe: &str, config: &str, member: &str, verb: &str) -> Vec<String> {
    vec![
        exe.to_string(),
        "--config".to_string(),
        config.to_string(),
        "--host".to_string(),
        member.to_string(),
        verb.to_string(),
    ]
}

/// Spawn one child on the current (main) thread and hand its lifecycle to spawned tasks that
/// fork nothing: one reader per stream, one `wait`. On a spawn failure the child is recorded as
/// exited and a backoff respawn is scheduled — never give up while wanted (spec §16.4).
#[allow(clippy::too_many_arguments)]
fn launch(
    name: &'static str,
    argv: Vec<String>,
    sup_pid: u32,
    needs_readiness: bool,
    spawner: &mut dyn Spawner,
    shared: &Arc<Mutex<Shared>>,
    exit_tx: &mpsc::UnboundedSender<ChildExit>,
    pending: &mut Vec<(&'static str, Instant)>,
) {
    shared.lock().unwrap().child_mut(name).want = true;
    match spawner.spawn(name, &argv, sup_pid) {
        Ok(Spawned {
            pid,
            child,
            stdout,
            stderr,
        }) => {
            shared
                .lock()
                .unwrap()
                .child_mut(name)
                .spawned(pid, Instant::now(), needs_readiness);
            let s = shared.clone();
            tokio::spawn(async move {
                tag_lines(name, stdout, move |l| {
                    if let Ok(mut st) = s.lock() {
                        st.child_mut(name).push_log(l);
                    }
                })
                .await;
            });
            let s = shared.clone();
            tokio::spawn(async move {
                tag_lines(name, stderr, move |l| {
                    if let Ok(mut st) = s.lock() {
                        st.child_mut(name).push_log(l);
                    }
                })
                .await;
            });
            let tx = exit_tx.clone();
            tokio::spawn(async move {
                let mut child = child;
                let status = child.wait().await;
                let _ = tx.send(ChildExit {
                    name,
                    cause: cause_of(status),
                });
            });
        }
        Err(e) => {
            eprintln!("{name}: spawn failed: {e}");
            let now = Instant::now();
            shared
                .lock()
                .unwrap()
                .child_mut(name)
                .exited(format!("spawn failed: {e}"), now);
            pending.retain(|(n, _)| *n != name);
            pending.push((name, now + BACKOFF));
        }
    }
}

/// What a reload (SIGHUP, or a `reapply` request — one code path) found in the declaration on
/// disk. The supervisor runs on the `Fabric` it was started with, so "the file changed" is a
/// question that can only be answered by re-reading it at reload time (finding F2: before this,
/// `systemctl reload cfab` silently re-applied the declaration loaded at start).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reload {
    /// The same fabric: re-apply in place (repair), exactly as every reload did before.
    Identical,
    /// A different, valid fabric that still declares this member. `apply::run` is
    /// create-if-absent / refuse-foreign and prunes nothing a declaration stopped declaring, so
    /// the only correct way to reach the new fabric is the full stop sequence plus a restart.
    Changed,
    /// Unreadable, unparseable, invalid, or no longer declaring this member: refuse and keep
    /// running on the fabric that is already up. Carries the operator-facing reason.
    Invalid(String),
}

/// The pure half of the reload decision: the running fabric plus the text now on disk. Equality
/// is over the DERIVED `Fabric`, not the file bytes, so a comment, a reordered key or a
/// whitespace edit re-applies in place instead of restarting the fabric.
pub(crate) fn classify_reload(current: &Fabric, member: &str, config: &str, text: &str) -> Reload {
    let refuse = |e: crate::error::Error| Reload::Invalid(format!("{config}: {e}"));
    let decl = match crate::decl::Declaration::parse(text) {
        Ok(d) => d,
        Err(e) => return refuse(e),
    };
    let next = match Fabric::from_decl(&decl) {
        Ok(f) => f,
        Err(e) => return refuse(e),
    };
    // A declaration that no longer names this host is invalid *for this supervisor*: applying it
    // would be applying somebody else's fabric, and exiting on it would tear this one down for
    // what is far more likely a typo than a decommission.
    if let Err(e) = next.member(member) {
        return refuse(e);
    }
    if next == *current {
        Reload::Identical
    } else {
        Reload::Changed
    }
}

/// The impure half: read `config` through `Sys` (never `std::fs`, so the mocks see it) and
/// classify it. An unreadable or missing file is `Invalid` — never a reason to tear a running
/// fabric down.
fn read_reload(sys: &dyn Sys, view: &View, config: &str) -> Reload {
    match sys.read(config) {
        Ok(text) => classify_reload(view.fabric, &view.member.name, config, &text),
        Err(e) => Reload::Invalid(format!("cannot read {config}: {e}")),
    }
}

/// Re-apply in place (spec §6): apply, then restart the engine and the shape daemon; leave a
/// running conf-sync alone (it may be mid-witness-window). A re-apply that fails at `apply::run`
/// keeps the previous fabric and every child, logs loudly, and answers the request with the
/// error — only the *initial* apply's refusal is terminal.
#[allow(clippy::too_many_arguments)]
async fn do_reapply(
    sys: &mut dyn Sys,
    view: &View<'_>,
    opts: &apply::ApplyOpts,
    shared: &Arc<Mutex<Shared>>,
    spawner: &mut dyn Spawner,
    exe: &str,
    config: &str,
    pid: u32,
    exit_tx: &mpsc::UnboundedSender<ChildExit>,
    exit_rx: &mut mpsc::UnboundedReceiver<ChildExit>,
    pending: &mut Vec<(&'static str, Instant)>,
    feed: &FeedFn,
) -> crate::error::Result<()> {
    let apply_started = Instant::now();
    {
        let mut st = shared.lock().unwrap();
        st.applying = true;
        st.apply_started_at = Some(apply_started);
    }
    // `block_in_place` as at the initial apply (spec §3): a re-apply is where the starvation
    // actually bites — it runs inside the live supervise loop, so a bare ~35 s apply on a
    // single-vCPU host would freeze the watchdog feed and the socket loop for its whole duration.
    match tokio::task::block_in_place(|| apply::run(sys, view, opts)) {
        Ok(warnings) => {
            for w in &warnings {
                println!("{w}");
            }
        }
        Err(e) => {
            let mut st = shared.lock().unwrap();
            st.applying = false;
            st.last_apply_error = Some(e.to_string());
            drop(st);
            eprintln!("cfab: re-apply failed, the previous fabric is kept: {e}");
            return Err(e);
        }
    }
    // Feed at each safe point — the select! loop's `feed` arm cannot run while we hold `&mut
    // sys` here, so these interior feeds are the only thing keeping systemd fed across the
    // reapply. Bounded by the same `Applying` tolerance, so a hung reapply still trips WatchdogSec.
    feed_during_reapply(feed, apply_started);
    restart_child(
        "engine", true, view, shared, spawner, exe, config, pid, exit_tx, exit_rx, pending,
    )
    .await;
    feed_during_reapply(feed, apply_started);
    if view.kind() == MemberKind::Host {
        restart_child(
            "shape-daemon",
            false,
            view,
            shared,
            spawner,
            exe,
            config,
            pid,
            exit_tx,
            exit_rx,
            pending,
        )
        .await;
        feed_during_reapply(feed, apply_started);
    }
    {
        let mut st = shared.lock().unwrap();
        st.applying = false;
        st.applies += 1;
        st.last_apply_error = None;
    }
    Ok(())
}

/// Restart one child: SIGTERM the old process, wait for its own `wait` task to report the exit
/// (handling any *other* child's exit that lands meanwhile), then spawn the replacement at once
/// — no 2 s backoff, because a re-apply wants it back promptly, and waiting for the old one to
/// die first keeps the engine's single-instance `flock` uncontended.
#[allow(clippy::too_many_arguments)]
async fn restart_child(
    name: &'static str,
    needs_readiness: bool,
    view: &View<'_>,
    shared: &Arc<Mutex<Shared>>,
    spawner: &mut dyn Spawner,
    exe: &str,
    config: &str,
    pid: u32,
    exit_tx: &mpsc::UnboundedSender<ChildExit>,
    exit_rx: &mut mpsc::UnboundedReceiver<ChildExit>,
    pending: &mut Vec<(&'static str, Instant)>,
) {
    let old = shared.lock().unwrap().child(name).pid();
    if let Some(p) = old {
        signal_pid(p, nix::sys::signal::Signal::SIGTERM);
        // Wait for the old process to exit, ≤ 10 s, SIGKILLing it if it will not go — the new
        // one cannot take the engine's single-instance flock while the old one lives.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut killed = false;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            match tokio::time::timeout(deadline - now, exit_rx.recv()).await {
                Ok(Some(ev)) if ev.name == name => {
                    shared
                        .lock()
                        .unwrap()
                        .child_mut(name)
                        .exited(ev.cause, Instant::now());
                    break;
                }
                Ok(Some(ev)) => {
                    let now = Instant::now();
                    let respawn = shared
                        .lock()
                        .unwrap()
                        .child_mut(ev.name)
                        .exited(ev.cause, now);
                    if respawn.is_some() {
                        pending.retain(|(n, _)| *n != ev.name);
                        pending.push((ev.name, now + BACKOFF));
                    }
                }
                Ok(None) => break,
                Err(_) if !killed => {
                    signal_pid(p, nix::sys::signal::Signal::SIGKILL);
                    killed = true;
                }
                Err(_) => break,
            }
        }
    }
    pending.retain(|(n, _)| *n != name);
    launch(
        name,
        engine_ctl_argv(exe, config, &view.member.name, name),
        pid,
        needs_readiness,
        spawner,
        shared,
        exit_tx,
        pending,
    );
}

/// Poll the engine's state socket until it answers `"ready": true`, ≤ `START_WAIT_MS`, every
/// `POLL_MS` (spec §4). `None` on timeout: the engine is a supervised child that will keep
/// restarting, not a start failure (§8).
fn wait_ready(sys: &mut dyn Sys, sock: &str) -> Option<serde_json::Value> {
    let mut waited = 0;
    loop {
        if let Ok(reply) = sys.unix_request(sock, "state\n")
            && let Ok(doc) = serde_json::from_str::<serde_json::Value>(&reply)
            && doc["ready"] == true
        {
            return Some(doc);
        }
        if waited >= START_WAIT_MS {
            return None;
        }
        sys.sleep(Duration::from_millis(POLL_MS));
        waited += POLL_MS;
    }
}

/// The three inputs `should_feed` decides on, kept separate so the decision is a pure function
/// testable without systemd, a socket, or a clock.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ApplyState {
    /// An apply is in progress; `since_s` is how many seconds ago it started.
    Applying { since_s: u64 },
    /// No apply in progress.
    Idle,
}

/// Whether a bounded `state\n` read on `engine.sock` returned a parseable document this tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StateRead {
    Ok,
    Failed,
}

/// Whether to feed the systemd watchdog this tick (spec §8), as a pure function of the apply
/// state, the engine child's state, and a bounded state read. WATCHDOG=1 is fed normally; it is
/// withheld ONLY when a `running` engine has stopped answering — an applying supervisor past its
/// time bound (a hang systemd should catch) or a stopped engine also withholds, but a `starting`
/// or crash-looping (`restarting`) engine still feeds, so a contained child fault never escalates
/// into systemd killing the whole unit (A2).
fn should_feed(apply: ApplyState, engine: child::State, read: StateRead) -> bool {
    match apply {
        ApplyState::Applying { since_s } => {
            // Within the bound the apply itself vouches for liveness; past it, withhold so a
            // supervisor hung inside the apply is caught at `WatchdogSec` (the accepted A3 gap).
            let bound_s = (START_WAIT_MS + engine_ctl::SETTLE_MS + 30_000) / 1000;
            since_s < bound_s
        }
        ApplyState::Idle => match engine {
            child::State::Running => read == StateRead::Ok,
            child::State::Starting | child::State::Restarting => true,
            child::State::Stopped => false,
        },
    }
}

/// The watchdog feed period: `WATCHDOG_USEC` ÷ 3, or `None` when systemd set no watchdog — in
/// which case the feed task never runs, so `WatchdogSec` lives in the unit file alone and is
/// never duplicated as a Rust constant (spec §8). Derived live from `sd_notify`, so it is `None`
/// on the container path with no `WATCHDOG_USEC`.
fn feed_period() -> Option<Duration> {
    sd_notify::watchdog_enabled().map(|d| d / 3)
}

/// One forwarding-watchdog tick (spec §5): run the synchronous check with `block_in_place` — on
/// this same thread, never `spawn_blocking`, whose pool retires idle threads and would SIGTERM a
/// child a future spawn forked from it (§7) — and record its outcome into `components`. Runs on
/// every member kind: `fwd_watchdog::run` guards its own transit-only work internally, so a leaf
/// ticks too and only reports what a leaf owns.
fn watchdog_tick(sys: &mut dyn Sys, view: &View, shared: &Arc<Mutex<Shared>>) {
    let (result, detail) = match tokio::task::block_in_place(|| fwd_watchdog::run(sys, view)) {
        Ok(report) => summarize_watchdog(&report),
        Err(e) => ("error".to_string(), Some(e.to_string())),
    };
    let mut st = shared.lock().unwrap();
    st.wd_last_tick = Some(Instant::now());
    st.wd_result = result;
    st.wd_detail = detail;
}

/// The forwarding watchdog tick's outcome, for `components` (spec §5): one of `ok` | `actuated`
/// | `rebuilt` | `failed-closed` | `blocked` | `error`, plus the first line of detail.
///
/// `rebuilt` ranks after the two conditions that mean something is WRONG right now (a member
/// failed closed, or a hazard was amputated) and before the rest: putting a re-enumerated wire's
/// legs back is a repair that leaves the member healthy, and the operator wants to see it said —
/// `status` renders it as `watchdog rebuilt 2s ago (rebuilt storage/cfab-st on eth9)`.
fn summarize_watchdog(report: &fwd_watchdog::WatchdogReport) -> (String, Option<String>) {
    if let Some(f) = &report.failed {
        ("failed-closed".to_string(), Some(f.clone()))
    } else if let Some(d) = report.downed.first() {
        ("actuated".to_string(), Some(d.clone()))
    } else if let Some(r) = report.rebuilt.first() {
        ("rebuilt".to_string(), Some(r.clone()))
    } else if let Some(b) = report.blocked.first() {
        ("blocked".to_string(), Some(b.clone()))
    } else if let Some(u) = report.unrestored.first() {
        ("error".to_string(), Some(u.clone()))
    } else {
        ("ok".to_string(), None)
    }
}

/// How a child died, as `components` renders it: `exit <code>`, `signal <NAME>` or `unknown`.
/// Exit 5 is a child telling us the supervisor vanished inside its fork window (spec §7/§10) —
/// one spelling, distinct from the supervisor's own code 4.
fn cause_of(status: std::io::Result<std::process::ExitStatus>) -> String {
    match status {
        Ok(s) => {
            if let Some(code) = s.code() {
                if code == 5 {
                    "exit 5 (supervisor vanished at spawn)".to_string()
                } else {
                    format!("exit {code}")
                }
            } else if let Some(sig) = s.signal() {
                match nix::sys::signal::Signal::try_from(sig) {
                    Ok(sg) => format!("signal {}", sg.as_str()),
                    Err(_) => format!("signal {sig}"),
                }
            } else {
                "unknown".to_string()
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

/// Signal a child by a pid we hold from having spawned it (spec §16.1: never a pid read from a
/// file). `ESRCH` — the child already exited and was reaped — is not an error here.
fn signal_pid(pid: u32, sig: nix::sys::signal::Signal) {
    let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), sig);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::engine_ctl::tests::healthy_doc;
    use crate::decl::Declaration;
    use crate::sys::mock::MockSys;
    use std::path::Path;

    const EXE: &str = "/usr/bin/cfab";
    const CONFIG: &str = "/etc/cfab/fabric.toml";

    /// The packaged example declaration with `[runtime] run_dir` moved into the test's tempdir.
    /// It is the TEXT, not just the model: a reload re-reads `CONFIG`, so the fixture's file and
    /// the fixture's fabric must be the same declaration or every reload would read "changed".
    fn decl_text(run_dir: &Path) -> String {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        let out = text.replace(
            "run_dir = \"/run/cfab\"",
            &format!("run_dir = \"{}\"", run_dir.display()),
        );
        assert_ne!(out, text, "the example's run_dir line moved");
        out
    }

    fn fabric_at(run_dir: &Path) -> Fabric {
        Fabric::from_decl(&Declaration::parse(&decl_text(run_dir)).unwrap()).unwrap()
    }

    /// A pmxcfs root with no `.members` — `probe()` returns `None`, so conf-sync is stopped
    /// "not clustered".
    fn no_pmx(run_dir: &Path) -> String {
        run_dir.join("no-pve").to_str().unwrap().to_string()
    }

    /// The fresh-member fixture (mirrors `apply::tests::up_sys`): the declared wires present,
    /// everything else absent, `/proc/sys` writable, the admin NIC addressed, the forward chain
    /// readable, and the engine socket answering a healthy state document for `view`.
    fn fresh_sys(view: &View, run_dir: &Path) -> MockSys {
        let mut sys = MockSys::default()
            .file(CONFIG, &decl_text(run_dir))
            .file("/proc/sys/net/ipv4/conf/all/rp_filter", "1\n")
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .on_stdout(
                &["ip", "-4", "-br", "addr", "show", "dev"],
                "x UP 192.168.10.9/24\n",
            )
            .on_stdout(
                &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
                "table inet cfab-fwd {\n chain forward {\n type filter hook forward priority 0; policy drop;\n}\n}\n",
            )
            .socket(
                &format!("{}/engine.sock", run_dir.display()),
                &healthy_doc(view).to_string(),
            );
        for w in view.wires() {
            sys = sys.on_stdout(
                &["ip", "link", "show", w.as_str()],
                &format!("2: {w}: <UP>\n"),
            );
        }
        sys
    }

    // ---- a recording Spawner that forks trivial, controllable processes -------------------
    #[derive(Default)]
    struct RecState {
        spawned: Vec<String>,
        threads: Vec<std::thread::ThreadId>,
        engine_calls: u32,
        engine_first_quick: bool,
        /// Children that trap and ignore SIGTERM, so the stop sequence must escalate to SIGKILL.
        ignore_term: std::collections::HashSet<&'static str>,
        /// Where an `ignore_term` child touches `<name>.trapped` once its trap is installed, so
        /// the driver can wait for that confirmation before firing the stop (no startup race
        /// between `trap '' TERM` and an early SIGTERM). `None` ⇒ no marker (the trap is still
        /// installed, but nothing waits on it).
        trap_marker_dir: Option<std::path::PathBuf>,
    }

    struct Rec {
        inner: Arc<Mutex<RecState>>,
    }

    impl Spawner for Rec {
        fn spawn(
            &mut self,
            name: &'static str,
            _argv: &[String],
            _sup_pid: u32,
        ) -> std::io::Result<Spawned> {
            let (quick, ignores_term, marker_dir) = {
                let mut st = self.inner.lock().unwrap();
                st.spawned.push(name.to_string());
                st.threads.push(std::thread::current().id());
                let q = name == "engine" && st.engine_first_quick && st.engine_calls == 0;
                if name == "engine" {
                    st.engine_calls += 1;
                }
                (q, st.ignore_term.contains(name), st.trap_marker_dir.clone())
            };
            // A long-lived child killed promptly by SIGTERM's default disposition (no trap: a
            // trapped signal can be deferred behind the running `sleep`, which would wedge a
            // restart's wait). `exit 0` is the crash-loop fixture. A child in `ignore_term`
            // traps and ignores SIGTERM, so the stop sequence must escalate to SIGKILL — and it
            // touches its marker *after* the trap is installed, so the driver can gate the stop
            // on that confirmation instead of racing the shell's startup.
            let script: String = if ignores_term {
                match &marker_dir {
                    Some(dir) => format!(
                        "trap '' TERM; touch '{}'; sleep 60",
                        dir.join(format!("{name}.trapped")).display()
                    ),
                    None => "trap '' TERM; sleep 60".to_string(),
                }
            } else if quick {
                "exit 0".to_string()
            } else {
                "exec sleep 60".to_string()
            };
            let mut child = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            let pid = child.id().unwrap_or(0);
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            Ok(Spawned {
                pid,
                child,
                stdout,
                stderr,
            })
        }
    }

    fn rec() -> (Rec, Arc<Mutex<RecState>>) {
        let inner = Arc::new(Mutex::new(RecState::default()));
        (
            Rec {
                inner: inner.clone(),
            },
            inner,
        )
    }

    // ---- a Sys wrapper: records commands so a driver can inspect them mid-run, and can be
    // made to fail `is_writable` after the first apply (so the second apply refuses) ----------
    struct TestSys {
        inner: MockSys,
        calls: Arc<Mutex<Vec<String>>>,
        writable_count: std::cell::Cell<u32>,
        fail_writable_after: Option<u32>,
    }

    impl TestSys {
        fn new(inner: MockSys, calls: Arc<Mutex<Vec<String>>>) -> Self {
            TestSys {
                inner,
                calls,
                writable_count: std::cell::Cell::new(0),
                fail_writable_after: None,
            }
        }
        fn fail_writable_after(mut self, n: u32) -> Self {
            self.fail_writable_after = Some(n);
            self
        }
    }

    impl Sys for TestSys {
        fn run(&mut self, argv: &[&str]) -> crate::error::Result<crate::sys::Output> {
            self.calls.lock().unwrap().push(argv.join(" "));
            self.inner.run(argv)
        }
        fn read(&self, p: &str) -> crate::error::Result<String> {
            self.inner.read(p)
        }
        fn write(&mut self, p: &str, c: &str) -> crate::error::Result<()> {
            self.calls.lock().unwrap().push(format!("write {p}"));
            self.inner.write(p, c)
        }
        fn exists(&self, p: &str) -> bool {
            self.inner.exists(p)
        }
        fn is_writable(&self, p: &str) -> bool {
            let n = self.writable_count.get() + 1;
            self.writable_count.set(n);
            if let Some(k) = self.fail_writable_after
                && n > k
            {
                return false;
            }
            self.inner.is_writable(p)
        }
        fn list_dir(&self, p: &str) -> crate::error::Result<Vec<String>> {
            self.inner.list_dir(p)
        }
        fn mkdir_p(&mut self, p: &str) -> crate::error::Result<()> {
            self.inner.mkdir_p(p)
        }
        fn remove(&mut self, p: &str) -> crate::error::Result<()> {
            self.calls.lock().unwrap().push(format!("rm {p}"));
            self.inner.remove(p)
        }
        fn rename(&mut self, a: &str, b: &str) -> crate::error::Result<()> {
            self.inner.rename(a, b)
        }
        fn sleep(&mut self, d: Duration) {
            self.inner.sleep(d);
        }
        fn unix_request(&mut self, p: &str, l: &str) -> crate::error::Result<String> {
            self.inner.unix_request(p, l)
        }
    }

    fn quiet_hooks(shared: Arc<Mutex<Shared>>, ready: tokio::sync::oneshot::Sender<()>) -> Hooks {
        Hooks {
            on_ready: Some(ready),
            run_watchdog: false,
            serve_socket: false,
            shared: Some(shared),
            trace: None,
            stop_grace: CHILD_STOP_GRACE,
            feed: Arc::new(|| {}),
        }
    }

    /// Spec §10: an initial apply refusal exits 3 and no child is ever started.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_initial_apply_refusal_is_terminal_and_starts_no_child() {
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve1-tb").unwrap();
        // MockSys::default(): the admin NIC has no IPv4 (and /proc/sys is not writable) — the
        // apply refuses before any daemon. An absent wire would only warn (§6); this is a real
        // refusal.
        let mut sys = MockSys::default();
        let (mut spawner, recs) = rec();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let code = run_with(
            &mut sys,
            &view,
            &mut spawner,
            EXE,
            CONFIG,
            &no_pmx(tmp.path()),
            cmd_tx,
            cmd_rx,
            Hooks {
                on_ready: None,
                run_watchdog: false,
                serve_socket: false,
                shared: None,
                trace: None,
                stop_grace: CHILD_STOP_GRACE,
                feed: Arc::new(|| {}),
            },
        )
        .await;
        assert_eq!(
            code, 3,
            "an apply refusal must exit 3 (RestartPreventExitStatus)"
        );
        assert!(
            recs.lock().unwrap().spawned.is_empty(),
            "no child may be started when the initial apply is refused"
        );
    }

    /// A leaf gets an engine and no shape-daemon; conf-sync is stopped "not clustered".
    #[tokio::test(flavor = "multi_thread")]
    async fn a_leaf_gets_an_engine_and_no_shape_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = fresh_sys(&view, tmp.path());
        let (mut spawner, recs) = rec();
        let shared = Arc::new(Mutex::new(Shared::new(std::process::id())));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let driver_tx = cmd_tx.clone();
        let sh = shared.clone();
        let driver = tokio::spawn(async move {
            ready_rx.await.ok();
            let snap = sh.lock().unwrap().components(Instant::now());
            driver_tx.send(Cmd::Terminate).ok();
            snap
        });
        let code = run_with(
            &mut sys,
            &view,
            &mut spawner,
            EXE,
            CONFIG,
            &no_pmx(tmp.path()),
            cmd_tx,
            cmd_rx,
            quiet_hooks(shared.clone(), ready_tx),
        )
        .await;
        let snap = driver.await.unwrap();
        assert_eq!(code, 0);
        let names = recs.lock().unwrap().spawned.clone();
        assert!(names.contains(&"engine".to_string()), "{names:?}");
        assert!(
            !names.contains(&"shape-daemon".to_string()),
            "a leaf runs no shape daemon: {names:?}"
        );
        let comp = |n: &str| {
            snap.components
                .iter()
                .find(|c| c.name == n)
                .unwrap()
                .clone()
        };
        assert_eq!(comp("engine").state, child::State::Running);
        assert_eq!(comp("shape-daemon").state, child::State::Stopped);
        assert_eq!(comp("conf-sync").state, child::State::Stopped);
        assert_eq!(comp("conf-sync").why.as_deref(), Some("not clustered"));
    }

    /// SIGHUP-equivalent re-apply restarts the engine and the shape daemon, never tears down
    /// (no `ip link del`), and leaves conf-sync untouched.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reapply_restarts_engine_and_shape_without_a_teardown() {
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve1-tb").unwrap();
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut sys = TestSys::new(fresh_sys(&view, tmp.path()), calls.clone());
        let (mut spawner, recs) = rec();
        let shared = Arc::new(Mutex::new(Shared::new(std::process::id())));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let driver_tx = cmd_tx.clone();
        let sh = shared.clone();
        let calls_c = calls.clone();
        let driver = tokio::spawn(async move {
            ready_rx.await.ok();
            let (rtx, rrx) = std::sync::mpsc::channel();
            driver_tx.send(Cmd::Reapply(rtx)).ok();
            let res = tokio::task::spawn_blocking(move || rrx.recv().unwrap())
                .await
                .unwrap();
            let calls_at_reapply = calls_c.lock().unwrap().clone();
            let snap = sh.lock().unwrap().components(Instant::now());
            driver_tx.send(Cmd::Terminate).ok();
            (res, calls_at_reapply, snap)
        });
        let code = run_with(
            &mut sys,
            &view,
            &mut spawner,
            EXE,
            CONFIG,
            &no_pmx(tmp.path()),
            cmd_tx,
            cmd_rx,
            quiet_hooks(shared.clone(), ready_tx),
        )
        .await;
        let (res, calls_at_reapply, snap) = driver.await.unwrap();
        assert_eq!(code, 0);
        assert!(res.is_ok(), "the re-apply must succeed: {res:?}");
        assert!(
            !calls_at_reapply
                .iter()
                .any(|c| c.starts_with("ip link del")),
            "a re-apply never tears anything down: {calls_at_reapply:?}"
        );
        let names = recs.lock().unwrap().spawned.clone();
        assert_eq!(
            names.iter().filter(|n| *n == "engine").count(),
            2,
            "engine restarted once by the re-apply: {names:?}"
        );
        assert_eq!(
            names.iter().filter(|n| *n == "shape-daemon").count(),
            2,
            "shape-daemon restarted once by the re-apply: {names:?}"
        );
        assert_eq!(
            names.iter().filter(|n| *n == "conf-sync").count(),
            0,
            "conf-sync is not clustered here and is never spawned or restarted: {names:?}"
        );
        let comp = |n: &str| {
            snap.components
                .iter()
                .find(|c| c.name == n)
                .unwrap()
                .clone()
        };
        assert_eq!(comp("engine").restarts, 1);
        assert_eq!(comp("shape-daemon").restarts, 1);
    }

    /// A re-apply that fails at `apply::run` keeps the previous fabric and every child, and the
    /// supervisor never sets an exit code (§6).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reapply_that_fails_keeps_the_previous_fabric_and_the_children() {
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve1-tb").unwrap();
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        // The first apply succeeds; the second finds /proc/sys "read-only" and refuses.
        let mut sys =
            TestSys::new(fresh_sys(&view, tmp.path()), calls.clone()).fail_writable_after(1);
        let (mut spawner, _recs) = rec();
        let shared = Arc::new(Mutex::new(Shared::new(std::process::id())));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let driver_tx = cmd_tx.clone();
        let sh = shared.clone();
        let driver = tokio::spawn(async move {
            ready_rx.await.ok();
            let (rtx, rrx) = std::sync::mpsc::channel();
            driver_tx.send(Cmd::Reapply(rtx)).ok();
            let res = tokio::task::spawn_blocking(move || rrx.recv().unwrap())
                .await
                .unwrap();
            let snap = sh.lock().unwrap().components(Instant::now());
            driver_tx.send(Cmd::Terminate).ok();
            (res, snap)
        });
        let code = run_with(
            &mut sys,
            &view,
            &mut spawner,
            EXE,
            CONFIG,
            &no_pmx(tmp.path()),
            cmd_tx,
            cmd_rx,
            quiet_hooks(shared.clone(), ready_tx),
        )
        .await;
        let (res, snap) = driver.await.unwrap();
        assert_eq!(code, 0);
        assert!(res.is_err(), "the re-apply must report the apply error");
        let comp = |n: &str| {
            snap.components
                .iter()
                .find(|c| c.name == n)
                .unwrap()
                .clone()
        };
        assert_eq!(
            comp("engine").state,
            child::State::Running,
            "the engine that was up stays up when a re-apply fails"
        );
        assert_eq!(
            comp("engine").restarts,
            0,
            "a failed re-apply restarts nothing"
        );
        assert_eq!(comp("shape-daemon").restarts, 0);
        assert!(
            snap.supervisor.last_apply_error.is_some(),
            "the failed re-apply is recorded for the operator surface"
        );
    }

    /// Spec §7: `PR_SET_PDEATHSIG` follows the parent thread, and tokio retires idle blocking
    /// workers — so every `Command::spawn` (initial, backoff respawn, re-apply restart) must be
    /// executed by the supervisor's main thread. Driven through one child crash and one
    /// re-apply.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_spawn_happens_on_the_supervisor_main_thread() {
        let main = std::thread::current().id();
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = fresh_sys(&view, tmp.path());
        let inner = Arc::new(Mutex::new(RecState {
            engine_first_quick: true,
            ..RecState::default()
        }));
        let mut spawner = Rec {
            inner: inner.clone(),
        };
        let shared = Arc::new(Mutex::new(Shared::new(std::process::id())));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let driver_tx = cmd_tx.clone();
        let driver = tokio::spawn(async move {
            ready_rx.await.ok();
            // Let the crashed engine's 2 s backoff respawn happen.
            tokio::time::sleep(Duration::from_millis(2500)).await;
            let (rtx, rrx) = std::sync::mpsc::channel();
            driver_tx.send(Cmd::Reapply(rtx)).ok();
            let _ = tokio::task::spawn_blocking(move || rrx.recv()).await;
            driver_tx.send(Cmd::Terminate).ok();
        });
        let code = run_with(
            &mut sys,
            &view,
            &mut spawner,
            EXE,
            CONFIG,
            &no_pmx(tmp.path()),
            cmd_tx,
            cmd_rx,
            quiet_hooks(shared, ready_tx),
        )
        .await;
        driver.await.unwrap();
        assert_eq!(code, 0);
        let st = inner.lock().unwrap();
        assert!(
            st.threads.iter().all(|t| *t == main),
            "a child was forked off the main thread: {:?} (main {:?})",
            st.threads,
            main
        );
        // The crash respawn and the re-apply restart both happened: engine forked ≥ 3 times.
        assert!(
            st.spawned.iter().filter(|n| *n == "engine").count() >= 3,
            "expected initial + crash-respawn + re-apply engine spawns: {:?}",
            st.spawned
        );
    }

    /// Finding B: an engine restarted in place must return to `running`, not stay `starting`.
    /// The first engine crashes (`engine_first_quick`); the backoff respawn puts it back into
    /// `starting`; the readiness-reconcile tick must then observe the socket ready and move it to
    /// `running`. Without that tick the respawned engine is stuck `starting` forever even though
    /// the fabric is up — this test times out waiting for `running` (its teeth).
    #[tokio::test(flavor = "multi_thread")]
    async fn an_in_place_engine_restart_returns_to_running() {
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = fresh_sys(&view, tmp.path());
        let inner = Arc::new(Mutex::new(RecState {
            engine_first_quick: true,
            ..RecState::default()
        }));
        let mut spawner = Rec {
            inner: inner.clone(),
        };
        let shared = Arc::new(Mutex::new(Shared::new(std::process::id())));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let driver_tx = cmd_tx.clone();
        let sh = shared.clone();
        let driver = tokio::spawn(async move {
            ready_rx.await.ok();
            // Wait for the crash-respawn (restarts >= 1) AND the reconcile back to running,
            // bounded well past the 2 s backoff + one poll interval.
            let deadline = std::time::Instant::now() + Duration::from_secs(8);
            let ok = loop {
                {
                    let st = sh.lock().unwrap();
                    let e = st.child("engine");
                    if e.restarts >= 1 && e.state == child::State::Running {
                        break true;
                    }
                }
                if std::time::Instant::now() >= deadline {
                    break false;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            driver_tx.send(Cmd::Terminate).ok();
            ok
        });
        let code = run_with(
            &mut sys,
            &view,
            &mut spawner,
            EXE,
            CONFIG,
            &no_pmx(tmp.path()),
            cmd_tx,
            cmd_rx,
            quiet_hooks(shared, ready_tx),
        )
        .await;
        let ok = driver.await.unwrap();
        assert_eq!(code, 0);
        assert!(
            ok,
            "a restarted engine must return to running, not stay starting"
        );
    }

    /// A6 + the container path: with no systemd watchdog, `feed_period` is derived from
    /// `watchdog_enabled()` (never a duplicated constant) and is `None`, so no feed task is ever
    /// started, and `sd_notify::notify` is a no-op that returns `Ok` with no `NOTIFY_SOCKET`.
    /// `cargo test` is not a systemd service, so neither variable is set; we cannot `remove_var`
    /// here because `unsafe_code = "forbid"` (edition 2024) forbids it even in tests and the crate
    /// has no safe env-manipulation helper — so the test asserts the derivation instead.
    #[test]
    fn sd_notify_is_a_no_op_without_notify_socket() {
        // `feed_period` is exactly `watchdog_enabled()/3` — proving it is derived, not a constant.
        assert_eq!(feed_period(), sd_notify::watchdog_enabled().map(|d| d / 3));
        assert!(
            sd_notify::notify(&[sd_notify::NotifyState::Ready]).is_ok(),
            "notify is a no-op returning Ok without NOTIFY_SOCKET"
        );
        assert!(sd_notify::watchdog_enabled().is_none());
        assert!(feed_period().is_none());
    }

    /// Spec §8 as a pure function: WATCHDOG=1 is fed normally and withheld ONLY when a running
    /// engine stops answering a bounded state read. A crash-looping (restarting) engine still
    /// feeds — a contained child fault must never escalate into systemd killing the whole unit
    /// (A2).
    #[test]
    fn the_feed_is_withheld_only_when_a_running_engine_stops_answering() {
        use ApplyState::{Applying, Idle};
        use child::State::{Restarting, Running};
        // An apply within its bound feeds regardless of the engine (it may not answer yet).
        assert!(should_feed(Applying { since_s: 5 }, Running, StateRead::Ok));
        // Past the apply bound, a running engine that will not answer withholds.
        assert!(!should_feed(
            Applying { since_s: 100 },
            Running,
            StateRead::Failed
        ));
        // Idle: a running engine feeds iff it answers.
        assert!(should_feed(Idle, Running, StateRead::Ok));
        assert!(!should_feed(Idle, Running, StateRead::Failed));
        // A crash-looping engine must NOT get the supervisor killed too (A2).
        assert!(should_feed(Idle, Restarting, StateRead::Failed));
    }

    /// The forwarding-watchdog tick runs on a leaf too (spec §5): `fwd_watchdog::run` is called on
    /// a leaf view and its report is recorded into `components`. A healthy leaf posture summarizes
    /// to `ok`.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_watchdog_ticks_on_a_leaf_too() {
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve3-tb").unwrap(); // a leaf
        let mut sys = healthy_leaf_sys(&view);
        let shared = Arc::new(Mutex::new(Shared::new(std::process::id())));
        watchdog_tick(&mut sys, &view, &shared);
        let snap = shared.lock().unwrap().components(Instant::now());
        assert_eq!(
            snap.watchdog.result, "ok",
            "a healthy leaf tick is ok (detail: {:?})",
            snap.watchdog.detail
        );
        assert!(
            snap.watchdog.last_tick_s_ago.is_some(),
            "the tick was recorded into components"
        );
    }

    /// A tick that put a re-enumerated wire's legs back is neither `ok` (something happened the
    /// operator wants to see) nor `actuated` (nothing was brought down): it is `rebuilt`, ranked
    /// after the two conditions that mean the member is unwell, with the first leg as detail.
    /// `status` renders it as `watchdog rebuilt 2s ago (rebuilt storage/cfab-st on eth9)`.
    #[test]
    fn a_rebuilt_leg_summarizes_to_rebuilt() {
        let rebuilt = |extra: fn(&mut fwd_watchdog::WatchdogReport)| {
            let mut r = fwd_watchdog::WatchdogReport {
                failed: None,
                corrected: Vec::new(),
                blocked: Vec::new(),
                resolved: None,
                restored: Vec::new(),
                downed: Vec::new(),
                unrestored: Vec::new(),
                rebuilt: vec![
                    "rebuilt storage/cfab-st on eth9".to_string(),
                    "rebuilt cluster/cfab-cl-bk on eth9".to_string(),
                ],
                transit_cost_error: None,
            };
            extra(&mut r);
            summarize_watchdog(&r)
        };
        assert_eq!(
            rebuilt(|_| {}),
            (
                "rebuilt".to_string(),
                Some("rebuilt storage/cfab-st on eth9".to_string())
            )
        );
        // ...but never ahead of a member that failed closed or had something amputated.
        assert_eq!(
            rebuilt(|r| r.downed.push("fallback storage down".to_string())).0,
            "actuated"
        );
        assert_eq!(
            rebuilt(|r| r.failed = Some("no policy".to_string())).0,
            "failed-closed"
        );
        // An empty `rebuilt` is the ordinary tick and stays `ok`.
        let mut r = fwd_watchdog::WatchdogReport {
            failed: None,
            corrected: Vec::new(),
            blocked: Vec::new(),
            resolved: None,
            restored: Vec::new(),
            downed: Vec::new(),
            unrestored: Vec::new(),
            rebuilt: Vec::new(),
            transit_cost_error: None,
        };
        assert_eq!(summarize_watchdog(&r), ("ok".to_string(), None));
        r.unrestored.push("stuck".to_string());
        assert_eq!(summarize_watchdog(&r).0, "error");
    }

    /// A healthy leaf forwarding posture for `fwd_watchdog::run` (mirrors its own leaf fixture):
    /// every L3 leg's `rp_filter` loose and `forwarding` off, every `ip rule` cfab installed
    /// present, and each fallback bond active on a slave of ours.
    fn healthy_leaf_sys(view: &View) -> MockSys {
        use crate::commands::common;
        let legs: Vec<String> = view
            .class_rows()
            .into_iter()
            .map(|r| r.ifname)
            .chain(view.fallback_rows().into_iter().map(|r| r.ifname))
            .collect();
        let mut sys = MockSys::default();
        for ifname in &legs {
            sys = sys
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{ifname}/forwarding"),
                    "0\n",
                );
        }
        let mut by_pref: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for r in common::leak_guard_rules(view)
            .into_iter()
            .chain(common::return_path_rules(view))
        {
            by_pref
                .entry(r.pref.clone())
                .or_default()
                .push(format!("{}: from all {}\n", r.pref, r.needle));
        }
        for (pref, lines) in by_pref {
            sys = sys.on_stdout(&["ip", "rule", "show", "pref", &pref], &lines.concat());
        }
        for r in view.fallback_rows() {
            let home = r
                .slaves
                .iter()
                .find(|s| s.wire == r.home)
                .expect("the home wire is one of the slaves");
            sys = sys.file(
                &format!("/sys/class/net/{}/bonding/active_slave", r.ifname),
                &format!("{}\n", home.ifname),
            );
        }
        // Every declared leg present and of cfab's own kind — the rebuild step must find
        // nothing to do. One definition, shared with the watchdog's own fixture.
        crate::commands::fwd_watchdog::tests::legs_present(sys, view)
    }

    /// A pmxcfs root whose `.members` reports a quorate cluster, so the conf-sync predicate
    /// holds and the stop sequence has all three children to signal.
    fn clustered_pmx(dir: &Path) -> String {
        let root = dir.join("pve");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(".members"),
            r#"{"nodename":"pve1-tb","version":1,"cluster":{"name":"tb","version":1,"nodes":3,"quorate":1},"nodelist":{}}"#,
        )
        .unwrap();
        root.to_string_lossy().into_owned()
    }

    /// The fresh-member apply fixture plus what the stop sequence's teardown acts on: an owned
    /// interface under `/proc/.../conf` so `forwarding_off` writes it, and the storage identity
    /// veth `cfab-id99` present (of the right kind, peer absent) so `teardown::run` performs an
    /// `ip link del`. A present veth of the right kind is accepted by the apply's `mk_identity`
    /// (a present bond, by contrast, triggers a params proof the mock cannot satisfy), so it
    /// survives bringup and is deleted only at teardown. Wrapped in the recording `TestSys` that
    /// appends every call to the shared `calls` trace.
    fn stop_fixture_sys(view: &View, run_dir: &Path, calls: Arc<Mutex<Vec<String>>>) -> TestSys {
        let inner = fresh_sys(view, run_dir)
            .file("/proc/sys/net/ipv4/conf/cfab-st/forwarding", "1\n")
            .on_stdout(
                &["ip", "link", "show", "cfab-id99"],
                "5: cfab-id99@cfab-id99-peer\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-id99"],
                "5: cfab-id99: veth \n",
            );
        TestSys::new(inner, calls)
    }

    /// Run the whole lifecycle on a clustered host to READY, then clear the trace (so only the
    /// stop sequence remains), send `Terminate`, and return the exit code and the single merged,
    /// ordered trace of the stop sequence — `Sys` calls (`write …/forwarding`, `ip link del …`)
    /// interleaved with the signal/wait/kill markers. `ignore_term` names children that trap
    /// SIGTERM (so the SIGKILL path runs); `grace` is the per-child SIGTERM→SIGKILL window.
    async fn drive_stop(ignore_term: &[&'static str], grace: Duration) -> (u8, Vec<String>) {
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve1-tb").unwrap();
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut sys = stop_fixture_sys(&view, tmp.path(), calls.clone());
        let marker_dir = tmp.path().to_path_buf();
        let inner = Arc::new(Mutex::new(RecState {
            ignore_term: ignore_term.iter().copied().collect(),
            trap_marker_dir: Some(marker_dir.clone()),
            ..RecState::default()
        }));
        let mut spawner = Rec {
            inner: inner.clone(),
        };
        let shared = Arc::new(Mutex::new(Shared::new(std::process::id())));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let driver_tx = cmd_tx.clone();
        let trace = calls.clone();
        let trap_children: Vec<&'static str> = ignore_term.to_vec();
        let driver = tokio::spawn(async move {
            ready_rx.await.ok();
            // Gate the stop on every `ignore_term` child having installed its SIGTERM trap: the
            // `on_ready` hook fires when the SUPERVISOR reaches its loop, which is after the
            // child is forked but before its shell has run `trap '' TERM`. Waiting for the marker
            // closes that startup race, so a survivor is genuinely a survivor every run — no
            // wall-clock guess (bounded only to fail loud if a marker never appears).
            for name in &trap_children {
                let marker = marker_dir.join(format!("{name}.trapped"));
                let mut waited = 0;
                while !marker.exists() {
                    assert!(
                        waited < 5_000,
                        "trap marker {} never appeared",
                        marker.display()
                    );
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    waited += 2;
                }
            }
            // Start fresh at the stop boundary: the apply's calls fall away, so the trace holds
            // only what the stop sequence did.
            trace.lock().unwrap().clear();
            driver_tx.send(Cmd::Terminate).ok();
        });
        let hooks = Hooks {
            on_ready: Some(ready_tx),
            run_watchdog: false,
            serve_socket: false,
            shared: Some(shared),
            trace: Some(calls.clone()),
            stop_grace: grace,
            feed: Arc::new(|| {}),
        };
        let code = run_with(
            &mut sys,
            &view,
            &mut spawner,
            EXE,
            CONFIG,
            &clustered_pmx(tmp.path()),
            cmd_tx,
            cmd_rx,
            hooks,
        )
        .await;
        driver.await.unwrap();
        let merged = calls.lock().unwrap().clone();
        (code, merged)
    }

    /// Spec §13 step 2 + invariant §16.5: forwarding goes off BEFORE any child is signalled or
    /// waited on, and before the netdevs — so everything after it can be SIGKILLed by
    /// `TimeoutStopSec` without a packet transiting a half-torn-down host. All three children are
    /// signalled, with no ordering among them.
    #[tokio::test(flavor = "multi_thread")]
    async fn forwarding_goes_off_before_any_child_signal_and_before_the_netdevs() {
        let (code, calls) = drive_stop(&[], CHILD_STOP_GRACE).await;
        assert_eq!(code, 0);
        let fwd = calls
            .iter()
            .position(|c| c.contains("conf/cfab-st/forwarding"))
            .unwrap_or_else(|| panic!("no forwarding-off in the stop trace: {calls:?}"));
        let first_signal = calls
            .iter()
            .position(|c| c.starts_with("signal "))
            .unwrap_or_else(|| panic!("no child signal: {calls:?}"));
        let first_wait = calls
            .iter()
            .position(|c| c.starts_with("wait "))
            .unwrap_or_else(|| panic!("no wait: {calls:?}"));
        let del = calls
            .iter()
            .position(|c| c.starts_with("ip link del"))
            .unwrap_or_else(|| panic!("no netdev deletion: {calls:?}"));
        assert!(
            fwd < first_signal,
            "forwarding must be off before any child is signalled: {calls:?}"
        );
        assert!(fwd < first_wait, "and before any wait: {calls:?}");
        assert!(fwd < del, "and before the netdevs: {calls:?}");
        let sigterms = calls.iter().filter(|c| c.ends_with("SIGTERM")).count();
        assert_eq!(
            sigterms, 3,
            "all three children signalled, no ordering among them: {calls:?}"
        );
    }

    /// Spec §13 steps 3–4: every child is SIGTERMed at once (all before any wait), and the one
    /// that traps SIGTERM is SIGKILLed after the grace — proven without a real 10 s wait by a
    /// shrunk `stop_grace`.
    #[tokio::test(flavor = "multi_thread")]
    async fn stop_signals_every_child_at_once_then_sigkills_the_one_that_ignores_sigterm() {
        let (code, calls) = drive_stop(&["shape-daemon"], Duration::from_millis(300)).await;
        assert_eq!(code, 0);
        let first_wait = calls
            .iter()
            .position(|c| c.starts_with("wait "))
            .unwrap_or_else(|| panic!("no wait: {calls:?}"));
        let sigterms: Vec<usize> = calls
            .iter()
            .enumerate()
            .filter(|(_, c)| c.ends_with("SIGTERM"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            sigterms.len(),
            3,
            "every child SIGTERMed at once: {calls:?}"
        );
        assert!(
            sigterms.iter().all(|i| *i < first_wait),
            "all three signals precede the first wait (signalled at once): {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == "signal shape-daemon SIGKILL"),
            "the child that ignored SIGTERM is SIGKILLed: {calls:?}"
        );
    }

    /// Spec §8 + the select!-arm coupling: while `do_reapply` runs it holds `&mut sys` and the
    /// loop's `feed` arm cannot be polled, so the reapply must feed the watchdog itself at each
    /// safe point or systemd starves and kills a healthy supervisor mid-reapply. With the feed
    /// routed through the injectable seam and no other feed active in the test (run_watchdog off,
    /// no `WATCHDOG_USEC`), every recorded feed is an interior reapply feed: none before it, one
    /// per safe point during it (after the apply, after each child restart).
    #[tokio::test(flavor = "multi_thread")]
    async fn the_watchdog_is_fed_at_each_safe_point_during_a_reapply() {
        let tmp = tempfile::tempdir().unwrap();
        let f = fabric_at(tmp.path());
        let view = View::new(&f, "pve1-tb").unwrap(); // a host: engine + shape both restart
        let mut sys = fresh_sys(&view, tmp.path());
        let (mut spawner, _recs) = rec();
        let shared = Arc::new(Mutex::new(Shared::new(std::process::id())));
        let feeds = Arc::new(Mutex::new(0usize));
        let feeds_in = feeds.clone();
        let feed: FeedFn = Arc::new(move || *feeds_in.lock().unwrap() += 1);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let driver_tx = cmd_tx.clone();
        let feeds_probe = feeds.clone();
        let driver = tokio::spawn(async move {
            ready_rx.await.ok();
            let before = *feeds_probe.lock().unwrap();
            let (rtx, rrx) = std::sync::mpsc::channel();
            driver_tx.send(Cmd::Reapply(rtx)).ok();
            let res = tokio::task::spawn_blocking(move || rrx.recv().unwrap())
                .await
                .unwrap();
            let after = *feeds_probe.lock().unwrap();
            driver_tx.send(Cmd::Terminate).ok();
            (before, after, res)
        });
        let hooks = Hooks {
            on_ready: Some(ready_tx),
            run_watchdog: false,
            serve_socket: false,
            shared: Some(shared.clone()),
            trace: None,
            stop_grace: CHILD_STOP_GRACE,
            feed,
        };
        let code = run_with(
            &mut sys,
            &view,
            &mut spawner,
            EXE,
            CONFIG,
            &no_pmx(tmp.path()),
            cmd_tx,
            cmd_rx,
            hooks,
        )
        .await;
        let (before, after, res) = driver.await.unwrap();
        assert_eq!(code, 0);
        assert!(res.is_ok(), "the reapply must succeed: {res:?}");
        assert_eq!(
            before, 0,
            "nothing feeds this seam before the reapply — the initial bringup is pre-READY"
        );
        // After the apply, after the engine restart, after the shape restart: three safe points.
        assert!(
            after >= 3,
            "the watchdog must be fed at each safe point DURING the reapply, not only around it: \
             got {after} feeds"
        );
    }

    /// Spec §3: the apply, `wait_ready` and `SockSource::reapply`'s recv are synchronous blocking
    /// sections wrapped in `block_in_place`, so that on a single-vCPU host — this project's target
    /// — the watchdog feed, the `cfab.sock` accept loop and signal handling keep being polled
    /// instead of freezing for the whole ~35 s apply.
    ///
    /// `block_in_place` PANICS on a current-thread runtime, so this guards the one property a
    /// unit test on a multi-core box can actually decide: the runtime `run()` builds
    /// (`new_multi_thread`) supports it, so the wraps are safe and a future switch to a
    /// current-thread runtime is caught here rather than at the first apply. The wraps
    /// themselves are verified by inspection against §3 — a live starvation repro would need a
    /// genuinely single-vCPU host: on a multi-thread runtime the `block_on` caller thread is
    /// distinct from its workers, so blocking the root future never starves the spawned tasks
    /// here (confirmed empirically while writing this).
    #[test]
    fn the_runtime_run_builds_supports_block_in_place() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let v = tokio::task::block_in_place(|| 40 + 2);
            assert_eq!(v, 42, "block_in_place must be usable in run()'s runtime");
        });
    }
}
