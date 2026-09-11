//! The flush actor: one task for the whole member that drains the neighbor table's dirty
//! queue and performs the kernel writes (gate C spec §4.1.1/§4.2, plan §4 task 3b).
//!
//! **The one rule the whole gate turns on** (spec §4.2, normative): *the actor forks no process
//! without first spending a token. A read spends one; a write spends one; a SKIP spends none
//! because it forks nothing.* Total forks are then bounded by tokens issued, by construction —
//! which is what makes R1 true against a VM forging BOOTREPLYs at wire rate. Before that rule
//! the bucket governed writes only, and a flood naming addresses the kernel already holds was
//! skipped every time while still buying a fork: a MEASURED 874 forks/s, one fully saturated
//! core, at zero token cost (spec §2).
//!
//! **The batching rule** (plan §1.1, normative, and the premise the whole worst-case
//! derivation rests on): the actor does not read until it holds `1 + min(dirty_depth, B - 1)`
//! tokens — the read plus every write that batch intends to fund. An actor that reads whenever
//! it holds a single token converges to one read per write, which is 1024 tokens = 102.4 s
//! against a 60 s `MIN_LEASE`: a legitimate short-lease ACK expires in the queue and R2.1 is
//! silently false with every other test green. Only the read-fork count over a full drain can
//! see it, which is what `one_read_fork_per_batch_over_a_full_drain` asserts.
//!
//! **The sweep is the sole coherence mechanism in this gate** (spec §4.3 item 4; triggers 2 and
//! 3 are both out of it), so `SWEEP` = 15 s is R2's bound outright. It runs here on the actor,
//! spends a token for its read like every other fork, and is a **diff** — it dirties only what
//! the kernel is missing or holds without an `lladdr`, so a coherent host does zero writes.
//!
//! **The dirty depth is read under the table lock and the SLEEP IS NOT.** Holding that guard
//! across a wait of up to `B / R` = 3.2 s stalls every relay upsert on the host — DHCP
//! forwarding stops (spec §4.2.3: "the relay's upsert never blocks"). The same applies to every
//! token spend, every journal line and every fork: the table lock is a leaf, taken last and
//! released before anything else happens.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::time::Instant;

use crate::workload::table::NeighborTable;
use crate::workload::writer::{NeighborIo, WriteVerb, write_argv};

/// `R`: the refill rate, in forks per second. A CONSTANT, never autotuned — the attacker sits
/// inside any feedback loop that measures cost, so a flood would shrink the budget under exactly
/// the load the budget exists to absorb (spec §4.2.2). ~1% of one core at the measured 1.0 ms
/// write (spec §2). Rack R2 may RAISE it; it may not lower it below **9.14/s** without
/// re-deriving `MIN_LEASE`, because `MIN_LEASE` = 60 s holds only while the worst-case wait
/// fits inside it: `(ceil(Σ C_i / (B - 1)) x B + sweeps) / R ≤ MIN_LEASE` gives
/// `R ≥ 548 / 60` = 9.14. Plan §1's floor of 8.89/s is derived from 533 tokens and is the
/// linear-token version of the same inequality — see `MIN_LEASE` (table.rs) for why the
/// reservation, not the token, is what the wait is made of.
pub const REFILL_PER_SEC: u32 = 10;

/// `B`: the burst. Makes R4 ("one VM booting is immediate") true on a quiet host — a lone VM
/// needs `1 + 1` = 2 tokens and a quiet host holds all 32.
pub const BURST: u32 = 32;

/// `SWEEP`: how often the actor diffs its table against the kernel. With triggers 2 and 3 both
/// out of this gate the sweep is the **sole** coherence mechanism, so this is R2's bound
/// outright — how long a live VM stays dark after the kernel loses its entry — not "the backstop
/// for when an event trigger is missing" (spec §4.3 item 4, call 5 RULED).
pub const SWEEP: Duration = Duration::from_secs(15);

/// How long one row's "entry expired before the actor reached it" journal line is suppressed
/// after it fires, per row (James, 2026-09-11, option (b)). This bounds the line at
/// declared-rows-per-window, which is the whole point: it needs no judgment about whether a row
/// "recovered", because there is no recovery inference here at all — only elapsed time. Three
/// earlier revisions each tried to infer a negative ("this row stopped expiring") from a row's
/// absence in `run_batch`'s necessarily-partial dropped list, and each was wrong in a different
/// way (host-wide flag silenced an unrelated row's first line; clearing on per-pass absence let
/// an attacker alternating two rows re-arm the line every batch; clearing only on a
/// nothing-dropped-host-wide pass let one chronically sick row mask every other row forever). A
/// time window makes both failure shapes unrepresentable: it neither over-attributes recovery
/// nor waits forever for a global "all clear" that a partial view can never honestly report.
const EXPIRY_LOG_WINDOW: Duration = Duration::from_secs(60);

/// One token's worth of time at `R`. Integer arithmetic on purpose: a float accumulator drifts,
/// and this rate is the bound `MIN_LEASE` is derived against.
const TOKEN_INTERVAL: Duration = Duration::from_millis(1_000 / REFILL_PER_SEC as u64);

/// The pre-drain kernel read: **exactly one per batch, for the WHOLE HOST, with no `dev`
/// filter** (spec §4.1.1, call 10 ruled option (a)). The `dev` filter is a cfab-side predicate
/// now, not an argv argument — matching each returned entry's `dev` against the row's leg.
/// Cheaper than the per-leg reads it replaces (1010 us against 3 x 773 us at `Σ C_i` = 512,
/// widening with row count, because process creation dominates and this pays it once), and it
/// removes row count from the `MIN_LEASE` derivation entirely.
///
/// `nud all` is load-bearing: without it a NUD_NONE entry is invisible to the listing entirely
/// (spec §2, measured), so the classifier would read it as absent, guess `add`, take EEXIST and
/// stick forever.
pub const READ_ARGV: [&str; 6] = ["ip", "-j", "neigh", "show", "nud", "all"];

/// What the actor does with one entry, decided by **one question: does the kernel hold an
/// `lladdr` for this address on this leg?** Never a list of state names — that rule was written
/// four different ways across six rounds and each list was missing a state (spec §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// No entry at all. `add … nud stale` — R2.1, restore absence.
    Add,
    /// An entry carrying no `lladdr` (FAILED, INCOMPLETE, NUD_NONE, or no `state` key at all).
    /// `replace … nud stale`: the kernel holds no MAC and `hostroutes` will not route to it, so
    /// cfab must treat it as absent too.
    Replace,
    /// An entry carrying an `lladdr`. **Nothing** — R2.2: a MAC the kernel learned beats a DHCP
    /// claim, and this branch is why a forged ACK cannot bind a live victim's address.
    Skip,
}

/// One pre-drain read of the kernel's neighbor table, indexed the way the classifier asks
/// about it.
pub struct KernelNeighbors {
    /// `(dev, dst)` -> does the entry carry an `lladdr`.
    by_key: HashMap<(String, Ipv4Addr), bool>,
}

impl KernelNeighbors {
    /// Parse one `ip -j neigh show nud all` document.
    ///
    /// `None` means **the document could not be read**, which is never the same thing as an
    /// empty kernel: a failed read is not evidence that every entry is missing, and treating it
    /// as one turns a transient error into a full re-write of the table (spec §4.1.1(c)). An
    /// EMPTY array is a real answer and parses to an empty map. A non-empty array none of whose
    /// entries carry a `dst` is an iproute2 that spells its keys otherwise — unreadable, the
    /// same fail-loud shape `hostroutes::local_vms` uses on the same document.
    pub fn parse(json: &str) -> Option<Self> {
        let doc: Value = serde_json::from_str(json).ok()?;
        let arr = doc.as_array()?;
        let mut by_key = HashMap::new();
        let mut understood = 0usize;
        for e in arr {
            let Some(dst) = e["dst"].as_str() else {
                continue;
            };
            understood += 1;
            // Every leg carries an fe80:: neighbor; it has a `dst` (so it is understood) and is
            // simply not an address this pipeline ever claims.
            let Ok(dst) = dst.parse::<Ipv4Addr>() else {
                continue;
            };
            let Some(dev) = e["dev"].as_str() else {
                continue;
            };
            by_key.insert((dev.to_string(), dst), e["lladdr"].as_str().is_some());
        }
        if understood == 0 && !arr.is_empty() {
            return None;
        }
        Some(KernelNeighbors { by_key })
    }

    /// **A row whose leg appears nowhere in the document has NO entry, and that is the `add`
    /// branch** — not a read failure. This is the one misreading the unfiltered read makes
    /// possible, and getting it wrong is a silent R2.1 hole with the fork-count assertion still
    /// green.
    pub fn classify(&self, leg: &str, addr: Ipv4Addr) -> Class {
        match self.by_key.get(&(leg.to_string(), addr)) {
            None => Class::Add,
            Some(true) => Class::Skip,
            Some(false) => Class::Replace,
        }
    }
}

/// The host-wide token bucket. **One for the whole member**, not one per row: with a per-row
/// bucket, N rows spend N x `R` forks/s of the host's CPU, which is the same mistake the table
/// cap corrects for the table budget. Not a ladder either — a ladder hands the attacker control
/// of legitimate latency by pinning the actor at its slowest rung.
pub struct Bucket {
    tokens: u32,
    /// When the next token lands. Advanced by whole `TOKEN_INTERVAL`s so the rate cannot drift.
    next_token_at: Instant,
}

impl Bucket {
    pub fn new(now: Instant) -> Self {
        Bucket {
            tokens: BURST,
            next_token_at: now + TOKEN_INTERVAL,
        }
    }

    fn refill(&mut self, now: Instant) {
        while self.tokens < BURST && now >= self.next_token_at {
            self.tokens += 1;
            self.next_token_at += TOKEN_INTERVAL;
        }
        // A full bucket banks nothing: an idle hour must not buy an hour's worth of forks.
        if self.tokens >= BURST && now >= self.next_token_at {
            self.next_token_at = now + TOKEN_INTERVAL;
        }
    }

    pub fn level(&mut self, now: Instant) -> u32 {
        self.refill(now);
        self.tokens
    }

    /// Spend one token, or refuse. Every fork the actor makes goes through here first.
    pub fn spend(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// How long until `want` tokens are available. `want` never exceeds `BURST`, because the
    /// batching rule asks for `1 + min(depth, B - 1)`.
    pub fn wait_for(&mut self, now: Instant, want: u32) -> Duration {
        self.refill(now);
        if self.tokens >= want {
            return Duration::ZERO;
        }
        let need = want - self.tokens;
        (self.next_token_at - now) + TOKEN_INTERVAL * (need - 1)
    }
}

/// The three things the actor does that must not happen under the table lock, made observable.
///
/// The rule's live symptom is a **hang**, not a wrong answer, which is why it needs a test and
/// not a careful reader — and why instrumenting the token spend alone is not enough: an
/// implementer could read the depth, keep the guard, sleep for a full bucket and release before
/// spending, leaving the ordering test green and DHCP forwarding stalled.
pub trait ActorObserver: Send {
    /// The actor woke and is starting a drain batch. The only hook here that is not about the
    /// table lock: it exists because "a quiet host performs no periodic work" is otherwise
    /// unobservable — an idle batch returns before it forks anything, so a polling loop in
    /// place of the sleep costs wakeups that no fork count can see.
    fn batch_start(&self) {}
    /// The actor is about to decide whether to wait for tokens — the wait site the batching
    /// rule created.
    fn wait_decision(&self) {}
    /// The actor is about to spend a token, i.e. about to fork.
    fn token_spend(&self) {}
    /// One journal line. The default is the journal: a plain `eprintln!`, never `tracing`.
    fn journal(&self, line: &str) {
        eprintln!("{line}");
    }
}

/// Production's observer: the journal, and nothing else.
pub struct Journal;

impl ActorObserver for Journal {}

/// What one batch did. Returned so a caller can drive the actor one batch at a time — which is
/// what keeps the bucket's tests deterministic and free of wall-clock time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Batch {
    /// Nothing was dirty; the actor has nothing to do until something wakes it.
    Idle,
    /// The pre-drain read failed. Nothing was taken, nothing was written, nothing was guessed.
    ReadFailed,
    /// The batch read the kernel and drained what its tokens funded.
    Drained,
}

/// What one sweep did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sweep {
    /// The read failed. **Nothing was dirtied — not everything.** A failed read is not evidence
    /// that the kernel is empty, and "failed read = empty document = everything is missing"
    /// turns one transient error into a full re-write of the table, up to `Σ C_i` = 512 forks
    /// (spec §4.1.1(c)).
    ReadFailed,
    /// The table was diffed against the kernel. `dirtied` counts the entries the kernel was
    /// missing or held with no `lladdr`; on a coherent host it is **zero**, which is what makes
    /// a 15 s period affordable at all.
    ///
    /// **Both numbers are best-effort and may disagree with `counts`/`per_row`**: an entry whose
    /// lease ends between this sweep's `remove_expired` and its own `re_dirty` is credited to
    /// `counts.expiries` but is not in `expired`, and `dirtied` counts the intent to re-queue
    /// rather than the result, so it includes that entry too. Nothing in `run()` reads either
    /// field — they exist for tests. Wire one to `/metrics` and this race becomes a wrong gauge.
    Diffed { dirtied: usize, expired: usize },
}

/// Counters the actor keeps. Exported in task 5; kept here because the task that produces a
/// counter is the one that can tell whether it moved for the right reason. `read_failures` is
/// separate from `write_failures` on purpose: a coherent host and a host that silently wrote
/// nothing look identical from the outside, which is why that defect survived six reviews.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub read_failures: u64,
    pub writes: u64,
    pub write_failures: u64,
    pub skips: u64,
    /// Table rows dropped because their lease ran out. cfab deletes no kernel entry when this
    /// moves — the row leaves cfab's table and the kernel keeps whatever it holds.
    pub expiries: u64,
}

/// The counters `Counts` cannot break down, because they happen inside the per-entry loop
/// where the row is known (spec §4.5's per-row export): `read_failures` is not here on purpose
/// — the pre-drain read is one fork for the whole host, so there is no row to credit it to, and
/// `/metrics` instead repeats the host-wide `read_failures` under every row's label (spec
/// §4.5's own words: "export per row: `read_failures`").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowCounts {
    pub writes: u64,
    pub write_failures: u64,
    pub skips: u64,
    pub expiries: u64,
}

/// What one iteration of the actor's life did — a sweep, or one drain batch. Returned so a
/// test can drive the real cadence (sweeps included, and they cost tokens) one step at a time
/// on a paused clock, rather than re-implementing the cadence beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Swept(Sweep),
    Batch(Batch),
}

/// One per host. Owns the bucket, the writer and the classifier; the table it drains is shared
/// with every relay task.
pub struct FlushActor {
    table: Arc<NeighborTable>,
    io: Box<dyn NeighborIo>,
    obs: Box<dyn ActorObserver>,
    bucket: Bucket,
    /// Set while a run of consecutive read failures is ongoing, so the line is once per streak.
    /// Without it a persistently failing read journals `R` = 10 lines a second forever: the
    /// fourth loud path, and the one the other three throttles did not cover.
    read_failing: bool,
    /// The same, per row, for write failures. There is no backoff anywhere here — the bucket is
    /// the bound, which is what let call 10's fix close the read-failure spin for free.
    write_failing: std::collections::BTreeSet<String>,
    /// The same, per row, for entries dropped because their lease ran out before the actor
    /// reached them. `MIN_LEASE` is derived so this cannot happen on a table within `Sigma C_i`,
    /// so it is loud — and loud at most once per `EXPIRY_LOG_WINDOW` per row, because the
    /// trigger is attacker-reachable. **Per row, not host-wide, for the same reason
    /// `write_failing` is:** one row in a continuous streak must not swallow another row's first
    /// line, which is the whole signal that a second row started losing entries.
    /// **Only the KEYING is shared. `write_failing` clears on a completed write because that is
    /// positive evidence about that row; nothing on the expiry path carries equivalent news, and
    /// copying its clear-on-success shape here is exactly the defect that failed twice.**
    ///
    /// Maps row -> the time its line was last journaled. A time window, not a streak flag or a
    /// set cleared on absence: see `EXPIRY_LOG_WINDOW` for why every absence-based shape tried
    /// here before was wrong.
    expiring: std::collections::BTreeMap<String, Instant>,
    /// When the next coherence sweep is due. Measured from the end of the last one, so a sweep
    /// that had to wait for a token cannot make the next one due the instant it finishes.
    next_sweep: Instant,
    pub counts: Counts,
    /// The per-row half of `counts` (spec §4.5). Kept alongside it rather than instead of it:
    /// `counts` is the host-wide total every earlier task's tests already assert against, and
    /// splitting it by row here is additive, not a replacement.
    per_row: std::collections::BTreeMap<String, RowCounts>,
    /// Where this actor republishes its state for `/metrics` (spec §4.5), if anywhere. `None`
    /// in every test that does not call `with_shared` — every test but the two in this module
    /// that construct a `Shared` on purpose to check what lands in it — so the whole rest of
    /// this file's tests, which drive `step`/`run_batch`/`sweep` directly, are unaffected.
    shared: Option<Arc<Mutex<crate::supervisor::Shared>>>,
}

impl FlushActor {
    pub fn new(table: Arc<NeighborTable>, io: Box<dyn NeighborIo>) -> Self {
        Self::with_observer(table, io, Box::new(Journal))
    }

    pub fn with_observer(
        table: Arc<NeighborTable>,
        io: Box<dyn NeighborIo>,
        obs: Box<dyn ActorObserver>,
    ) -> Self {
        let now = Instant::now();
        FlushActor {
            table,
            io,
            obs,
            bucket: Bucket::new(now),
            read_failing: false,
            write_failing: std::collections::BTreeSet::new(),
            expiring: std::collections::BTreeMap::new(),
            next_sweep: now + SWEEP,
            counts: Counts::default(),
            per_row: std::collections::BTreeMap::new(),
            shared: None,
        }
    }

    /// Wire in where `run` republishes this actor's counters (spec §4.5). Additive on the
    /// builder so every existing constructor call and every test that never calls this keeps
    /// building the exact `FlushActor` it always has.
    pub(crate) fn with_shared(mut self, shared: Arc<Mutex<crate::supervisor::Shared>>) -> Self {
        self.shared = Some(shared);
        self
    }

    /// The actor's whole life: sweep when one is due, drain when anything is dirty, and sleep
    /// otherwise — until an upsert wakes it or the next sweep falls due, whichever comes first.
    /// Never returns.
    pub async fn run(mut self) {
        loop {
            let step = self.step().await;
            self.publish();
            if let Step::Batch(Batch::Idle) = step {
                let table = self.table.clone();
                let next_sweep = self.next_sweep;
                tokio::select! {
                    _ = table.wait_dirty() => {}
                    _ = tokio::time::sleep_until(next_sweep) => {}
                }
            }
        }
    }

    /// Republish this actor's state into `Shared` for `/metrics` (spec §4.5), after every batch
    /// and every sweep. A no-op unless production wired a `Shared` in via `with_shared`.
    ///
    /// The row list is the union of every row `per_row` has touched (a write, a write failure,
    /// a skip or an expiry) and every row the table currently has entries or cap refusals for —
    /// a row that has done none of those legitimately reports nothing, the same absence
    /// convention every other row-keyed `/metrics` family in this codebase uses. `read_failures`
    /// is host-wide (one pre-drain read per batch, for every row at once) and is repeated under
    /// every row in the union, which is what spec §4.5 asks for by naming it "per row" even
    /// though nothing about the read itself is row-scoped.
    fn publish(&mut self) {
        let Some(shared) = self.shared.clone() else {
            return;
        };
        let sizes = self.table.row_sizes();
        let refusals = self.table.cap_refusals_snapshot();
        let mut rows: std::collections::BTreeMap<
            String,
            crate::supervisor::report::NeighborRowInfo,
        > = std::collections::BTreeMap::new();
        for name in sizes
            .keys()
            .chain(refusals.keys())
            .chain(self.per_row.keys())
        {
            rows.entry(name.clone()).or_insert_with(|| {
                crate::supervisor::report::NeighborRowInfo {
                    name: name.clone(),
                    ..Default::default()
                }
            });
        }
        for (name, size) in &sizes {
            rows.get_mut(name).unwrap().table_size = *size;
        }
        for (name, n) in &refusals {
            rows.get_mut(name).unwrap().cap_refusals = *n;
        }
        for (name, c) in &self.per_row {
            let r = rows.get_mut(name).unwrap();
            r.writes = c.writes;
            r.write_failures = c.write_failures;
            r.skips = c.skips;
            r.expiries = c.expiries;
        }
        for r in rows.values_mut() {
            r.read_failures = self.counts.read_failures;
        }
        let now = Instant::now();
        let host = crate::supervisor::report::NeighborActorInfo {
            dirty_depth: self.table.dirty_depth() as u64,
            oldest_dirty_age_seconds: self
                .table
                .oldest_dirty_age(now.into_std())
                .map(|d| d.as_secs_f64()),
            token_level: self.bucket.level(now),
        };
        shared
            .lock()
            .unwrap()
            .publish_neighbor(rows.into_values().collect(), host);
    }

    /// One iteration: the sweep if it is due, otherwise one drain batch. The sweep runs **on
    /// the actor** and therefore spends a token like any other fork (spec §4.2) — which is
    /// where the sweep tokens in `MIN_LEASE`'s worst-case derivation come from (plan §1.2). On the command loop via `Sys::run` it would instead be a fork on
    /// exactly the loop this gate exists to keep clear, and would escape `WRITE_DEADLINE`,
    /// which is scoped to every child the actor spawns.
    pub async fn step(&mut self) -> Step {
        if Instant::now() >= self.next_sweep {
            let swept = self.sweep().await;
            self.next_sweep = Instant::now() + SWEEP;
            return Step::Swept(swept);
        }
        Step::Batch(self.run_batch().await)
    }

    /// The coherence sweep (trigger 4): **a DIFF, never a blind re-dirty.** r4 specified
    /// "re-dirty every unexpired row", which on a quiet host with a full /24 is 254 forks a
    /// minute forever and makes a VM booting just after a sweep wait behind up to 254 FIFO
    /// entries — the table's whole steady-state cost set by the attacker's entry count.
    ///
    /// It issues the **same argv** as the drain's read and never the same **document**: a
    /// sweep's document is stale by the time a drain runs, and classifying a write against it
    /// is the exact stale-read window this design deleted the published snapshot to close
    /// (spec §10, r13). It dirties only what the kernel is missing or holds without an
    /// `lladdr`, removes expired **table rows**, **deletes no kernel entry**, and **extends no
    /// expiry**.
    pub async fn sweep(&mut self) -> Sweep {
        // Expiry is cfab's own clock, not the kernel's: it is reaped before the read and
        // therefore even when the read fails. A row whose lease ran out must not hold its slot
        // against the cap for as long as the kernel happens to be unreadable.
        let mut dropped = self.table.remove_expired(Instant::now().into_std());
        let expired = dropped.len();

        self.wait_and_spend(1).await;
        let Some(doc) = self.read_kernel() else {
            self.note_expiries(&dropped, Instant::now());
            return Sweep::ReadFailed;
        };

        let now = Instant::now();
        let now_std = now.into_std();
        let mut dirtied = 0usize;
        for (row, addr, leg) in self.table.list_entries() {
            match doc.classify(&leg, addr) {
                // R2.2 again, and for the same reason as in the drain: a MAC the kernel holds
                // is never something cfab schedules a write over.
                Class::Skip => {}
                Class::Add | Class::Replace => {
                    // The verb is not decided here. The drain re-reads and classifies at write
                    // time; all the sweep says is "this one needs looking at".
                    // A `None` here means the entry expired between this sweep's own
                    // `remove_expired` and now, and was dropped rather than queued.
                    dropped.extend(self.table.re_dirty(&row, addr, now_std));
                    dirtied += 1;
                }
            }
        }
        self.note_expiries(&dropped, now);
        Sweep::Diffed { dirtied, expired }
    }

    /// Credit every entry that left the table because its lease ran out, and say so **at most
    /// once per `EXPIRY_LOG_WINDOW` per row**. Both places an entry can expire report here: the
    /// sweep's `remove_expired`, and the drain's own take and put-back — a drop on the drain
    /// path used to be credited nowhere at all, so `cfab_workload_neighbor_expiries` was blind
    /// to exactly the path a flood travels and a row could vanish with no counter and no line.
    ///
    /// `MIN_LEASE` is derived so that an entry inside `Sigma C_i` cannot expire before the
    /// actor reaches it, which makes this loud by construction: if it moves on the drain path,
    /// a premise of that derivation is wrong. Throttled by row and by time, never by inferring a
    /// row "recovered" from its absence in this pass's necessarily-partial `rows` list — the
    /// window needs no such judgment at all, which is the entire point of `EXPIRY_LOG_WINDOW`.
    fn note_expiries(&mut self, rows: &[String], now: Instant) {
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for row in rows {
            self.per_row.entry(row.clone()).or_default().expiries += 1;
            seen.insert(row.as_str());
        }
        self.counts.expiries += rows.len() as u64;
        // A row is fresh iff it has never been journaled, or its last line is at least a full
        // window old. `duration_since` saturates rather than panicking when `now` is not after
        // `last` (tokio's guarantee), so equal instants read as "not yet due" rather than
        // underflowing.
        let fresh: Vec<&str> = seen
            .into_iter()
            .filter(|row| match self.expiring.get(*row) {
                None => true,
                Some(last) => now.duration_since(*last) >= EXPIRY_LOG_WINDOW,
            })
            .collect();
        if fresh.is_empty() {
            return;
        }
        // The count and the row list must describe the SAME set, or a reader attributes every
        // drop this pass to whichever row happened to be fresh.
        let counted = rows.iter().filter(|r| fresh.contains(&r.as_str())).count();
        for row in &fresh {
            self.expiring.insert((*row).to_string(), now);
        }
        self.obs.journal(&format!(
            "cfab: dhcp neighbor actor: {} table entry/entries expired before the write; \
             the workload row(s): {}",
            counted,
            fresh.join(", ")
        ));
    }

    /// Wait until the bucket holds `want` tokens, then spend one of them for the fork that is
    /// about to happen. **The wait is never under the table lock** — holding that guard across
    /// a wait of up to `B / R` = 3.2 s blocks every relay upsert on the host, which is DHCP
    /// forwarding stopping.
    async fn wait_and_spend(&mut self, want: u32) {
        loop {
            self.obs.wait_decision();
            let wait = self.bucket.wait_for(Instant::now(), want);
            if wait.is_zero() {
                self.obs.token_spend();
                if self.bucket.spend(Instant::now()) {
                    return;
                }
            } else {
                tokio::time::sleep(wait).await;
            }
        }
    }

    /// One `ip -j neigh show nud all`, its failures counted and journaled once per streak.
    ///
    /// `None` is **"the kernel could not be read"**, and it is never the same answer as an
    /// empty kernel — in the drain (write nothing, take nothing, keep every queue position) or
    /// in the sweep (dirty nothing). The token for the fork is already spent by the caller, so
    /// a fast-failing read cannot spin: the bucket is the bound, and there is no backoff
    /// anywhere.
    fn read_kernel(&mut self) -> Option<KernelNeighbors> {
        let doc = match self.io.run(&READ_ARGV) {
            Ok(o) if o.ok() => KernelNeighbors::parse(&o.stdout)
                .ok_or_else(|| "cannot read the neighbor document".to_string()),
            Ok(o) => Err(format!("ip exited {}: {}", o.status, o.stderr.trim())),
            Err(e) => Err(e.to_string()),
        };
        match doc {
            Ok(doc) => {
                self.read_failing = false;
                Some(doc)
            }
            Err(why) => {
                self.counts.read_failures += 1;
                if !self.read_failing {
                    self.read_failing = true;
                    self.obs.journal(&format!(
                        "cfab: dhcp neighbor actor: kernel read failed: {why}; nothing written \
                         and nothing dirtied this pass"
                    ));
                }
                None
            }
        }
    }

    /// One batch: wait for the tokens this batch intends to spend, read the kernel once, then
    /// drain in queue order.
    pub async fn run_batch(&mut self) -> Batch {
        self.obs.batch_start();
        // Under the lock for exactly this long. The wait below is NOT.
        let depth = self.table.dirty_depth();
        if depth == 0 {
            return Batch::Idle;
        }
        let want = 1 + u32::try_from(depth).unwrap_or(u32::MAX).min(BURST - 1);

        // The read is a fork, so it spends a token like any other (spec §4.2). This is also
        // what makes the read-failure path below unable to spin: a batch whose read fails has
        // already paid for it.
        self.wait_and_spend(want).await;
        // Nothing was taken — **take follows the read, never precedes it** — so on a failed
        // read every entry keeps its queue position and the next batch retries. The actor does
        // not guess: a failed read is the one case where neither `add` nor `replace` can be
        // justified.
        let Some(doc) = self.read_kernel() else {
            return Batch::ReadFailed;
        };

        // At most `B - 1` entries per batch: that is what the batch reserved tokens for. A skip
        // costs no token but still counts against this, so a queue of nothing but skips is
        // bounded to one read fork per batch rather than spinning.
        let mut handled = 0u32;
        // One address gets at most one write per batch, and anything put back waits for the
        // NEXT batch — which re-reads. Retrying inside this batch would classify the retry
        // against a document that is now known to be wrong about that address, which is the
        // stale-read window this design deleted the published snapshot to close.
        let mut seen: std::collections::HashSet<(String, Ipv4Addr)> =
            std::collections::HashSet::new();
        let mut put_back: Vec<(String, Ipv4Addr)> = Vec::new();
        // Entries the take and the put-back below DROPPED because their lease ran out. Both
        // arms report rather than discard; `note_expiries` credits them once, at the end.
        let mut dropped: Vec<String> = Vec::new();
        while handled < BURST - 1 {
            let now_std = Instant::now().into_std();
            let next = self.table.take_next_dirty(now_std);
            dropped.extend(next.expired);
            let Some(t) = next.taken else {
                break;
            };
            handled += 1;
            let key = (t.row.clone(), t.addr);
            if !seen.insert(key.clone()) {
                // An upsert re-claimed this address while the batch was running. Its claim is
                // real and must not be lost, but it belongs to the next read.
                put_back.push(key);
                continue;
            }
            let verb = match doc.classify(&t.leg, t.addr) {
                Class::Skip => {
                    self.counts.skips += 1;
                    self.per_row.entry(t.row.clone()).or_default().skips += 1;
                    continue;
                }
                Class::Add => WriteVerb::Add,
                Class::Replace => WriteVerb::Replace,
            };
            self.obs.token_spend();
            if !self.bucket.spend(Instant::now()) {
                // Only reachable when upserts arrived AFTER this batch sized its reservation,
                // so the entry going back on the queue is one that was not in it when the batch
                // started.
                put_back.push(key);
                break;
            }
            let argv = write_argv(verb, t.addr, t.mac, &t.leg);
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            // **Every non-zero exit is a failure, EEXIST included.** No string match on stderr,
            // ever again: the actor read the kernel milliseconds ago, so EEXIST can only be a
            // race inside that window, and re-dirtying re-reads and does the right thing on the
            // next batch — strictly faster than the EEXIST-as-success rule it replaces.
            let failure = match self.io.run(&argv) {
                Ok(o) if o.ok() => None,
                Ok(o) => Some(format!("ip exited {}: {}", o.status, o.stderr.trim())),
                Err(e) => Some(e.to_string()),
            };
            match failure {
                None => {
                    self.counts.writes += 1;
                    self.per_row.entry(t.row.clone()).or_default().writes += 1;
                    self.write_failing.remove(&t.row);
                }
                Some(why) => {
                    self.counts.write_failures += 1;
                    self.per_row
                        .entry(t.row.clone())
                        .or_default()
                        .write_failures += 1;
                    if self.write_failing.insert(t.row.clone()) {
                        self.obs.journal(&format!(
                            "cfab: workload {}: neighbor write for {} failed: {why}",
                            t.row, t.addr
                        ));
                    }
                    put_back.push(key);
                }
            }
        }
        // Put everything back AFTER the batch, never during it: an entry re-dirtied here is
        // queued for the next read, and an entry an upsert already re-queued keeps the place
        // that upsert gave it.
        let now = Instant::now();
        let now_std = now.into_std();
        for (row, addr) in put_back {
            dropped.extend(self.table.re_dirty(&row, addr, now_std));
        }
        self.note_expiries(&dropped, now);
        Batch::Drained
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::table::{CapBound, GC_THRESH3_DEFAULT, RowCap};
    use crate::workload::writer::mock::MockNeighborIo;
    use std::sync::Mutex;

    const ROW: &str = "vms";
    const LEG: &str = "cfab-work-vms";
    const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

    fn cap(value: u32) -> RowCap {
        RowCap {
            value,
            bound_by: CapBound::GcThresh3,
            gc_thresh3: GC_THRESH3_DEFAULT,
            rows: 1,
        }
    }

    fn addr(n: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 9, 0, 0)) + n + 1)
    }

    /// A lease long enough that no test trips over expiry unless it means to.
    fn long() -> std::time::Instant {
        Instant::now().into_std() + Duration::from_secs(3600)
    }

    fn table_with(n: u32) -> Arc<NeighborTable> {
        let t = Arc::new(NeighborTable::new());
        for i in 0..n {
            t.upsert(
                ROW,
                LEG,
                addr(i),
                MAC_A,
                long(),
                &cap(u32::MAX),
                Instant::now().into_std(),
            );
        }
        t
    }

    /// Every argv the io was asked to run that is a kernel READ.
    fn reads(calls: &[Vec<String>]) -> Vec<Vec<String>> {
        calls
            .iter()
            .filter(|c| c.get(3).map(String::as_str) == Some("show"))
            .cloned()
            .collect()
    }

    /// Every argv that is a WRITE.
    fn writes(calls: &[Vec<String>]) -> Vec<Vec<String>> {
        calls
            .iter()
            .filter(|c| {
                matches!(c.get(2).map(String::as_str), Some("add") | Some("replace"))
                    && c.first().map(String::as_str) == Some("ip")
            })
            .cloned()
            .collect()
    }

    /// An `ip -j neigh show nud all` document holding `entries` as `(dev, dst, lladdr)`.
    fn kernel_doc(entries: &[(&str, Ipv4Addr, Option<&str>)]) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|(dev, dst, lladdr)| match lladdr {
                Some(l) => format!(
                    r#"{{"dst":"{dst}","dev":"{dev}","lladdr":"{l}","state":["REACHABLE"]}}"#
                ),
                None => format!(r#"{{"dst":"{dst}","dev":"{dev}","state":["FAILED"]}}"#),
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    // ---- the classifier: one question, asked of an unfiltered document --------------------

    /// **T6.** A REACHABLE entry the kernel learned always wins: an upsert claiming a DIFFERENT
    /// MAC produces **no write at all**. This is R2.2 and the reason a forged ACK cannot bind a
    /// live victim's address.
    ///
    /// Regression: make `classify` return `Class::Replace` for `Some(true)` (the unconditional
    /// `replace` r4 shipped).
    #[tokio::test(start_paused = true)]
    async fn the_kernels_valid_entry_always_wins() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_B,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let doc = kernel_doc(&[(LEG, addr(0), Some("aa:bb:cc:dd:ee:ff"))]);
        let io = MockNeighborIo::kernel(&doc);
        let calls = io.calls();
        let mut a = FlushActor::new(t, Box::new(io));
        a.run_batch().await;
        let calls = calls.lock().unwrap().clone();
        assert!(
            writes(&calls).is_empty(),
            "a MAC the kernel learned beats a DHCP claim: {calls:?}"
        );
        assert_eq!(a.counts.skips, 1);
    }

    /// **T6a.** The two branches are **not interchangeable**, and both argvs are asserted: a
    /// FAILED entry (no `lladdr`) takes `replace … nud stale`; no entry at all takes
    /// `add … nud stale`. `add` is the create-only rule's enforcement inside the read-to-write
    /// window — a collapsed `replace` overwrites a MAC the kernel just learned from the VM
    /// itself, and passes every other test in this file.
    ///
    /// Regression: return `Class::Replace` from `classify`'s `None` arm (the collapse), and
    /// watch the `add` assertion fail while everything else stays green.
    #[tokio::test(start_paused = true)]
    async fn a_non_valid_entry_is_absent_and_the_verb_says_which() {
        // FAILED -> replace.
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = MockNeighborIo::kernel(&kernel_doc(&[(LEG, addr(0), None)]));
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), 1, "{w:?}");
        assert_eq!(w[0][2], "replace", "{:?}", w[0]);
        assert!(w[0].windows(2).any(|p| p == ["nud", "stale"]), "{:?}", w[0]);

        // Absent -> add.
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), 1, "{w:?}");
        assert_eq!(w[0][2], "add", "{:?}", w[0]);
        assert!(w[0].windows(2).any(|p| p == ["nud", "stale"]), "{:?}", w[0]);
    }

    /// **T6d.** The NUD_NONE shape spec §2 measured — `{"dst": …}` with no `state` and no
    /// `lladdr` — is treated as absent-of-MAC and takes the replace path.
    ///
    /// Regression: classify by matching known-bad state names (`FAILED`/`INCOMPLETE`) instead
    /// of by the presence of `lladdr`; a NUD_NONE entry then matches none of them and is
    /// skipped forever.
    #[tokio::test(start_paused = true)]
    async fn an_entry_with_no_lladdr_is_treated_as_absent() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let doc = format!(r#"[{{"dst":"{}","dev":"{LEG}"}}]"#, addr(0));
        let io = MockNeighborIo::kernel(&doc);
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), 1, "{w:?}");
        assert_eq!(
            w[0][2], "replace",
            "a bare dst is no MAC, so cfab may write"
        );
    }

    /// **T6f.** A NOARP entry — an operator's hand-pinned neighbor, absent from `RESOLVED` —
    /// carries a real MAC (spec §2, measured) and is **never touched**. Fourth appearance of one
    /// defect; the test exists so there is not a fifth.
    ///
    /// Regression: classify by `state ∩ RESOLVED ≠ ∅` (r6's rule), which overwrites exactly the
    /// entry the operator went out of their way to install.
    #[tokio::test(start_paused = true)]
    async fn a_noarp_entry_is_never_touched() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_B,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let doc = format!(
            r#"[{{"dst":"{}","dev":"{LEG}","lladdr":"aa:bb:cc:dd:ee:ff","state":["NOARP"]}}]"#,
            addr(0)
        );
        let io = MockNeighborIo::kernel(&doc);
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        assert!(
            writes(&calls.lock().unwrap()).is_empty(),
            "NOARP carries an lladdr, and the rule is the lladdr — never the state list"
        );
    }

    /// **T6e.** The read argv asks for `nud all`. Drop it and a NUD_NONE entry is invisible, so
    /// `an_entry_with_no_lladdr_is_treated_as_absent` cannot fire at all — which is exactly how
    /// this defect hides.
    ///
    /// Regression: remove `"nud", "all"` from `READ_ARGV`.
    #[tokio::test(start_paused = true)]
    async fn the_read_asks_for_nud_all() {
        let t = table_with(1);
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let r = reads(&calls.lock().unwrap());
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].windows(2).any(|p| p == ["nud", "all"]), "{:?}", r[0]);
    }

    /// **T3b, argv half.** Rows on three different legs in one batch: **exactly one read fork,
    /// its argv carrying no `dev`**, and all three rows still classified correctly from that
    /// one document.
    ///
    /// Regression 1: read per row — the fork count goes to 3.
    /// Regression 2: re-add `"dev", <leg>` to `READ_ARGV` (per row it cannot be, so: append the
    /// first taken entry's leg) — the fork count STAYS 1 and every other test stays green, so
    /// this argv assertion is the only thing standing between the ruling and a silent revert.
    #[tokio::test(start_paused = true)]
    async fn one_unfiltered_read_fork_per_batch_across_legs() {
        let t = Arc::new(NeighborTable::new());
        for (row, leg) in [("a", "leg-a"), ("b", "leg-b"), ("c", "leg-c")] {
            t.upsert(
                row,
                leg,
                addr(0),
                MAC_A,
                long(),
                &cap(10),
                Instant::now().into_std(),
            );
        }
        let doc = kernel_doc(&[
            ("leg-a", addr(0), Some("aa:bb:cc:dd:ee:01")),
            ("leg-b", addr(0), None),
        ]);
        let io = MockNeighborIo::kernel(&doc);
        let calls = io.calls();
        let mut a = FlushActor::new(t, Box::new(io));
        a.run_batch().await;
        let calls = calls.lock().unwrap().clone();

        let r = reads(&calls);
        assert_eq!(
            r.len(),
            1,
            "one read for the whole host, not one per row: {r:?}"
        );
        assert!(
            !r[0].iter().any(|w| w == "dev"),
            "the dev filter is a cfab-side predicate, never an argv argument: {:?}",
            r[0]
        );
        let w = writes(&calls);
        assert_eq!(
            w.len(),
            2,
            "leg-a is valid and skipped; b and c are written: {w:?}"
        );
        assert_eq!(w[0][2], "replace", "leg-b holds an entry with no lladdr");
        assert_eq!(w[0][7], "leg-b");
        assert_eq!(
            w[1][2], "add",
            "leg-c appears nowhere in the document: that is ABSENT, not a read failure"
        );
        assert_eq!(w[1][7], "leg-c");
        assert_eq!(a.counts.skips, 1);
    }

    /// **T3c.** A row whose leg is absent from the unfiltered document takes the `add` branch,
    /// and **no retry is scheduled** — the entry is written and left clean, not queued again.
    ///
    /// Regression: treat an empty per-row filter result as a failed read (return `ReadFailed`
    /// when `classify` finds nothing for the leg), whereupon the row is never written, the
    /// failure is silent, and the one-read-per-batch assertion stays green.
    #[tokio::test(start_paused = true)]
    async fn an_absent_leg_is_the_add_branch_and_schedules_no_retry() {
        let t = Arc::new(NeighborTable::new());
        t.upsert(
            "busy",
            "leg-busy",
            addr(5),
            MAC_B,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let doc = kernel_doc(&[("leg-busy", addr(5), Some("aa:bb:cc:dd:ee:01"))]);
        let io = MockNeighborIo::kernel(&doc);
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        assert_eq!(a.run_batch().await, Batch::Drained);
        let calls = calls.lock().unwrap().clone();
        let w = writes(&calls);
        assert_eq!(w.len(), 1, "{w:?}");
        assert_eq!(w[0][2], "add");
        assert_eq!(
            a.counts.read_failures, 0,
            "an absent leg is not a read failure"
        );
        assert_eq!(t.dirty_depth(), 0, "a written entry schedules no retry");
        assert_eq!(
            reads(&calls).len(),
            1,
            "and no second read is issued for it"
        );
    }

    // ---- the fork-token rule and the batching rule ----------------------------------------

    /// **T3a — the bucket counts FORKS, not writes.** Every address here is one the kernel
    /// already holds VALID, so **zero writes are issued** and every entry is skipped — and the
    /// fork rate is still bounded by `R`, because the read spends a token like any other fork.
    ///
    /// Regression: spend tokens on writes only (delete the read's `self.bucket.spend(...)` and
    /// drop the read's token from `want`). Every batch then costs nothing, the bucket never
    /// drains because nothing writes, and the actor reads as fast as it can fork — a MEASURED
    /// 874 forks/s (spec §2), with the write-rate test below still passing. That is exactly how
    /// the defect hid.
    #[tokio::test(start_paused = true)]
    async fn the_bucket_bounds_forks_even_when_every_entry_is_skipped() {
        let n = 200u32;
        let t = table_with(n);
        let entries: Vec<(&str, Ipv4Addr, Option<&str>)> = (0..n)
            .map(|i| (LEG, addr(i), Some("aa:bb:cc:dd:ee:ff")))
            .collect();
        let io = MockNeighborIo::kernel(&kernel_doc(&entries));
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));

        let started = Instant::now();
        const BATCHES: u32 = 40;
        for _ in 0..BATCHES {
            // The queue never empties: the relay keeps claiming what the kernel already holds.
            for i in 0..n {
                t.upsert(
                    ROW,
                    LEG,
                    addr(i),
                    MAC_A,
                    long(),
                    &cap(u32::MAX),
                    Instant::now().into_std(),
                );
            }
            a.run_batch().await;
        }
        let elapsed = started.elapsed();
        let calls = calls.lock().unwrap().clone();

        assert!(writes(&calls).is_empty(), "every address is already valid");
        let forks = calls.len() as u32;
        assert_eq!(forks, BATCHES, "one read fork per batch");
        // tokens spent <= burst + R * elapsed, which is the bucket's whole guarantee.
        let allowed = BURST + REFILL_PER_SEC * elapsed.as_secs() as u32 + REFILL_PER_SEC;
        assert!(
            forks <= allowed,
            "{forks} forks in {elapsed:?} exceeds the bucket's {allowed}"
        );
        // And the teeth: without the read's token this loop costs no virtual time at all.
        let floor =
            Duration::from_millis(u64::from(BATCHES - BURST) * 1000 / u64::from(REFILL_PER_SEC));
        assert!(
            elapsed >= floor,
            "{BATCHES} skip-only batches must have WAITED on the bucket: {elapsed:?} < {floor:?}"
        );
    }

    /// **T3 — the bucket is a ceiling on writes too.** N distinct addresses the kernel holds
    /// nothing for: the write rate never exceeds `R` once the burst is spent.
    ///
    /// Regression: remove the bucket (make `wait_for` return `Duration::ZERO` and `spend`
    /// return `true` unconditionally) and watch the whole queue drain in zero virtual time.
    #[tokio::test(start_paused = true)]
    async fn the_write_rate_never_exceeds_the_refill() {
        let n = 300u32;
        let t = table_with(n);
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t, Box::new(io));
        let started = Instant::now();
        while a.counts.writes < u64::from(n) {
            a.run_batch().await;
        }
        let elapsed = started.elapsed();
        let forks = calls.lock().unwrap().len() as u32;
        let allowed = BURST + REFILL_PER_SEC * (elapsed.as_millis() as u32).div_ceil(1000);
        assert!(
            forks <= allowed,
            "{forks} forks in {elapsed:?} exceeds burst + R x t = {allowed}"
        );
    }

    /// **T3b, the batching half — the only assertion in the suite that can see plan §1.1
    /// violated.** Over a full drain of `Σ C_i` = 512 entries the total read forks must be at
    /// most `ceil(512 / (B - 1))` = **17**, which is the `529 = 512 writes + 17 reads` the
    /// ruling's `MIN_LEASE` derivation rests on.
    ///
    /// Regression: read whenever one token is available (`let want = 1;`). The actor then
    /// converges to one read per write — 512 reads here — which is 1024 tokens = 102.4 s
    /// against a 60 s `MIN_LEASE`, with T3, T3a, T4 and every classifier test still green.
    #[tokio::test(start_paused = true)]
    async fn one_read_fork_per_batch_over_a_full_drain() {
        const SIGMA_C: u32 = 512;
        let t = table_with(SIGMA_C);
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        while a.run_batch().await != Batch::Idle {}
        let calls = calls.lock().unwrap().clone();

        assert_eq!(a.counts.writes, u64::from(SIGMA_C));
        let want = SIGMA_C.div_ceil(BURST - 1);
        assert_eq!(want, 17, "ceil(512 / 31), the ruling's own read count");
        assert!(
            reads(&calls).len() <= want as usize,
            "{} read forks over a full drain; the batching rule allows {want}",
            reads(&calls).len()
        );
    }

    /// **T4 — no starvation, and the number is stated.** 511 entries are re-dirtied after every
    /// batch; the 512th (the highest address, dirtied first) must still be written inside the
    /// worst case — which the sweep moved, because the sweep runs on this actor and its read
    /// spends a token like every other fork:
    ///
    /// The entry at the back of a `Σ C_i` = 512 queue is reached in batch
    /// `ceil(Σ C_i / (B - 1))` = 17, and the batching rule makes the actor **wait for that
    /// batch's whole reservation of `B` = 32 tokens before it starts it** — including the
    /// tokens it will spend on entries queued behind the victim. So the wait is governed by
    /// tokens RESERVED, not by tokens spent on the victim's own path:
    ///
    /// `(ceil(Σ C_i / (B - 1)) x B + sweeps) / R` = `(17 x 32 + 4) / 10` = **54.8 s**, where
    /// the 4 is one read per sweep in the window (`ceil(54.8 / SWEEP)`; self-consistent).
    /// `MIN_LEASE` = 60 s still clears it, with an 8.7% margin.
    ///
    /// **This corrects plan §1.2's 533 tokens / 53.3 s, which is reported as an erratum rather
    /// than fixed silently.** §1.2 converts tokens to seconds linearly — 512 writes + 17 drain
    /// reads + 4 sweeps — but the batching rule §1.1 itself introduced means a batch is not
    /// started until its full reservation is in hand. 512 does not divide by `B - 1` = 31, and
    /// the sweep keeps `dirty_depth` above `B - 1` whenever the kernel is missing entries, so
    /// the batch carrying the victim reserves a full 32 rather than the 17 the linear model
    /// assumes. MEASURED on this tree at 54.7 s (three sweeps, the actor's first falling at
    /// `SWEEP` rather than at t = 0); 54.8 s is the bound that also covers a sweep at t = 0.
    ///
    /// The loop drives `step`, not `run_batch`, precisely so those sweep tokens are spent: an
    /// actor driven batch-by-batch never sweeps, and the bound it measures is one no live
    /// member enjoys.
    ///
    /// **Honest scope, MEASURED rather than assumed.** The victim here is dirtied FIRST, so
    /// FIFO reaches it in the first batch and the elapsed time is **0** — the deadline above is
    /// the bound written down, not a bound this test exercises. What it genuinely pins is the
    /// starvation rule: under the regression below the victim is never written at all and the
    /// in-loop assertion fires. The test that actually measures the worst case is
    /// `a_min_lease_entry_survives_the_full_queue_and_is_written`, whose victim is dirtied
    /// LAST; it comes in at 54.7 s against this same 54.8 s.
    ///
    /// Regression: take entries in address order (make `take_next_dirty` scan `entries` for the
    /// first dirty key instead of popping the queue) — the victim's high address is then never
    /// reached, because the low ones are re-dirtied faster than `R`.
    #[tokio::test(start_paused = true)]
    async fn the_nth_entry_is_written_inside_the_stated_worst_case() {
        const SIGMA_C: u32 = 512;
        let victim = addr(SIGMA_C);
        let t = Arc::new(NeighborTable::new());
        // Dirtied FIRST, so FIFO reaches it after at most the other 511.
        t.upsert(
            ROW,
            LEG,
            victim,
            MAC_B,
            long(),
            &cap(u32::MAX),
            Instant::now().into_std(),
        );
        for i in 0..SIGMA_C - 1 {
            t.upsert(
                ROW,
                LEG,
                addr(i),
                MAC_A,
                long(),
                &cap(u32::MAX),
                Instant::now().into_std(),
            );
        }
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));

        let started = Instant::now();
        let deadline = Duration::from_millis(54_800);
        let victim_str = victim.to_string();
        loop {
            a.step().await;
            if calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.get(3) == Some(&victim_str))
            {
                break;
            }
            assert!(
                started.elapsed() <= deadline,
                "the victim was not written within (17 x 32 + 4) / 10 = 54.8 s"
            );
            // The attacker keeps every other address dirty.
            for i in 0..SIGMA_C - 1 {
                t.upsert(
                    ROW,
                    LEG,
                    addr(i),
                    MAC_A,
                    long(),
                    &cap(u32::MAX),
                    Instant::now().into_std(),
                );
            }
        }
        assert!(started.elapsed() <= deadline, "{:?}", started.elapsed());
    }

    /// **T4a — a re-upsert of an already-dirty entry enqueues nothing.** An address upserted
    /// faster than `R` does not starve itself, and — the half that is actually observable —
    /// the dirty queue does not grow by one key per packet.
    ///
    /// **Honest scope, recorded rather than overclaimed.** The stated regression for this rule
    /// ("re-enqueue on every upsert") does NOT change the service order: the earlier key is
    /// still at the front and `take_next_dirty` walks past the duplicates as stale, so a test
    /// that asserts only order passes under the regression. What the guard genuinely prevents
    /// is unbounded growth — at wire-rate forged ACKs for one address the queue would grow by
    /// one key per packet, forever, on a member whose whole table is capped at `C`. So that is
    /// what this asserts.
    ///
    /// Regression: in `upsert`'s existing-entry arm, `queue.push_back(key)` unconditionally
    /// instead of only when the entry was clean.
    #[tokio::test(start_paused = true)]
    async fn a_re_upsert_of_a_dirty_entry_enqueues_nothing() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        for i in 1..5 {
            t.upsert(
                ROW,
                LEG,
                addr(i),
                MAC_A,
                long(),
                &cap(10),
                Instant::now().into_std(),
            );
        }
        assert_eq!(t.queued_len(), 5);
        for _ in 0..500 {
            t.upsert(
                ROW,
                LEG,
                addr(0),
                MAC_B,
                long(),
                &cap(10),
                Instant::now().into_std(),
            );
        }
        assert_eq!(
            t.queued_len(),
            5,
            "500 re-claims of one dirty address must add no queue keys"
        );

        // And the order the rule is named for still holds.
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(
            w[0][3],
            addr(0).to_string(),
            "the self-upserting address kept its place at the front: {w:?}"
        );
    }

    /// **T-ONEACTOR — one queue, one actor, host-wide FIFO.** Two rows; the entry dirtied first
    /// is written first regardless of which row woke last, and the row that sorts FIRST is the
    /// one dirtied SECOND, so map order and queue order disagree.
    ///
    /// Regression: per-row actors racing a shared bucket — or, equivalently at this boundary,
    /// serve the queue in `(row, addr)` map order instead of FIFO.
    #[tokio::test(start_paused = true)]
    async fn one_actor_serves_both_rows_in_first_dirty_order() {
        let t = Arc::new(NeighborTable::new());
        t.upsert(
            "zz",
            "leg-z",
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        t.upsert(
            "aa",
            "leg-a",
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), 2, "{w:?}");
        assert_eq!(w[0][7], "leg-z", "first dirtied, first written: {w:?}");
        assert_eq!(w[1][7], "leg-a");
    }

    // ---- the failure paths ----------------------------------------------------------------

    /// **T5 — a failed write is retried.** And **T6c's actor half**: a non-zero exit is never
    /// success, whatever the stderr says.
    ///
    /// Regression: on a write failure, do not call `re_dirty` (i.e. clear the entry on failure).
    #[tokio::test(start_paused = true)]
    async fn a_failed_write_is_retried() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = MockNeighborIo::new(|argv, nth| {
            if argv.contains(&"show") {
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: "[]".to_string(),
                    stderr: String::new(),
                });
            }
            // The first write fails with the exact text every earlier round matched on.
            Ok(crate::sys::Output {
                status: if nth == 1 { 2 } else { 0 },
                stdout: String::new(),
                stderr: "RTNETLINK answers: File exists".to_string(),
            })
        });
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        a.run_batch().await;
        assert_eq!(
            a.counts.write_failures, 1,
            "EEXIST is a failure, not a success"
        );
        assert_eq!(t.dirty_depth(), 1, "a failed write re-dirties the entry");
        a.run_batch().await;
        assert_eq!(a.counts.writes, 1, "and the next batch retries it");
        assert_eq!(writes(&calls.lock().unwrap()).len(), 2);
    }

    /// **T5a — the failure path goes to the BACK of the queue.** An entry an unrelated kernel
    /// failure put back must not jump ahead of a claim that was already waiting behind it.
    ///
    /// The batch cap is what makes this observable at all: with `B - 1` = 31 entries handled per
    /// batch and 33 queued, entry 32 is still waiting when the first entry's failure is put back
    /// — so the next batch's ORDER is the whole assertion.
    ///
    /// Regression: `queue.push_front` instead of `push_back` in `re_dirty`. The failed entry
    /// then outranks everything already waiting, forever if it keeps failing — one wedged
    /// address starving the queue behind it, which is R3.
    #[tokio::test(start_paused = true)]
    async fn a_failed_write_goes_to_the_back_of_the_queue() {
        const N: u32 = 33;
        let t = table_with(N);
        let io = MockNeighborIo::new(|argv, nth| {
            if argv.contains(&"show") {
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: "[]".to_string(),
                    stderr: String::new(),
                });
            }
            Ok(crate::sys::Output {
                status: i32::from(nth == 1),
                stdout: String::new(),
                stderr: "ENOBUFS".to_string(),
            })
        });
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        a.run_batch().await;
        assert_eq!(a.counts.write_failures, 1);
        a.run_batch().await;
        let w = writes(&calls.lock().unwrap());
        // Batch 1 handled entries 0..30 (31 of them, `B - 1`); 31 and 32 were still queued when
        // entry 0's failure was put back, so batch 2 serves 31, 32, then the retry of 0.
        let tail: Vec<String> = w[BURST as usize - 1..]
            .iter()
            .map(|c| c[3].clone())
            .collect();
        assert_eq!(
            tail,
            vec![
                addr(31).to_string(),
                addr(32).to_string(),
                addr(0).to_string()
            ],
            "the retry went behind what was already waiting: {w:?}"
        );
    }

    /// **T2 — an in-flight write does not swallow an upsert.** The relay upserts a new MAC
    /// while the write for that address is in flight; the entry must be dirty again when the
    /// write returns, and the next pass must carry the NEW MAC.
    ///
    /// Regression: mark clean on success instead of on take — i.e. delete `e.dirty = false`
    /// from `take_next_dirty` and clear it after a successful write. The mid-write upsert then
    /// finds the entry still dirty, does not re-queue it, and the new MAC is discarded with
    /// nothing to retry it.
    #[tokio::test(start_paused = true)]
    async fn an_in_flight_write_does_not_swallow_an_upsert() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let t_write = t.clone();
        let io = MockNeighborIo::new(move |argv, nth| {
            if argv.contains(&"show") {
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: "[]".to_string(),
                    stderr: String::new(),
                });
            }
            if nth == 1 {
                t_write.upsert(
                    ROW,
                    LEG,
                    addr(0),
                    MAC_B,
                    Instant::now().into_std() + Duration::from_secs(3600),
                    &cap(10),
                    Instant::now().into_std(),
                );
            }
            Ok(crate::sys::Output {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        });
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        a.run_batch().await;
        assert_eq!(
            t.dirty_depth(),
            1,
            "the mid-write claim is queued, not swallowed"
        );
        a.run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), 2, "{w:?}");
        assert_eq!(
            w[1][5],
            crate::workload::relay::mac_str(MAC_B),
            "the second pass carries the LAST claim"
        );
    }

    /// **T1, write half.** Two claims for one address between takes are ONE write, carrying the
    /// SECOND MAC.
    ///
    /// Regression: reinstate round 3's dedupe (gate the upsert on the last `(addr, mac)` seen)
    /// and the second claim never reaches the table, so the stale MAC is written.
    #[tokio::test(start_paused = true)]
    async fn coalesced_claims_are_one_write_carrying_the_last_mac() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_B,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(
            w.len(),
            1,
            "two claims for one address are one write: {w:?}"
        );
        assert_eq!(w[0][5], crate::workload::relay::mac_str(MAC_B));
    }

    /// **T7, write half.** An entry whose lease ran out while it sat in the queue is dropped at
    /// take — **no write, no fork**. That is one of the two places expiry is enforced, and the
    /// only one on this side of the boundary.
    ///
    /// Regression: delete `take_next_dirty`'s `e.expires_at <= now` arm.
    #[tokio::test(start_paused = true)]
    async fn an_expired_entry_is_never_written() {
        let t = table_with(0);
        let soon = Instant::now().into_std() + Duration::from_millis(10);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            soon,
            &cap(10),
            Instant::now().into_std(),
        );
        t.upsert(
            ROW,
            LEG,
            addr(1),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        tokio::time::sleep(Duration::from_millis(50)).await;
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), 1, "only the unexpired entry is written: {w:?}");
        assert_eq!(w[0][3], addr(1).to_string());
    }

    /// **T-DEADLINE, read half.** The pre-drain read is wedged (the deadline kills it and the
    /// writer returns `Err`): nothing is written, no `add` is guessed, `read_failures` ticks,
    /// one journal line is emitted for the streak, and every entry **keeps its queue position**
    /// because take follows the read and nothing was taken.
    ///
    /// **More entries than one batch, and the ORDER is asserted over the whole queue.** A
    /// take-first batch takes the WHOLE batch — at most `B - 1` = 31 entries — so at any count
    /// of 31 or fewer, re-dirtying on failure puts every entry back in the same relative order
    /// and the position assertion reads green while the rule is violated. Only a queue LONGER
    /// than one batch can show the defect: the entries the batch could not reach stay at the
    /// front while the ones it took go to the back. That is why this test seeds 40 — the count
    /// is load-bearing, not arbitrary, and it is the defect class spec §10 names, in the test
    /// written to pin it.
    ///
    /// Regression: take the entry before the read and re-dirty it on read failure.
    #[tokio::test(start_paused = true)]
    async fn a_failed_read_writes_nothing_and_keeps_queue_position() {
        // More than `BURST - 1` = 31, so a take-first batch cannot take the whole queue.
        const N: u32 = 40;
        let t = table_with(N);
        let said = Arc::new(Mutex::new(Vec::new()));
        let io = MockNeighborIo::new(|argv, _| {
            if argv.contains(&"show") {
                return Err(crate::error::Error::fatal("ip: timed out after 2s, killed"));
            }
            Ok(crate::sys::Output {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        });
        let calls = io.calls();
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: None,
                woke: None,
            }),
        );
        assert_eq!(a.run_batch().await, Batch::ReadFailed);
        assert_eq!(a.run_batch().await, Batch::ReadFailed);
        assert_eq!(a.counts.read_failures, 2);
        assert!(
            writes(&calls.lock().unwrap()).is_empty(),
            "nothing is guessed"
        );
        assert_eq!(t.dirty_depth(), N as usize, "nothing was taken");
        assert_eq!(
            said.lock().unwrap().len(),
            1,
            "one line per streak, not per read"
        );

        let now = Instant::now().into_std();
        let order: Vec<Ipv4Addr> =
            std::iter::from_fn(|| t.take_next_dirty(now).taken.map(|x| x.addr)).collect();
        assert_eq!(
            order,
            (0..N).map(addr).collect::<Vec<_>>(),
            "a failed read moved nothing in the queue"
        );
    }

    /// A document that does not parse is a **read failure**, never an empty kernel. "Failed
    /// read = empty document = everything is missing" is the natural implementation that turns
    /// one transient error into a full re-write of the table.
    ///
    /// Regression: make `KernelNeighbors::parse` return an empty map instead of `None`, and
    /// watch the whole table get `add`-ed against a document cfab could not read.
    #[tokio::test(start_paused = true)]
    async fn an_unreadable_document_is_not_an_empty_kernel() {
        let t = table_with(3);
        let io = MockNeighborIo::kernel(r#"[{"ip":"10.9.0.1"}]"#);
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        assert_eq!(a.run_batch().await, Batch::ReadFailed);
        assert!(writes(&calls.lock().unwrap()).is_empty());
        assert_eq!(a.counts.read_failures, 1);
        assert_eq!(t.dirty_depth(), 3);
    }

    /// An EMPTY array, by contrast, is a real answer: the kernel holds nothing and every entry
    /// takes the `add` branch. Stated as its own test so the rule above cannot be "fixed" by
    /// treating `[]` as unreadable too.
    #[tokio::test(start_paused = true)]
    async fn an_empty_document_is_a_real_answer() {
        let t = table_with(3);
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t, Box::new(io));
        a.run_batch().await;
        assert_eq!(writes(&calls.lock().unwrap()).len(), 3);
        assert_eq!(a.counts.read_failures, 0);
    }

    // ---- T-LEAFLOCK -------------------------------------------------------------------------

    /// An observer that asserts the table lock is free at every site the actor could be holding
    /// it, and records what it was asked to journal.
    struct RecordingObserver {
        said: Arc<Mutex<Vec<String>>>,
        table: Option<Arc<NeighborTable>>,
        /// Set when a test counts how often the actor woke to try a batch, which is the only
        /// way to see idle cost that forks nothing.
        woke: Option<Arc<Mutex<Vec<String>>>>,
    }

    impl RecordingObserver {
        fn check(&self, site: &str) {
            if let Some(t) = &self.table {
                assert!(
                    t.lock_is_free(),
                    "the table lock is a LEAF and was held at {site}: whatever happens next \
                     (a fork, a journal write, a token spend, a sleep of up to B/R = 3.2 s) \
                     blocks every relay upsert on this host"
                );
            }
        }
    }

    impl ActorObserver for RecordingObserver {
        fn batch_start(&self) {
            self.check("the batch start");
            if let Some(w) = &self.woke {
                w.lock().unwrap().push("batch".to_string());
            }
        }
        fn wait_decision(&self) {
            self.check("the wait decision");
        }
        fn token_spend(&self) {
            self.check("the token spend");
        }
        fn journal(&self, line: &str) {
            self.check("the journal write");
            self.said.lock().unwrap().push(line.to_string());
        }
    }

    /// **T-LEAFLOCK — no wait, no token spend, no journal line and no fork under the table
    /// lock** (spec §4.2.3). Four sites, not one: instrumenting the token spend alone leaves an
    /// implementer free to read the dirty depth, keep the guard, sleep for a full bucket and
    /// release before spending — this test green, DHCP forwarding stalled. The **wait
    /// decision** is the site plan §1.1 created and the one that matters most, because that
    /// wait can be a full `B / R` = 3.2 s.
    ///
    /// Regression: in `run_batch`, hold the guard across the wait — replace the
    /// `self.table.dirty_depth()` call with one that returns the depth *and* a live
    /// `MutexGuard`, and keep the guard alive to the end of the function. Its live symptom is a
    /// **hang**, which is why this needs a test and not a careful reader.
    #[tokio::test(start_paused = true)]
    async fn nothing_the_actor_does_happens_under_the_table_lock() {
        let t = table_with(40);
        let said = Arc::new(Mutex::new(Vec::new()));
        let t_io = t.clone();
        // The mock writer's SPAWN asserts it too, so "at write time" cannot be read as the
        // journal alone.
        let io = MockNeighborIo::new(move |argv, nth| {
            assert!(
                t_io.lock_is_free(),
                "a fork ({argv:?}) was issued while holding the table lock"
            );
            if argv.contains(&"show") {
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: "[]".to_string(),
                    stderr: String::new(),
                });
            }
            // Fail one write so the journal path is exercised under the same assertion.
            Ok(crate::sys::Output {
                status: i32::from(nth == 2),
                stdout: String::new(),
                stderr: "ENOBUFS".to_string(),
            })
        });
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: Some(t.clone()),
                woke: None,
            }),
        );
        // Two batches: the first spends the burst and the second must WAIT, which is the site
        // that only exists because of the batching rule.
        a.run_batch().await;
        a.run_batch().await;
        assert!(a.counts.writes > 0);
        assert_eq!(
            said.lock().unwrap().len(),
            1,
            "the write failure was journaled"
        );
    }

    // ---- the bucket itself ------------------------------------------------------------------

    /// The burst is real and does not bank: an idle hour buys 32 forks, never 36 000.
    #[tokio::test(start_paused = true)]
    async fn the_bucket_bursts_but_does_not_bank() {
        let mut b = Bucket::new(Instant::now());
        assert_eq!(b.level(Instant::now()), BURST);
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert_eq!(
            b.level(Instant::now()),
            BURST,
            "a full bucket banks nothing"
        );
        for _ in 0..BURST {
            assert!(b.spend(Instant::now()));
        }
        assert!(!b.spend(Instant::now()), "the burst is spent");
        tokio::time::sleep(TOKEN_INTERVAL).await;
        assert!(b.spend(Instant::now()), "and refills at R");
    }

    /// `wait_for` asks for exactly the time the tokens need, so the actor sleeps once rather
    /// than spinning on a poll.
    #[tokio::test(start_paused = true)]
    async fn wait_for_returns_the_time_the_tokens_need() {
        let mut b = Bucket::new(Instant::now());
        for _ in 0..BURST {
            b.spend(Instant::now());
        }
        let d = b.wait_for(Instant::now(), 10);
        assert!(
            d >= TOKEN_INTERVAL * 9 && d <= TOKEN_INTERVAL * 10,
            "10 tokens at R = {REFILL_PER_SEC}/s is ~1 s: {d:?}"
        );
        tokio::time::sleep(d).await;
        assert!(b.level(Instant::now()) >= 10);
    }

    /// R4 — one VM booting on a quiet host is written **immediately**: `1 + 1` = 2 tokens, not a
    /// full burst. An implementation that waits for `B` before every read passes every other
    /// bucket test here and fails this one.
    #[tokio::test(start_paused = true)]
    async fn a_lone_vm_on_a_quiet_host_is_written_immediately() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t, Box::new(io));
        // Drain the burst down to exactly the two tokens the lone entry needs.
        for _ in 0..BURST - 2 {
            a.bucket.spend(Instant::now());
        }
        let started = Instant::now();
        a.run_batch().await;
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "no wait for a full burst"
        );
        assert_eq!(writes(&calls.lock().unwrap()).len(), 1);
    }

    /// The actor sleeps on a clean table and wakes on an upsert — the idle path R4 asks for,
    /// with no polling tick anywhere in it.
    #[tokio::test(start_paused = true)]
    async fn a_clean_table_idles_until_an_upsert_wakes_the_actor() {
        let t = table_with(0);
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        assert_eq!(a.run_batch().await, Batch::Idle);
        assert!(
            calls.lock().unwrap().is_empty(),
            "an idle batch forks nothing"
        );

        let t_up = t.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            t_up.upsert(
                ROW,
                LEG,
                addr(0),
                MAC_A,
                Instant::now().into_std() + Duration::from_secs(3600),
                &cap(10),
                Instant::now().into_std(),
            );
        });
        tokio::time::timeout(Duration::from_secs(30), t.wait_dirty())
            .await
            .expect("the upsert must wake the actor");
    }

    // ---- task 3c guard tests: T13, T14b, T-THROTTLE (write half), T-MINLEASE (second half) --

    /// **T13 — the fork rate is a CONSTANT under every input, never derived from anything
    /// measured at runtime** (spec §4.2.2: not autotuned, because the attacker sits inside any
    /// feedback loop that measures cost — a flood would shrink the very budget meant to absorb
    /// it). A failed write still spends exactly one token, the same as a successful one (spec
    /// §4.2, "a write spends one"), so the elapsed simulated time to exhaust the SAME token
    /// budget must be bit-for-bit identical whether every write in it succeeds or every one
    /// fails. `N` = 200 keeps `dirty_depth` above `B - 1` for both scenarios across the
    /// compared batches, so `want` never diverges between them for a reason that has nothing to
    /// do with the rate.
    ///
    /// Regression: add ANY runtime-derived slowdown to the wait — e.g. sleep an extra interval
    /// after a write failure ("back off under load"), which is exactly what §5 item 9's "no
    /// backoff, the bucket is the bound" forbids. That change makes the two runs' elapsed times
    /// unequal, which is the only thing this test checks.
    #[tokio::test(start_paused = true)]
    async fn the_fork_rate_never_varies_with_success_or_failure() {
        const N: u32 = 200;
        const BATCHES: u32 = 3;

        async fn run_batches(succeed: bool) -> Duration {
            let t = table_with(N);
            let io = MockNeighborIo::new(move |argv, _| {
                if argv.contains(&"show") {
                    return Ok(crate::sys::Output {
                        status: 0,
                        stdout: "[]".to_string(),
                        stderr: String::new(),
                    });
                }
                Ok(crate::sys::Output {
                    status: i32::from(!succeed),
                    stdout: String::new(),
                    stderr: if succeed {
                        String::new()
                    } else {
                        "ENOBUFS".to_string()
                    },
                })
            });
            let mut a = FlushActor::new(t.clone(), Box::new(io));
            let started = Instant::now();
            for _ in 0..BATCHES {
                a.run_batch().await;
            }
            Instant::now() - started
        }

        let succeeded = run_batches(true).await;
        let failed = run_batches(false).await;
        assert_eq!(
            succeeded, failed,
            "the same number of forks took different simulated wall time depending on \
             success or failure ({succeeded:?} vs {failed:?}) — something is deriving the \
             rate from a runtime observation"
        );
    }

    /// **T14b — the orphan case, which T-NODEL's expiry case does not cover.** An address the
    /// kernel holds that cfab's own table has NEVER claimed (another host's static entry, say)
    /// is touched by NOTHING cfab does, on the first batch or any later one. `WriteVerb` has
    /// only `Add` and `Replace` (writer.rs) — there is structurally no way to build a delete
    /// argv through it — but the pre-drain read is unfiltered and host-wide (spec §4.1.1), so
    /// nothing in the TYPE SYSTEM stops a future change from walking the read DOCUMENT instead
    /// of the table's own dirty queue and "cleaning up" what it does not recognize. This test
    /// pins the actual behavior across several ticks, not just the type shape.
    ///
    /// Regression: in `run_batch`, after classifying the queue's own entries, also walk
    /// `doc`'s raw entries and delete anything absent from `self.table` — a "clean up what I
    /// don't recognize" pass that reads as reasonable and is exactly what spec §5 item 10
    /// forbids.
    #[tokio::test(start_paused = true)]
    async fn an_orphan_kernel_entry_is_never_touched_at_start_or_on_any_tick() {
        let t = table_with(1);
        let orphan = Ipv4Addr::new(10, 9, 99, 99);
        let io = MockNeighborIo::new(move |argv, _| {
            if argv.contains(&"show") {
                // The unfiltered, host-wide read surfaces the orphan alongside cfab's own row.
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: kernel_doc(&[(LEG, orphan, Some("aa:bb:cc:dd:ee:ff"))]),
                    stderr: String::new(),
                });
            }
            Ok(crate::sys::Output {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        });
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        for tick in 0..5 {
            a.run_batch().await;
            // Keep feeding the actor real work every tick, so several ticks actually run
            // something rather than idling after the first.
            t.upsert(
                ROW,
                LEG,
                addr(tick + 100),
                MAC_B,
                long(),
                &cap(u32::MAX),
                Instant::now().into_std(),
            );
        }
        let orphan_str = orphan.to_string();
        for c in calls.lock().unwrap().iter() {
            assert!(
                !c.iter().any(|a| a == "del"),
                "cfab issues no `ip neigh del`, ever: {c:?}"
            );
            assert!(
                !c.contains(&orphan_str),
                "the orphan address is named in an argv cfab ran: {c:?}"
            );
        }
    }

    /// **T-THROTTLE, write-failure half.** A row whose write keeps failing journals ONCE per
    /// failure streak, not once per attempt — the failure rate is whatever the kernel does on
    /// each retry, and with retries bounded only by the bucket (no backoff, spec §5 item 9) a
    /// persistent EEXIST/ENOBUFS race would otherwise print `R` = 10 lines a second forever.
    /// A recovery ends the streak, and the next failure is loud again — proven in the same test
    /// so the reset half cannot be "fixed" by never resetting at all.
    ///
    /// Regression: drop the `write_failing.insert(...)` guard in `run_batch` and journal on
    /// every failed write.
    #[tokio::test(start_paused = true)]
    async fn a_persistently_failing_write_journals_once_per_streak_then_resets() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let said = Arc::new(Mutex::new(Vec::new()));
        let succeed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let succeed_in_io = succeed.clone();
        let io = MockNeighborIo::new(move |argv, _| {
            if argv.contains(&"show") {
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: "[]".to_string(),
                    stderr: String::new(),
                });
            }
            let ok = succeed_in_io.load(std::sync::atomic::Ordering::SeqCst);
            Ok(crate::sys::Output {
                status: i32::from(!ok),
                stdout: String::new(),
                stderr: if ok {
                    String::new()
                } else {
                    "ENOBUFS".to_string()
                },
            })
        });
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: None,
                woke: None,
            }),
        );
        // Ten consecutive failures for the SAME row are one journal line.
        for _ in 0..10 {
            a.run_batch().await;
        }
        assert_eq!(a.counts.write_failures, 10, "every attempt is counted");
        assert_eq!(
            said.lock().unwrap().len(),
            1,
            "ten failures in one streak are one journal line"
        );

        // The write succeeds: the streak ends.
        succeed.store(true, std::sync::atomic::Ordering::SeqCst);
        a.run_batch().await;
        assert_eq!(a.counts.writes, 1);

        // A fresh claim that fails again starts a NEW streak, and it is loud again.
        succeed.store(false, std::sync::atomic::Ordering::SeqCst);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_B,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        for _ in 0..10 {
            a.run_batch().await;
        }
        assert_eq!(
            said.lock().unwrap().len(),
            2,
            "a recovery resets the streak; the next failure streak is loud once, not zero \
             times and not ten"
        );
    }

    /// **T-MINLEASE, second half.** The first half (table.rs) proves `clamp_lease` raises a
    /// `lease = 1` ACK to `MIN_LEASE` = 60 s; this half is the only place that floor is checked
    /// against the mechanism it exists to survive, because task 2 has no queue to check it
    /// against. Placed at the genuine BACK of a full `Σ C_i` = 512 queue (dirtied LAST, unlike
    /// `the_nth_entry_is_written_inside_the_stated_worst_case`'s fairness case, which dirties
    /// its victim FIRST), the clamped entry must still be unexpired — and WRITTEN, not silently
    /// dropped at take — when the actor finally reaches it at the stated worst case.
    ///
    /// Regression: shrink `MIN_LEASE` toward the naive 51.2 s = `Σ C_i / R`, the bound that
    /// ignores the drain's own read forks, the sweep's, and the batch reservations the
    /// batching rule waits on (plan §1.2's erratum, and this test's own correction of it). The
    /// victim then expires in the queue before the actor reaches it and is silently dropped by
    /// `take_next_dirty`'s expiry arm — invisible to T3, T3a, T3b, T4 and T4a, all of which use
    /// `long()` (effectively infinite) expiries and cannot see a floor that is too low.
    #[tokio::test(start_paused = true)]
    async fn a_min_lease_entry_survives_the_full_queue_and_is_written() {
        const SIGMA_C: u32 = 512;
        let t = Arc::new(NeighborTable::new());
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        // Drain the actor's one-time starting burst first, so this reproduces the STEADY-STATE
        // worst case `MIN_LEASE` is derived against (see `MIN_LEASE` in table.rs) rather
        // than a cold start's one-off 32-token credit, which would understate the wait by
        // `B / R` = 3.2 s and let a shorter, unsafe `MIN_LEASE` pass this test by accident.
        for _ in 0..BURST {
            a.bucket.spend(Instant::now());
        }

        for i in 0..SIGMA_C - 1 {
            t.upsert(
                ROW,
                LEG,
                addr(i),
                MAC_A,
                long(),
                &cap(u32::MAX),
                Instant::now().into_std(),
            );
        }
        // Dirtied LAST: the genuine worst FIFO position, behind all 511 others.
        let victim = addr(SIGMA_C);
        let victim_expiry =
            Instant::now().into_std() + crate::workload::table::clamp_lease(Some(1));
        t.upsert(
            ROW,
            LEG,
            victim,
            MAC_B,
            victim_expiry,
            &cap(u32::MAX),
            Instant::now().into_std(),
        );

        let started = Instant::now();
        // Matches `the_nth_entry_is_written_inside_the_stated_worst_case`'s own number and
        // derivation: `(ceil(512 / 31) x B + 4 sweeps) / R` = 54.8 s, the sweep's own read
        // forks and the batch reservations included.
        let deadline = Duration::from_millis(54_800);
        let victim_str = victim.to_string();
        loop {
            a.step().await;
            if calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.get(3) == Some(&victim_str))
            {
                break;
            }
            assert!(
                started.elapsed() <= deadline,
                "the victim was not reached within the worst-case window: {:?}",
                started.elapsed()
            );
            assert!(
                t.dirty_depth() > 0 || t.entry(ROW, victim).is_some(),
                "the queue drained to nothing without ever writing the victim — it must have \
                 expired in the queue and been silently dropped"
            );
        }
        assert!(started.elapsed() <= deadline, "{:?}", started.elapsed());
    }

    // ---- task 4: the sweep, the sole coherence mechanism -----------------------------------

    /// A kernel document the test can change between reads, so a sweep and the drain that
    /// follows it can be given DIFFERENT answers — which is the only way to see whether the
    /// drain re-read or reused the sweep's document.
    fn changing_kernel(doc: &Arc<Mutex<String>>) -> MockNeighborIo {
        let doc = doc.clone();
        MockNeighborIo::new(move |argv, _| {
            Ok(crate::sys::Output {
                status: 0,
                stdout: if argv.contains(&"show") {
                    doc.lock().unwrap().clone()
                } else {
                    String::new()
                },
                stderr: String::new(),
            })
        })
    }

    /// **T11a — a coherent sweep writes nothing, and dirties nothing.** Table and kernel agree;
    /// the sweep costs exactly one read fork and produces no work at all. This is what makes a
    /// 15 s period affordable, and it is the assertion r4's "re-dirty every unexpired row"
    /// fails: at a full /24 that is 254 forks a minute forever on a quiet host.
    ///
    /// The sweep's argv is asserted to be `READ_ARGV` itself — the SAME ARGV as the drain's
    /// read, never the same document (spec §4.3 item 4). Without this, a sweep that re-added
    /// `dev <leg>` (or dropped `nud all`, whereupon every NUD_NONE entry reads as absent and
    /// dirties forever) leaves every other test in this file green.
    ///
    /// Regression: in `sweep`, re-dirty every entry instead of only the `Add`/`Replace` ones —
    /// i.e. delete the `Class::Skip => {}` arm's distinction and call `re_dirty` unconditionally.
    #[tokio::test(start_paused = true)]
    async fn a_coherent_sweep_writes_nothing_and_dirties_nothing() {
        let n = 64u32;
        let t = table_with(n);
        let entries: Vec<(&str, Ipv4Addr, Option<&str>)> = (0..n)
            .map(|i| (LEG, addr(i), Some("aa:bb:cc:dd:ee:ff")))
            .collect();
        let io = MockNeighborIo::kernel(&kernel_doc(&entries));
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        // Drain first, so the table is clean when the sweep runs: the sweep's job is to find
        // what a clean table has silently lost, and a coherent one has lost nothing.
        while a.run_batch().await != Batch::Idle {}
        let before = calls.lock().unwrap().len();

        let swept = a.sweep().await;

        assert_eq!(
            swept,
            Sweep::Diffed {
                dirtied: 0,
                expired: 0
            }
        );
        assert_eq!(t.dirty_depth(), 0, "a coherent sweep queues no work");
        let calls = calls.lock().unwrap().clone();
        assert_eq!(
            calls.len() - before,
            1,
            "one read fork for the whole sweep: {calls:?}"
        );
        assert_eq!(
            calls.last().unwrap().as_slice(),
            READ_ARGV,
            "the sweep issues the SAME ARGV as the drain's read"
        );
    }

    /// **T11 — the sweep converges on its own**, with the upsert trigger dead. The entry is
    /// claimed once, written, and then the kernel silently loses it — no ACK, no rebind, no
    /// netlink event, nothing that could re-dirty the row. Only the sweep can notice, and it
    /// must, because with triggers 2 and 3 out of this gate it is the sole coherence mechanism.
    ///
    /// Regression: disable the sweep (make `step` never call it, or make `sweep` return
    /// `Diffed { dirtied: 0, .. }` without diffing). The address then stays dark forever, and
    /// every other test in this file stays green.
    #[tokio::test(start_paused = true)]
    async fn the_sweep_restores_an_entry_the_kernel_silently_lost() {
        let doc = Arc::new(Mutex::new(kernel_doc(&[])));
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = changing_kernel(&doc);
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));

        a.run_batch().await;
        assert_eq!(writes(&calls.lock().unwrap()).len(), 1, "the first write");
        // The kernel now holds it, and the actor agrees.
        *doc.lock().unwrap() = kernel_doc(&[(LEG, addr(0), Some("aa:bb:cc:dd:ee:ff"))]);
        while a.run_batch().await != Batch::Idle {}

        // The kernel loses it. Nothing tells cfab.
        *doc.lock().unwrap() = kernel_doc(&[]);
        let started = Instant::now();
        loop {
            if matches!(a.step().await, Step::Batch(Batch::Idle)) {
                tokio::time::sleep(SWEEP).await;
            }
            if writes(&calls.lock().unwrap()).len() == 2 {
                break;
            }
            assert!(
                started.elapsed() <= SWEEP * 3,
                "nothing restored the lost entry within three sweep periods: {:?}",
                started.elapsed()
            );
        }
        let w = writes(&calls.lock().unwrap());
        assert_eq!(
            w[1][2], "add",
            "the kernel holds nothing, so create-only applies"
        );
        assert_eq!(w[1][3], addr(0).to_string());
    }

    /// **T12 — idle costs almost nothing, and the sweep is the ONLY thing that wakes.** The
    /// actor runs for four sweep periods with a clean table and a coherent kernel: exactly four
    /// forks, all of them the sweep's read, and no writes. R4's "a quiet host performs no
    /// periodic work" is overstated and is corrected here to its true form — a sleeping actor
    /// does no periodic work of its own, and a coherent sweep does no writes (T11a).
    ///
    /// Two regressions, because the two halves hide from each other. **Forks:** drop the
    /// `next_sweep` check from `step` so every iteration sweeps — the fork count goes from 4 to
    /// the bucket's whole output. **Wakeups:** poll the table on a timer instead of sleeping on
    /// `wait_dirty` (replace the `select!` in `run` with `sleep(100ms)`) — the fork count does
    /// NOT move, because an idle batch returns before forking anything, which is why this test
    /// counts batch starts as well.
    #[tokio::test(start_paused = true)]
    async fn an_idle_actor_wakes_only_for_the_sweep() {
        let t = table_with(0);
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let woke = Arc::new(Mutex::new(Vec::new()));
        let a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: woke.clone(),
                table: Some(t.clone()),
                woke: Some(woke.clone()),
            }),
        );
        let h = tokio::spawn(a.run());

        tokio::time::sleep(SWEEP * 4 + SWEEP / 2).await;
        h.abort();

        let calls = calls.lock().unwrap().clone();
        assert!(writes(&calls).is_empty(), "an idle host writes nothing");
        assert_eq!(
            calls.len(),
            4,
            "four sweep periods, four read forks, and nothing else forked: {calls:?}"
        );
        assert!(calls.iter().all(|c| c.as_slice() == READ_ARGV));
        // One batch attempt per sweep wakeup, plus the one at start. A polling loop in place
        // of the sleep multiplies this by the polling rate and forks nothing extra at all.
        assert!(
            woke.lock().unwrap().len() <= 5,
            "the actor woke {} times in four sweep periods; a sleeping actor does no periodic \
             work of its own",
            woke.lock().unwrap().len()
        );
    }

    /// **The sweep's read spends a token like every other fork** (spec §4.2; plan §1.2). This
    /// is the assertion that makes the sweep's share of the worst case real: without it the
    /// sweep is a fork the bucket does not govern, at 4 a minute per member, and the 54.8 s
    /// bound becomes an over-estimate hiding an ungoverned fork path rather than a bound.
    ///
    /// Regression: delete the `wait_and_spend(1)` call from `sweep`. The sweep then forks with
    /// an empty bucket and this test's wait collapses to zero.
    #[tokio::test(start_paused = true)]
    async fn the_sweep_spends_a_token_for_its_read() {
        let t = table_with(0);
        let io = MockNeighborIo::kernel("[]");
        let mut a = FlushActor::new(t, Box::new(io));
        for _ in 0..BURST {
            a.bucket.spend(Instant::now());
        }
        let started = Instant::now();
        a.sweep().await;
        assert_eq!(
            started.elapsed(),
            TOKEN_INTERVAL,
            "an empty bucket must make the sweep WAIT for its one token"
        );
    }

    /// **T-REBUILD — a leg rebuild actually restores every entry.** The table is populated by
    /// ACK and drained; the leg is then rebuilt, so the kernel holds nothing for any of those
    /// addresses and nothing tells cfab. A sweep, then a drain, must write every one of them.
    ///
    /// Regression: classify against anything other than a read taken inside the drain — any
    /// cached or published kernel state reintroduces r10's defect, under which the rebuild
    /// produced ZERO writes on the happy path, six reviews deep.
    #[tokio::test(start_paused = true)]
    async fn a_leg_rebuild_restores_every_entry() {
        const N: u32 = 20;
        let entries: Vec<(&str, Ipv4Addr, Option<&str>)> = (0..N)
            .map(|i| (LEG, addr(i), Some("aa:bb:cc:dd:ee:ff")))
            .collect();
        let doc = Arc::new(Mutex::new(kernel_doc(&entries)));
        let t = table_with(N);
        let io = changing_kernel(&doc);
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        while a.run_batch().await != Batch::Idle {}
        assert!(
            writes(&calls.lock().unwrap()).is_empty(),
            "the kernel already held every address"
        );

        // The leg is rebuilt: every neighbor entry on it is gone.
        *doc.lock().unwrap() = kernel_doc(&[]);
        let swept = a.sweep().await;
        assert_eq!(
            swept,
            Sweep::Diffed {
                dirtied: N as usize,
                expired: 0
            }
        );
        while a.run_batch().await != Batch::Idle {}

        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), N as usize, "every entry restored: {w:?}");
        assert!(w.iter().all(|c| c[2] == "add"));
    }

    /// **T-REBUILD-C — the drain does not reuse the sweep's document.** T-REBUILD alone CANNOT
    /// see this: its sweep runs after the rebuild, so the sweep's document and the drain's own
    /// read both say "absent" and the forbidden convention produces identical writes. §10
    /// records that T-REBUILD passed under two opposite conventions once.
    ///
    /// So: sweep against an empty kernel (the entry dirties), **then let the VM's entry appear
    /// REACHABLE**, then drain. The actor must SKIP it, because it re-read and saw a real
    /// `lladdr`.
    ///
    /// Regression: classify from the sweep's document — hand `run_batch` the document `sweep`
    /// last read instead of calling `read_kernel` again. The actor then writes over a MAC the
    /// kernel learned from the VM itself, which is the R2.2 violation create-only exists to
    /// prevent, reachable in a millisecond.
    #[tokio::test(start_paused = true)]
    async fn the_drain_re_reads_and_does_not_reuse_the_sweeps_document() {
        let doc = Arc::new(Mutex::new(kernel_doc(&[])));
        let t = table_with(1);
        let io = changing_kernel(&doc);
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        while a.run_batch().await != Batch::Idle {}
        let written_before = writes(&calls.lock().unwrap()).len();

        // The kernel holds nothing, so the sweep dirties the row.
        let swept = a.sweep().await;
        assert_eq!(
            swept,
            Sweep::Diffed {
                dirtied: 1,
                expired: 0
            }
        );
        assert_eq!(t.dirty_depth(), 1);

        // Between the sweep and the drain the VM speaks for itself and the kernel resolves it.
        *doc.lock().unwrap() = kernel_doc(&[(LEG, addr(0), Some("aa:bb:cc:dd:ee:ff"))]);
        a.run_batch().await;

        assert_eq!(
            writes(&calls.lock().unwrap()).len(),
            written_before,
            "the drain re-read, saw an lladdr, and skipped — it must never write over a MAC \
             the kernel learned from the VM itself"
        );
        assert_eq!(a.counts.skips, 1);
    }

    /// **T-SWEEPREAD — a sweep whose read fails dirties NOTHING.** Not everything: "failed read
    /// = empty document = every entry is missing" is a natural implementation that turns one
    /// transient error into a full re-write of the table — up to `Σ C_i` = 512 forks on one
    /// transient error (spec §4.1.1(c)). Nothing in spec §6 could see this; T-DEADLINE's read
    /// half wedges the PRE-DRAIN read, not the sweep's.
    ///
    /// It also pins the other half of that rule: expiry is cfab's own clock, so it is reaped
    /// **before** the read and therefore even when the read fails. A row whose lease ran out
    /// must not hold its slot against the cap for as long as the kernel happens to be
    /// unreadable — which is a table that fills, and a cap that refuses live VMs, on exactly
    /// the degraded path.
    ///
    /// Regression 1: in `sweep`, treat the `None` from `read_kernel` as an empty document
    /// (`KernelNeighbors::parse("[]").unwrap()`) and diff against it. Every entry then dirties.
    /// Regression 2: move the `remove_expired` call below the read-failure early return.
    #[tokio::test(start_paused = true)]
    async fn a_sweep_whose_read_fails_dirties_nothing() {
        const N: u32 = 32;
        let n_entries: Vec<(&str, Ipv4Addr, Option<&str>)> = (0..N)
            .map(|i| (LEG, addr(i), Some("aa:bb:cc:dd:ee:ff")))
            .collect();
        let t = table_with(N);
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fail_io = fail.clone();
        let coherent = kernel_doc(&n_entries);
        let io = MockNeighborIo::new(move |argv, _| {
            if argv.contains(&"show") && fail_io.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(crate::sys::Output {
                    status: 1,
                    stdout: String::new(),
                    stderr: "Cannot bind netlink socket: Address family not supported".to_string(),
                });
            }
            Ok(crate::sys::Output {
                status: 0,
                stdout: if argv.contains(&"show") {
                    coherent.clone()
                } else {
                    String::new()
                },
                stderr: String::new(),
            })
        });
        let calls = io.calls();
        let said = Arc::new(Mutex::new(Vec::new()));
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: Some(t.clone()),
                woke: None,
            }),
        );
        while a.run_batch().await != Batch::Idle {}
        assert_eq!(t.dirty_depth(), 0);

        fail.store(true, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..10 {
            assert_eq!(a.sweep().await, Sweep::ReadFailed);
        }

        assert_eq!(
            t.dirty_depth(),
            0,
            "a failed read is not an empty kernel: a transient error must not queue the whole \
             table for rewriting"
        );
        assert!(writes(&calls.lock().unwrap()).is_empty());
        assert_eq!(a.counts.read_failures, 10, "every failure is counted");
        assert_eq!(
            said.lock().unwrap().len(),
            1,
            "ten failures in one streak are ONE journal line, not ten: the rate is \
             attacker-reachable"
        );

        // And the streak resets, so a later failure is loud again.
        fail.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            a.sweep().await,
            Sweep::Diffed {
                dirtied: 0,
                expired: 0
            }
        );
        fail.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(a.sweep().await, Sweep::ReadFailed);
        assert_eq!(said.lock().unwrap().len(), 2);

        // And a row whose lease runs out while the kernel is unreadable still leaves the table.
        let before = t.len();
        t.upsert(
            ROW,
            LEG,
            addr(N),
            MAC_A,
            Instant::now().into_std() + Duration::from_secs(30),
            &cap(u32::MAX),
            Instant::now().into_std(),
        );
        assert_eq!(t.len(), before + 1);
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(a.sweep().await, Sweep::ReadFailed);
        assert_eq!(
            t.len(),
            before,
            "expiry is reaped before the read, and therefore even when the read fails: an \
             expired row must not hold its slot against the cap for as long as the kernel \
             happens to be unreadable"
        );
        assert_eq!(t.dirty_depth(), 0, "and it is not queued on its way out");
    }

    /// The sweep removes expired **table rows** and deletes no kernel entry — the second of the
    /// two places expiry is enforced (the drain's take is the first, and it only catches rows
    /// the drain actually reaches). Without this a row nothing ever re-dirties holds its slot
    /// against the cap forever.
    ///
    /// Regression: delete the `remove_expired` call from `sweep`. The expired row then stays in
    /// the table, and the sweep goes on re-dirtying it against a kernel that still holds it.
    #[tokio::test(start_paused = true)]
    async fn a_sweep_removes_expired_table_rows_and_deletes_no_kernel_entry() {
        let t = table_with(0);
        let soon = Instant::now().into_std() + Duration::from_secs(60);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            soon,
            &cap(10),
            Instant::now().into_std(),
        );
        t.upsert(
            ROW,
            LEG,
            addr(1),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));
        while a.run_batch().await != Batch::Idle {}

        tokio::time::sleep(Duration::from_secs(61)).await;
        let swept = a.sweep().await;

        assert_eq!(
            swept,
            Sweep::Diffed {
                dirtied: 1,
                expired: 1
            }
        );
        assert_eq!(a.counts.expiries, 1);
        assert_eq!(t.len(), 1, "the expired row is gone from cfab's table");
        assert!(t.entry(ROW, addr(0)).is_none());
        let calls = calls.lock().unwrap().clone();
        assert!(
            !calls.iter().any(|c| c.contains(&"del".to_string())),
            "cfab deletes no kernel neighbor entry, ever: {calls:?}"
        );
    }

    // ---- Task 5: observability — each counter moves on its own path, and no other ---------

    /// **The named counters test (plan §4 task 5).** `skips`, `write_failures`, cap refusals
    /// and expiries each have a distinct trigger, and this proves none of the four fires on any
    /// of the others' — the shape spec §4.5 asks for, because a counter that moves on the wrong
    /// trigger defeats "a coherent host and a host that silently wrote nothing must not look
    /// the same" just as surely as one that never moves at all.
    ///
    /// Five rows, five disjoint triggers, asserted in full for every row and not just the one
    /// each name suggests: `skiprow` (the kernel already holds a valid MAC), `addrow` (a plain
    /// successful write, the control), `failrow` (the write fails), `caprow` (a second claim
    /// refused at `C` = 1), `exprow` (its lease runs out before the actor ever reads the
    /// kernel). A `skips` that also ticked `caprow`'s cap-refusal counter would pass an
    /// assertion that only checks `skiprow`, so every row checks every counter.
    ///
    /// Regressions proved by hand against this test (each turns exactly one assertion red):
    /// crediting a skip's row instead of the caller's addr's row; counting a cap refusal
    /// against every row instead of the one refused; using `remove_expired`'s scalar count
    /// instead of its per-row breakdown, which would credit expiries to the wrong row entirely;
    /// and folding `write_failures` into `skips` (or vice versa) in the per-row map.
    #[tokio::test(start_paused = true)]
    async fn skips_write_failures_cap_refusals_and_expiries_each_move_on_their_own_path() {
        let t = Arc::new(NeighborTable::new());
        let now = Instant::now().into_std();

        t.upsert("skiprow", "leg-skip", addr(0), MAC_A, long(), &cap(10), now);
        t.upsert("addrow", "leg-add", addr(0), MAC_A, long(), &cap(10), now);
        t.upsert("failrow", "leg-fail", addr(0), MAC_A, long(), &cap(10), now);
        t.upsert("caprow", "leg-cap", addr(0), MAC_A, long(), &cap(1), now);
        t.upsert("caprow", "leg-cap", addr(1), MAC_A, long(), &cap(1), now);
        t.upsert(
            "exprow",
            "leg-exp",
            addr(0),
            MAC_A,
            now + Duration::from_secs(60),
            &cap(10),
            now,
        );

        // The kernel already holds `skiprow`'s address with a valid MAC; `addrow` and `failrow`
        // are absent, so both are a plain `add`.
        let doc = kernel_doc(&[("leg-skip", addr(0), Some("aa:bb:cc:dd:ee:ff"))]);
        let io = MockNeighborIo::new(move |argv, _| {
            if argv.contains(&"show") {
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: doc.clone(),
                    stderr: String::new(),
                });
            }
            if argv.contains(&"leg-fail") {
                return Ok(crate::sys::Output {
                    status: 2,
                    stdout: String::new(),
                    stderr: "RTNETLINK answers: File exists".to_string(),
                });
            }
            Ok(crate::sys::Output {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        });
        let mut a = FlushActor::new(t.clone(), Box::new(io));

        // The expiry fires on the sweep, before anything is read for the drain: `exprow` never
        // reaches classification at all.
        tokio::time::sleep(Duration::from_secs(61)).await;
        let swept = a.sweep().await;
        assert!(
            matches!(swept, Sweep::Diffed { expired: 1, .. }),
            "{swept:?}"
        );
        assert_eq!(a.counts.expiries, 1, "exprow's lease ran out");

        // One batch is enough: four entries are dirty (`exprow` already expired above) and
        // `BURST - 1` = 31 handles all four. Looping to `Idle` would be wrong here — `failrow`
        // fails and re-dirties itself every time, so a caller draining until idle would retry
        // it forever (correct production behavior, no backoff exists) rather than reach it.
        a.run_batch().await;

        assert_eq!(a.counts.skips, 1);
        assert_eq!(
            a.counts.writes, 2,
            "addrow's write succeeded, and so does caprow's ADMITTED claim — the cap refuses \
             the second address, not the row's first write"
        );
        assert_eq!(a.counts.write_failures, 1, "failrow's write failed");

        let row = |name: &str| a.per_row.get(name).copied().unwrap_or_default();
        assert_eq!(row("skiprow").skips, 1);
        assert_eq!(row("skiprow").writes, 0);
        assert_eq!(row("skiprow").write_failures, 0);
        assert_eq!(row("skiprow").expiries, 0);

        assert_eq!(row("addrow").writes, 1);
        assert_eq!(row("addrow").skips, 0);
        assert_eq!(row("addrow").write_failures, 0);
        assert_eq!(row("addrow").expiries, 0);

        assert_eq!(row("failrow").write_failures, 1);
        assert_eq!(row("failrow").skips, 0);
        assert_eq!(row("failrow").writes, 0);
        assert_eq!(row("failrow").expiries, 0);

        assert_eq!(row("exprow").expiries, 1);
        assert_eq!(row("exprow").skips, 0);
        assert_eq!(row("exprow").writes, 0);
        assert_eq!(row("exprow").write_failures, 0);

        assert_eq!(row("caprow").writes, 1, "the first, admitted claim");
        assert_eq!(row("caprow").skips, 0);
        assert_eq!(row("caprow").write_failures, 0);
        assert_eq!(row("caprow").expiries, 0);

        let refusals = t.cap_refusals_snapshot();
        assert_eq!(refusals.get("caprow").copied().unwrap_or(0), 1);
        assert_eq!(refusals.get("skiprow").copied().unwrap_or(0), 0);
        assert_eq!(refusals.get("addrow").copied().unwrap_or(0), 0);
        assert_eq!(refusals.get("failrow").copied().unwrap_or(0), 0);
        assert_eq!(refusals.get("exprow").copied().unwrap_or(0), 0);

        let sizes = t.row_sizes();
        assert_eq!(
            sizes.get("caprow").copied().unwrap_or(0),
            1,
            "the admitted claim stays; the refused one never entered the table"
        );
        assert!(!sizes.contains_key("exprow"), "the expired row is gone");
    }

    /// **Alternating rows must not re-arm the throttle.** Revision 2 cleared a row's entry
    /// whenever it was absent from a pass, which treats "row B's turn" as evidence that row A
    /// recovered. `dropped` is FIFO by upsert time, so drops cluster by row and an attacker
    /// flooding A, then B, then A gets a fresh line every pass — batches are bucket-bounded at
    /// `R`, so that is **10 lines a second, sustained, on demand**, MEASURED at 20 passes = 20
    /// lines. Spec §6 T-THROTTLE: the rate is attacker-chosen, so an unthrottled line is a log
    /// flood on demand.
    ///
    /// The per-row time window fixes this with no recovery inference at all: every pass here
    /// lands inside one `EXPIRY_LOG_WINDOW`, so each row's line fires once (its first incident)
    /// and every later incident of that same row, no matter which row took the turn in between,
    /// is still within its own window and stays silent.
    ///
    /// Regression: clear a row's entry when it is absent from a pass (revision 2's shape) and
    /// this goes red at the line count (20, not 2) while every counter assertion stays green.
    #[tokio::test(start_paused = true)]
    async fn alternating_rows_cannot_re_arm_the_expiry_line_every_batch() {
        let t = Arc::new(NeighborTable::new());
        let io = MockNeighborIo::kernel("[]");
        let said = Arc::new(Mutex::new(Vec::new()));
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: Some(t.clone()),
                woke: None,
            }),
        );

        // Twenty passes, one row each, alternating, each entry already expired by the time its
        // batch runs — small advances so all twenty land inside one 60 s window.
        for i in 0..20u32 {
            let row = if i % 2 == 0 { "rowa" } else { "rowb" };
            let leg = if i % 2 == 0 { "leg-a" } else { "leg-b" };
            let now = Instant::now().into_std();
            t.upsert(
                row,
                leg,
                addr(i),
                MAC_A,
                now + Duration::from_millis(1),
                &cap(10),
                now,
            );
            tokio::time::advance(Duration::from_secs(2)).await;
            assert_eq!(a.run_batch().await, Batch::Drained);
        }
        // 20 passes x 2 s = 40 s of simulated time, inside one 60 s window.

        assert_eq!(a.counts.expiries, 20, "every drop is still counted");
        let row = |name: &str| a.per_row.get(name).copied().unwrap_or_default();
        assert_eq!(row("rowa").expiries, 10);
        assert_eq!(row("rowb").expiries, 10);

        let lines = said.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            2,
            "one line per row that started, not one per pass: {lines:?}"
        );
    }

    /// **One row's expiry streak must not silence another row's FIRST line.** `write_failing`
    /// keys its throttle per row; revision 1 made this one host-wide, so a row dropping entries
    /// continuously held the single flag set and a second row's first-ever drop produced **no
    /// line at all** — not attributed to the wrong row, simply absent. The per-row counters
    /// stayed right, so the only signal that a second row had started losing entries was the one
    /// that went missing. The per-row time window keeps this fixed: each row has its own entry
    /// and its own clock, so one row being mid-window says nothing about any other row.
    ///
    /// Regression: make `expiring` host-wide again (a single bool/flag, revision 1's shape) and
    /// the second assertion goes red while every counter assertion stays green — which is
    /// exactly how it shipped.
    #[tokio::test(start_paused = true)]
    async fn one_rows_expiry_streak_never_silences_another_rows_first_line() {
        let t = Arc::new(NeighborTable::new());
        let now = Instant::now().into_std();
        let soon = |base: std::time::Instant| base + Duration::from_secs(30);
        t.upsert("rowa", "leg-a", addr(0), MAC_A, soon(now), &cap(10), now);

        let io = MockNeighborIo::kernel("[]");
        let said = Arc::new(Mutex::new(Vec::new()));
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: Some(t.clone()),
                woke: None,
            }),
        );

        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);
        let lines = said.lock().unwrap().clone();
        assert_eq!(lines.len(), 1, "rowa opens its streak: {lines:?}");
        assert!(lines[0].contains("rowa"), "{}", lines[0]);

        // rowa keeps dropping — its streak never breaks — and rowb starts dropping too.
        let now = Instant::now().into_std();
        t.upsert("rowa", "leg-a", addr(1), MAC_A, soon(now), &cap(10), now);
        t.upsert("rowb", "leg-b", addr(2), MAC_A, soon(now), &cap(10), now);
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);

        assert_eq!(a.counts.expiries, 3, "every drop is still counted");
        let row = |name: &str| a.per_row.get(name).copied().unwrap_or_default();
        assert_eq!(row("rowa").expiries, 2);
        assert_eq!(row("rowb").expiries, 1);

        let lines = said.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            2,
            "rowb's first drop is loud even though rowa is mid-streak: {lines:?}"
        );
        assert!(
            lines[1].contains("rowb"),
            "and the new line names the row that just started losing entries: {}",
            lines[1]
        );
        assert!(
            !lines[1].contains("rowa"),
            "rowa is mid-streak and does not repeat itself: {}",
            lines[1]
        );
        assert!(
            lines[1].starts_with("cfab: dhcp neighbor actor: 1 table"),
            "the count describes the rows the line NAMES, not every drop in the pass — \
             rowa lost one too and is not on this line: {}",
            lines[1]
        );

        // Two drops of ONE row in ONE pass count twice: a flood on a single row is the dominant
        // case, and counting rows instead of drops would under-report it by up to `C`.
        let now = Instant::now().into_std();
        t.upsert("rowb", "leg-b", addr(3), MAC_A, soon(now), &cap(10), now);
        t.upsert("rowb", "leg-b", addr(4), MAC_A, soon(now), &cap(10), now);
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);
        assert_eq!(
            a.per_row.get("rowb").copied().unwrap_or_default().expiries,
            3,
            "two drops in one pass, counted twice"
        );
        assert_eq!(a.counts.expiries, 5);
    }

    /// **A row's own repeat incident inside the window stays silent.** This is the base case
    /// `EXPIRY_LOG_WINDOW` exists for: the same row expiring twice a second apart must not
    /// double the line, or the throttle does nothing at all against a row an attacker floods.
    ///
    /// Regression: drop the window check in `note_expiries` so every row is always "fresh" (a
    /// row journals on every incident) and this goes red at the line count (2, not 1) while
    /// every counter assertion stays green.
    #[tokio::test(start_paused = true)]
    async fn a_rows_repeat_expiry_inside_the_window_is_not_journaled() {
        let t = Arc::new(NeighborTable::new());
        let io = MockNeighborIo::kernel("[]");
        let said = Arc::new(Mutex::new(Vec::new()));
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: Some(t.clone()),
                woke: None,
            }),
        );

        let now = Instant::now().into_std();
        t.upsert(
            "rowa",
            "leg-a",
            addr(0),
            MAC_A,
            now + Duration::from_millis(1),
            &cap(10),
            now,
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);

        // Second incident, 1 s later: well inside the 60 s window.
        let now = Instant::now().into_std();
        t.upsert(
            "rowa",
            "leg-a",
            addr(1),
            MAC_A,
            now + Duration::from_millis(1),
            &cap(10),
            now,
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);

        assert_eq!(a.counts.expiries, 2, "both incidents are counted");
        assert_eq!(
            a.per_row.get("rowa").copied().unwrap_or_default().expiries,
            2
        );

        let lines = said.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            1,
            "the second incident is inside the window: {lines:?}"
        );
    }

    /// **An ongoing incident must not go silent forever.** This is what revision 3 broke: it
    /// ended a row's streak only on a pass that dropped nothing host-wide, so one chronically
    /// sick row masked every later incident of every row — MEASURED zero lines for the
    /// recurrence. A time window has no such failure mode: once `EXPIRY_LOG_WINDOW` elapses
    /// since the row's last line, the next incident is fresh again, unconditionally.
    ///
    /// Regression: make the window infinite (once a row has an entry in `expiring`, never
    /// re-journal it — revision 3's masking, generalized to a single row) and this goes red at
    /// the line count (1, not 2) while every counter assertion stays green.
    #[tokio::test(start_paused = true)]
    async fn a_rows_expiry_is_journaled_again_once_the_window_passes() {
        let t = Arc::new(NeighborTable::new());
        let io = MockNeighborIo::kernel("[]");
        let said = Arc::new(Mutex::new(Vec::new()));
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: Some(t.clone()),
                woke: None,
            }),
        );

        let now = Instant::now().into_std();
        t.upsert(
            "rowa",
            "leg-a",
            addr(0),
            MAC_A,
            now + Duration::from_millis(1),
            &cap(10),
            now,
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);

        // Second incident at +61 s from the first line: outside the 60 s window.
        let now = Instant::now().into_std();
        t.upsert(
            "rowa",
            "leg-a",
            addr(1),
            MAC_A,
            now + Duration::from_millis(1),
            &cap(10),
            now,
        );
        tokio::time::advance(Duration::from_secs(61)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);

        assert_eq!(a.counts.expiries, 2, "both incidents are counted");
        assert_eq!(
            a.per_row.get("rowa").copied().unwrap_or_default().expiries,
            2
        );

        let lines = said.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            2,
            "the window passed, so the recurrence is loud again: {lines:?}"
        );
    }

    /// **The metric is never throttled, only the line.** `note_expiries` must credit
    /// `per_row[..].expiries` and `counts.expiries` for every expiry it is handed, independent
    /// of whether that row's line is inside its window. A fix that moved the counting inside the
    /// `fresh` branch would under-report every throttled incident — exactly the blind spot
    /// `cfab_workload_neighbor_expiries` exists to not have.
    #[tokio::test(start_paused = true)]
    async fn every_expiry_is_counted_even_when_the_line_is_throttled() {
        let t = Arc::new(NeighborTable::new());
        let io = MockNeighborIo::kernel("[]");
        let said = Arc::new(Mutex::new(Vec::new()));
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: Some(t.clone()),
                woke: None,
            }),
        );

        for i in 0..3u32 {
            let now = Instant::now().into_std();
            t.upsert(
                "rowa",
                "leg-a",
                addr(i),
                MAC_A,
                now + Duration::from_millis(1),
                &cap(10),
                now,
            );
            tokio::time::advance(Duration::from_secs(1)).await;
            assert_eq!(a.run_batch().await, Batch::Drained);
        }

        assert_eq!(
            a.counts.expiries, 3,
            "the metric counts every expiry, never throttled"
        );
        assert_eq!(
            a.per_row.get("rowa").copied().unwrap_or_default().expiries,
            3
        );

        let lines = said.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            1,
            "only the journal line is throttled: {lines:?}"
        );
    }

    /// **Expiry on the DRAIN path is counted and said.** The test above drives every expiry
    /// through `sweep`, and `counts.expiries` was credited there and only there — so an entry
    /// whose lease ran out while it sat in the queue left the table with **no counter and no
    /// journal line**. Two arms did it silently: `take_next_dirty`'s, when the actor reaches an
    /// entry late, and `re_dirty`'s, when a failed write is put back after its lease ended.
    /// `cfab_workload_neighbor_expiries` must move on the drain, not only on the sweep: the
    /// drain is the path a flood travels, and a row vanishing with no signal at all is the
    /// shape of the hole `MIN_LEASE` is derived to make impossible.
    ///
    /// This drives `run_batch` only — never `sweep` — so a credit that comes from the sweep
    /// cannot make it pass.
    ///
    /// Regression: drop the `expired` field from `NextDirty` (or stop extending `dropped` with
    /// it) and both expiry assertions go red while every write assertion stays green.
    #[tokio::test(start_paused = true)]
    async fn an_entry_that_expires_in_the_queue_is_counted_and_journaled() {
        let t = Arc::new(NeighborTable::new());
        let now = Instant::now().into_std();
        t.upsert(
            "exprow",
            "leg-exp",
            addr(0),
            MAC_A,
            now + Duration::from_secs(30),
            &cap(10),
            now,
        );
        t.upsert("liverow", "leg-live", addr(1), MAC_A, long(), &cap(10), now);

        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let said = Arc::new(Mutex::new(Vec::new()));
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(io),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: None,
                woke: None,
            }),
        );

        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);

        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), 1, "only the live entry is written: {w:?}");
        assert_eq!(w[0][3], addr(1).to_string());

        assert_eq!(
            a.counts.expiries, 1,
            "the entry that expired in the queue is counted on the drain path, not only in a sweep that may not have run yet"
        );
        let row = |name: &str| a.per_row.get(name).copied().unwrap_or_default();
        assert_eq!(row("exprow").expiries, 1);
        assert_eq!(row("exprow").writes, 0);
        assert_eq!(row("liverow").expiries, 0, "a live row is credited nothing");
        assert_eq!(row("liverow").writes, 1);
        assert!(
            !t.row_sizes().contains_key("exprow"),
            "and it left the table"
        );

        let lines = said.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            1,
            "one line, and the drop is not silent: {lines:?}"
        );
        assert!(
            lines[0].contains("exprow"),
            "the line names the workload row that lost an entry: {}",
            lines[0]
        );

        // Once per row per `EXPIRY_LOG_WINDOW`, not once per batch: the trigger is
        // attacker-reachable. Nothing here infers that a row recovered.
        t.upsert(
            "exprow",
            "leg-exp",
            addr(2),
            MAC_A,
            Instant::now().into_std() + Duration::from_secs(30),
            &cap(10),
            Instant::now().into_std(),
        );
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);
        assert_eq!(a.counts.expiries, 2, "every drop is counted");
        assert_eq!(
            said.lock().unwrap().len(),
            1,
            "a second drop 31 s later is INSIDE the 60 s window, so it says nothing new"
        );

        // 31 s further on the row's last line is 62 s old, so the window has elapsed and the
        // line is due again. An ongoing incident re-reports rather than going silent forever --
        // the defect revision 3 had. NOTE: nothing ends a "streak" any more; an empty pass is
        // not evidence about any row, which is exactly the inference the window deleted.
        t.upsert(
            "exprow",
            "leg-exp",
            addr(4),
            MAC_A,
            Instant::now().into_std() + Duration::from_secs(30),
            &cap(10),
            Instant::now().into_std(),
        );
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(a.run_batch().await, Batch::Drained);
        assert_eq!(a.counts.expiries, 3);
        assert_eq!(
            said.lock().unwrap().len(),
            2,
            "the window elapsed (62 s since the row's last line), so it is loud again"
        );
    }

    /// The window rule is `>=`, so a recurrence at EXACTLY `EXPIRY_LOG_WINDOW` is due, not
    /// suppressed. Pins the boundary the other tests clear by a second.
    ///
    /// Regression: weaken `>=` to `>` in `note_expiries` and this goes red at one line.
    #[tokio::test(start_paused = true)]
    async fn a_recurrence_at_exactly_the_window_boundary_is_journaled() {
        let t = Arc::new(NeighborTable::new());
        let said = Arc::new(Mutex::new(Vec::new()));
        let mut a = FlushActor::with_observer(
            t.clone(),
            Box::new(MockNeighborIo::kernel("[]")),
            Box::new(RecordingObserver {
                said: said.clone(),
                table: Some(t.clone()),
                woke: None,
            }),
        );

        let now = Instant::now();
        a.note_expiries(&["boundary".to_string()], now);
        assert_eq!(said.lock().unwrap().len(), 1, "first line is always due");

        a.note_expiries(&["boundary".to_string()], now + EXPIRY_LOG_WINDOW);
        assert_eq!(
            said.lock().unwrap().len(),
            2,
            "exactly one window later is DUE: the rule is `>=`, not `>`"
        );
    }

    /// The **other** unaccounted arm: an entry whose lease ends between the take and the
    /// put-back. `re_dirty` drops it rather than resurrecting it (T5a), and that drop was
    /// credited nowhere either. Reachable in production because a batch of 31 writes each
    /// wedged to `WRITE_DEADLINE` = 2 s spans 62 s, past `MIN_LEASE`.
    ///
    /// **Real time, not the paused clock**: tokio's paused clock only advances when the runtime
    /// is idle on a timer, and there is no await between the take and the put-back — the write
    /// is a synchronous fork. So the write mock sleeps on the thread and the lease is set in
    /// milliseconds, with a 2x margin either side of it.
    ///
    /// Regression: stop extending `dropped` with `re_dirty`'s return in the put-back loop. The
    /// write-failure assertions stay green and only the expiry ones go red.
    #[tokio::test]
    async fn a_lease_that_ends_during_a_failed_write_is_counted_as_an_expiry() {
        let t = Arc::new(NeighborTable::new());
        let now = Instant::now().into_std();
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            now + Duration::from_millis(300),
            &cap(10),
            now,
        );

        let io = MockNeighborIo::new(|argv, _| {
            if argv.contains(&"show") {
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: "[]".to_string(),
                    stderr: String::new(),
                });
            }
            std::thread::sleep(Duration::from_millis(600));
            Ok(crate::sys::Output {
                status: 1,
                stdout: String::new(),
                stderr: "RTNETLINK answers: Network is down".to_string(),
            })
        });
        let mut a = FlushActor::new(t.clone(), Box::new(io));

        assert_eq!(a.run_batch().await, Batch::Drained);
        assert_eq!(a.counts.write_failures, 1, "the write failed");
        assert_eq!(
            a.counts.expiries, 1,
            "the lease ran out before the put-back, so the entry was dropped rather than re-queued — and that drop is counted, not silent"
        );
        assert_eq!(
            a.per_row.get(ROW).copied().unwrap_or_default().expiries,
            1,
            "credited to the row that lost it"
        );
        assert_eq!(t.len(), 0, "and it is gone, not resurrected");
    }

    /// **`read_failures` above all (plan §4 task 5)** — the counter spec §4.5 says would have
    /// caught r10's defect six reviews earlier, because a host whose reads are silently failing
    /// looks exactly like a coherent one from every OTHER counter here: nothing is dirtied
    /// wrong, nothing is written wrong, there is just nothing written at all. Proved both
    /// directions: a write failure must not move it, and a read failure must not move
    /// `write_failures` (a failed read attempts no write).
    ///
    /// Regression proved by hand: incrementing `read_failures` inside the write-failure arm (or
    /// vice versa) turns one of this test's two assertions red while leaving T3c/T-THROTTLE,
    /// which only ever exercise one of the two failures per test, green.
    #[tokio::test(start_paused = true)]
    async fn read_failures_moves_only_on_a_failed_kernel_read_never_on_a_write_failure() {
        let t = table_with(0);
        t.upsert(
            ROW,
            LEG,
            addr(0),
            MAC_A,
            long(),
            &cap(10),
            Instant::now().into_std(),
        );
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = failing.clone();
        let io = MockNeighborIo::new(move |argv, _| {
            if argv.contains(&"show") {
                if f.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(crate::error::Error::fatal("kernel read failed"));
                }
                return Ok(crate::sys::Output {
                    status: 0,
                    stdout: "[]".to_string(),
                    stderr: String::new(),
                });
            }
            // Every write fails, so the first batch below exercises write_failures alone.
            Ok(crate::sys::Output {
                status: 2,
                stdout: String::new(),
                stderr: "boom".to_string(),
            })
        });
        let mut a = FlushActor::new(t.clone(), Box::new(io));

        a.run_batch().await;
        assert_eq!(a.counts.write_failures, 1);
        assert_eq!(
            a.counts.read_failures, 0,
            "a write failure is not a read failure"
        );

        // The entry the failed write put back is still dirty, so this batch reads again — and
        // this time the read itself fails.
        failing.store(true, std::sync::atomic::Ordering::SeqCst);
        a.run_batch().await;
        assert_eq!(a.counts.read_failures, 1);
        assert_eq!(
            a.counts.write_failures, 1,
            "a failed read attempts no write at all, so the count from the first batch must \
             not move"
        );
    }
}
