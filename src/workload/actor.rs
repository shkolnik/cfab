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
//! **The batching rule** (plan §1.1, normative, and the premise the ruling's own 529-token
//! worst case rests on): the actor does not read until it holds `1 + min(dirty_depth, B - 1)`
//! tokens — the read plus every write that batch intends to fund. An actor that reads whenever
//! it holds a single token converges to one read per write, which is 1024 tokens = 102.4 s
//! against a 60 s `MIN_LEASE`: a legitimate short-lease ACK expires in the queue and R2.1 is
//! silently false with every other test green. Only the read-fork count over a full drain can
//! see it, which is what `one_read_fork_per_batch_over_a_full_drain` asserts.
//!
//! **The dirty depth is read under the table lock and the SLEEP IS NOT.** Holding that guard
//! across a wait of up to `B / R` = 3.2 s stalls every relay upsert on the host — DHCP
//! forwarding stops (spec §4.2.3: "the relay's upsert never blocks"). The same applies to every
//! token spend, every journal line and every fork: the table lock is a leaf, taken last and
//! released before anything else happens.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::time::Instant;

use crate::workload::table::NeighborTable;
use crate::workload::writer::{NeighborIo, WriteVerb, write_argv};

/// `R`: the refill rate, in forks per second. A CONSTANT, never autotuned — the attacker sits
/// inside any feedback loop that measures cost, so a flood would shrink the budget under exactly
/// the load the budget exists to absorb (spec §4.2.2). ~1% of one core at the measured 1.0 ms
/// write (spec §2). Rack R2 may RAISE it; it may not lower it below 8.89/s without re-deriving
/// `MIN_LEASE`, because `MIN_LEASE` = 60 s holds only while the 533-token worst case fits inside
/// it (plan §1.2).
pub const REFILL_PER_SEC: u32 = 10;

/// `B`: the burst. Makes R4 ("one VM booting is immediate") true on a quiet host — a lone VM
/// needs `1 + 1` = 2 tokens and a quiet host holds all 32.
pub const BURST: u32 = 32;

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

/// Counters the actor keeps. Exported in task 5; kept here because the task that produces a
/// counter is the one that can tell whether it moved for the right reason. `read_failures` is
/// separate from `write_failures` on purpose: a coherent host and a host that silently wrote
/// nothing look identical from the outside, which is why that defect survived six reviews.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub reads: u64,
    pub read_failures: u64,
    pub writes: u64,
    pub write_failures: u64,
    pub skips: u64,
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
    pub counts: Counts,
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
        FlushActor {
            table,
            io,
            obs,
            bucket: Bucket::new(Instant::now()),
            read_failing: false,
            write_failing: std::collections::BTreeSet::new(),
            counts: Counts::default(),
        }
    }

    /// The actor's whole life: batch, batch, batch, sleep when clean. Never returns.
    pub async fn run(mut self) {
        loop {
            if let Batch::Idle = self.run_batch().await {
                self.table.wait_dirty().await;
            }
        }
    }

    /// One batch: wait for the tokens this batch intends to spend, read the kernel once, then
    /// drain in queue order.
    pub async fn run_batch(&mut self) -> Batch {
        // Under the lock for exactly this long. The wait below is NOT.
        let depth = self.table.dirty_depth();
        if depth == 0 {
            return Batch::Idle;
        }
        let want = 1 + u32::try_from(depth).unwrap_or(u32::MAX).min(BURST - 1);

        loop {
            self.obs.wait_decision();
            let wait = self.bucket.wait_for(Instant::now(), want);
            if wait.is_zero() {
                break;
            }
            tokio::time::sleep(wait).await;
        }

        // The read is a fork, so it spends a token like any other (spec §4.2). This is also
        // what makes the read-failure path below unable to spin: a batch whose read fails has
        // already paid for it.
        self.obs.token_spend();
        if !self.bucket.spend(Instant::now()) {
            return Batch::Idle;
        }
        self.counts.reads += 1;
        let doc = match self.io.run(&READ_ARGV) {
            Ok(o) if o.ok() => KernelNeighbors::parse(&o.stdout)
                .ok_or_else(|| "cannot read the neighbor document".to_string()),
            Ok(o) => Err(format!("ip exited {}: {}", o.status, o.stderr.trim())),
            Err(e) => Err(e.to_string()),
        };
        let doc = match doc {
            Ok(doc) => {
                self.read_failing = false;
                doc
            }
            Err(why) => {
                // Nothing was taken — **take follows the read, never precedes it** — so every
                // entry keeps its queue position and the next batch retries. The actor does
                // not guess: a failed read is the one case where neither `add` nor `replace`
                // can be justified.
                self.counts.read_failures += 1;
                if !self.read_failing {
                    self.read_failing = true;
                    self.obs.journal(&format!(
                        "cfab: dhcp neighbor actor: kernel read failed: {why}; no neighbor \
                         written this pass"
                    ));
                }
                return Batch::ReadFailed;
            }
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
        while handled < BURST - 1 {
            let now_std = Instant::now().into_std();
            let Some(t) = self.table.take_next_dirty(now_std) else {
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
                    self.write_failing.remove(&t.row);
                }
                Some(why) => {
                    self.counts.write_failures += 1;
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
        let now_std = Instant::now().into_std();
        for (row, addr) in put_back {
            self.table.re_dirty(&row, addr, now_std);
        }
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
            t.upsert(ROW, LEG, addr(i), MAC_A, long(), &cap(u32::MAX));
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
        t.upsert(ROW, LEG, addr(0), MAC_B, long(), &cap(10));
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
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
        let io = MockNeighborIo::kernel(&kernel_doc(&[(LEG, addr(0), None)]));
        let calls = io.calls();
        FlushActor::new(t, Box::new(io)).run_batch().await;
        let w = writes(&calls.lock().unwrap());
        assert_eq!(w.len(), 1, "{w:?}");
        assert_eq!(w[0][2], "replace", "{:?}", w[0]);
        assert!(w[0].windows(2).any(|p| p == ["nud", "stale"]), "{:?}", w[0]);

        // Absent -> add.
        let t = table_with(0);
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
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
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
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
        t.upsert(ROW, LEG, addr(0), MAC_B, long(), &cap(10));
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
            t.upsert(row, leg, addr(0), MAC_A, long(), &cap(10));
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
        t.upsert("busy", "leg-busy", addr(5), MAC_B, long(), &cap(10));
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
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
                t.upsert(ROW, LEG, addr(i), MAC_A, long(), &cap(u32::MAX));
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
    /// true worst case `(Σ C_i + ceil(Σ C_i / (B - 1))) / R` = **(512 + 17) / 10 = 52.9 s**.
    /// Not `Σ C_i / R` = 51.2 s, which is unachievable now that the drain also spends read
    /// tokens.
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
        t.upsert(ROW, LEG, victim, MAC_B, long(), &cap(u32::MAX));
        for i in 0..SIGMA_C - 1 {
            t.upsert(ROW, LEG, addr(i), MAC_A, long(), &cap(u32::MAX));
        }
        let io = MockNeighborIo::kernel("[]");
        let calls = io.calls();
        let mut a = FlushActor::new(t.clone(), Box::new(io));

        let started = Instant::now();
        let deadline = Duration::from_millis(52_900);
        let victim_str = victim.to_string();
        loop {
            a.run_batch().await;
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
                "the victim was not written within (512 + 17) / 10 = 52.9 s"
            );
            // The attacker keeps every other address dirty.
            for i in 0..SIGMA_C - 1 {
                t.upsert(ROW, LEG, addr(i), MAC_A, long(), &cap(u32::MAX));
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
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
        for i in 1..5 {
            t.upsert(ROW, LEG, addr(i), MAC_A, long(), &cap(10));
        }
        assert_eq!(t.queued_len(), 5);
        for _ in 0..500 {
            t.upsert(ROW, LEG, addr(0), MAC_B, long(), &cap(10));
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
        t.upsert("zz", "leg-z", addr(0), MAC_A, long(), &cap(10));
        t.upsert("aa", "leg-a", addr(0), MAC_A, long(), &cap(10));
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
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
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
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
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
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
        t.upsert(ROW, LEG, addr(0), MAC_B, long(), &cap(10));
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
        t.upsert(ROW, LEG, addr(0), MAC_A, soon, &cap(10));
        t.upsert(ROW, LEG, addr(1), MAC_A, long(), &cap(10));
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
    /// Three entries, not two, and the ORDER is asserted over the whole queue: with two entries
    /// and two failed batches a take-before-read implementation rotates the queue exactly twice
    /// and lands back where it started, so the position assertion reads green while the rule is
    /// violated — the defect class spec §10 names, in the test written to pin it.
    ///
    /// Regression: take the entry before the read and re-dirty it on failure.
    #[tokio::test(start_paused = true)]
    async fn a_failed_read_writes_nothing_and_keeps_queue_position() {
        let t = table_with(3);
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
            }),
        );
        assert_eq!(a.run_batch().await, Batch::ReadFailed);
        assert_eq!(a.run_batch().await, Batch::ReadFailed);
        assert_eq!(a.counts.read_failures, 2);
        assert!(
            writes(&calls.lock().unwrap()).is_empty(),
            "nothing is guessed"
        );
        assert_eq!(t.dirty_depth(), 3, "nothing was taken");
        assert_eq!(
            said.lock().unwrap().len(),
            1,
            "one line per streak, not per read"
        );

        let now = Instant::now().into_std();
        let order: Vec<Ipv4Addr> =
            std::iter::from_fn(|| t.take_next_dirty(now).map(|x| x.addr)).collect();
        assert_eq!(
            order,
            vec![addr(0), addr(1), addr(2)],
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
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
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
            t.upsert(ROW, LEG, addr(tick + 100), MAC_B, long(), &cap(u32::MAX));
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
        t.upsert(ROW, LEG, addr(0), MAC_A, long(), &cap(10));
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
        t.upsert(ROW, LEG, addr(0), MAC_B, long(), &cap(10));
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
    /// ignores the drain's own read forks (spec §1's own erratum over call 10's ruling). The
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
        // worst case the spec derives `MIN_LEASE` against (spec §1.2's 533 tokens / R) rather
        // than a cold start's one-off 32-token credit, which would understate the wait by
        // `B / R` = 3.2 s and let a shorter, unsafe `MIN_LEASE` pass this test by accident.
        for _ in 0..BURST {
            a.bucket.spend(Instant::now());
        }

        for i in 0..SIGMA_C - 1 {
            t.upsert(ROW, LEG, addr(i), MAC_A, long(), &cap(u32::MAX));
        }
        // Dirtied LAST: the genuine worst FIFO position, behind all 511 others.
        let victim = addr(SIGMA_C);
        let victim_expiry =
            Instant::now().into_std() + crate::workload::table::clamp_lease(Some(1));
        t.upsert(ROW, LEG, victim, MAC_B, victim_expiry, &cap(u32::MAX));

        let started = Instant::now();
        // Matches `the_nth_entry_is_written_inside_the_stated_worst_case`'s own number; task 4
        // moves both to 53.3 s when the sweep starts spending tokens on the actor too.
        let deadline = Duration::from_millis(52_900);
        let victim_str = victim.to_string();
        loop {
            a.run_batch().await;
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
}
