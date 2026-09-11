//! The neighbor write table: what a relayed DHCPACK is allowed to claim, for how long, and how
//! many claims one workload row may hold at once (gate C spec §4.1).
//!
//! Accepting the fact is separated from performing the write. The relay task upserts here and
//! returns; the flush actor drains the dirty queue and does the kernel write. Everything in this
//! module is pure state behind one mutex — **no I/O of any kind runs under that lock**, and the
//! lock is a leaf: nothing here acquires `Shared`, so the relay's `shared`→(read cap)→`table`
//! path can never form an AB/BA inversion against the command loop's.
//!
//! Time is a parameter, never `Instant::now()` read in here: expiry is the one rule an attacker
//! chooses the input to, so every caller states the instant it is deciding at and every test can
//! state a different one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::model::Ipv4Prefix;
use crate::sys::Sys;

/// The floor a DHCPACK's option 51 is clamped up to. Derived, not chosen (spec §8 call 9): it
/// must exceed the worst-case wait in the flush actor's queue, or a legitimate short-lease ACK
/// is admitted, queued, and expires before the actor reaches it — the write silently never
/// happens. At `Σ C_i` = 512 writes plus the batch and sweep reads the worst case is 533 tokens
/// at 10 forks/s = 53.3 s, so 60 s carries an 11.2% margin (plan §1.2).
pub const MIN_LEASE: Duration = Duration::from_secs(60);

/// The ceiling option 51 is clamped down to. RFC 2132's `0xFFFFFFFF` means "infinite", and
/// anyone on the VLAN can send an ACK carrying it (spec §2), so unclamped a single forged packet
/// buys a table entry that never expires. 24 h is the site's own `max-lease-time` (spec §8
/// call 6), comfortably above any real homelab lease and far below "forever".
pub const MAX_LEASE: Duration = Duration::from_secs(24 * 60 * 60);

/// What an ACK with no option 51 at all is worth. An ACK MUST carry one (RFC 2131 §4.3.1
/// table 3) but a forged one need not, and "no expiry" is never the answer: this is the site's
/// `default-lease-time` (spec §8 call 6).
pub const NO_LEASE_DEFAULT: Duration = Duration::from_secs(60 * 60);

/// The kernel refuses every new neighbor entry **host-wide** past this many (per address
/// family), so it is the number cfab sizes itself against. 1024 is the kernel's documented
/// default and was VERIFIED as the stock value on pve1-tb (spec §2). It is used twice on
/// purpose: as the ceiling `C` is never allowed above, and as the value assumed when the sysctl
/// cannot be read — so the degraded path and the ceiling are one number, not two.
pub const GC_THRESH3_DEFAULT: u32 = 1024;

/// Where the kernel publishes it. Per address family, not per device: there is no per-device
/// knob, which is why cfab caps itself instead of writing one (spec §4.1.4).
pub const GC_THRESH3_PATH: &str = "/proc/sys/net/ipv4/neigh/default/gc_thresh3";

/// `expires_at - now` for one ACK: option 51, clamped both ways, with a stated default when it
/// is absent. Both ends matter and for different reasons — see `MIN_LEASE` and `MAX_LEASE`.
pub fn clamp_lease(option_51: Option<u32>) -> Duration {
    match option_51 {
        None => NO_LEASE_DEFAULT,
        Some(secs) => Duration::from_secs(u64::from(secs)).clamp(MIN_LEASE, MAX_LEASE),
    }
}

/// Which term of `C = min(prefix hosts, min(gc_thresh3, 1024) / 2 / rows)` actually bound it.
/// Carried because the refusal line must name the remedy that works: at the /24 a real site
/// declares, the prefix binds and raising the sysctl changes `C` by exactly zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapBound {
    /// The declared prefix's host count. No sysctl affects `C` here.
    Prefix,
    /// The kernel's `gc_thresh3`, halved and shared across the member's workload rows.
    GcThresh3,
}

/// One row's admission cap, with everything its refusal line has to state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowCap {
    /// `C`: the most table entries this row may hold at once.
    pub value: u32,
    pub bound_by: CapBound,
    /// `gc_thresh3` as read, or `GC_THRESH3_DEFAULT` if the read failed.
    pub gc_thresh3: u32,
    /// How many workload rows the kernel allowance is divided between.
    pub rows: u32,
}

impl RowCap {
    /// The one line an operator gets when a row hits its cap. States `gc_thresh3` (that name
    /// alone — the published recipes raise all three thresholds together and `gc_thresh1` is a
    /// different decision with host-wide GC consequences), the derived `C`, and **which term
    /// bound it**, because a remedy that changes `C` by zero is worse than no remedy at all.
    pub fn refusal_line(&self, row: &str, addr: Ipv4Addr, prefix: Ipv4Prefix) -> String {
        let head = format!(
            "cfab: workload {row}: dhcp ack for {addr} refused: this row already holds C = {} \
             neighbor claims",
            self.value
        );
        match self.bound_by {
            CapBound::Prefix => format!(
                "{head}, which is every host address in prefix {prefix}; gc_thresh3 = {} allows \
                 more, so raising it does not raise C",
                self.gc_thresh3
            ),
            CapBound::GcThresh3 if self.gc_thresh3 < GC_THRESH3_DEFAULT => format!(
                "{head}, bound by gc_thresh3 = {} halved across {} workload row(s); raise \
                 gc_thresh3 toward its {GC_THRESH3_DEFAULT} default to raise C",
                self.gc_thresh3, self.rows
            ),
            CapBound::GcThresh3 => format!(
                "{head}, bound by gc_thresh3 = {} halved across {} workload row(s); C never \
                 exceeds half the kernel default of {GC_THRESH3_DEFAULT}, so raising gc_thresh3 \
                 does not raise C",
                self.gc_thresh3, self.rows
            ),
        }
    }
}

/// The host-wide half of the cap: the kernel's ceiling and how many workload rows share it.
/// Read once at start and refreshed by the workload tick's publication — one source, one
/// cadence (spec §4.1.4) — so an operator who lowers the sysctl sees `C` follow it down on the
/// next tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapSource {
    pub gc_thresh3: u32,
    pub rows: u32,
}

impl CapSource {
    /// Read `gc_thresh3`. A file read, never a fork, so it is cheap enough for the command loop.
    /// A read that fails or does not parse yields `GC_THRESH3_DEFAULT` and the reason, for the
    /// caller to journal: cfab **never refuses to start** over this, and never writes the
    /// sysctl either.
    pub fn read(sys: &dyn Sys, rows: u32) -> (CapSource, Option<String>) {
        match sys.read(GC_THRESH3_PATH) {
            Ok(text) => match text.trim().parse::<u32>() {
                Ok(gc_thresh3) => (CapSource { gc_thresh3, rows }, None),
                Err(e) => (
                    CapSource {
                        gc_thresh3: GC_THRESH3_DEFAULT,
                        rows,
                    },
                    Some(format!("{GC_THRESH3_PATH} holds {:?}: {e}", text.trim())),
                ),
            },
            Err(e) => (
                CapSource {
                    gc_thresh3: GC_THRESH3_DEFAULT,
                    rows,
                },
                Some(format!("cannot read {GC_THRESH3_PATH}: {e}")),
            ),
        }
    }

    /// `C = min(prefix hosts, min(gc_thresh3, 1024) / 2 / rows)` (RULED 2026-09-11).
    ///
    /// `C` follows the sysctl **down, never above the kernel default**: `Σ C_i` is then bounded
    /// by `gc_thresh3 / 2` whatever the row count (the `/rows` divisor cancels in the sum), so
    /// the sysctl alone sets the actor's worst-case queue depth — which is what `MIN_LEASE`
    /// is derived against. Letting `C` follow an operator's raised sysctl upward spends that
    /// margin and then breaks it, with no human in the loop to re-derive anything. The `/2` is
    /// a deliberate under-claim, not an accounting: the neighbor table is host-global and not
    /// namespaced (spec §2), so the other half is cfab's allowance for every container, CT and
    /// pod on the box that it can neither see nor count.
    pub fn for_prefix(&self, prefix: Ipv4Prefix) -> RowCap {
        let hosts = prefix_hosts(prefix);
        let kernel = self.gc_thresh3.min(GC_THRESH3_DEFAULT) / 2 / self.rows.max(1);
        let (value, bound_by) = if hosts <= kernel {
            (hosts, CapBound::Prefix)
        } else {
            (kernel, CapBound::GcThresh3)
        };
        RowCap {
            value,
            bound_by,
            gc_thresh3: self.gc_thresh3,
            rows: self.rows,
        }
    }
}

/// Addresses in `prefix` a VM can actually hold: every address less the network and broadcast
/// ones. Computed in 64 bits because a `/0` is 2^32 of them.
fn prefix_hosts(prefix: Ipv4Prefix) -> u32 {
    let all = 1u64 << (32 - u32::from(prefix.len));
    u32::try_from(all.saturating_sub(2)).unwrap_or(u32::MAX)
}

/// One table entry: one address, one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The leg the write goes out (`ip neigh … dev <leg>`), carried so the actor can build the
    /// argv from the entry alone.
    pub leg: String,
    /// The MAC the LAST ACK claimed — coalescing performs the last update, never the first.
    pub mac: [u8; 6],
    pub expires_at: Instant,
    /// Queued for the actor. cfab's own flag; never a cached kernel NUD state.
    pub dirty: bool,
}

/// What one `upsert` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    /// Admitted: a new entry, or the last update coalesced onto an existing one.
    Admitted,
    /// The row is at `C`. `first_of_streak` is true exactly once per refusal run per row, so
    /// the journal line is once per streak and not once per attacker-chosen packet.
    Refused { first_of_streak: bool },
}

/// One entry the actor took off the dirty queue, with everything the write needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taken {
    pub row: String,
    pub leg: String,
    pub addr: Ipv4Addr,
    pub mac: [u8; 6],
}

type Key = (String, Ipv4Addr);

#[derive(Default)]
struct Inner {
    entries: BTreeMap<Key, Entry>,
    /// The host-wide dirty queue, oldest first. It shares the table's lock on purpose (spec
    /// §4.2.3): one lock, one FIFO, one actor. Keys of entries that were removed stay here
    /// until a take walks past them — cheaper than a scan, and a stale key is unambiguous
    /// because the entry it names is gone.
    queue: VecDeque<Key>,
    /// Rows in an ongoing refusal streak.
    refusing: BTreeSet<String>,
}

/// The table. Host-wide: one per member, shared by every relay task and the flush actor.
#[derive(Default)]
pub struct NeighborTable {
    inner: std::sync::Mutex<Inner>,
    /// How a newly dirtied entry wakes the flush actor, so a quiet host costs no polling tick.
    /// Outside the mutex, and notified only after the guard has dropped: the table lock is a
    /// leaf and nothing — not even a wakeup — happens under it. `Notify::notify_one` stores a
    /// permit when no one is waiting, so an upsert that races the actor's own dirty-depth check
    /// cannot be lost.
    dirty: tokio::sync::Notify,
}

impl NeighborTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register what one relayed DHCPACK claimed. Never blocks on anything but the lock, never
    /// forks, and never drops a claim silently: a refusal is returned and counted.
    ///
    /// An address already in the table is updated in place and re-queued only if it was not
    /// already dirty, so re-upserting faster than the actor drains cannot push an entry to the
    /// back of its own queue. The cap is checked only for a NEW key: coalescing onto an entry
    /// the row already holds adds nothing to the kernel's table.
    pub fn upsert(
        &self,
        row: &str,
        leg: &str,
        addr: Ipv4Addr,
        mac: [u8; 6],
        expires_at: Instant,
        cap: &RowCap,
    ) -> Upsert {
        let key = (row.to_string(), addr);
        let outcome = {
            let mut g = self.inner.lock().unwrap();
            let Inner {
                entries,
                queue,
                refusing,
            } = &mut *g;
            match entries.get_mut(&key) {
                Some(e) => {
                    e.leg = leg.to_string();
                    e.mac = mac;
                    e.expires_at = expires_at;
                    if !e.dirty {
                        e.dirty = true;
                        queue.push_back(key);
                    }
                    refusing.remove(row);
                    Upsert::Admitted
                }
                None => {
                    if row_len(entries, row) >= cap.value {
                        let first_of_streak = refusing.insert(row.to_string());
                        Upsert::Refused { first_of_streak }
                    } else {
                        entries.insert(
                            key.clone(),
                            Entry {
                                leg: leg.to_string(),
                                mac,
                                expires_at,
                                dirty: true,
                            },
                        );
                        queue.push_back(key);
                        refusing.remove(row);
                        Upsert::Admitted
                    }
                }
            }
        };
        // The guard is gone by here on purpose: the actor must never be woken from under this
        // lock, because the first thing it does on waking is take it.
        if matches!(outcome, Upsert::Admitted) {
            self.dirty.notify_one();
        }
        outcome
    }

    /// Put back an entry the actor took and could not write. The rules it encodes are §4.1.2's,
    /// and each one is a defect some round shipped:
    ///
    /// - An entry an upsert re-dirtied *during* the write is already queued and **keeps its
    ///   position** — an unrelated kernel failure must not push a newer legitimate claim to the
    ///   back of the FIFO.
    /// - An entry whose lease ran out between take and completion is **not resurrected**;
    ///   expiry wins over the retry.
    /// - Anything else goes to the **back**, so one failing address cannot hold the queue.
    pub fn re_dirty(&self, row: &str, addr: Ipv4Addr, now: Instant) {
        let key = (row.to_string(), addr);
        let woke = {
            let mut g = self.inner.lock().unwrap();
            let Inner { entries, queue, .. } = &mut *g;
            match entries.get_mut(&key) {
                None => false,
                Some(e) if e.expires_at <= now => {
                    entries.remove(&key);
                    false
                }
                Some(e) if e.dirty => false,
                Some(e) => {
                    e.dirty = true;
                    queue.push_back(key);
                    true
                }
            }
        };
        if woke {
            self.dirty.notify_one();
        }
    }

    /// Sleep until something is dirty. The actor's only idle path: a quiet host runs no timer
    /// and does no work at all here (R4).
    pub async fn wait_dirty(&self) {
        self.dirty.notified().await;
    }

    /// Whether this lock is free *right now*, from the calling thread. `std::sync::Mutex` is
    /// not reentrant, so a thread already holding the guard gets `false` — which is what makes
    /// this an observable proxy for "no I/O, no `Shared`, no token spend under the table lock"
    /// (spec §4.2.3), whose live symptom is otherwise a hang rather than a wrong answer.
    pub fn lock_is_free(&self) -> bool {
        self.inner.try_lock().is_ok()
    }

    /// The next dirty entry in host-wide FIFO order, cleared of its dirty flag.
    ///
    /// **An entry whose lease expired is dropped here, not written**: the actor reaching it
    /// late is exactly the case `MIN_LEASE` bounds and never the case where a stale claim
    /// should still be installed. Stale queue keys (an entry removed while queued) are walked
    /// past.
    pub fn take_next_dirty(&self, now: Instant) -> Option<Taken> {
        let mut g = self.inner.lock().unwrap();
        let Inner { entries, queue, .. } = &mut *g;
        while let Some(key) = queue.pop_front() {
            let Some(e) = entries.get_mut(&key) else {
                continue;
            };
            if !e.dirty {
                continue;
            }
            if e.expires_at <= now {
                entries.remove(&key);
                continue;
            }
            e.dirty = false;
            let taken = Taken {
                row: key.0.clone(),
                leg: e.leg.clone(),
                addr: key.1,
                mac: e.mac,
            };
            return Some(taken);
        }
        None
    }

    /// Drop every entry whose lease has run out, freeing its slot against the cap. Nothing in
    /// this table extends an expiry and nothing here reads the kernel: the kernel entry cfab
    /// wrote is left exactly where it is — cfab deletes no neighbor entry, ever. Returns how
    /// many rows were dropped.
    pub fn remove_expired(&self, now: Instant) -> usize {
        let mut g = self.inner.lock().unwrap();
        let before = g.entries.len();
        g.entries.retain(|_, e| e.expires_at > now);
        before - g.entries.len()
    }

    /// How many entries are queued for the actor. Read under the lock and returned — the caller
    /// must drop the guard before it waits on anything.
    pub fn dirty_depth(&self) -> usize {
        let g = self.inner.lock().unwrap();
        g.entries.values().filter(|e| e.dirty).count()
    }

    /// How many keys sit in the dirty queue, duplicates and stale keys included. Distinct from
    /// `dirty_depth`, which counts entries: the difference is exactly what re-enqueueing an
    /// already-dirty entry would grow without bound under a flood.
    pub fn queued_len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every entry the table holds, as `(row, addr, leg)`, copied out.
    ///
    /// Copied rather than iterated under the guard because the one caller — the sweep — then
    /// classifies each of these against a kernel document and calls back into `re_dirty`. The
    /// table lock is a leaf: it is taken here, released, and taken again per re-dirty, which
    /// costs one uncontended lock per entry and buys the rule that nothing at all happens under
    /// it (spec §4.2.3).
    pub fn list_entries(&self) -> Vec<(String, Ipv4Addr, String)> {
        self.inner
            .lock()
            .unwrap()
            .entries
            .iter()
            .map(|((row, addr), e)| (row.clone(), *addr, e.leg.clone()))
            .collect()
    }

    /// A copy of one entry, for the sweep and for tests.
    pub fn entry(&self, row: &str, addr: Ipv4Addr) -> Option<Entry> {
        self.inner
            .lock()
            .unwrap()
            .entries
            .get(&(row.to_string(), addr))
            .cloned()
    }
}

/// How many entries one row holds. `BTreeMap` keys sort by row first, so this is a range walk,
/// not a scan of the whole table.
fn row_len(entries: &BTreeMap<Key, Entry>, row: &str) -> u32 {
    let lo = (row.to_string(), Ipv4Addr::UNSPECIFIED);
    let hi = (row.to_string(), Ipv4Addr::BROADCAST);
    u32::try_from(entries.range(lo..=hi).count()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    const ROW: &str = "vms";
    const OTHER: &str = "lab";
    const LEG: &str = "cfab-work-vms";
    const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

    fn p22() -> Ipv4Prefix {
        Ipv4Prefix::parse("10.9.0.0/22").unwrap()
    }

    fn p24() -> Ipv4Prefix {
        Ipv4Prefix::parse("192.168.20.0/24").unwrap()
    }

    /// A cap of `value`, shaped however the test needs; the derivation itself is T8's subject.
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

    // ---- T1: coalescing performs the LAST update -----------------------------------------

    /// **T1 (table half).** Two claims for one address between takes leave the SECOND MAC in
    /// the table and produce exactly one entry to write. Round 3's dedupe performed the FIRST
    /// update and dropped the rest, which on a VM that changed MAC writes the stale binding.
    ///
    /// Regression: in `upsert`'s existing-entry arm, leave `e.mac` alone.
    #[test]
    fn coalescing_performs_the_last_update() {
        let t = NeighborTable::new();
        let exp = Instant::now() + Duration::from_secs(600);
        t.upsert(ROW, LEG, addr(1), MAC_A, exp, &cap(10));
        t.upsert(ROW, LEG, addr(1), MAC_B, exp, &cap(10));

        let taken = t
            .take_next_dirty(Instant::now())
            .expect("one entry to write");
        assert_eq!(taken.mac, MAC_B, "the LAST claim is the one written");
        assert_eq!(taken.addr, addr(1));
        assert_eq!(taken.leg, LEG, "the entry carries the leg the write needs");
        assert!(
            t.take_next_dirty(Instant::now()).is_none(),
            "two claims for one address are one write, not two"
        );
    }

    /// **T1a (table half).** The same claim twice with the row expiring in between: the second
    /// is a fresh admission, not a repeat the table already knows about. `serve`'s own half is
    /// `a_repeated_identical_ack_still_reaches_the_table` in `relay.rs`.
    ///
    /// Regression: gate `upsert` on "this row already claimed this (address, mac)".
    #[test]
    fn a_repeated_identical_claim_after_expiry_is_admitted_again() {
        let t = NeighborTable::new();
        let t0 = Instant::now();
        t.upsert(
            ROW,
            LEG,
            addr(1),
            MAC_A,
            t0 + Duration::from_secs(60),
            &cap(10),
        );
        assert_eq!(t.remove_expired(t0 + Duration::from_secs(61)), 1);

        t.upsert(
            ROW,
            LEG,
            addr(1),
            MAC_A,
            t0 + Duration::from_secs(3600),
            &cap(10),
        );
        assert_eq!(
            t.entry(ROW, addr(1)).map(|e| e.mac),
            Some(MAC_A),
            "an identical claim is exactly what a VM whose entry was lost re-sends"
        );
    }

    // ---- T7 / T7c: expiry, in both of its places ------------------------------------------

    /// **T7 (table half).** An expired entry is removed by the sweep's pass and is dropped at
    /// take rather than written — the two places expiry is enforced, and neither is the other.
    ///
    /// Regression: ignore `expires_at` in `remove_expired`, or in `take_next_dirty`.
    #[test]
    fn an_expired_entry_is_removed_and_is_never_taken_for_a_write() {
        let t0 = Instant::now();
        let live = t0 + Duration::from_secs(600);
        let dead = t0 + Duration::from_secs(30);

        // The take half: the entry expires while it sits in the queue.
        let t = NeighborTable::new();
        t.upsert(ROW, LEG, addr(1), MAC_A, dead, &cap(10));
        assert!(
            t.take_next_dirty(t0 + Duration::from_secs(31)).is_none(),
            "an entry that expired in the queue is dropped at take, not written"
        );
        assert_eq!(t.len(), 0, "and it frees its slot against the cap");

        // The sweep half: an entry nothing ever takes still leaves the table.
        let t = NeighborTable::new();
        t.upsert(ROW, LEG, addr(1), MAC_A, dead, &cap(10));
        t.upsert(ROW, LEG, addr(2), MAC_A, live, &cap(10));
        assert_eq!(t.remove_expired(t0 + Duration::from_secs(31)), 1);
        assert!(t.entry(ROW, addr(1)).is_none());
        assert!(t.entry(ROW, addr(2)).is_some(), "a live entry is untouched");
    }

    /// **T7c.** NOTHING extends a row's expiry. r6 extended it while the kernel held the entry
    /// (one forgery burst becomes immortal); r7 extended it while the entry's `used` counter
    /// was fresh (working VMs get expired instead). Two failed mechanisms, and the measurement
    /// that killed the second showed no third could work — for a genuinely idle VM there is no
    /// liveness signal on this host to condition on. So the table takes no input but `now`:
    /// being queued, having been taken, or being about to be written changes nothing.
    ///
    /// Regression: any "keep it a bit longer because …" clause in `remove_expired` — e.g.
    /// `&& !e.dirty`, the shape an in-flight-entry exemption takes.
    #[test]
    fn nothing_extends_an_expiry() {
        let t0 = Instant::now();
        let dead = t0 + Duration::from_secs(30);
        let after = t0 + Duration::from_secs(31);

        let t = NeighborTable::new();
        t.upsert(ROW, LEG, addr(1), MAC_A, dead, &cap(10));
        assert!(t.entry(ROW, addr(1)).unwrap().dirty);
        assert_eq!(
            t.remove_expired(after),
            1,
            "a queued entry expires on schedule like any other"
        );

        let t = NeighborTable::new();
        t.upsert(ROW, LEG, addr(1), MAC_A, dead, &cap(10));
        let taken = t.take_next_dirty(t0).expect("taken while still live");
        assert_eq!(taken.addr, addr(1));
        assert_eq!(
            t.entry(ROW, addr(1)).unwrap().expires_at,
            dead,
            "taking an entry does not move its expiry"
        );
        assert_eq!(
            t.remove_expired(after),
            1,
            "nor does having been written: an expiry is the lease, and only a new ACK sets it"
        );
    }

    // ---- T7a / T-MINLEASE: the lease clamp ------------------------------------------------

    /// **T7a.** Option 51 is written by whoever sent the ACK and anyone on the VLAN can send
    /// one, so RFC 2132's `0xFFFFFFFF` ("infinite") must not become an entry that never
    /// expires; an absent option 51 gets a stated default, never "forever".
    ///
    /// Regression: take option 51 verbatim.
    #[test]
    fn the_lease_is_clamped_at_both_ends() {
        assert_eq!(clamp_lease(Some(u32::MAX)), MAX_LEASE);
        assert_eq!(clamp_lease(None), NO_LEASE_DEFAULT);
        assert_eq!(clamp_lease(Some(240)), Duration::from_secs(240));
        assert!(
            NO_LEASE_DEFAULT <= MAX_LEASE && NO_LEASE_DEFAULT >= MIN_LEASE,
            "the stated default must itself be a legal lease"
        );
    }

    /// **T-MINLEASE (first half).** A `lease = 1` ACK is raised to `MIN_LEASE`. Without the
    /// floor such an ACK is admitted, queued, and expires before the actor reaches it under
    /// boot-storm load: the write silently never happens and R2.1 is false with every other
    /// test green. The second half — that the floor outlives the worst-case queue — is the
    /// actor's, in task 3b.
    ///
    /// Regression: clamp only the upper bound.
    #[test]
    fn a_one_second_lease_is_raised_to_the_floor() {
        assert_eq!(clamp_lease(Some(1)), MIN_LEASE);
        assert_eq!(clamp_lease(Some(0)), MIN_LEASE);
    }

    // ---- T8 / T8c: the cap ----------------------------------------------------------------

    /// **T8.** `C = min(prefix hosts, min(gc_thresh3, 1024) / 2 / rows)`. The TWO-ROW case is
    /// the point: without the divisor two rows can hold the whole kernel ceiling between them.
    /// The /22 fixture is deliberate — it is the only shape where the cap bites at all, since
    /// at the /24 a real site declares the prefix binds.
    ///
    /// Regression 1: cap per row without dividing (two rows read 512 each).
    /// Regression 2: cap at the prefix host count alone — the tautology that can never refuse
    /// anything, because `ack_discovery`'s prefix check already bounds the keys.
    #[test]
    fn the_cap_is_the_smaller_of_the_prefix_and_the_kernels_share() {
        let one = CapSource {
            gc_thresh3: 1024,
            rows: 1,
        };
        assert_eq!(
            one.for_prefix(p22()),
            RowCap {
                value: 512,
                bound_by: CapBound::GcThresh3,
                gc_thresh3: 1024,
                rows: 1
            }
        );
        let two = CapSource {
            gc_thresh3: 1024,
            rows: 2,
        };
        assert_eq!(
            two.for_prefix(p22()).value,
            256,
            "the rows share the ceiling"
        );

        let c24 = one.for_prefix(p24());
        assert_eq!(c24.value, 254, "at a /24 the prefix binds, not the sysctl");
        assert_eq!(c24.bound_by, CapBound::Prefix);

        // And the cap actually refuses: the row stops admitting at C.
        let t = NeighborTable::new();
        let c = two.for_prefix(p22());
        let exp = Instant::now() + Duration::from_secs(600);
        for n in 0..c.value {
            assert_eq!(
                t.upsert(ROW, LEG, addr(n), MAC_A, exp, &c),
                Upsert::Admitted
            );
        }
        assert!(matches!(
            t.upsert(ROW, LEG, addr(c.value), MAC_A, exp, &c),
            Upsert::Refused { .. }
        ));
        assert_eq!(t.len(), c.value as usize);
        // Per ROW, not per table: a second row has its own C.
        assert_eq!(
            t.upsert(OTHER, LEG, addr(0), MAC_A, exp, &c),
            Upsert::Admitted
        );
    }

    /// **T8 (read-failure case).** A `gc_thresh3` cfab cannot read is treated as the kernel's
    /// documented default of 1024 — NOT as `C` = 1024, which would double the cap at one row
    /// and quadruple it at two, on exactly the degraded path. cfab journals and carries on; it
    /// never refuses to start over a sysctl it could not read, and it never writes one.
    ///
    /// Regression: fall back to `C` = 1024, or return an error.
    #[test]
    fn an_unreadable_gc_thresh3_falls_back_to_the_kernel_default() {
        let sys = MockSys::default();
        let (src, why) = CapSource::read(&sys, 2);
        assert_eq!(src.gc_thresh3, GC_THRESH3_DEFAULT);
        assert!(
            why.expect("a failed read must be journaled, never silent")
                .contains(GC_THRESH3_PATH)
        );
        assert_eq!(src.for_prefix(p22()).value, 256, "512 / rows, not 1024");

        let sys = MockSys::default().file(GC_THRESH3_PATH, "not-a-number\n");
        let (src, why) = CapSource::read(&sys, 1);
        assert_eq!(src.gc_thresh3, GC_THRESH3_DEFAULT);
        assert!(why.is_some(), "an unparsable value is a failed read");

        let sys = MockSys::default().file(GC_THRESH3_PATH, "512\n");
        let (src, why) = CapSource::read(&sys, 1);
        assert_eq!(src.gc_thresh3, 512);
        assert!(why.is_none());
    }

    /// **T8c (derivation half).** `C` follows the sysctl DOWN and never above the kernel
    /// default. Raising `gc_thresh3` past 1024 leaves `C` alone: `Σ C_i` is what `MIN_LEASE`
    /// is derived against, and there is no human in the loop to re-derive it when an operator
    /// raises a threshold on a live member. Lowering it DOES lower `C` — an operator shrinking
    /// the kernel table under cfab must not be ignored.
    ///
    /// Regression 1: drop the `min(gc_thresh3, 1024)` clamp — `Σ C_i` then grows past 512 and
    /// `MIN_LEASE` is silently false, which no other test can see.
    /// Regression 2: clamp to a constant 1024 instead of to the live value.
    #[test]
    fn the_cap_follows_the_sysctl_down_but_never_above_the_kernel_default() {
        let raised = CapSource {
            gc_thresh3: 16384,
            rows: 1,
        };
        assert_eq!(
            raised.for_prefix(p22()).value,
            512,
            "a raised sysctl buys cfab nothing: the ceiling is the kernel default"
        );
        assert_eq!(
            raised.for_prefix(p22()).gc_thresh3,
            16384,
            "but the journal line still states what the operator actually set"
        );

        let lowered = CapSource {
            gc_thresh3: 256,
            rows: 1,
        };
        assert_eq!(
            lowered.for_prefix(p22()).value,
            128,
            "a lowered sysctl lowers C on the next tick"
        );
    }

    /// A cap lowered below a row's current occupancy evicts NOTHING: it refuses new admissions
    /// until expiry shrinks the row. Eviction would be cfab deleting rows it promised to
    /// restore. Regression: drop entries down to the new `C` on refresh.
    #[test]
    fn lowering_the_cap_refuses_rather_than_evicts() {
        let t = NeighborTable::new();
        let exp = Instant::now() + Duration::from_secs(600);
        for n in 0..4 {
            t.upsert(ROW, LEG, addr(n), MAC_A, exp, &cap(4));
        }
        assert!(matches!(
            t.upsert(ROW, LEG, addr(9), MAC_A, exp, &cap(2)),
            Upsert::Refused { .. }
        ));
        assert_eq!(t.len(), 4, "the four already admitted stay");
    }

    // ---- T-FIFO-ADMIT ---------------------------------------------------------------------

    /// **T-FIFO-ADMIT.** Admission at a full cap is plain FIFO: whoever arrived first keeps the
    /// slot and the newcomer is refused. r8 preferred addresses the kernel already held, which
    /// is self-validating in exactly the way its expiry rule was — a booting VM loses its slot
    /// to an attacker's earlier forgery, which by then the kernel does hold.
    ///
    /// Regression: evict to admit (drop the oldest entry and let the newcomer in).
    #[test]
    fn admission_at_a_full_cap_is_plain_fifo() {
        let t = NeighborTable::new();
        let exp = Instant::now() + Duration::from_secs(600);
        for n in 0..3 {
            assert_eq!(
                t.upsert(ROW, LEG, addr(n), MAC_A, exp, &cap(3)),
                Upsert::Admitted
            );
        }
        assert!(matches!(
            t.upsert(ROW, LEG, addr(3), MAC_A, exp, &cap(3)),
            Upsert::Refused { .. }
        ));
        for n in 0..3 {
            assert!(
                t.entry(ROW, addr(n)).is_some(),
                "an earlier arrival is never displaced by a later one"
            );
        }
        assert!(t.entry(ROW, addr(3)).is_none());
        assert_eq!(
            t.upsert(ROW, LEG, addr(0), MAC_B, exp, &cap(3)),
            Upsert::Admitted,
            "a claim for an address the row already holds is a coalesce, not an admission: \
             refusing it would freeze a full row's MACs at whatever they were"
        );
        assert_eq!(t.entry(ROW, addr(0)).unwrap().mac, MAC_B);
    }

    // ---- T-THROTTLE, cap half -------------------------------------------------------------

    /// **T-THROTTLE (cap half).** The refusal rate is attacker-chosen, so the line is once per
    /// refusal STREAK per row, not once per refused packet. A successful admission ends the
    /// streak; the next refusal starts a new one.
    ///
    /// Regression: report every refusal as the first of its streak (drop `refusing` and return
    /// `first_of_streak: true`) — a log flood on demand.
    #[test]
    fn the_cap_refusal_is_journaled_once_per_streak_per_row() {
        let t = NeighborTable::new();
        let t0 = Instant::now();
        let short = t0 + Duration::from_secs(30);
        t.upsert(ROW, LEG, addr(0), MAC_A, short, &cap(1));

        let firsts = (0..10)
            .filter(|n| {
                matches!(
                    t.upsert(ROW, LEG, addr(100 + n), MAC_A, short, &cap(1)),
                    Upsert::Refused {
                        first_of_streak: true
                    }
                )
            })
            .count();
        assert_eq!(firsts, 1, "ten refusals in one streak are one journal line");

        // A second row refusing is its own streak: one row's flood must not silence another's
        // first line.
        assert_eq!(
            t.upsert(OTHER, LEG, addr(0), MAC_A, short, &cap(0)),
            Upsert::Refused {
                first_of_streak: true
            }
        );

        // The streak ends when the row admits again, and the next refusal is loud.
        t.remove_expired(t0 + Duration::from_secs(31));
        assert_eq!(
            t.upsert(ROW, LEG, addr(0), MAC_A, short, &cap(1)),
            Upsert::Admitted
        );
        assert_eq!(
            t.upsert(ROW, LEG, addr(1), MAC_A, short, &cap(1)),
            Upsert::Refused {
                first_of_streak: true
            }
        );
    }

    /// The refusal line's CONTENT is normative, not just its cadence: it states `gc_thresh3`
    /// (that name alone — the published recipes raise all three together and `gc_thresh1` is a
    /// different decision), the derived `C`, and WHICH TERM bound `C`. At the /24 a real site
    /// declares the prefix is the binding term, so a line telling the operator to raise a
    /// sysctl that changes `C` by exactly zero is the failure CLAUDE.md's "verify the remedy
    /// actually works" rule exists to prevent.
    ///
    /// Regression: collapse the arms of `refusal_line` to one that always names the sysctl, or
    /// say "the thresholds" instead of `gc_thresh3`.
    #[test]
    fn the_cap_refusal_line_names_the_remedy_that_actually_works() {
        let prefix_bound = CapSource {
            gc_thresh3: 1024,
            rows: 1,
        }
        .for_prefix(p24());
        let line = prefix_bound.refusal_line(ROW, addr(7), p24());
        assert!(line.contains("C = 254"), "{line}");
        assert!(line.contains("192.168.20.0/24"), "the binding term: {line}");
        assert!(line.contains("gc_thresh3 = 1024"), "{line}");
        assert!(
            line.contains("does not raise C"),
            "at a /24 raising the sysctl changes C by zero and the line must say so: {line}"
        );

        let sysctl_bound = CapSource {
            gc_thresh3: 256,
            rows: 2,
        }
        .for_prefix(p22());
        let line = sysctl_bound.refusal_line(ROW, addr(7), p22());
        assert_eq!(sysctl_bound.value, 64);
        assert!(line.contains("C = 64"), "{line}");
        assert!(line.contains("gc_thresh3 = 256"), "{line}");
        assert!(
            line.contains("raise gc_thresh3"),
            "here the sysctl IS the binding term and raising it does work: {line}"
        );

        // At or above the kernel default the sysctl is no longer a remedy either: C is at
        // cfab's own ceiling. Naming it would be the same wrong advice in the other direction.
        let at_ceiling = CapSource {
            gc_thresh3: 1024,
            rows: 4,
        }
        .for_prefix(p22());
        let line = at_ceiling.refusal_line(ROW, addr(7), p22());
        assert!(line.contains("does not raise C"), "{line}");

        for line in [
            prefix_bound.refusal_line(ROW, addr(7), p24()),
            sysctl_bound.refusal_line(ROW, addr(7), p22()),
            at_ceiling.refusal_line(ROW, addr(7), p22()),
        ] {
            assert!(
                !line.contains("thresholds") && !line.contains("gc_thresh1"),
                "one sysctl is named, by its own name: {line}"
            );
        }
    }
    // ---- re_dirty's own two guards ---------------------------------------------------------

    /// **T5a, resurrection half — `re_dirty` never brings an expired entry back.** Tested here
    /// rather than through the actor: expiry is enforced at take as well, so in any actor-level
    /// test the take arm fires first and this one is never reached. It is still reachable in
    /// production — a batch of 31 writes each wedged to `WRITE_DEADLINE` = 2 s spans 62 s,
    /// past `MIN_LEASE` — so it is a guard, and a guard needs a test that reaches it.
    ///
    /// Regression: drop `re_dirty`'s `e.expires_at <= now` arm and watch the entry come back.
    #[test]
    fn re_dirty_does_not_resurrect_an_expired_entry() {
        let t = NeighborTable::new();
        let t0 = Instant::now();
        t.upsert(
            ROW,
            LEG,
            addr(1),
            MAC_A,
            t0 + Duration::from_secs(60),
            &cap(10),
        );
        assert!(t.take_next_dirty(t0).is_some());
        t.re_dirty(ROW, addr(1), t0 + Duration::from_secs(61));
        assert_eq!(t.len(), 0, "expiry wins over the retry");
        assert!(t.take_next_dirty(t0 + Duration::from_secs(61)).is_none());
    }

    /// `re_dirty` on an entry an upsert already re-queued adds no second key — the same
    /// unbounded-growth guard `upsert` carries, on the other write path into the queue.
    #[test]
    fn re_dirty_of_an_already_queued_entry_enqueues_nothing() {
        let t = NeighborTable::new();
        let t0 = Instant::now();
        let exp = t0 + Duration::from_secs(600);
        t.upsert(ROW, LEG, addr(1), MAC_A, exp, &cap(10));
        assert!(t.take_next_dirty(t0).is_some());
        t.upsert(ROW, LEG, addr(1), MAC_B, exp, &cap(10));
        assert_eq!(t.queued_len(), 1);
        t.re_dirty(ROW, addr(1), t0);
        assert_eq!(t.queued_len(), 1, "already queued: no second key");
    }
}
