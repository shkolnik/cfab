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
            }
            None => {
                if row_len(entries, row) >= cap.value {
                    let first_of_streak = refusing.insert(row.to_string());
                    return Upsert::Refused { first_of_streak };
                }
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
            }
        }
        refusing.remove(row);
        Upsert::Admitted
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

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
