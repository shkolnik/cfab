//! VM workload runtime: neighbour-event/FDB-poll triggered gratuitous-ARP announcing, and
//! uplink identification. `emit::workload` holds the pure text this module's callers render;
//! everything here is I/O or a pure state machine driven by it.

use std::collections::BTreeSet;
use std::fmt;

use crate::derive::View;
use crate::sys::Sys;

pub mod announce;
pub mod hostroutes;
pub mod leg;
pub mod neigh;
pub mod uplink;

/// The rows `apply` (or a previous watchdog tick) left deferred (spec addendum 2026-09-09): no
/// gw address on the wire yet, the forwarding watchdog installs it once the uplink forwards. One
/// parser, two readers — the supervisor (which announcer to start) and `status` (which reason to
/// report) — so a change to the file's shape or path is one edit, never two spellings that can
/// drift apart. No file (the normal case on a member whose rows all applied) is no deferred row.
pub fn deferred_names(sys: &mut dyn Sys, view: &View) -> BTreeSet<String> {
    let path = format!("{}/workload-deferred", view.fabric.run_dir);
    sys.read(&path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

/// What woke the announcer for a given workload interface (ruling 12, spec §5.1.8): the
/// rtnetlink neighbour subscription when it is open, else the FDB-poll fallback — `status`
/// reports which is active, never silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    NeighEvents,
    FdbPoll { reason: String },
}

impl fmt::Display for Trigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Trigger::NeighEvents => write!(f, "neigh events"),
            Trigger::FdbPoll { reason } => write!(f, "fdb poll ({reason})"),
        }
    }
}
