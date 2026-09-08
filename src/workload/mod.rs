//! VM workload runtime: neighbour-event/FDB-poll triggered gratuitous-ARP announcing, and
//! uplink identification. `emit::workload` holds the pure text this module's callers render;
//! everything here is I/O or a pure state machine driven by it.

use std::fmt;

pub mod announce;
pub mod neigh;
pub mod uplink;

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
