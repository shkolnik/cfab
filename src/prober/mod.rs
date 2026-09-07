//! The ingress router prober (finding F21).
//!
//! The migrating ingress leg (`gw = { domain = "any" }`) is an active-backup bond over every
//! wire, and the kernel judges its slaves by carrier. An island whose uplink is dead — cable,
//! PoE, upstream port, or a switch still booting — keeps carrier and keeps switching locally,
//! so the fabric's own BFD stays fully up while the router can no longer reach this member's
//! identities. Measured on the rack 2026-09-07: goal 3 lost indefinitely, and for ~20 s on
//! every island boot.
//!
//! The kernel's own ARP monitor cannot answer this. VLAN 249 spans the islands through the
//! backbone, so the bond's slaves are three ports into ONE broadcast domain; the kernel probes
//! with the bond's MAC, so the router's unicast reply lands on whichever port last learned that
//! MAC rather than on the slave that asked. Both `fail_over_mac` modes flapped (measured).
//!
//! So cfab asks the question itself, per wire, with a frame of its own (`frame`) on a raw
//! socket bound to the slave (`io`), and folds the answers with the pure state machine and
//! decision function in `decide`.

pub mod decide;
pub mod frame;
