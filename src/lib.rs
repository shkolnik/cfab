//! cfab — the per-host runtime of a resilient converged network fabric for small clusters.
//!
//! `fabric.conf` declares the fabric: members, physical wires, segments, traffic classes.
//! This crate turns that declaration into a typed model, derives each member's view of it,
//! generates every artifact from it with pure functions (nftables forward policy and
//! traffic-class marking, HTB shaping trees, FRR configuration), and applies, verifies, and
//! tears down the result on the host. Everything that touches the system goes through the
//! `sys` layer, so every imperative branch is unit-testable.
