//! cfab — the per-host runtime of a resilient converged network fabric for small clusters.
//!
//! `fabric.conf` declares the fabric: members, physical wires, segments, traffic classes.
//! This crate turns that declaration into a typed model, derives each member's view of it,
//! generates every artifact from it with pure functions (nftables forward policy and
//! traffic-class marking, HTB shaping trees, FRR configuration), and applies, verifies, and
//! tears down the result on the host. Everything that touches the system goes through the
//! `sys` layer, so every imperative branch is unit-testable.

pub mod caps;
pub mod cluster;
pub mod config;
pub mod derive;
pub mod emit;
pub mod error;
pub mod model;
pub mod sys;

use std::path::Path;

pub use error::{Error, Result};

/// Load + type + validate the declaration; warn (stderr) about literal keys the model does not
/// know, so a declaration added for shell tooling is never silently ignored here.
pub fn load_fabric(path: &Path) -> Result<model::Fabric> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::fatal(format!("cannot read {}: {e}", path.display())))?;
    let raw = config::RawConfig::parse(&text)?;
    for key in raw.unconsumed(model::CONSUMED_KEYS) {
        eprintln!("cfab: warning: fabric.conf declares {key}, which this binary does not consume");
    }
    model::Fabric::from_raw(&raw)
}
