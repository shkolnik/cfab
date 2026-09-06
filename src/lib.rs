//! cfab — the per-host runtime of a resilient converged network fabric for small clusters.
//!
//! `fabric.toml` declares the fabric: members, physical wires, segments, traffic classes.
//! This crate turns that declaration into a typed model, derives each member's view of it,
//! generates every artifact from it with pure functions (nftables forward policy and
//! traffic-class marking, HTB shaping trees, the routing engine's configuration tree), and applies, verifies, and
//! tears down the result on the host. Everything that touches the system goes through the
//! `sys` layer, so every imperative branch is unit-testable.

pub mod caps;
pub mod cluster;
pub mod commands;
pub mod decl;
pub mod derive;
pub mod emit;
pub mod engine;
pub mod error;
pub mod model;
pub mod sock_frame;
pub mod supervisor;
pub mod sys;

use std::path::Path;

pub use error::{Error, Result};

/// Load + type + validate the declaration. An unknown key is an ERROR from the parser, not a
/// warning: the declaration is the whole input, so a key nothing consumes is a mistake.
pub fn load_fabric(path: &Path) -> Result<model::Fabric> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::fatal(format!("cannot read {}: {e}", path.display())))?;
    model::Fabric::from_decl(&decl::Declaration::parse(&text)?)
}
