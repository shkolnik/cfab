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

/// The copy of the declaration the supervisor actually applied, kept in the run dir. `cfab
/// status` reads it so it can describe the RUNNING fabric while the file on disk is mid-edit or
/// refused — exactly when the operator needs status to work (finding F9).
pub const APPLIED_DECL_NAME: &str = "fabric.toml.applied";

pub fn applied_decl_path(run_dir: &str) -> String {
    format!("{}/{APPLIED_DECL_NAME}", run_dir.trim_end_matches('/'))
}

/// Load + type + validate the declaration. An unknown key is an ERROR from the parser, not a
/// warning: the declaration is the whole input, so a key nothing consumes is a mistake.
pub fn load_fabric(path: &Path) -> Result<model::Fabric> {
    Ok(load_fabric_text(path)?.0)
}

/// `load_fabric`, plus the exact text it parsed — the supervisor keeps that text beside the
/// running fabric (`applied_decl_path`), so re-reading the file later cannot substitute a
/// different declaration for the one that was applied.
pub fn load_fabric_text(path: &Path) -> Result<(model::Fabric, String)> {
    if let Some(e) = retired_format_error(path) {
        return Err(e);
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::fatal(format!("cannot read {}: {e}", path.display())))?;
    let fabric = model::Fabric::from_decl(&decl::Declaration::parse(&text)?)?;
    Ok((fabric, text))
}

/// The declaration is missing but the RETIRED shell-format file sits beside it: say what
/// happened, because "cannot read fabric.toml" on a host that has a `fabric.conf` sends the
/// operator looking for a lost file instead of a replaced format. Pre-user: no shim, no
/// migration — the file is rewritten by hand from the packaged example.
pub fn retired_format_error(path: &Path) -> Option<Error> {
    let retired = path.with_file_name("fabric.conf");
    if path.exists() || !retired.exists() {
        return None;
    }
    Some(Error::config(format!(
        "{} does not exist, but {} does. fabric.conf is the retired shell format; the \
         declaration is now TOML in fabric.toml — rewrite it from the packaged example \
         (/usr/share/doc/cfab/examples/fabric.toml.example). There is no automatic migration",
        path.display(),
        retired.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retired file next to the missing one: the error names the format change, not a
    /// missing file.
    #[test]
    fn a_retired_fabric_conf_beside_the_declaration_is_named() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fabric.conf"), "FABRIC_MODE=tagged\n").unwrap();
        let err = load_fabric(&dir.path().join("fabric.toml"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("retired shell format"), "{err}");
        assert!(err.contains("fabric.toml.example"), "{err}");
        // ...and with no retired file, the plain "cannot read" error stands.
        std::fs::remove_file(dir.path().join("fabric.conf")).unwrap();
        let err = load_fabric(&dir.path().join("fabric.toml"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot read"), "{err}");
        assert!(!err.contains("retired"), "{err}");
    }
}
