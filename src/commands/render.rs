//! The host-facing half of the `gen` family (module named `render`: `gen` is a reserved
//! keyword in edition 2024). `gen` renders a named `[[member]]` row from the
//! declaration and makes no claim about which member this box is, so it is safe for anything
//! holding a `View` to call — including the equivalence test, which renders all three members
//! of the example from one process and would otherwise have to keep a second copy of this.

use crate::derive::View;
use crate::emit;
use crate::error::{Error, Result};
use crate::model::Fabric;
use crate::sys::RealSys;

/// The manual `gen shape` path: `[runtime] run_dir` cap files with the cluster-published cap as
/// the absent-local fallback, and CFAB_UP_IFS as the authoritative up-set, else sysfs carrier,
/// else assume up (never demote on missing information).
pub fn shape_for(view: &View<'_>, fabric: &Fabric, dev: &str) -> Result<emit::shape::Derivation> {
    let mut sys = RealSys::default();
    let measured = crate::caps::read_cap(
        &mut sys,
        &crate::cluster::Pmxcfs::new(),
        &view.member.name,
        &fabric.run_dir,
        dev,
    );
    let up_env = std::env::var("CFAB_UP_IFS").ok();
    let up = move |w: &str| -> bool {
        if let Some(set) = &up_env {
            return set.split_whitespace().any(|u| u == w);
        }
        match std::fs::read_to_string(format!("/sys/class/net/{w}/carrier")) {
            Ok(s) => s.trim() == "1",
            Err(_) => true,
        }
    };
    emit::shape::derive(view, dev, measured, &up)
}

/// `gen shape`'s stdout and stderr for one wire, exactly as the CLI prints them: the derivation
/// warnings go to stderr, the selected rendering to stdout.
pub fn shape_output(
    view: &View<'_>,
    fabric: &Fabric,
    dev: &str,
    tc: bool,
    expect: bool,
) -> Result<(String, String)> {
    let d = shape_for(view, fabric, dev)?;
    let err = d
        .warnings
        .iter()
        .map(|w| format!("{w}\n"))
        .collect::<String>();
    let out = if tc {
        d.render_tc()
    } else if expect {
        d.render_expect()
    } else {
        d.render_derive(view)
    };
    Ok((out, err))
}

/// `gen engine`'s stdout, exactly as the CLI prints it (pretty JSON plus the trailing newline
/// `println!` adds).
pub fn engine_json(view: &View<'_>) -> Result<String> {
    let tree = emit::engine::generate(view)?;
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&tree).map_err(Error::fatal)?
    ))
}
