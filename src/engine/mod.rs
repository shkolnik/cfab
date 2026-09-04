//! The resident routing engine (`cfab engine`, spec §4): holo-interface + holo-routing
//! (OSPF instances, BFD, FIB) in this process, driven by cfab's own northbound. No config
//! file: (re)start rebuilds everything from fabric.conf; `up` restarts it, `down` stops it.

pub mod northbound;
pub mod sock;
pub mod state;

use std::path::PathBuf;

use holo_utils::southbound::FibPolicy;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{info, warn};

use crate::derive::View;
use crate::emit::engine::{PROTO_BASE, generate, prefsrc_rules};
use crate::error::{Error, Result};
use crate::model::Fabric;

/// Under `fabric.run_dir`.
pub const SOCK_NAME: &str = "engine.sock";
pub const PID_NAME: &str = "engine.pid";
/// Cap on one state request's provider round-trip; below the client's own request timeout
/// so the client sees the engine's error text instead of its own timeout.
const STATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Run the engine until SIGTERM/SIGINT. Never returns Ok while healthy. `unsafe_no_prefsrc`
/// is the gate-0 teeth knob (hidden CLI flag): install routes without the prefsrc rules so
/// the oracle's src assertion must go RED.
pub fn run(fabric: &Fabric, view: &View, unsafe_no_prefsrc: bool) -> Result<()> {
    init_tracing()?;
    let cfg = generate(view)?;
    let prefsrc = if unsafe_no_prefsrc {
        warn!("--unsafe-no-prefsrc: routes will be installed WITHOUT preferred sources");
        Vec::new()
    } else {
        parse_prefsrc(&prefsrc_rules(view))?
    };
    let policy = FibPolicy {
        proto_base: Some(PROTO_BASE),
        prefsrc,
    };
    let sock_path = PathBuf::from(&fabric.run_dir).join(SOCK_NAME);
    let pid_path = PathBuf::from(&fabric.run_dir).join(PID_NAME);
    // Before anything destructive: starting the providers purges the private-proto routes
    // and opens the OSPF/BFD sockets, which would damage an engine already owning this
    // run_dir. Prove the run_dir is free first (spec §4, "prove ownership before destroy").
    sock::refuse_if_live(&sock_path, &pid_path)?;

    // The YANG context is process-global and must exist before any provider resolves paths.
    northbound::yang_ctx();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::fatal(format!("engine: cannot create async runtime: {e}")))?;
    rt.block_on(async {
        info!(member = %view.member.name, "engine starting");
        let mut nb = northbound::Northbound::start(&view.member.name, policy);
        let result = serve(&mut nb, &cfg, fabric, &sock_path, &pid_path).await;
        // Every exit, healthy or not, is holod's teardown: stop answering, drop the
        // providers, wait for every task (holo-routing uninstalls its routes on that path).
        cleanup(&sock_path, &pid_path);
        nb.shutdown().await;
        info!("engine stopped");
        result
    })
}

/// Commit, publish readiness (pid + socket), answer state requests until a signal.
async fn serve(
    nb: &mut northbound::Northbound,
    cfg: &serde_json::Value,
    fabric: &Fabric,
    sock_path: &std::path::Path,
    pid_path: &std::path::Path,
) -> Result<()> {
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| Error::fatal(format!("engine: cannot listen for SIGTERM: {e}")))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| Error::fatal(format!("engine: cannot listen for SIGINT: {e}")))?;

    let candidate = northbound::parse_candidate(cfg)?;
    nb.commit(candidate).await?;
    info!("configuration committed; engine ready");

    // Ready = pid + socket. Nothing is bound before the commit, so `up`'s poll sees one
    // signal (connection refused / no file) instead of a partial state. Re-check liveness
    // BEFORE writing the pid: an overwritten engine.pid would name ourselves and disarm the
    // pid signal (measured: a stopped engine's socket was then taken over silently).
    sock::refuse_if_live(sock_path, pid_path)?;
    std::fs::create_dir_all(&fabric.run_dir)
        .map_err(|e| Error::fatal(format!("cannot create {}: {e}", fabric.run_dir)))?;
    std::fs::write(pid_path, format!("{}\n", std::process::id()))
        .map_err(|e| Error::fatal(format!("cannot write {}: {e}", pid_path.display())))?;
    let listener = sock::bind(sock_path, pid_path)?;

    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let nb = &*nb;
                    sock::serve_one(stream, async move || {
                        // A provider that stops answering Get must not wedge the engine
                        // (this loop also handles SIGTERM): bounded, logged by serve_one.
                        let tree = tokio::time::timeout(STATE_TIMEOUT, nb.get_state())
                            .await
                            .map_err(|_| {
                                Error::fatal(format!(
                                    "engine: state request timed out after {STATE_TIMEOUT:?} (a provider is not answering)"
                                ))
                            })??;
                        Ok(state::document(true, cfg, &[tree]))
                    })
                    .await;
                }
                Err(e) => warn!(%e, "engine.sock accept failed"),
            },
            notification = nb.rx_providers.recv() => match notification {
                Some(n) => tracing::debug!(path = %n.path, "YANG notification"),
                // All providers have exited on their own: nothing left to run.
                None => return Err(Error::fatal("engine: every provider exited")),
            },
            _ = sigterm.recv() => { info!("received SIGTERM"); return Ok(()); }
            _ = sigint.recv() => { info!("received SIGINT"); return Ok(()); }
        }
    }
}

/// Remove the readiness files, but only when engine.pid names this process: an engine
/// refused at readiness time must not unlink the files of the engine that owns them.
fn cleanup(sock_path: &std::path::Path, pid_path: &std::path::Path) {
    let owner = std::fs::read_to_string(pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    if owner != Some(std::process::id()) {
        return;
    }
    let _ = std::fs::remove_file(sock_path);
    let _ = std::fs::remove_file(pid_path);
}

fn init_tracing() -> Result<()> {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::from_default_env().add_directive(
        "info"
            .parse()
            .map_err(|e| Error::fatal(format!("engine: log filter: {e}")))?,
    );
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init()
        .map_err(|e| Error::fatal(format!("engine: cannot initialize logging: {e}")))
}

/// `emit::engine::prefsrc_rules` as holo's typed policy.
pub fn parse_prefsrc(
    rules: &[(String, String)],
) -> Result<Vec<(ipnetwork::IpNetwork, std::net::IpAddr)>> {
    rules
        .iter()
        .map(|(net, src)| {
            let net = net
                .parse()
                .map_err(|e| Error::fatal(format!("engine: prefsrc prefix {net}: {e}")))?;
            let src = src
                .parse()
                .map_err(|e| Error::fatal(format!("engine: prefsrc address {src}: {e}")))?;
            Ok((net, src))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_removes_only_files_this_process_owns() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join(SOCK_NAME);
        let pid = dir.path().join(PID_NAME);
        std::fs::write(&sock, "").unwrap();
        std::fs::write(&pid, "4194305\n").unwrap();
        cleanup(&sock, &pid);
        assert!(sock.exists() && pid.exists(), "foreign files must survive");
        std::fs::write(&pid, format!("{}\n", std::process::id())).unwrap();
        cleanup(&sock, &pid);
        assert!(!sock.exists() && !pid.exists());
    }

    #[test]
    fn prefsrc_rules_parse_into_policy_and_match_inside_the_block() {
        let rules = vec![
            ("10.99.0.0/16".to_string(), "10.99.0.1".to_string()),
            ("10.249.0.0/16".to_string(), "10.249.0.1".to_string()),
        ];
        let policy = FibPolicy {
            proto_base: Some(PROTO_BASE),
            prefsrc: parse_prefsrc(&rules).unwrap(),
        };
        let inside: ipnetwork::IpNetwork = "10.249.0.2/32".parse().unwrap();
        let outside: ipnetwork::IpNetwork = "192.168.249.0/24".parse().unwrap();
        assert_eq!(
            policy.prefsrc_for(&inside),
            Some("10.249.0.1".parse().unwrap())
        );
        assert_eq!(policy.prefsrc_for(&outside), None);
        assert!(parse_prefsrc(&[("nonsense".into(), "10.0.0.1".into())]).is_err());
    }
}
