//! The resident routing engine (`cfab engine`, spec §4): holo-interface + holo-routing
//! (OSPF instances, BFD, FIB) in this process, driven by cfab's own northbound. No config
//! file: (re)start rebuilds everything from fabric.toml; `up` restarts it, `down` stops it.

pub mod northbound;
pub mod sock;
pub mod state;

use std::path::PathBuf;

use holo_utils::bfd::BfdSocketPolicy;
use holo_utils::bgp::BgpListenPolicy;
use holo_utils::southbound::FibPolicy;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{info, warn};

use crate::derive::View;
use crate::emit::engine::{PROTO_BASE, TransitCost, generate, generate_at, prefsrc_rules};
use crate::error::{Error, Result};
use crate::model::Fabric;

/// Under `fabric.run_dir`.
pub const SOCK_NAME: &str = "engine.sock";
/// The `flock` (spec §14) that replaces `engine.pid`: held for the process's whole lifetime,
/// released by the kernel on any death including `SIGKILL`/OOM.
pub const LOCK_NAME: &str = "engine.lock";
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
    let bfd_policy = bfd_socket_policy(fabric);
    let bgp_policy = bgp_listen_policy(fabric);
    let control_priority = control_priority(fabric);
    let sock_path = PathBuf::from(&fabric.run_dir).join(SOCK_NAME);
    let lock_path = PathBuf::from(&fabric.run_dir).join(LOCK_NAME);
    // Before anything destructive: starting the providers purges the private-proto routes
    // and opens the OSPF/BFD sockets, which would damage an engine already owning this
    // run_dir. Prove the run_dir is free first (spec §4, "prove ownership before destroy") —
    // an exclusive flock, held for the rest of this function's lifetime, is that proof; unlike
    // the pid file it replaces, the kernel itself releases it on any death, so no later
    // "is that pid actually a cfab engine" check is ever needed again.
    std::fs::create_dir_all(&fabric.run_dir)
        .map_err(|e| Error::fatal(format!("cannot create {}: {e}", fabric.run_dir)))?;
    let _lock = crate::supervisor::lock::hold(&lock_path).map_err(|held| {
        Error::fatal(format!(
            "another engine is running (pid {} per {}); stop it first (cfab down)",
            held.pid.map_or("unknown".to_string(), |p| p.to_string()),
            lock_path.display()
        ))
    })?;

    // The YANG context is process-global and must exist before any provider resolves paths.
    northbound::yang_ctx();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::fatal(format!("engine: cannot create async runtime: {e}")))?;
    rt.block_on(async {
        info!(member = %view.member.name, "engine starting");
        let mut nb = northbound::Northbound::start(
            &view.member.name,
            policy,
            bfd_policy,
            bgp_policy,
            control_priority,
        );
        let result = serve(&mut nb, view, &cfg, &sock_path).await;
        // Every exit, healthy or not, is holod's teardown: stop answering, drop the
        // providers, wait for every task (holo-routing uninstalls its routes on that path).
        cleanup(&sock_path);
        nb.shutdown().await;
        info!("engine stopped");
        result
    })
    // `_lock` drops here, releasing the flock — after cleanup, so nothing can observe the
    // lock free while our socket file still exists.
}

/// The Rx sockets holo-bfd may bind: IPv4 single-hop on BFD_PORT and nothing else. cfab runs
/// no multihop and no IPv6 BFD sessions, and every socket holo binds that we never read is one
/// more wildcard address another BFD daemon on this host can collide with.
fn bfd_socket_policy(fabric: &Fabric) -> BfdSocketPolicy {
    BfdSocketPolicy {
        single_hop_port: fabric.bfd_port,
        ipv6: false,
        ..Default::default()
    }
}

/// The BGP listening socket holo-bgp may bind: none. cfab's neighbors are ACTIVE only — the
/// upstream router is the passive side (it runs `bgp listen range`), so an inbound listener is
/// never used. holo-bgp's default is a wildcard `0.0.0.0:179` with `SO_REUSEADDR`, which
/// silently shares the port with any other BGP daemon on the host (PVE SDN's bgpd is the
/// realistic one). Same design rule as the BFD socket policy: never a wildcard bind, fail loud
/// on a collision. `fabric` is taken for symmetry with `bfd_socket_policy` — no declaration
/// can turn the listener on.
fn bgp_listen_policy(_fabric: &Fabric) -> BgpListenPolicy {
    BgpListenPolicy::NoListener
}

/// Commit, publish readiness (the socket), answer state requests until a signal.
async fn serve(
    nb: &mut northbound::Northbound,
    view: &View<'_>,
    cfg: &serde_json::Value,
    sock_path: &std::path::Path,
) -> Result<()> {
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| Error::fatal(format!("engine: cannot listen for SIGTERM: {e}")))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| Error::fatal(format!("engine: cannot listen for SIGINT: {e}")))?;

    let candidate = northbound::parse_candidate(cfg)?;
    nb.commit(candidate).await?;
    info!("configuration committed; engine ready");

    // Ready = the socket. Nothing is bound before the commit, so `up`'s poll sees one
    // signal (connection refused / no file) instead of a partial state. Exclusivity for the
    // whole run is already proven by the `engine.lock` flock held before `serve` was called;
    // `bind`'s own `refuse_if_live` is only the stale-socket-path re-check.
    let listener = sock::bind(sock_path)?;

    // One event at a time, handled AFTER the select: `transit-cost` needs `&mut nb`, which
    // it cannot take while the select's other arms hold borrows of it.
    enum Ev {
        Accepted(tokio::net::UnixStream),
        Ignore,
        ProvidersGone,
        Signal(&'static str),
    }

    loop {
        let ev = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => Ev::Accepted(stream),
                Err(e) => { warn!(%e, "engine.sock accept failed"); Ev::Ignore }
            },
            notification = nb.rx_providers.recv() => match notification {
                Some(n) => { tracing::debug!(path = %n.path, "YANG notification"); Ev::Ignore }
                // All providers have exited on their own: nothing left to run.
                None => Ev::ProvidersGone,
            },
            _ = sigterm.recv() => Ev::Signal("SIGTERM"),
            _ = sigint.recv() => Ev::Signal("SIGINT"),
        };
        match ev {
            Ev::Ignore => {}
            Ev::ProvidersGone => return Err(Error::fatal("engine: every provider exited")),
            Ev::Signal(sig) => {
                info!("received {sig}");
                return Ok(());
            }
            Ev::Accepted(stream) => {
                sock::serve_one(stream, async |req| match req {
                    sock::Request::State => {
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
                    }
                    sock::Request::TransitCost(at) => {
                        set_transit_cost(nb, view, at).await?;
                        Ok(serde_json::json!({ "transit_cost": at.word() }))
                    }
                })
                .await;
            }
        }
    }
}

/// Re-advertise this member's transit links at `at` (spec §12 (b)): regenerate the tree with
/// the new costs and re-commit it. `Northbound::commit` diffs against running, so re-asking
/// for the cost already in force is free — the watchdog re-asserts on every tick rather than
/// keeping a state file that could disagree with the engine. VERIFIED on the container fixture
/// 2026-09-05: a cost-only diff re-originates the Router-LSA (+30000 on every transit link)
/// in 2.8 ms with no carrier change and no adjacency or BFD session drop.
async fn set_transit_cost(
    nb: &mut northbound::Northbound,
    view: &View<'_>,
    at: TransitCost,
) -> Result<()> {
    let tree = generate_at(view, at)?;
    let candidate = northbound::parse_candidate(&tree)?;
    // The watchdog re-asserts on every tick; only a tick that actually moved the cost is
    // worth a log line, or the record of the change drowns in the record of no change.
    if nb.commit(candidate).await? {
        info!(?at, "transit cost re-committed");
    }
    Ok(())
}

/// Remove the socket file. Safe unconditionally: the caller still holds the `engine.lock`
/// flock at this point (it is dropped only after `run` returns), so no other engine can have
/// taken over this run_dir out from under us.
fn cleanup(sock_path: &std::path::Path) {
    let _ = std::fs::remove_file(sock_path);
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

/// The engine marks its own OSPF/BFD frames with the fabric's control priority: the VLAN
/// sub-interface's egress-qos-map turns sk_priority into the 802.1p bits, so the lift needs no
/// netfilter and works on kernels that have none. Always set: PCP_CTRL is required and range
/// checked at parse.
fn control_priority(fabric: &Fabric) -> Option<u32> {
    Some(u32::from(fabric.pcp_ctrl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_removes_the_socket_file() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join(SOCK_NAME);
        std::fs::write(&sock, "").unwrap();
        cleanup(&sock);
        assert!(!sock.exists());
    }

    #[test]
    fn the_control_priority_is_the_declared_pcp_ctrl() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        let mut fabric =
            Fabric::from_decl(&crate::decl::Declaration::parse(&text).unwrap()).unwrap();
        assert_eq!(control_priority(&fabric), Some(6));
        fabric.pcp_ctrl = 5;
        assert_eq!(control_priority(&fabric), Some(5));
    }

    #[test]
    fn the_bfd_policy_asks_for_exactly_one_rx_socket() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        let mut fabric =
            Fabric::from_decl(&crate::decl::Declaration::parse(&text).unwrap()).unwrap();
        fabric.bfd_port = 3785;
        let policy = bfd_socket_policy(&fabric);
        assert_eq!(policy.port(holo_utils::bfd::PathType::IpSingleHop), 3785);
        assert!(policy.binds_af(holo_utils::ip::AddressFamily::Ipv4));
        assert!(!policy.binds_af(holo_utils::ip::AddressFamily::Ipv6));
        // The multihop port keeps its default; cfab never opens a multihop session, so
        // holo-bfd never starts a multihop Rx task and never binds it.
        assert_eq!(
            policy.port(holo_utils::bfd::PathType::IpMultihop),
            BfdSocketPolicy::default().multihop_port
        );
    }

    /// No member, and no declaration, can turn the listener on: cfab is the active side of
    /// every session it opens, so port 179 stays free for whatever else runs on the host.
    #[test]
    fn no_member_of_the_shipped_fabric_binds_a_bgp_listener() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        let fabric = Fabric::from_decl(&crate::decl::Declaration::parse(&text).unwrap()).unwrap();
        assert!(!fabric.members.is_empty());
        for m in &fabric.members {
            let view = View::new(&fabric, &m.name).unwrap();
            let policy = bgp_listen_policy(view.fabric);
            assert_eq!(policy, BgpListenPolicy::NoListener, "{}", m.name);
            assert!(!policy.binds_listener(), "{}", m.name);
        }
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
