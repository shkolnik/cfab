//! The engine socket: `run_dir/engine.sock`, mode 0600. Protocol: the client sends one
//! request line; the server answers one JSON object, then closes. Three verbs: `state` (read
//! the operational document), `transit-cost leaf|normal` (re-advertise this member's
//! transit links at the leaf offset, or at the declared cost — spec §12 (b)), and
//! `workload-routes <leg> <ifindex> [<cidr> …]` (the host routes this member originates for
//! the VMs it currently sees on a workload leg).

use std::collections::BTreeSet;
use std::path::Path;

use ipnetwork::Ipv4Network;
use tokio::net::{UnixListener, UnixStream};

use crate::emit::engine::TransitCost;
use crate::error::{Error, Result};

/// One request line, already parsed. An unknown verb never reaches the handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `state`: the operational document.
    State,
    /// `transit-cost leaf|normal`: re-commit with this member's transit links at that cost.
    TransitCost(TransitCost),
    /// `workload-routes <leg> <ifindex> [<cidr> …]`: the WHOLE wanted set of host routes on
    /// one workload leg, level triggered — an empty list withdraws every route on that leg.
    /// `ifindex` is the leg's current kernel index, not part of the emitted configuration:
    /// holo resolves a static route's outgoing interface once, at commit, so a leg the
    /// watchdog rebuilt needs the routes withdrawn and re-installed to be re-resolved, and
    /// this is how the engine learns that happened.
    WorkloadRoutes {
        leg: String,
        ifindex: u32,
        cidrs: BTreeSet<Ipv4Network>,
    },
}

impl Request {
    /// One short journal line for a request the engine acted on. Never the whole route set:
    /// a member can carry dozens of VMs and this is logged on every commit that moved.
    pub fn summary(&self) -> String {
        match self {
            Request::State => "state".to_string(),
            Request::TransitCost(at) => format!("transit-cost {}", at.word()),
            Request::WorkloadRoutes {
                leg,
                ifindex,
                cidrs,
            } => format!("workload-routes {leg} {ifindex} ({} routes)", cidrs.len()),
        }
    }
}

/// `state\n`, `transit-cost leaf\n` and `workload-routes …\n` are the whole protocol;
/// anything else is `None` and is answered with an error rather than guessed at.
pub fn parse_request(line: &str) -> Option<Request> {
    let line = line.trim();
    match line {
        "state" => return Some(Request::State),
        "transit-cost leaf" => return Some(Request::TransitCost(TransitCost::LeafOffset)),
        "transit-cost normal" => return Some(Request::TransitCost(TransitCost::Declared)),
        _ => {}
    }
    let mut words = line.strip_prefix("workload-routes ")?.split_whitespace();
    let leg = words.next()?.to_string();
    let ifindex: u32 = words.next()?.parse().ok()?;
    let mut cidrs = BTreeSet::new();
    for w in words {
        let net: Ipv4Network = w.parse().ok()?;
        // Host bits set would mean two spellings of one destination, and the tree cfab emits
        // is compared against what the kernel has by exact key: refuse rather than normalize.
        if net.ip() != net.network() {
            return None;
        }
        cidrs.insert(net);
    }
    Some(Request::WorkloadRoutes {
        leg,
        ifindex,
        cidrs,
    })
}

/// Refuse to start when another engine already answers on this socket. The exclusivity
/// guarantee itself is `supervisor::lock::hold` on `engine.lock`, held for the process's
/// whole lifetime BEFORE the providers start (they purge the private-proto routes and open
/// the BFD/OSPF sockets, so a late check would damage a surviving engine); this is the
/// cheap belt-and-suspenders re-check at bind time, for a stale socket path left by a
/// process that died without a lock (a lock is held only from `hold()` onward — nothing
/// answers this socket if that process's flock is free).
pub fn refuse_if_live(sock_path: &Path) -> Result<()> {
    if crate::sock_frame::answers(sock_path, "state") {
        return Err(Error::fatal(format!(
            "another engine is running (answering on {}); stop it first (cfab down)",
            sock_path.display()
        )));
    }
    Ok(())
}

/// Bind the socket. A leftover path is unlinked ONLY when nothing answers on it; a live
/// answer means another engine owns this run_dir — fatal, never a silent takeover. The
/// real guard is the `engine.lock` flock, taken before this is ever called; this is the
/// cheap re-check at readiness time.
pub fn bind(path: &Path) -> Result<UnixListener> {
    crate::sock_frame::bind_reclaiming(path, "state", "engine")
}

/// Serve one accepted connection: read the request line, reply with `respond`'s JSON.
/// A client that sends nothing within the timeout is dropped without a reply. Reading the
/// request and answering it are separate so the engine loop can hand `respond` a `&mut`
/// borrow of the northbound (`transit-cost` re-commits; `state` only reads). Framing itself
/// (read one line, write one JSON object, close) lives in `sock_frame`, shared with
/// `cfab.sock`; only the engine's own three-verb vocabulary lives here.
pub async fn serve_one<F>(stream: UnixStream, respond: F)
where
    F: AsyncFnOnce(Request) -> Result<serde_json::Value>,
{
    crate::sock_frame::serve_one(stream, async |line: &str| match parse_request(line) {
        Some(req) => respond(req).await,
        None => Ok(serde_json::json!({ "error": format!("unknown request {:?}", line.trim()) })),
    })
    .await;
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream as StdUnixStream;

    use super::*;

    #[test]
    fn stale_socket_is_unlinked_live_socket_is_refused() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("engine.sock");
        rt.block_on(async {
            // Stale: a bound-then-dropped path nobody listens on.
            drop(UnixListener::bind(&sock).unwrap());
            assert!(sock.exists());
            let listener = bind(&sock).unwrap();
            assert_eq!(
                std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
                0o600
            );
            // Live: the listener answers, so a second bind must refuse.
            let server = tokio::spawn(async move {
                let (s, _) = listener.accept().await.unwrap();
                serve_one(s, async |_| Ok(serde_json::json!({ "ready": true }))).await;
            });
            let err = tokio::task::spawn_blocking({
                let sock = sock.clone();
                move || bind(&sock).err().map(|e| e.to_string())
            })
            .await
            .unwrap()
            .unwrap();
            assert!(err.contains("another engine is running"), "{err}");
            server.await.unwrap();
        });
    }

    /// No socket at all: `refuse_if_live` finds nothing to be suspicious of. The exclusivity
    /// guarantee itself moved to `supervisor::lock` (Task 9) — this function's only remaining
    /// job is the stale-vs-live distinction at bind time.
    #[test]
    fn no_socket_is_not_suspicious() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("engine.sock");
        refuse_if_live(&sock).unwrap();
    }

    /// The whole protocol, in one place: three verbs, and everything else refused rather
    /// than guessed at (a mis-typed verb must not silently read state or re-commit).
    #[test]
    fn the_protocol_is_three_verbs_and_nothing_else() {
        assert_eq!(parse_request("state\n"), Some(Request::State));
        assert_eq!(
            parse_request("transit-cost leaf\n"),
            Some(Request::TransitCost(TransitCost::LeafOffset))
        );
        assert_eq!(
            parse_request("transit-cost normal\n"),
            Some(Request::TransitCost(TransitCost::Declared))
        );
        for bogus in [
            "",
            "State",
            "transit-cost",
            "transit-cost lea",
            "transit-cost leaf x",
            "workload-routes",
            "workload-routes cfab-work-vms",
        ] {
            assert_eq!(parse_request(bogus), None, "{bogus:?}");
        }
    }

    fn routes(cidrs: &[&str]) -> std::collections::BTreeSet<ipnetwork::Ipv4Network> {
        cidrs.iter().map(|c| c.parse().unwrap()).collect()
    }

    /// `workload-routes <leg> <ifindex> [<cidr> …]`: the wanted set for one leg, level
    /// triggered. An EMPTY cidr list is the withdrawal — the driver never has a separate
    /// verb for "take them all away", so a row that lost its VMs and a row that never had
    /// any are the same request.
    #[test]
    fn workload_routes_carries_a_leg_an_ifindex_and_the_whole_wanted_set() {
        assert_eq!(
            parse_request("workload-routes cfab-work-vms 42 192.168.20.103/32\n"),
            Some(Request::WorkloadRoutes {
                leg: "cfab-work-vms".into(),
                ifindex: 42,
                cidrs: routes(&["192.168.20.103/32"]),
            })
        );
        assert_eq!(
            parse_request("workload-routes cfab-work-vms 42\n"),
            Some(Request::WorkloadRoutes {
                leg: "cfab-work-vms".into(),
                ifindex: 42,
                cidrs: routes(&[]),
            })
        );
        // More than one, deduplicated and ordered by the set, so the emitted tree does not
        // depend on the order the driver happened to walk its neighbor table in.
        assert_eq!(
            parse_request(
                "workload-routes cfab-work-vms 7 192.168.20.104/32 192.168.20.103/32 192.168.20.104/32\n"
            ),
            Some(Request::WorkloadRoutes {
                leg: "cfab-work-vms".into(),
                ifindex: 7,
                cidrs: routes(&["192.168.20.103/32", "192.168.20.104/32"]),
            })
        );
    }

    /// A cidr the engine cannot turn into a route is refused whole: a request that carried
    /// one bad element must not commit the others, or a typo silently withdraws a live VM.
    #[test]
    fn a_malformed_workload_routes_request_is_refused_whole() {
        for bogus in [
            "workload-routes cfab-work-vms 42 nonsense",
            "workload-routes cfab-work-vms 42 192.168.20.103/33",
            "workload-routes cfab-work-vms 42 192.168.20.256/32",
            "workload-routes cfab-work-vms 42 192.168.20.103/24", // host bits set
            "workload-routes cfab-work-vms 42 192.168.20.103/32 nonsense",
            "workload-routes cfab-work-vms -1 192.168.20.103/32",
            "workload-routes cfab-work-vms notanifindex 192.168.20.103/32",
            "workload-routes cfab-work-vms 42 ::1/128",
        ] {
            assert_eq!(parse_request(bogus), None, "{bogus:?}");
        }
    }

    #[test]
    fn serve_one_answers_state_and_rejects_other_requests() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("engine.sock");
        rt.block_on(async {
            let listener = bind(&sock).unwrap();
            let server = tokio::spawn(async move {
                for _ in 0..4 {
                    let (s, _) = listener.accept().await.unwrap();
                    serve_one(s, async |req| match req {
                        Request::State => Ok(serde_json::json!({ "ready": true, "bfd": [] })),
                        Request::TransitCost(t) => {
                            Ok(serde_json::json!({ "transit_cost": t.word() }))
                        }
                        Request::WorkloadRoutes { leg, cidrs, .. } => Ok(serde_json::json!({
                            "workload_routes": { "leg": leg, "routes": cidrs.len() }
                        })),
                    })
                    .await;
                }
            });
            let ask = |line: &'static str| {
                let sock = sock.clone();
                tokio::task::spawn_blocking(move || {
                    let mut s = StdUnixStream::connect(&sock).unwrap();
                    s.write_all(line.as_bytes()).unwrap();
                    let mut out = String::new();
                    s.read_to_string(&mut out).unwrap();
                    out
                })
            };
            let ok = ask("state\n").await.unwrap();
            assert_eq!(ok, "{\"ready\":true,\"bfd\":[]}\n");
            let bad = ask("bogus\n").await.unwrap();
            assert!(bad.contains("unknown request \\\"bogus\\\""), "{bad}");
            let tc = ask("transit-cost leaf\n").await.unwrap();
            assert_eq!(tc, "{\"transit_cost\":\"leaf\"}\n");
            let wr = ask("workload-routes cfab-work-vms 42 192.168.20.103/32\n")
                .await
                .unwrap();
            assert_eq!(
                wr,
                "{\"workload_routes\":{\"leg\":\"cfab-work-vms\",\"routes\":1}}\n"
            );
            server.await.unwrap();
        });
    }
}
