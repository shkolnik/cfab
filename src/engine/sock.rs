//! The engine socket: `run_dir/engine.sock`, mode 0600. Protocol: the client sends one
//! request line; the server answers one JSON object, then closes. Two verbs: `state` (read
//! the operational document) and `transit-cost leaf|normal` (re-advertise this member's
//! transit links at the leaf offset, or at the declared cost — spec §12 (b)).

use std::path::Path;

use tokio::net::{UnixListener, UnixStream};

use crate::emit::engine::TransitCost;
use crate::error::{Error, Result};

/// One request line, already parsed. An unknown verb never reaches the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// `state`: the operational document.
    State,
    /// `transit-cost leaf|normal`: re-commit with this member's transit links at that cost.
    TransitCost(TransitCost),
}

/// `state\n` and `transit-cost leaf\n` are the whole protocol; anything else is `None` and
/// is answered with an error rather than guessed at.
pub fn parse_request(line: &str) -> Option<Request> {
    match line.trim() {
        "state" => Some(Request::State),
        "transit-cost leaf" => Some(Request::TransitCost(TransitCost::LeafOffset)),
        "transit-cost normal" => Some(Request::TransitCost(TransitCost::Declared)),
        _ => None,
    }
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
/// `cfab.sock`; only the engine's own two-verb vocabulary lives here.
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

    /// The whole protocol, in one place: two verbs, and everything else refused rather
    /// than guessed at (a mis-typed verb must not silently read state or re-commit).
    #[test]
    fn the_protocol_is_two_verbs_and_nothing_else() {
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
                for _ in 0..3 {
                    let (s, _) = listener.accept().await.unwrap();
                    serve_one(s, async |req| match req {
                        Request::State => Ok(serde_json::json!({ "ready": true, "bfd": [] })),
                        Request::TransitCost(t) => {
                            Ok(serde_json::json!({ "transit_cost": t.word() }))
                        }
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
            server.await.unwrap();
        });
    }
}
