//! The state socket: `run_dir/engine.sock`, mode 0600. Protocol: the client sends the line
//! `state\n`; the server answers one JSON object, then closes.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::error::{Error, Result};

const CLIENT_IO: Duration = Duration::from_secs(2);

/// Refuse to start when another engine owns this run_dir. Two independent liveness
/// signals, either one refuses: something answers `state\n` on the socket, or the pid in
/// `engine.pid` is a running `cfab engine` (a busy engine that misses the answer window
/// is still alive). Called BEFORE the providers start: they purge the private-proto routes
/// and open the BFD/OSPF sockets, so a late check would damage the surviving engine.
pub fn refuse_if_live(sock_path: &Path, pid_path: &Path) -> Result<()> {
    let pid = std::fs::read_to_string(pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    if sock_path.exists() && answers(sock_path) {
        let pid = pid.map_or("unknown".to_string(), |p| p.to_string());
        return Err(Error::fatal(format!(
            "another engine is running (pid {pid} per {}, answering on {}); stop it first (cfab down)",
            pid_path.display(),
            sock_path.display()
        )));
    }
    if let Some(pid) = pid
        && pid != std::process::id()
        && is_cfab_engine(pid)
    {
        return Err(Error::fatal(format!(
            "another engine is running (pid {pid} per {}); stop it first (cfab down), or \
             remove that file if pid {pid} is not a cfab engine",
            pid_path.display()
        )));
    }
    Ok(())
}

/// Is `pid` alive and running `cfab engine`? Read from /proc so a recycled pid belonging
/// to some other program does not count (cmdline = NUL-separated argv).
fn is_cfab_engine(pid: u32) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    cmdline.split(|b| *b == 0).any(|arg| arg == b"engine")
}

/// Bind the socket. A leftover path is unlinked ONLY when nothing answers on it; a live
/// answer means another engine owns this run_dir — fatal, never a silent takeover. The
/// real guard is `refuse_if_live` before the providers start; this one is the cheap
/// re-check at readiness time.
pub fn bind(path: &Path, pid_path: &Path) -> Result<UnixListener> {
    if path.exists() {
        refuse_if_live(path, pid_path)?;
        std::fs::remove_file(path)
            .map_err(|e| Error::fatal(format!("cannot remove stale {}: {e}", path.display())))?;
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| Error::fatal(format!("cannot bind {}: {e}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::fatal(format!("cannot chmod {}: {e}", path.display())))?;
    Ok(listener)
}

/// Does a process answer `state\n` on this socket?
fn answers(path: &Path) -> bool {
    let Ok(mut s) = StdUnixStream::connect(path) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(CLIENT_IO));
    let _ = s.set_write_timeout(Some(CLIENT_IO));
    if s.write_all(b"state\n").is_err() {
        return false;
    }
    let mut buf = [0u8; 1];
    matches!(s.read(&mut buf), Ok(n) if n > 0)
}

/// Serve one accepted connection: read the request line, reply with `respond`'s JSON.
/// A client that sends nothing within the timeout is dropped without a reply.
pub async fn serve_one<F>(stream: UnixStream, respond: F)
where
    F: AsyncFnOnce() -> Result<serde_json::Value>,
{
    let (rd, mut wr) = stream.into_split();
    let mut line = String::new();
    let read = tokio::time::timeout(CLIENT_IO, BufReader::new(rd).read_line(&mut line)).await;
    let reply = match read {
        Ok(Ok(_)) if line.trim() == "state" => match respond().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%e, "state request failed");
                serde_json::json!({ "error": e.to_string() })
            }
        },
        Ok(Ok(_)) => serde_json::json!({ "error": format!("unknown request {:?}", line.trim()) }),
        Ok(Err(_)) | Err(_) => return,
    };
    let mut text = reply.to_string();
    text.push('\n');
    let _ = tokio::time::timeout(CLIENT_IO, wr.write_all(text.as_bytes())).await;
    let _ = wr.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_socket_is_unlinked_live_socket_is_refused() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("engine.sock");
        let pid = dir.path().join("engine.pid");
        std::fs::write(&pid, "4242\n").unwrap();
        rt.block_on(async {
            // Stale: a bound-then-dropped path nobody listens on.
            drop(UnixListener::bind(&sock).unwrap());
            assert!(sock.exists());
            let listener = bind(&sock, &pid).unwrap();
            assert_eq!(
                std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
                0o600
            );
            // Live: the listener answers, so a second bind must refuse.
            let server = tokio::spawn(async move {
                let (s, _) = listener.accept().await.unwrap();
                serve_one(s, async || Ok(serde_json::json!({ "ready": true }))).await;
            });
            let err = tokio::task::spawn_blocking({
                let sock = sock.clone();
                let pid = pid.clone();
                move || bind(&sock, &pid).err().map(|e| e.to_string())
            })
            .await
            .unwrap()
            .unwrap();
            assert!(err.contains("another engine is running (pid 4242"), "{err}");
            server.await.unwrap();
        });
    }

    #[test]
    fn pid_file_naming_a_live_engine_refuses_dead_or_foreign_pid_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("engine.sock");
        let pid = dir.path().join("engine.pid");
        // No files at all: fine.
        refuse_if_live(&sock, &pid).unwrap();
        // A pid that cannot be alive (beyond pid_max).
        std::fs::write(&pid, "4194305\n").unwrap();
        refuse_if_live(&sock, &pid).unwrap();
        // Our own live pid, but its cmdline carries no `engine` argument: foreign, not ours.
        std::fs::write(&pid, format!("{}\n", std::process::id())).unwrap();
        assert!(!is_cfab_engine(std::process::id()));
        refuse_if_live(&sock, &pid).unwrap();
        // A live process whose argv contains `engine`: refused without any socket. The
        // shell's builtin `read` blocks on the piped stdin, so sh itself stays alive with
        // its argv intact (no exec) until it is killed.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "read _", "sh", "engine"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::fs::write(&pid, format!("{}\n", child.id())).unwrap();
        // Until the forked child execs sh, /proc shows OUR argv; once it has, the argv
        // stays `sh -c … sh engine` for good, so waiting for it is race-free.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !is_cfab_engine(child.id()) && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(is_cfab_engine(child.id()));
        let err = refuse_if_live(&sock, &pid).unwrap_err().to_string();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            err.contains(&format!("another engine is running (pid {}", child.id())),
            "{err}"
        );
        assert!(err.contains("not a cfab engine"), "{err}");
    }

    #[test]
    fn serve_one_answers_state_and_rejects_other_requests() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("engine.sock");
        let pid = dir.path().join("engine.pid");
        rt.block_on(async {
            let listener = bind(&sock, &pid).unwrap();
            let server = tokio::spawn(async move {
                for _ in 0..2 {
                    let (s, _) = listener.accept().await.unwrap();
                    serve_one(s, async || {
                        Ok(serde_json::json!({ "ready": true, "bfd": [] }))
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
            server.await.unwrap();
        });
    }
}
