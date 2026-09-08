//! The unix-socket request/reply frame shared by every cfab socket (`engine.sock`,
//! `cfab.sock`): the client writes one request line, the server writes one JSON object and
//! closes. One staleness policy for every socket (`bind_reclaiming`): a leftover path is
//! unlinked only when nothing answers on it; a live answer is a refusal, never a takeover.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::error::{Error, Result};

const CLIENT_IO: Duration = Duration::from_secs(2);

/// Does a process answer `probe` on this socket? A bare connect is not enough: the kernel
/// accepts a connect to a path whose listener is gone only until the backlog is consumed,
/// and a path left by a SIGKILLed process connects with ECONNREFUSED — both read as "no".
pub fn answers(path: &Path, probe: &str) -> bool {
    let Ok(mut s) = StdUnixStream::connect(path) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(CLIENT_IO));
    let _ = s.set_write_timeout(Some(CLIENT_IO));
    if s.write_all(format!("{probe}\n").as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 1];
    matches!(s.read(&mut buf), Ok(n) if n > 0)
}

/// Bind `path`, reclaiming a stale one. A leftover path (a predecessor that died without
/// unlinking: SIGKILL, container kill, power loss with a persistent run dir) is unlinked ONLY
/// when nothing answers `probe` on it; a live answer means another `owner` owns this run dir —
/// fatal, never a silent takeover. The real exclusivity guard is each owner's flock, taken
/// before this is called; this is the cheap re-check at bind time. Without it a restarted
/// owner fails `bind` with EADDRINUSE and, if that failure is only logged, runs with no
/// operator surface at all (seen live 2026-09-06: a SIGKILLed leaf container restarted with a
/// supervisor nobody could reach — `status` said "no supervisor answering" until `down`/`up`).
pub fn bind_reclaiming(path: &Path, probe: &str, owner: &str) -> Result<UnixListener> {
    if path.exists() {
        if answers(path, probe) {
            return Err(Error::fatal(format!(
                "another {owner} is running (answering on {}); stop it first (cfab down)",
                path.display()
            )));
        }
        std::fs::remove_file(path)
            .map_err(|e| Error::fatal(format!("cannot remove stale {}: {e}", path.display())))?;
    }
    bind(path)
}

/// Bind the socket at `path`, mode 0600, with no staleness policy: `bind_reclaiming` is what
/// a long-lived owner wants; this is for a fresh path (tests, or a caller that already checked).
pub fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::fatal(format!("cannot create {}: {e}", parent.display())))?;
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| Error::fatal(format!("cannot bind {}: {e}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::fatal(format!("cannot chmod {}: {e}", path.display())))?;
    Ok(listener)
}

/// Serve one accepted connection: read the request line, hand it (trimmed of its trailing
/// newline) to `respond`, reply with the JSON it returns, then close. A client that sends
/// nothing within the timeout is dropped without a reply. Each caller parses its own verbs
/// from the raw line, so this frame stays ignorant of any protocol's vocabulary.
pub async fn serve_one<F>(stream: UnixStream, respond: F)
where
    F: AsyncFnOnce(&str) -> Result<serde_json::Value>,
{
    let (rd, mut wr) = stream.into_split();
    let mut line = String::new();
    let read = tokio::time::timeout(CLIENT_IO, BufReader::new(rd).read_line(&mut line)).await;
    let reply = match read {
        Ok(Ok(_)) => match respond(line.trim_end_matches('\n')).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%e, request = %line.trim(), "request failed");
                serde_json::json!({ "error": e.to_string() })
            }
        },
        Ok(Err(_)) | Err(_) => return,
    };
    let mut text = reply.to_string();
    text.push('\n');
    let _ = tokio::time::timeout(CLIENT_IO, wr.write_all(text.as_bytes())).await;
    let _ = wr.shutdown().await;
}

#[cfg(test)]
mod tests {
    use crate::sys::Sys;

    /// The path a SIGKILLed owner leaves behind: bound once, listener dropped, file still there.
    fn stale(path: &std::path::Path) {
        let l = super::bind(path).unwrap();
        drop(l);
        assert!(path.exists(), "a dropped listener leaves its path behind");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_stale_path_is_reclaimed_and_the_new_owner_answers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("o.sock");
        stale(&path);
        assert!(
            !super::answers(&path, "probe"),
            "nothing answers a stale path"
        );
        let listener = super::bind_reclaiming(&path, "probe", "owner").unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            super::serve_one(s, async |_: &str| Ok(serde_json::json!({"ok": true}))).await;
        });
        let p = path.clone();
        let reply = tokio::task::spawn_blocking(move || {
            crate::sys::RealSys::default()
                .unix_request(p.to_str().unwrap(), "probe\n")
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(reply.trim(), r#"{"ok":true}"#);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_live_owner_is_refused_by_name_never_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("o.sock");
        let listener = super::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                super::serve_one(s, async |_: &str| Ok(serde_json::json!({"live": true}))).await;
            }
        });
        let p = path.clone();
        let err = tokio::task::spawn_blocking(move || {
            assert!(super::answers(&p, "probe"), "the live owner answers");
            super::bind_reclaiming(&p, "probe", "supervisor")
                .unwrap_err()
                .to_string()
        })
        .await
        .unwrap();
        assert!(
            err.contains("another supervisor is running") && err.contains("cfab down"),
            "{err}"
        );
        assert!(path.exists(), "a live owner's socket is never unlinked");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_line_request_one_json_reply_then_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sock");
        let listener = super::bind(&path).unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            super::serve_one(s, async |line: &str| {
                Ok(serde_json::json!({ "echo": line }))
            })
            .await;
        });
        let reply = crate::sys::RealSys::default()
            .unix_request(path.to_str().unwrap(), "components\n")
            .unwrap();
        assert_eq!(reply, "{\"echo\":\"components\"}\n");
    }
}
