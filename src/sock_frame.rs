//! The unix-socket request/reply frame shared by every cfab socket (`engine.sock`,
//! `cfab.sock`): the client writes one request line, the server writes one JSON object and
//! closes. Liveness/staleness policy is caller-specific and stays with each caller
//! (`engine/sock.rs::refuse_if_live`); this module only does the socket mechanics.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::error::{Error, Result};

const CLIENT_IO: Duration = Duration::from_secs(2);

/// Bind the socket at `path`, mode 0600. No liveness/staleness policy here: a caller that
/// cares whether a stale path is safe to unlink (or another process already owns it) does
/// that check before calling this — see `engine/sock.rs::bind`.
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
        let reply = crate::sys::RealSys
            .unix_request(path.to_str().unwrap(), "components\n")
            .unwrap();
        assert_eq!(reply, "{\"echo\":\"components\"}\n");
    }
}
