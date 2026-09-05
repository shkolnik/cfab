//! `<run_dir>/cfab.sock`: the supervisor answers `components`, `log` and `reapply` (spec §9).
//!
//! An internal file, not an operator surface — the operator surface is `cfab status` and
//! `systemctl`. The framing is `sock_frame`, shared with `engine.sock`.

use std::path::Path;
use std::sync::Arc;

use super::report::Components;
use crate::error::{Error, Result};

/// Default and ceiling for `log <name> [n]`: the ring holds 200 lines, so asking for more
/// than that is answered with what exists rather than refused.
const LOG_DEFAULT: usize = 50;
const LOG_MAX: usize = 200;

/// What the socket serves. The supervisor's own state implements it; the trait exists so the
/// server is testable — and reviewable — without a supervisor.
pub trait ComponentsSource {
    fn snapshot(&self) -> Components;
    /// The last `n` captured lines of that child, or `None` if this member has no such
    /// component.
    fn log_tail(&self, name: &str, n: usize) -> Option<Vec<String>>;
    /// Re-apply the fabric, blocking until it finishes.
    fn reapply(&self) -> Result<()>;
}

/// Answer one request line. Unknown verbs are an error, never a partial or empty document:
/// a caller that misspells a verb must be told, not silently given nothing.
pub fn respond<S: ComponentsSource + ?Sized>(source: &S, line: &str) -> Result<serde_json::Value> {
    let mut words = line.split_whitespace();
    match words.next() {
        Some("components") => serde_json::to_value(source.snapshot()).map_err(Error::fatal),
        Some("log") => {
            let name = words
                .next()
                .ok_or_else(|| Error::fatal("log needs a component name"))?;
            let n = match words.next() {
                Some(v) => v
                    .parse::<usize>()
                    .map_err(|_| Error::fatal(format!("log: {v} is not a line count")))?,
                None => LOG_DEFAULT,
            };
            let lines = source
                .log_tail(name, n.min(LOG_MAX))
                .ok_or_else(|| Error::fatal(format!("unknown component: {name}")))?;
            Ok(serde_json::json!({ "lines": lines }))
        }
        Some("reapply") => Ok(match source.reapply() {
            Ok(()) => serde_json::json!({ "ok": true }),
            Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
        }),
        Some(other) => Err(Error::fatal(format!("unknown request: {other}"))),
        None => Err(Error::fatal("empty request")),
    }
}

/// Bind `path` (mode 0600) and serve until the task is dropped. One connection per request:
/// the client writes one line, we write one JSON object and close.
pub async fn serve<S>(source: Arc<S>, path: &Path) -> Result<()>
where
    S: ComponentsSource + Send + Sync + 'static,
{
    let listener = crate::sock_frame::bind(path)?;
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::warn!(%e, "cfab.sock accept failed");
                continue;
            }
        };
        let source = source.clone();
        tokio::spawn(async move {
            crate::sock_frame::serve_one(stream, async |line: &str| respond(&*source, line)).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Sys;

    const FIXTURE: &str = r#"{
      "supervisor": {"pid": 1234, "uptime_s": 3721, "applying": false, "applies": 3, "last_apply_error": null},
      "components": [
        {"name": "engine", "state": "running", "pid": 1240, "uptime_s": 3720, "restarts": 0, "last_exit": null}
      ],
      "watchdog": {"last_tick_s_ago": 2, "result": "ok", "detail": null}
    }"#;

    struct Fake {
        apply_fails: bool,
    }

    impl ComponentsSource for Fake {
        fn snapshot(&self) -> Components {
            serde_json::from_str(FIXTURE).unwrap()
        }
        fn log_tail(&self, name: &str, n: usize) -> Option<Vec<String>> {
            (name == "engine").then(|| {
                ["one", "two", "three"]
                    .iter()
                    .rev()
                    .take(n)
                    .rev()
                    .map(|s| s.to_string())
                    .collect()
            })
        }
        fn reapply(&self) -> crate::error::Result<()> {
            if self.apply_fails {
                Err(crate::error::Error::fatal("wire eno9 absent"))
            } else {
                Ok(())
            }
        }
    }

    /// Multi-thread flavor throughout: the client blocks on the synchronous
    /// `RealSys::unix_request` while the accept task runs on the same runtime.
    fn start(apply_fails: bool) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfab.sock");
        let p = path.clone();
        tokio::spawn(async move {
            serve(std::sync::Arc::new(Fake { apply_fails }), &p)
                .await
                .unwrap();
        });
        (dir, path.to_string_lossy().into_owned())
    }

    async fn ask(path: &str, line: &str) -> serde_json::Value {
        let path = path.to_string();
        let line = format!("{line}\n");
        let text = tokio::task::spawn_blocking(move || {
            for _ in 0..100 {
                if let Ok(r) = crate::sys::RealSys.unix_request(&path, &line) {
                    return r;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            panic!("socket never answered");
        })
        .await
        .unwrap();
        serde_json::from_str(&text).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_socket_answers_components_and_refuses_an_unknown_verb() {
        let (_dir, path) = start(false);
        let v = ask(&path, "components").await;
        assert_eq!(v["components"][0]["name"], "engine");
        assert_eq!(v["supervisor"]["pid"], 1234);
        let v = ask(&path, "nonsense").await;
        assert_eq!(v["error"], "FATAL: unknown request: nonsense");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_socket_returns_a_log_tail_and_names_an_unknown_component() {
        let (_dir, path) = start(false);
        let v = ask(&path, "log engine 2").await;
        assert_eq!(v["lines"][0], "two");
        assert_eq!(v["lines"][1], "three");
        let v = ask(&path, "log nosuch").await;
        assert_eq!(v["error"], "FATAL: unknown component: nosuch");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reapply_returns_the_applier_error_text() {
        let (_dir, path) = start(true);
        let v = ask(&path, "reapply").await;
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "FATAL: wire eno9 absent");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_successful_reapply_is_ok_true() {
        let (_dir, path) = start(false);
        let v = ask(&path, "reapply").await;
        assert_eq!(v["ok"], true);
        assert!(v.get("error").is_none());
    }
}
