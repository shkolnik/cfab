use std::fmt;

/// One error type for the whole binary. Config errors carry a `fabric.conf: ` prefix so
/// operators (and greps) can tell a declaration problem from a host problem at a glance.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A problem in fabric.conf itself (parse or validation). Printed as `fabric.conf: <msg>`.
    #[error("fabric.conf: {0}")]
    Config(String),
    /// A precondition on the running system failed (missing tool, missing interface, read-only
    /// /proc/sys …). Fatal, never degrade.
    #[error("FATAL: {0}")]
    Fatal(String),
    /// An external command we ran failed.
    #[error("{cmd}: exit {status}{}", fmt_stderr(.stderr))]
    Cmd {
        cmd: String,
        status: i32,
        stderr: String,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn fmt_stderr(stderr: &str) -> String {
    let s = stderr.trim();
    if s.is_empty() {
        String::new()
    } else {
        format!(" — {s}")
    }
}

impl Error {
    pub fn config(msg: impl fmt::Display) -> Self {
        Error::Config(msg.to_string())
    }
    pub fn fatal(msg: impl fmt::Display) -> Self {
        Error::Fatal(msg.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
