use std::fmt;

/// One error type for the whole binary. Config errors carry a `fabric.toml: ` prefix so
/// operators (and greps) can tell a declaration problem from a host problem at a glance.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A problem in fabric.toml itself (parse or validation). Printed as `fabric.toml: <msg>`.
    #[error("fabric.toml: {0}")]
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

    /// Wrap a config error in more context. The `fabric.toml: ` prefix belongs to the
    /// OUTERMOST error only — formatting an `Error` into another error's message would
    /// print it twice, which is how "fabric.toml: zone mgmt: gw fabric.toml: domain ..."
    /// happens.
    pub fn context(prefix: impl fmt::Display, inner: Error) -> Self {
        match inner {
            Error::Config(msg) => Error::Config(format!("{prefix}{msg}")),
            other @ (Error::Fatal(_) | Error::Cmd { .. } | Error::Io(_)) => {
                Error::Config(format!("{prefix}{other}"))
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
