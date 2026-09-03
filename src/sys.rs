//! The system boundary: every command execution, file read/write, and sleep the runtime does
//! goes through `Sys`, so command logic is unit-testable against a mock (`sys::mock`), and the
//! real implementation stays a thin, obvious shim. No shell anywhere: argv vectors only.

use std::time::Duration;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

pub trait Sys {
    /// Run argv, capture everything; a nonzero exit is a normal `Output`, not an `Err` (callers
    /// decide — `run_ok` when failure is fatal).
    fn run(&mut self, argv: &[&str]) -> Result<Output>;
    fn read(&self, path: &str) -> Result<String>;
    fn write(&mut self, path: &str, content: &str) -> Result<()>;
    fn exists(&self, path: &str) -> bool;
    fn is_writable(&self, path: &str) -> bool;
    fn list_dir(&self, path: &str) -> Result<Vec<String>>;
    fn mkdir_p(&mut self, path: &str) -> Result<()>;
    fn remove(&mut self, path: &str) -> Result<()>;
    fn rename(&mut self, from: &str, to: &str) -> Result<()>;
    fn sleep(&mut self, d: Duration);
}

/// Run and require exit 0.
pub fn run_ok(sys: &mut dyn Sys, argv: &[&str]) -> Result<Output> {
    let out = sys.run(argv)?;
    if !out.ok() {
        return Err(Error::Cmd {
            cmd: argv.join(" "),
            status: out.status,
            stderr: out.stderr.clone(),
        });
    }
    Ok(out)
}

/// Run, ignore failure (bash `|| true`).
pub fn run_ignore(sys: &mut dyn Sys, argv: &[&str]) -> Result<()> {
    let _ = sys.run(argv)?;
    Ok(())
}

/// Is a tool on PATH? (precondition checks — fail loud, never degrade.)
pub fn have_tool(sys: &mut dyn Sys, tool: &str) -> Result<bool> {
    // `command -v` is a shell builtin; `which` may be absent. /usr/bin/env is everywhere.
    Ok(sys
        .run(&["/usr/bin/env", "sh", "-c", &format!("command -v {tool}")])?
        .ok())
}

pub struct RealSys;

impl Sys for RealSys {
    fn run(&mut self, argv: &[&str]) -> Result<Output> {
        let out = std::process::Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|e| Error::fatal(format!("cannot exec {}: {e}", argv[0])))?;
        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn read(&self, path: &str) -> Result<String> {
        Ok(std::fs::read_to_string(path)?)
    }

    fn write(&mut self, path: &str, content: &str) -> Result<()> {
        std::fs::write(path, content).map_err(|e| Error::fatal(format!("cannot write {path}: {e}")))
    }

    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn is_writable(&self, path: &str) -> bool {
        std::fs::OpenOptions::new().write(true).open(path).is_ok()
    }

    fn list_dir(&self, path: &str) -> Result<Vec<String>> {
        let mut names: Vec<String> = std::fs::read_dir(path)?
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort();
        Ok(names)
    }

    fn mkdir_p(&mut self, path: &str) -> Result<()> {
        Ok(std::fs::create_dir_all(path)?)
    }

    fn remove(&mut self, path: &str) -> Result<()> {
        let p = std::path::Path::new(path);
        if p.is_dir() {
            std::fs::remove_dir_all(p)?;
        } else if p.exists() {
            std::fs::remove_file(p)?;
        }
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        Ok(std::fs::rename(from, to)?)
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[cfg(test)]
pub mod mock {
    //! A scripted `Sys` for unit tests: file contents in a map, command outputs matched by
    //! prefix rules (later rules win), every call recorded for sequence assertions.

    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::{Output, Sys};
    use crate::error::{Error, Result};

    #[derive(Default)]
    pub struct MockSys {
        pub files: BTreeMap<String, String>,
        pub writable: Vec<String>,
        /// (argv-prefix, output) — the LAST matching rule wins; unmatched commands succeed
        /// silently (status 0, empty output).
        pub cmd_rules: Vec<(Vec<String>, Output)>,
        pub calls: Vec<String>,
        pub slept: Vec<Duration>,
        /// Test hook run on each sleep with the 1-based sleep count — lets a test mutate
        /// external state "while time passes" (e.g. a peer ack appearing mid-window).
        #[allow(clippy::type_complexity)]
        pub on_sleep: Option<Box<dyn FnMut(usize)>>,
    }

    impl MockSys {
        pub fn file(mut self, path: &str, content: &str) -> Self {
            self.files.insert(path.to_string(), content.to_string());
            self
        }

        pub fn on(mut self, prefix: &[&str], out: Output) -> Self {
            self.cmd_rules
                .push((prefix.iter().map(|s| s.to_string()).collect(), out));
            self
        }

        pub fn on_stdout(self, prefix: &[&str], stdout: &str) -> Self {
            self.on(
                prefix,
                Output {
                    status: 0,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                },
            )
        }

        pub fn on_fail(self, prefix: &[&str], status: i32, stderr: &str) -> Self {
            self.on(
                prefix,
                Output {
                    status,
                    stdout: String::new(),
                    stderr: stderr.to_string(),
                },
            )
        }

        pub fn ran(&self, needle: &str) -> bool {
            self.calls.iter().any(|c| c.contains(needle))
        }

        pub fn writes_to(&self, path: &str) -> Option<&str> {
            self.files.get(path).map(String::as_str)
        }
    }

    impl Sys for MockSys {
        fn run(&mut self, argv: &[&str]) -> Result<Output> {
            self.calls.push(argv.join(" "));
            let hit = self
                .cmd_rules
                .iter()
                .rev()
                .find(|(prefix, _)| {
                    argv.len() >= prefix.len()
                        && prefix.iter().zip(argv.iter()).all(|(p, a)| p == a)
                })
                .map(|(_, out)| out.clone());
            Ok(hit.unwrap_or_default())
        }

        fn read(&self, path: &str) -> Result<String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| Error::fatal(format!("mock: no file {path}")))
        }

        fn write(&mut self, path: &str, content: &str) -> Result<()> {
            self.calls.push(format!("write {path}"));
            self.files.insert(path.to_string(), content.to_string());
            Ok(())
        }

        fn exists(&self, path: &str) -> bool {
            self.files.contains_key(path)
        }

        fn is_writable(&self, path: &str) -> bool {
            self.writable.iter().any(|p| p == path) || self.files.contains_key(path)
        }

        fn list_dir(&self, path: &str) -> Result<Vec<String>> {
            let prefix = format!("{}/", path.trim_end_matches('/'));
            let mut names: Vec<String> = self
                .files
                .keys()
                .filter_map(|k| k.strip_prefix(&prefix))
                .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
                .collect();
            names.sort();
            names.dedup();
            Ok(names)
        }

        fn mkdir_p(&mut self, path: &str) -> Result<()> {
            self.calls.push(format!("mkdir -p {path}"));
            Ok(())
        }

        fn remove(&mut self, path: &str) -> Result<()> {
            self.calls.push(format!("rm {path}"));
            self.files
                .retain(|k, _| k != path && !k.starts_with(&format!("{path}/")));
            Ok(())
        }

        fn rename(&mut self, from: &str, to: &str) -> Result<()> {
            self.calls.push(format!("mv {from} {to}"));
            if let Some(v) = self.files.remove(from) {
                self.files.insert(to.to_string(), v);
            }
            Ok(())
        }

        fn sleep(&mut self, d: Duration) {
            self.slept.push(d);
            let n = self.slept.len();
            if let Some(hook) = &mut self.on_sleep {
                hook(n);
            }
        }
    }
}
