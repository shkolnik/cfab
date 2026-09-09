//! The system boundary: every command execution, file read/write, and sleep the runtime does
//! goes through `Sys`, so command logic is unit-testable against a mock (`sys::mock`), and the
//! real implementation stays a thin, obvious shim. No shell anywhere: argv vectors only.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::netlink::{BondNetlink, PortState};

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

/// The outcome of probing a Unix socket for a listener (`Sys::unix_probe`). The point of the
/// three-way split is a safety one: a caller deciding whether it is safe to act as if nobody
/// owns the socket must be able to tell "provably nothing is listening" from "connected, but no
/// usable reply". A post-connect failure (a slow peer, a read timeout) is NOT absence — a
/// successful `connect(2)` already proves a listener owns the socket.
#[derive(Debug)]
pub enum UnixProbe {
    /// `connect(2)` failed with `ENOENT` (no socket file) or `ECONNREFUSED` (a socket file with
    /// nothing accepting): provably nobody is listening.
    NotListening,
    /// Connected and read a reply to EOF.
    Answered(String),
    /// A listener may own the socket — connected but the exchange did not yield a usable reply
    /// (a write/read error or the 5 s read timeout), or a connect error that does not prove
    /// absence (e.g. `EACCES`). Carries a diagnostic. Callers must treat this as "occupied".
    Unreachable(String),
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
    /// The target of one symlink, unresolved. `/proc/<pid>/fd/<n>` is the only caller so far:
    /// its target (`socket:[<inode>]`) is not a path and has no contents, so `read` cannot
    /// answer it.
    fn read_link(&self, path: &str) -> Result<String>;
    fn mkdir_p(&mut self, path: &str) -> Result<()>;
    fn remove(&mut self, path: &str) -> Result<()>;
    fn rename(&mut self, from: &str, to: &str) -> Result<()>;
    fn sleep(&mut self, d: Duration);
    /// One request, one reply over a Unix stream socket: connect to `path`, write `line`, read
    /// until the peer closes. The engine's state socket speaks exactly this shape.
    fn unix_request(&mut self, path: &str, line: &str) -> Result<String>;
    /// Like `unix_request`, but reports whether a listener owns the socket (`UnixProbe`). The
    /// default cannot see the connect errno, so it maps any error to `Unreachable` — the safe
    /// side, since a caller must never read a post-connect failure as "nobody home". `RealSys`
    /// overrides it to read the connect errno; `MockSys` overrides it to model an unregistered
    /// socket as `NotListening`.
    fn unix_probe(&mut self, path: &str, line: &str) -> UnixProbe {
        match self.unix_request(path, line) {
            Ok(reply) => UnixProbe::Answered(reply),
            Err(e) => UnixProbe::Unreachable(e.to_string()),
        }
    }

    /// Everything the prober needs to know about one bond port, in one kernel round trip:
    /// carrier, the bonding driver's own link state, and which bond owns it. `Err` carrying
    /// `ENODEV` (`netlink::is_no_device`) means the netdev is gone, which is a fact about the
    /// wire; any other error is a fault to report, never a silent "no carrier".
    fn bond_port_state(&mut self, port: &str) -> Result<PortState>;

    /// Make `port` the bond's active port. The kernel's refusal (`EINVAL` when the port is
    /// down or its link is not up) comes back as the errno it is.
    fn set_active_port(&mut self, bond: &str, port: &str) -> Result<()>;
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
/// Run a command that may not be installed at all. An exec failure (`iptables` absent on a host
/// that never had Docker) is `None`, not a fatal error; a nonzero exit is still `Some`.
pub fn run_optional(sys: &mut dyn Sys, argv: &[&str]) -> Option<Output> {
    sys.run(argv).ok()
}

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

/// The real system. It owns the prober's netlink socket, which is opened on first use and kept
/// for the life of the value — the loop that reads it every 500 ms pays for one socket, not one
/// per tick.
#[derive(Default)]
pub struct RealSys {
    nl: BondNetlink,
}

impl Sys for RealSys {
    fn bond_port_state(&mut self, port: &str) -> Result<PortState> {
        self.nl.port_state(port)
    }

    fn set_active_port(&mut self, bond: &str, port: &str) -> Result<()> {
        self.nl.set_active_port(bond, port)
    }

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

    fn read_link(&self, path: &str) -> Result<String> {
        Ok(std::fs::read_link(path)?.to_string_lossy().into_owned())
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

    fn unix_request(&mut self, path: &str, line: &str) -> Result<String> {
        use std::io::{Read, Write};
        let timeout = Some(Duration::from_secs(5));
        let mut s = std::os::unix::net::UnixStream::connect(path)
            .map_err(|e| Error::fatal(format!("cannot connect to {path}: {e}")))?;
        s.set_read_timeout(timeout)?;
        s.set_write_timeout(timeout)?;
        s.write_all(line.as_bytes())
            .map_err(|e| Error::fatal(format!("cannot write to {path}: {e}")))?;
        let mut reply = String::new();
        s.read_to_string(&mut reply)
            .map_err(|e| Error::fatal(format!("cannot read from {path}: {e}")))?;
        Ok(reply)
    }

    fn unix_probe(&mut self, path: &str, line: &str) -> UnixProbe {
        use std::io::{ErrorKind, Read, Write};
        let timeout = Some(Duration::from_secs(5));
        let mut s = match std::os::unix::net::UnixStream::connect(path) {
            Ok(s) => s,
            // The only two outcomes that prove nobody is listening.
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                return UnixProbe::NotListening;
            }
            // Any other connect error (EACCES, EADDRINUSE-races, …) does not prove absence.
            Err(e) => return UnixProbe::Unreachable(format!("cannot connect to {path}: {e}")),
        };
        // From a successful connect on, every failure is "occupied", never "absent".
        if let Err(e) = s
            .set_read_timeout(timeout)
            .and_then(|()| s.set_write_timeout(timeout))
        {
            return UnixProbe::Unreachable(format!("{path}: {e}"));
        }
        if let Err(e) = s.write_all(line.as_bytes()) {
            return UnixProbe::Unreachable(format!("cannot write to {path}: {e}"));
        }
        let mut reply = String::new();
        match s.read_to_string(&mut reply) {
            Ok(_) => UnixProbe::Answered(reply),
            Err(e) => UnixProbe::Unreachable(format!("cannot read from {path}: {e}")),
        }
    }
}

#[cfg(test)]
pub mod mock {
    //! A scripted `Sys` for unit tests: file contents in a map, command outputs matched by
    //! prefix rules (later rules win), every call recorded for sequence assertions.

    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::time::Duration;

    use super::{Output, Sys, UnixProbe};
    use crate::error::{Error, Result};
    use crate::netlink::PortState;

    #[derive(Default)]
    pub struct MockSys {
        pub files: BTreeMap<String, String>,
        /// path → symlink target, read back by `read_link` and listed by `list_dir` alongside
        /// the files (a `/proc/<pid>/fd` entry is a link, not a file).
        pub links: BTreeMap<String, String>,
        pub writable: Vec<String>,
        /// Paths whose `write` fails (a read-only `/proc`, an EPERM sysctl): the only way to
        /// exercise "the restore itself could not be done".
        pub write_fails: Vec<String>,
        /// (argv-prefix, output) — the LAST matching rule wins; unmatched commands succeed
        /// silently (status 0, empty output).
        pub cmd_rules: Vec<(Vec<String>, Output)>,
        pub calls: Vec<String>,
        pub slept: Vec<Duration>,
        /// socket path → the replies `unix_request` hands back in order; the last one
        /// repeats forever. Unknown path → Err. Serves every verb on the path the same reply;
        /// use `socket_verb` when one path must answer different verbs differently.
        pub sockets: HashMap<String, VecDeque<String>>,
        /// (path, verb) → replies, checked before `sockets` so one socket answers `components`
        /// and `log engine` independently and order-free (both are read in one status run). The
        /// verb is the first whitespace-delimited word of the request line.
        pub socket_verbs: HashMap<(String, String), VecDeque<String>>,
        /// Socket paths that `unix_probe` reports as `Unreachable`: a listener that accepts the
        /// connection but yields no usable reply (a slow supervisor, a read timeout). Distinct
        /// from an unregistered path, which probes as `NotListening`.
        pub unreachable_sockets: Vec<String>,
        /// Test hook run on each sleep with the 1-based sleep count — lets a test mutate
        /// external state "while time passes" (e.g. a peer ack appearing mid-window).
        #[allow(clippy::type_complexity)]
        pub on_sleep: Option<Box<dyn FnMut(usize)>>,
        /// (sleep count, path, content): a file that comes into existence after that many
        /// sleeps. `on_sleep` cannot do this — it borrows nothing of the sys it would have to
        /// write to — and a poll loop that waits for something to appear (a run dir written by
        /// a restarting supervisor) has no other way to be tested.
        pub appear_after: Vec<(usize, String, String)>,
        /// Every (path, content) written, in order — a refused write included, so a test can see
        /// a write was attempted even where `write_fails` blocked it from landing in `files`.
        pub writes: Vec<(String, String)>,
        /// port netdev -> what `bond_port_state` answers for it. A port that is not in the map
        /// does not exist: the read fails with `ENODEV`, which is how a real kernel reports a
        /// netdev that has gone away.
        pub port_states: BTreeMap<String, PortState>,
        /// Ports whose state cannot be read at all (`EIO`) — the socket is there but the answer
        /// is not, which is neither "no carrier" nor "the netdev is gone".
        pub unreadable_ports: Vec<String>,
    }

    impl MockSys {
        pub fn file(mut self, path: &str, content: &str) -> Self {
            self.files.insert(path.to_string(), content.to_string());
            self
        }

        /// A symlink at `path` pointing at `target` (e.g. `/proc/812/fd/7` → `socket:[41231]`).
        pub fn link(mut self, path: &str, target: &str) -> Self {
            self.links.insert(path.to_string(), target.to_string());
            self
        }

        /// One reply, answered to every request on `path`.
        pub fn socket(self, path: &str, reply: &str) -> Self {
            self.socket_seq(path, &[reply.to_string()])
        }

        /// Successive replies on `path`, one per request; the last repeats. Lets a test show
        /// a value the engine changes between two reads (an interface leaving `down`).
        pub fn socket_seq(mut self, path: &str, replies: &[String]) -> Self {
            self.sockets
                .insert(path.to_string(), replies.iter().cloned().collect());
            self
        }

        /// A reply keyed by the request verb (first word of the line), so one socket path can
        /// answer `components` and `log engine` independently of call order. Matched ahead of the
        /// path-level `socket`/`socket_seq` reply; successive calls with the same verb queue,
        /// last repeating.
        pub fn socket_verb(mut self, path: &str, verb: &str, reply: &str) -> Self {
            self.socket_verbs
                .entry((path.to_string(), verb.to_string()))
                .or_default()
                .push_back(reply.to_string());
            self
        }

        /// A socket that `unix_probe` reports as `Unreachable` — connected, no usable reply:
        /// the live-but-slow supervisor a `cfab down` must refuse rather than tear down under.
        pub fn socket_unreachable(mut self, path: &str) -> Self {
            self.unreachable_sockets.push(path.to_string());
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

        /// `path` exists only from the `n`th sleep on: state a test needs to arrive while the
        /// code under test is waiting for it.
        pub fn appears_after(mut self, n: usize, path: &str, content: &str) -> Self {
            self.appear_after
                .push((n, path.to_string(), content.to_string()));
            self
        }

        /// Make `write` to this path fail, as a read-only or EPERM path does.
        pub fn write_fail(mut self, path: &str) -> Self {
            self.write_fails.push(path.to_string());
            self
        }

        /// One bond port and everything the kernel would say about it.
        pub fn port(mut self, name: &str, state: PortState) -> Self {
            self.port_states.insert(name.to_string(), state);
            self
        }

        /// Change (or add) a port's state mid-test — a cable pulled between two ticks.
        pub fn set_port(&mut self, name: &str, state: PortState) {
            self.port_states.insert(name.to_string(), state);
        }

        /// A port whose state the kernel does not answer for: the failure the prober must
        /// report rather than read as an absent cable.
        pub fn port_unreadable(mut self, name: &str) -> Self {
            self.unreadable_ports.push(name.to_string());
            self
        }

        /// Take a port's netdev away entirely, as a re-enumerating USB NIC does.
        pub fn remove_port(&mut self, name: &str) {
            self.port_states.remove(name);
        }

        pub fn ran(&self, needle: &str) -> bool {
            self.calls.iter().any(|c| c.contains(needle))
        }

        pub fn writes_to(&self, path: &str) -> Option<&str> {
            self.files.get(path).map(String::as_str)
        }

        /// Every content written to `path`, in order (a refused write included).
        pub fn writes_of(&self, path: &str) -> Vec<&str> {
            self.writes
                .iter()
                .filter(|(p, _)| p == path)
                .map(|(_, c)| c.as_str())
                .collect()
        }
    }

    impl Sys for MockSys {
        fn bond_port_state(&mut self, port: &str) -> Result<PortState> {
            if self.unreadable_ports.iter().any(|p| p == port) {
                return Err(Error::Io(std::io::Error::from_raw_os_error(
                    nix::errno::Errno::EIO as i32,
                )));
            }
            self.port_states.get(port).copied().ok_or_else(|| {
                Error::Io(std::io::Error::from_raw_os_error(
                    nix::errno::Errno::ENODEV as i32,
                ))
            })
        }

        /// Records the call and models what the kernel would then report: `status` still reads
        /// the bond's active port out of sysfs, so the modelled write lands there.
        fn set_active_port(&mut self, bond: &str, port: &str) -> Result<()> {
            self.calls.push(format!("set_active_port {bond} {port}"));
            let path = format!("/sys/class/net/{bond}/bonding/active_slave");
            if self.write_fails.iter().any(|p| p.as_str() == path) {
                return Err(Error::Io(std::io::Error::from_raw_os_error(
                    nix::errno::Errno::EINVAL as i32,
                )));
            }
            self.files.insert(path, port.to_string());
            Ok(())
        }

        fn run(&mut self, argv: &[&str]) -> Result<Output> {
            self.calls.push(argv.join(" "));
            // A deleted netdev stops existing. Without this the mock answers `ip link show
            // <dev>` for a device cfab has just removed, and any path that deletes and then
            // rebuilds under the same name (the ingress leg's two shapes) could not be tested
            // at all: the builder's own probe would still see the netdev it just destroyed.
            if let ["ip", "link", "del", dev] = argv {
                self.cmd_rules.retain(|(prefix, _)| {
                    prefix.as_slice() != ["ip", "link", "show", dev]
                        && prefix.as_slice() != ["ip", "-d", "link", "show", dev]
                });
                self.files
                    .retain(|p, _| !p.starts_with(&format!("/sys/class/net/{dev}/")));
            }
            // Same reason, for `ip rule`: `drop_rules` loops on `ip rule show pref <pref>`
            // until the needle is gone, so a mock that keeps answering "still there" forever
            // would hang any test of the present-then-deleted case rather than fail it. Only
            // the deleted rule's own line is dropped from the stub (never the whole `show`
            // rule), so a pref stubbed with several rules on one line each survives a single
            // delete with the others intact.
            if let ["ip", "rule", "del", "pref", pref, tail @ ..] = argv {
                let selector = tail.join(" ");
                for (prefix, out) in &mut self.cmd_rules {
                    if prefix.as_slice() == ["ip", "rule", "show", "pref", pref] {
                        out.stdout = out
                            .stdout
                            .lines()
                            .filter(|l| !l.contains(&selector))
                            .map(|l| format!("{l}\n"))
                            .collect();
                    }
                }
            }
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
            self.writes.push((path.to_string(), content.to_string()));
            if self.write_fails.iter().any(|p| p == path) {
                return Err(Error::fatal(format!(
                    "cannot write {path}: permission denied"
                )));
            }
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
                .chain(self.links.keys())
                .filter_map(|k| k.strip_prefix(&prefix))
                .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
                .collect();
            names.sort();
            names.dedup();
            Ok(names)
        }

        fn read_link(&self, path: &str) -> Result<String> {
            self.links
                .get(path)
                .cloned()
                .ok_or_else(|| Error::fatal(format!("mock: no link {path}")))
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
            let due: Vec<(String, String)> = self
                .appear_after
                .iter()
                .filter(|(at, _, _)| *at == n)
                .map(|(_, p, c)| (p.clone(), c.clone()))
                .collect();
            for (p, c) in due {
                self.files.insert(p, c);
            }
            if let Some(hook) = &mut self.on_sleep {
                hook(n);
            }
        }

        fn unix_request(&mut self, path: &str, line: &str) -> Result<String> {
            self.calls
                .push(format!("unix_request {path} {}", line.trim_end()));
            let verb = line.split_whitespace().next().unwrap_or("");
            self.socket_reply(path, verb)
                .ok_or_else(|| Error::fatal(format!("mock: no socket {path}")))
        }

        fn unix_probe(&mut self, path: &str, line: &str) -> UnixProbe {
            self.calls
                .push(format!("unix_probe {path} {}", line.trim_end()));
            if self.unreachable_sockets.iter().any(|p| p == path) {
                return UnixProbe::Unreachable(format!("{path}: connected, no reply (mock)"));
            }
            let verb = line.split_whitespace().next().unwrap_or("");
            // A registered socket (verb-keyed or path-level) answers; an unregistered one models
            // ENOENT/ECONNREFUSED.
            match self.socket_reply(path, verb) {
                Some(reply) => UnixProbe::Answered(reply),
                None => UnixProbe::NotListening,
            }
        }
    }

    impl MockSys {
        /// The next reply for `(path, verb)`: a verb-keyed queue if one is registered, else the
        /// path-level queue. Either pops when more than one remains, so the last reply repeats.
        /// `None` means the path is not registered at all.
        fn socket_reply(&mut self, path: &str, verb: &str) -> Option<String> {
            let key = (path.to_string(), verb.to_string());
            let q = match self.socket_verbs.get_mut(&key) {
                Some(q) => q,
                None => self.sockets.get_mut(path)?,
            };
            if q.len() > 1 {
                Some(q.pop_front().expect("len > 1"))
            } else {
                Some(q.front().cloned().unwrap_or_default())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    use super::mock::MockSys;
    use super::{RealSys, Sys};

    #[test]
    fn mock_socket_replies_or_fails_loud() {
        let mut sys = MockSys::default().socket("/run/cfab/engine.sock", "{\"ready\":true}\n");
        assert_eq!(
            sys.unix_request("/run/cfab/engine.sock", "state\n")
                .unwrap(),
            "{\"ready\":true}\n"
        );
        assert!(sys.ran("unix_request /run/cfab/engine.sock state"));
        let err = sys
            .unix_request("/run/cfab/other.sock", "state\n")
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("mock: no socket /run/cfab/other.sock")
        );
    }

    /// `ip rule del pref <pref> <selector>` drops only the stubbed line naming that selector —
    /// a pref stubbed with several rules survives a single delete with the others intact,
    /// which is what lets a `drop_rules` test converge instead of hanging (a static stub that
    /// never changes loops forever) without losing the other rules at the same pref.
    #[test]
    fn deleting_one_rule_at_a_pref_leaves_the_others_stubbed() {
        let mut sys = MockSys::default().on_stdout(
            &["ip", "rule", "show", "pref", "2000"],
            "2000:\tfrom 10.99.0.0/16 to 10.99.0.0/16 lookup main\n\
             2000:\tfrom 10.99.0.0/16 to 192.168.20.0/24 lookup main\n",
        );
        sys.run(&[
            "ip",
            "rule",
            "del",
            "pref",
            "2000",
            "from",
            "10.99.0.0/16",
            "to",
            "192.168.20.0/24",
            "lookup",
            "main",
        ])
        .unwrap();
        let shown = sys.run(&["ip", "rule", "show", "pref", "2000"]).unwrap();
        assert!(
            !shown.stdout.contains("192.168.20.0/24"),
            "{}",
            shown.stdout
        );
        assert!(
            shown.stdout.contains("to 10.99.0.0/16 lookup main"),
            "the other rule at this pref must survive: {}",
            shown.stdout
        );
    }

    #[test]
    fn real_unix_request_round_trips_one_line() {
        let dir = std::env::temp_dir().join(format!("cfab-sys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engine.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut stream = reader.into_inner();
            stream.write_all(format!("got {line}").as_bytes()).unwrap();
            // Return drops the stream: EOF is the reply terminator.
        });
        let reply = RealSys::default()
            .unix_request(path.to_str().unwrap(), "state\n")
            .unwrap();
        server.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(reply, "got state\n");
    }

    #[test]
    fn the_mock_records_every_write_in_order_with_its_content() {
        let mut sys = MockSys::default();
        sys.write("/proc/sys/net/ipv4/conf/all/arp_ignore", "1").unwrap();
        sys.write("/proc/sys/net/ipv4/conf/eth0/forwarding", "0").unwrap();
        sys.write("/proc/sys/net/ipv4/conf/all/arp_ignore", "0").unwrap();
        assert_eq!(sys.writes_of("/proc/sys/net/ipv4/conf/all/arp_ignore"), vec!["1", "0"]);
        assert_eq!(sys.writes_of("/proc/sys/net/ipv4/conf/eth0/forwarding"), vec!["0"]);
        assert!(sys.writes_of("/proc/sys/net/ipv4/conf/eth0/rp_filter").is_empty());
        assert_eq!(sys.writes_to("/proc/sys/net/ipv4/conf/all/arp_ignore"), Some("0"), "writes_to keeps its last-value meaning");
    }

    #[test]
    fn real_unix_request_missing_socket_names_path() {
        let err = RealSys::default()
            .unix_request("/nonexistent/cfab/engine.sock", "state\n")
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot connect to /nonexistent/cfab/engine.sock")
        );
    }
}
