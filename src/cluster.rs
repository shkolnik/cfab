//! pmxcfs coordination: probe, quorum, atomic publish, cluster lock, generation counter.
//!
//! Additive layer over Proxmox's cluster filesystem (`/etc/pve`) — never a core dependency:
//! when pmxcfs is absent or in local mode, callers get `None` from the probe and behave exactly
//! as on a single host. Facts this module encodes (all live-verified against a real three-node
//! pmxcfs): `rename` is a single
//! totally-ordered cluster message (the atomic publish primitive); `mkdir` is the atomic
//! cluster lock, with 120 s crash-expiry ONLY under the literal path `priv/lock/`; quorum is
//! the owner-write bit on `/etc/pve/local`; files are capped at 1 MiB.
//!
//! Filesystem access is direct `std::fs` against a root path (a tempdir in tests); the one
//! external command (the stale-lock unlock request) goes through `Sys`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::sys::{Sys, run_ignore};

/// pmxcfs refuses larger files (`MEMDB_MAX_FILE_SIZE` = 1 MiB).
pub const MAX_FILE_SIZE: usize = 1024 * 1024;

/// pmxcfs expires a `priv/lock/` mkdir-lock this long after its mtime — but only when a caller
/// requests it (utime(0,0) on the dir); expiry is not automatic.
pub const LOCK_EXPIRY: Duration = Duration::from_secs(120);

/// Total acquisition budget, matching Proxmox's own `cfs_lock` retry window.
const LOCK_RETRY_ATTEMPTS: u32 = 10;
const LOCK_RETRY_PAUSE: Duration = Duration::from_secs(1);

/// Parsed `/etc/pve/.members`. `cluster` is absent when pmxcfs runs in local mode (single
/// node / `-l`): that means NOT clustered — coordination disabled.
#[derive(Debug, Clone, Deserialize)]
pub struct Members {
    pub nodename: String,
    pub version: u64,
    pub cluster: Option<ClusterInfo>,
    #[serde(default)]
    pub nodelist: BTreeMap<String, Node>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClusterInfo {
    pub name: String,
    pub version: u64,
    pub nodes: u64,
    #[serde(deserialize_with = "int_bool")]
    pub quorate: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    pub id: u64,
    #[serde(deserialize_with = "int_bool")]
    pub online: bool,
    pub ip: Option<String>,
}

/// pmxcfs writes 0/1 where a boolean is meant.
fn int_bool<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<bool, D::Error> {
    Ok(u8::deserialize(d)? != 0)
}

/// Parse the `.members` JSON; a file that exists but does not parse is a fault, not "absent".
pub fn parse_members(json: &str, path: &Path) -> Result<Members> {
    serde_json::from_str(json).map_err(|e| {
        Error::fatal(format!(
            "{} is not valid pmxcfs member JSON ({e}); is /etc/pve a healthy pmxcfs mount?",
            path.display()
        ))
    })
}

/// Parse the generation counter (decimal u64 text; caller maps an absent file to 0).
pub fn parse_gen(text: &str, path: &Path) -> Result<u64> {
    text.trim().parse().map_err(|_| {
        Error::fatal(format!(
            "{} does not hold a decimal generation counter (got {:?}); \
             remove it to restart at 0 or fix it by hand",
            path.display(),
            text.trim()
        ))
    })
}

pub fn format_gen(generation: u64) -> String {
    format!("{generation}\n")
}

/// A lock whose mtime is older than the 120 s expiry may be reclaimed (after the unlock
/// request); a younger one is held.
pub fn lock_is_stale(age: Duration) -> bool {
    age > LOCK_EXPIRY
}

/// The 1 MiB pmxcfs per-file cap, checked before any write.
pub fn check_size(len: usize, what: &str) -> Result<()> {
    if len > MAX_FILE_SIZE {
        return Err(Error::fatal(format!(
            "{what} is {len} bytes — over the pmxcfs 1 MiB per-file limit; \
             it cannot be published (shrink it)"
        )));
    }
    Ok(())
}

/// Handle on a pmxcfs mount (or a tempdir standing in for one in tests).
pub struct Pmxcfs {
    root: PathBuf,
}

/// A held cluster lock. Release is explicit — no Drop magic, so an unreleased lock is a
/// visible bug (and expires cluster-wide after 120 s anyway).
#[derive(Debug)]
pub struct LockGuard {
    path: PathBuf,
}

impl Default for Pmxcfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Pmxcfs {
    pub fn new() -> Self {
        Self::at("/etc/pve")
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Pmxcfs { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // Layout under the mount.
    pub fn members_path(&self) -> PathBuf {
        self.root.join(".members")
    }
    pub fn cfab_dir(&self) -> PathBuf {
        self.root.join("cfab")
    }
    pub fn conf_path(&self) -> PathBuf {
        self.cfab_dir().join("fabric.conf")
    }
    pub fn gen_path(&self) -> PathBuf {
        self.cfab_dir().join("gen")
    }
    pub fn acks_dir(&self, generation: u64) -> PathBuf {
        self.cfab_dir().join("acks").join(generation.to_string())
    }
    pub fn ack_path(&self, generation: u64, member: &str) -> PathBuf {
        self.acks_dir(generation).join(member)
    }
    pub fn caps_dir(&self) -> PathBuf {
        self.cfab_dir().join("caps")
    }
    pub fn member_caps_dir(&self, member: &str) -> PathBuf {
        self.caps_dir().join(member)
    }
    pub fn cap_path(&self, member: &str, dev: &str) -> PathBuf {
        self.member_caps_dir(member).join(format!("cap-{dev}"))
    }
    fn lock_path(&self, name: &str) -> PathBuf {
        self.root.join("priv/lock").join(format!("cfab-{name}"))
    }

    /// Is pmxcfs mounted here, and what does it say? `None` = no `.members` = no pmxcfs.
    /// A parsed result with `cluster: None` is pmxcfs in local mode — also not clustered.
    pub fn probe(&self) -> Result<Option<Members>> {
        let path = self.members_path();
        match std::fs::read_to_string(&path) {
            Ok(json) => Ok(Some(parse_members(&json, &path)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::fatal(format!("cannot read {}: {e}", path.display()))),
        }
    }

    /// The cheap quorum probe: owner-write bit, from the mode flip pmxcfs applies to every
    /// directory with quorum (0777/0555; one RAM-served getattr). Proxmox stats `local`, but
    /// that is a symlink to `nodes/<name>`, which only PVE tooling creates — dangling on a
    /// bare cluster (live-verified) — so we stat the mount root, which always exists.
    pub fn quorate(&self) -> Result<bool> {
        use std::os::unix::fs::PermissionsExt;
        let path = self.root.clone();
        let meta = std::fs::metadata(&path).map_err(|e| {
            Error::fatal(format!(
                "cannot stat {} for the quorum probe: {e}; is pmxcfs mounted?",
                path.display()
            ))
        })?;
        Ok(meta.permissions().mode() & 0o200 != 0)
    }

    /// Atomic cluster-wide publish: write `<dir>/.<name>.tmp`, then rename over the target
    /// (rename is one totally-ordered cluster message). Size-guarded.
    pub fn publish(&self, target: &Path, content: &str) -> Result<()> {
        check_size(content.len(), &target.display().to_string())?;
        let dir = target
            .parent()
            .ok_or_else(|| Error::fatal(format!("{} has no parent directory", target.display())))?;
        let name = target
            .file_name()
            .ok_or_else(|| Error::fatal(format!("{} has no file name", target.display())))?
            .to_string_lossy();
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, content).map_err(|e| {
            Error::fatal(format!(
                "cannot write {}: {e}; non-quorate pmxcfs refuses writes (EACCES) — check quorum",
                tmp.display()
            ))
        })?;
        std::fs::rename(&tmp, target).map_err(|e| {
            Error::fatal(format!(
                "cannot rename {} over {}: {e}",
                tmp.display(),
                target.display()
            ))
        })
    }

    /// Current generation; an absent counter is generation 0.
    pub fn read_gen(&self) -> Result<u64> {
        let path = self.gen_path();
        match std::fs::read_to_string(&path) {
            Ok(text) => parse_gen(&text, &path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(Error::fatal(format!("cannot read {}: {e}", path.display()))),
        }
    }

    pub fn write_gen(&self, generation: u64) -> Result<()> {
        self.publish(&self.gen_path(), &format_gen(generation))
    }

    /// Acquire the cluster lock `cfab-<name>` (mkdir under `priv/lock/`, the only path where
    /// pmxcfs applies its 120 s crash-expiry). Held elsewhere = EEXIST; a stale lock (mtime
    /// older than 120 s) gets the unlock request, then a retry. Bounded at ~10 s total, like
    /// Proxmox's cfs_lock.
    pub fn lock(&self, sys: &mut dyn Sys, name: &str) -> Result<LockGuard> {
        let parent = self.root.join("priv/lock");
        // priv/lock is absent on a bare cluster (PVE tooling normally creates it).
        std::fs::create_dir_all(&parent)
            .map_err(|e| Error::fatal(format!("cannot create {}: {e}", parent.display())))?;
        let path = self.lock_path(name);
        for attempt in 0..LOCK_RETRY_ATTEMPTS {
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(LockGuard { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if self.lock_age(&path).is_some_and(lock_is_stale) {
                        // Stale: request the unlock by setting the dir's times to epoch 0.
                        // Verified quirk: pmxcfs returns EPERM for this utime yet honors it as
                        // the unlock request — ignore the exit status and retry the mkdir.
                        run_ignore(sys, &["touch", "-d", "@0", &path.to_string_lossy()])?;
                    }
                    if attempt + 1 < LOCK_RETRY_ATTEMPTS {
                        sys.sleep(LOCK_RETRY_PAUSE);
                    }
                }
                Err(e) => {
                    return Err(Error::fatal(format!(
                        "cannot acquire cluster lock {}: {e}; \
                         non-quorate pmxcfs refuses writes — check quorum",
                        path.display()
                    )));
                }
            }
        }
        Err(Error::fatal(format!(
            "cluster lock {} still held after ~10 s of retries; \
             if the holder crashed it expires 120 s after the lock's mtime — retry then",
            path.display()
        )))
    }

    /// Age of an existing lock dir; `None` when it vanished mid-look (a racing release) or
    /// its mtime is in the future.
    fn lock_age(&self, path: &Path) -> Option<Duration> {
        let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
        SystemTime::now().duration_since(mtime).ok()
    }
}

impl LockGuard {
    /// Release the lock (rmdir). Failure names the path: a wedged release leaves the lock to
    /// the 120 s expiry, which the message says.
    pub fn release(self) -> Result<()> {
        std::fs::remove_dir(&self.path).map_err(|e| {
            Error::fatal(format!(
                "cannot release cluster lock {}: {e}; it expires cluster-wide 120 s after \
                 its mtime",
                self.path.display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTERED: &str = r#"{
      "nodename": "pve1-tb", "version": 7,
      "cluster": {"name": "cfab-test", "version": 3, "nodes": 3, "quorate": 1},
      "nodelist": {
        "pve1-tb": {"id": 1, "online": 1, "ip": "10.249.0.1"},
        "pve2-tb": {"id": 2, "online": 1, "ip": "10.249.0.2"},
        "pve3-tb": {"id": 3, "online": 0}
      }
    }"#;

    #[test]
    fn members_clustered_parses() {
        let m = parse_members(CLUSTERED, Path::new("/etc/pve/.members")).unwrap();
        assert_eq!(m.nodename, "pve1-tb");
        let c = m.cluster.as_ref().unwrap();
        assert_eq!(
            (c.name.as_str(), c.nodes, c.quorate),
            ("cfab-test", 3, true)
        );
        assert_eq!(m.nodelist.len(), 3);
        assert!(m.nodelist["pve2-tb"].online);
        assert!(!m.nodelist["pve3-tb"].online);
        assert_eq!(m.nodelist["pve3-tb"].ip, None);
    }

    #[test]
    fn members_standalone_has_no_cluster() {
        let m = parse_members(
            r#"{"nodename": "solo", "version": 1}"#,
            Path::new("/etc/pve/.members"),
        )
        .unwrap();
        assert!(m.cluster.is_none());
        assert!(m.nodelist.is_empty());
    }

    #[test]
    fn members_garbage_is_a_loud_error() {
        let err = parse_members("not json", Path::new("/etc/pve/.members")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/etc/pve/.members"), "{msg}");
        assert!(msg.contains("pmxcfs"), "{msg}");
    }

    #[test]
    fn gen_parse_bump_roundtrip() {
        let p = Path::new("/etc/pve/cfab/gen");
        assert_eq!(parse_gen("0\n", p).unwrap(), 0);
        assert_eq!(parse_gen(" 41 ", p).unwrap(), 41);
        let bumped = parse_gen("41", p).unwrap() + 1;
        assert_eq!(parse_gen(&format_gen(bumped), p).unwrap(), 42);
        let err = parse_gen("banana", p).unwrap_err().to_string();
        assert!(err.contains("/etc/pve/cfab/gen"), "{err}");
        assert!(err.contains("banana"), "{err}");
    }

    #[test]
    fn stale_lock_boundary() {
        assert!(!lock_is_stale(Duration::from_secs(119)));
        assert!(lock_is_stale(Duration::from_secs(121)));
    }

    #[test]
    fn size_guard() {
        check_size(MAX_FILE_SIZE, "x").unwrap();
        let err = check_size(MAX_FILE_SIZE + 1, "fabric.conf")
            .unwrap_err()
            .to_string();
        assert!(err.contains("1 MiB"), "{err}");
        assert!(err.contains("fabric.conf"), "{err}");
    }

    #[test]
    fn path_helpers() {
        let p = Pmxcfs::at("/etc/pve");
        assert_eq!(p.conf_path(), Path::new("/etc/pve/cfab/fabric.conf"));
        assert_eq!(p.gen_path(), Path::new("/etc/pve/cfab/gen"));
        assert_eq!(
            p.ack_path(7, "pve2-tb"),
            Path::new("/etc/pve/cfab/acks/7/pve2-tb")
        );
        assert_eq!(
            p.cap_path("pve2-tb", "eth9"),
            Path::new("/etc/pve/cfab/caps/pve2-tb/cap-eth9")
        );
    }

    #[test]
    fn probe_absent_is_none_and_gen_absent_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let p = Pmxcfs::at(dir.path());
        assert!(p.probe().unwrap().is_none());
        assert_eq!(p.read_gen().unwrap(), 0);
    }

    #[test]
    fn publish_writes_tmp_then_renames() {
        let dir = tempfile::tempdir().unwrap();
        let p = Pmxcfs::at(dir.path());
        std::fs::create_dir_all(p.cfab_dir()).unwrap();
        p.publish(&p.conf_path(), "A=1\n").unwrap();
        assert_eq!(std::fs::read_to_string(p.conf_path()).unwrap(), "A=1\n");
        assert!(!dir.path().join("cfab/.fabric.conf.tmp").exists());
        p.write_gen(5).unwrap();
        assert_eq!(p.read_gen().unwrap(), 5);
    }

    #[test]
    fn lock_acquire_conflict_release() {
        let dir = tempfile::tempdir().unwrap();
        let p = Pmxcfs::at(dir.path());
        let mut sys = crate::sys::mock::MockSys::default();
        let guard = p.lock(&mut sys, "conf").unwrap();
        assert!(dir.path().join("priv/lock/cfab-conf").is_dir());
        // Held (fresh mtime): a second acquire retries then fails, without touching it.
        let err = p.lock(&mut sys, "conf").unwrap_err().to_string();
        assert!(err.contains("cfab-conf"), "{err}");
        assert!(err.contains("120 s"), "{err}");
        assert!(!sys.ran("touch"));
        assert_eq!(sys.slept.len(), 9);
        guard.release().unwrap();
        assert!(!dir.path().join("priv/lock/cfab-conf").exists());
        p.lock(&mut sys, "conf").unwrap().release().unwrap();
    }

    #[test]
    fn stale_lock_gets_the_unlock_request() {
        let dir = tempfile::tempdir().unwrap();
        let p = Pmxcfs::at(dir.path());
        std::fs::create_dir_all(dir.path().join("priv/lock/cfab-conf")).unwrap();
        // Age the lock past expiry with a real utime (the tempdir honors it; pmxcfs would
        // EPERM but honor the request — that path is exercised live, not here).
        let mut sys = crate::sys::mock::MockSys::default();
        std::process::Command::new("touch")
            .args(["-d", "@100", "--"])
            .arg(dir.path().join("priv/lock/cfab-conf"))
            .status()
            .unwrap();
        let err = p.lock(&mut sys, "conf").unwrap_err();
        // The mock's touch does nothing to the real dir, so acquisition still times out —
        // but the unlock request must have been issued.
        assert!(sys.ran("touch -d @0"), "calls: {:?}", sys.calls);
        assert!(err.to_string().contains("cfab-conf"));
    }
}
