//! The measured-cap chain, shared by every shape-derivation reader (gen shape, verify,
//! shape-daemon): local cap file → cluster-published cap (pmxcfs, written back locally) →
//! `None` (the declared rate). The local file stays the single source at derivation time: a
//! cluster cap is cached back to it on first use, so the host is self-sufficient afterward
//! and the fallback message does not repeat.

use crate::cluster::Pmxcfs;
use crate::sys::Sys;

/// The directory holding `cap-<dev>` files: `$CFAB_CAP_DIR`, else the declaration's run dir.
pub fn cap_dir(run_dir: &str) -> String {
    std::env::var("CFAB_CAP_DIR").unwrap_or_else(|_| run_dir.to_string())
}

/// The cap the shape derivation prefers over the declared link speed, or `None` for the
/// declared rate. Local file first (a present-but-garbage local file is `None` — the cluster
/// is only consulted when the local file is ABSENT); then, when clustered, this member's own
/// published cap under `/etc/pve/cfab/caps/`.
pub fn read_cap(
    sys: &mut dyn Sys,
    pmx: &Pmxcfs,
    member: &str,
    run_dir: &str,
    dev: &str,
) -> Option<u64> {
    let dir = cap_dir(run_dir);
    let local = format!("{dir}/cap-{dev}");
    if let Ok(text) = sys.read(&local) {
        return text.trim().parse().ok().filter(|v: &u64| *v > 0);
    }
    match pmx.probe() {
        Ok(Some(m)) if m.cluster.is_some() => {}
        Ok(_) => return None, // no pmxcfs, or local mode — not clustered
        Err(e) => {
            eprintln!("cfab: warning: cap cluster fallback unavailable: {e}");
            return None;
        }
    }
    let cluster_path = pmx.cap_path(member, dev);
    let text = std::fs::read_to_string(&cluster_path).ok()?;
    let Some(v) = text.trim().parse::<u64>().ok().filter(|v| *v > 0) else {
        eprintln!(
            "cfab: warning: cluster cap {} does not hold a positive integer (got {:?}); \
             ignoring it — the declared rate applies",
            cluster_path.display(),
            text.trim()
        );
        return None;
    };
    // Write back so the host is self-sufficient (run_dir is typically tmpfs — the published
    // cap survives a reboot when the local file does not) and the message fires once.
    let cached = sys
        .mkdir_p(&dir)
        .and_then(|()| sys.write(&local, &format!("{v}\n")));
    match cached {
        Ok(()) => eprintln!(
            "cfab: using cluster-published cap for {dev}: {v} Mbit/s (from {}; cached to {local})",
            cluster_path.display()
        ),
        Err(e) => eprintln!(
            "cfab: using cluster-published cap for {dev}: {v} Mbit/s (from {}); \
             warning: cannot cache it to {local}: {e}",
            cluster_path.display()
        ),
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    const CLUSTERED: &str = r#"{
      "nodename": "pve1-tb", "version": 7,
      "cluster": {"name": "cfab-test", "version": 3, "nodes": 3, "quorate": 1},
      "nodelist": {"pve1-tb": {"id": 1, "online": 1, "ip": "10.249.0.1"}}
    }"#;

    fn clustered_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".members"), CLUSTERED).unwrap();
        dir
    }

    fn publish_cap(pmx: &Pmxcfs, member: &str, dev: &str, content: &str) {
        std::fs::create_dir_all(pmx.member_caps_dir(member)).unwrap();
        std::fs::write(pmx.cap_path(member, dev), content).unwrap();
    }

    #[test]
    fn local_cap_wins_over_cluster() {
        let dir = clustered_root();
        let pmx = Pmxcfs::at(dir.path());
        publish_cap(&pmx, "pve1-tb", "eth9", "9999\n");
        let mut sys = MockSys::default().file("/run/cfab/cap-eth9", "4805\n");
        let v = read_cap(&mut sys, &pmx, "pve1-tb", "/run/cfab", "eth9");
        assert_eq!(v, Some(4805));
        // Local was authoritative — nothing written back.
        assert_eq!(sys.writes_to("/run/cfab/cap-eth9"), Some("4805\n"));
        assert!(!sys.ran("write /run/cfab/cap-eth9"));
    }

    #[test]
    fn cluster_cap_used_when_local_absent_and_written_back() {
        let dir = clustered_root();
        let pmx = Pmxcfs::at(dir.path());
        publish_cap(&pmx, "pve1-tb", "eth9", "4805\n");
        let mut sys = MockSys::default();
        let v = read_cap(&mut sys, &pmx, "pve1-tb", "/run/cfab", "eth9");
        assert_eq!(v, Some(4805));
        assert_eq!(sys.writes_to("/run/cfab/cap-eth9"), Some("4805\n"));
    }

    #[test]
    fn garbage_cluster_cap_is_ignored_and_not_cached() {
        let dir = clustered_root();
        let pmx = Pmxcfs::at(dir.path());
        publish_cap(&pmx, "pve1-tb", "eth9", "banana\n");
        let mut sys = MockSys::default();
        assert_eq!(
            read_cap(&mut sys, &pmx, "pve1-tb", "/run/cfab", "eth9"),
            None
        );
        assert_eq!(sys.writes_to("/run/cfab/cap-eth9"), None);
        // Zero is not a positive cap either.
        publish_cap(&pmx, "pve1-tb", "eth9", "0\n");
        assert_eq!(
            read_cap(&mut sys, &pmx, "pve1-tb", "/run/cfab", "eth9"),
            None
        );
    }

    #[test]
    fn not_clustered_means_no_fallback() {
        let dir = tempfile::tempdir().unwrap(); // no .members
        let pmx = Pmxcfs::at(dir.path());
        // A cap file planted where the cluster path would be must NOT be consulted.
        publish_cap(&pmx, "pve1-tb", "eth9", "4805\n");
        let mut sys = MockSys::default();
        assert_eq!(
            read_cap(&mut sys, &pmx, "pve1-tb", "/run/cfab", "eth9"),
            None
        );
        assert_eq!(sys.writes_to("/run/cfab/cap-eth9"), None);
    }

    #[test]
    fn garbage_local_cap_is_none_without_cluster_consult() {
        let dir = clustered_root();
        let pmx = Pmxcfs::at(dir.path());
        publish_cap(&pmx, "pve1-tb", "eth9", "4805\n");
        let mut sys = MockSys::default().file("/run/cfab/cap-eth9", "garbage\n");
        // Present-but-garbage local = declared rate; the cluster is not consulted.
        assert_eq!(
            read_cap(&mut sys, &pmx, "pve1-tb", "/run/cfab", "eth9"),
            None
        );
    }
}
