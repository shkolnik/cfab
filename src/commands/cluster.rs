//! `cfab cluster status` and `cfab conf publish` — the human surface of the pmxcfs
//! coordination layer. Not clustered is a clean report, never an error, for `status`;
//! `publish` refuses loudly (there is nothing to coordinate).

use crate::cluster::{Members, Pmxcfs};
use crate::error::{Error, Result};
use crate::sys::Sys;

/// What `status` reports about the published conf (gen, size, first line). No hashing
/// dependency exists in this crate, so gen + byte length + first line stand in for a digest.
pub struct ConfState {
    pub generation: u64,
    pub bytes: usize,
    pub first_line: String,
}

pub fn status(pmx: &Pmxcfs) -> Result<String> {
    let members = match pmx.probe()? {
        None => {
            return Ok(not_clustered(&format!(
                "{} is not a pmxcfs mount (no .members)",
                pmx.root().display()
            )));
        }
        Some(m) if m.cluster.is_none() => {
            return Ok(not_clustered("pmxcfs is in local mode (single node)"));
        }
        Some(m) => m,
    };
    let quorate = pmx.quorate()?;
    let conf = match std::fs::read(pmx.conf_path()) {
        Ok(bytes) => Some(ConfState {
            generation: pmx.read_gen()?,
            bytes: bytes.len(),
            first_line: String::from_utf8_lossy(&bytes)
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(Error::fatal(format!(
                "cannot read {}: {e}",
                pmx.conf_path().display()
            )));
        }
    };
    Ok(render_status(
        &members,
        quorate,
        conf.as_ref(),
        &read_caps(pmx),
    ))
}

/// Published measured caps under `cfab/caps/`: one `(member, [(file, value)])` per member dir,
/// sorted. Best-effort report data: unreadable entries are simply absent.
fn read_caps(pmx: &Pmxcfs) -> Vec<(String, Vec<(String, String)>)> {
    let Ok(members) = std::fs::read_dir(pmx.caps_dir()) else {
        return Vec::new(); // no caps dir → "published caps: none"
    };
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for m in members.filter_map(|e| e.ok()) {
        let member = m.file_name().to_string_lossy().into_owned();
        let Ok(files) = std::fs::read_dir(m.path()) else {
            continue;
        };
        let mut caps: Vec<(String, String)> = files
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let value = std::fs::read_to_string(e.path()).ok()?.trim().to_string();
                Some((name, value))
            })
            .collect();
        caps.sort();
        out.push((member, caps));
    }
    out.sort();
    out
}

fn not_clustered(reason: &str) -> String {
    format!("not clustered: {reason}; coordination disabled, local fabric.conf only\n")
}

/// Pure rendering, unit-testable without a filesystem.
pub fn render_status(
    members: &Members,
    quorate: bool,
    conf: Option<&ConfState>,
    caps: &[(String, Vec<(String, String)>)],
) -> String {
    let mut out = String::new();
    let c = members
        .cluster
        .as_ref()
        .expect("render_status is only called when clustered");
    out.push_str(&format!(
        "cluster {}: this node {}, quorate {}\n",
        c.name,
        members.nodename,
        if quorate {
            "yes"
        } else {
            "no (pmxcfs read-only, reads may be stale)"
        }
    ));
    out.push_str(&format!("members ({} declared):\n", c.nodes));
    for (name, node) in &members.nodelist {
        out.push_str(&format!(
            "  {name}  id {}  {}{}\n",
            node.id,
            if node.online { "online" } else { "OFFLINE" },
            node.ip
                .as_deref()
                .map(|ip| format!("  {ip}"))
                .unwrap_or_default()
        ));
    }
    match conf {
        Some(c) => out.push_str(&format!(
            "published fabric.conf: gen {} ({} bytes) — first line: {}\n",
            c.generation, c.bytes, c.first_line
        )),
        None => out.push_str("published fabric.conf: none\n"),
    }
    if caps.is_empty() {
        out.push_str("published caps: none\n");
    } else {
        out.push_str("published caps:\n");
        for (member, entries) in caps {
            let line: Vec<String> = entries
                .iter()
                .map(|(file, value)| format!("{file} {value}"))
                .collect();
            out.push_str(&format!("  {member}: {}\n", line.join("  ")));
        }
    }
    out
}

/// Publish the (already fully validated) local fabric.conf cluster-wide: require clustered +
/// quorate, take the `cfab-conf` lock, temp+rename the conf, bump the generation, release.
pub fn publish(sys: &mut dyn Sys, pmx: &Pmxcfs, conf_text: &str) -> Result<String> {
    match pmx.probe()? {
        None => {
            return Err(Error::fatal(format!(
                "refusing to publish: {} is not a pmxcfs mount (no .members); \
                 not clustered — the local fabric.conf is already the only one",
                pmx.root().display()
            )));
        }
        Some(m) if m.cluster.is_none() => {
            return Err(Error::fatal(
                "refusing to publish: pmxcfs is in local mode (single node); \
                 not clustered — the local fabric.conf is already the only one",
            ));
        }
        Some(_) => {}
    }
    if !pmx.quorate()? {
        return Err(Error::fatal(
            "refusing to publish: pmxcfs is not quorate (writes fail EACCES, members may be \
             partitioned); restore quorum first",
        ));
    }
    std::fs::create_dir_all(pmx.cfab_dir())
        .map_err(|e| Error::fatal(format!("cannot create {}: {e}", pmx.cfab_dir().display())))?;
    let lock = pmx.lock(sys, "conf")?;
    let published = (|| -> Result<u64> {
        let generation = pmx.read_gen()? + 1;
        pmx.publish(&pmx.conf_path(), conf_text)?;
        pmx.write_gen(generation)?;
        Ok(generation)
    })();
    // Release even when the critical section failed; report the section's error first.
    let released = lock.release();
    let generation = published?;
    released?;
    clean_old_acks(pmx, generation);
    Ok(format!(
        "published fabric.conf gen {generation} ({} bytes) to {}/\n",
        conf_text.len(),
        pmx.cfab_dir().display()
    ))
}

/// Ack dirs from before the previous generation are garbage after a publish: remove
/// `acks/<g>` for g < N-1 (N-1 stays — a slow member may still be mid-protocol on it).
/// Best-effort: a cleanup failure warns but never fails the publish, which is already
/// visible cluster-wide. Non-numeric names are not ours and are left alone.
fn clean_old_acks(pmx: &Pmxcfs, generation: u64) {
    let Ok(entries) = std::fs::read_dir(pmx.cfab_dir().join("acks")) else {
        return; // no acks dir yet — nothing to clean
    };
    for e in entries.filter_map(|e| e.ok()) {
        let Ok(g) = e.file_name().to_string_lossy().parse::<u64>() else {
            continue;
        };
        if g + 1 < generation
            && let Err(err) = std::fs::remove_dir_all(e.path())
            && err.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "cfab: warning: cannot remove old ack dir {}: {err}",
                e.path().display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    const CLUSTERED: &str = r#"{
      "nodename": "pve1-tb", "version": 7,
      "cluster": {"name": "cfab-test", "version": 3, "nodes": 3, "quorate": 1},
      "nodelist": {
        "pve1-tb": {"id": 1, "online": 1, "ip": "10.249.0.1"},
        "pve3-tb": {"id": 3, "online": 0}
      }
    }"#;

    fn clustered_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".members"), CLUSTERED).unwrap();
        // The tempdir root carries the owner-write bit = the quorate probe's yes.
        dir
    }

    #[test]
    fn status_no_pmxcfs_is_clean_not_clustered() {
        let dir = tempfile::tempdir().unwrap();
        let out = status(&Pmxcfs::at(dir.path())).unwrap();
        assert!(out.starts_with("not clustered:"), "{out}");
        assert!(out.contains("coordination disabled"), "{out}");
    }

    #[test]
    fn status_standalone_is_clean_not_clustered() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".members"),
            r#"{"nodename": "solo", "version": 1}"#,
        )
        .unwrap();
        let out = status(&Pmxcfs::at(dir.path())).unwrap();
        assert!(
            out.contains("not clustered: pmxcfs is in local mode"),
            "{out}"
        );
    }

    #[test]
    fn status_clustered_reports_members_and_conf() {
        let dir = clustered_root();
        let pmx = Pmxcfs::at(dir.path());
        std::fs::create_dir_all(pmx.cfab_dir()).unwrap();
        std::fs::write(pmx.conf_path(), "ZONE_TABLE=\"x\"\nmore\n").unwrap();
        std::fs::write(pmx.gen_path(), "4\n").unwrap();
        let out = status(&pmx).unwrap();
        assert!(
            out.contains("cluster cfab-test: this node pve1-tb, quorate yes"),
            "{out}"
        );
        assert!(out.contains("pve1-tb  id 1  online  10.249.0.1"), "{out}");
        assert!(out.contains("pve3-tb  id 3  OFFLINE"), "{out}");
        assert!(
            out.contains("gen 4 (20 bytes) — first line: ZONE_TABLE=\"x\""),
            "{out}"
        );
    }

    #[test]
    fn status_clustered_without_published_conf() {
        let dir = clustered_root();
        let out = status(&Pmxcfs::at(dir.path())).unwrap();
        assert!(out.contains("published fabric.conf: none"), "{out}");
        assert!(out.contains("published caps: none"), "{out}");
    }

    #[test]
    fn status_lists_published_caps_per_member() {
        let dir = clustered_root();
        let pmx = Pmxcfs::at(dir.path());
        for (member, dev, v) in [
            ("pve1-tb", "eth9", "4805\n"),
            ("pve1-tb", "eth1", "941\n"),
            ("pve2-tb", "eth9", "4779\n"),
        ] {
            std::fs::create_dir_all(pmx.member_caps_dir(member)).unwrap();
            std::fs::write(pmx.cap_path(member, dev), v).unwrap();
        }
        let out = status(&pmx).unwrap();
        assert!(out.contains("published caps:\n"), "{out}");
        assert!(
            out.contains("  pve1-tb: cap-eth1 941  cap-eth9 4805\n"),
            "{out}"
        );
        assert!(out.contains("  pve2-tb: cap-eth9 4779\n"), "{out}");
    }

    #[test]
    fn publish_refuses_when_not_clustered() {
        let dir = tempfile::tempdir().unwrap();
        let mut sys = MockSys::default();
        let err = publish(&mut sys, &Pmxcfs::at(dir.path()), "A=1\n").unwrap_err();
        assert!(err.to_string().contains("refusing to publish"), "{err}");
        std::fs::write(
            dir.path().join(".members"),
            r#"{"nodename": "solo", "version": 1}"#,
        )
        .unwrap();
        let err = publish(&mut sys, &Pmxcfs::at(dir.path()), "A=1\n").unwrap_err();
        assert!(err.to_string().contains("local mode"), "{err}");
    }

    #[test]
    fn publish_refuses_when_not_quorate() {
        use std::os::unix::fs::PermissionsExt;
        let dir = clustered_root();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut sys = MockSys::default();
        let err = publish(&mut sys, &Pmxcfs::at(dir.path()), "A=1\n").unwrap_err();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.to_string().contains("not quorate"), "{err}");
    }

    #[test]
    fn publish_refuses_oversize() {
        let dir = clustered_root();
        let mut sys = MockSys::default();
        let big = "x".repeat(crate::cluster::MAX_FILE_SIZE + 1);
        let err = publish(&mut sys, &Pmxcfs::at(dir.path()), &big).unwrap_err();
        assert!(err.to_string().contains("1 MiB"), "{err}");
        // The failed publish must not leave the lock held.
        assert!(!dir.path().join("priv/lock/cfab-conf").exists());
    }

    #[test]
    fn publish_bumps_gen_and_releases_lock() {
        let dir = clustered_root();
        let pmx = Pmxcfs::at(dir.path());
        let mut sys = MockSys::default();
        let out = publish(&mut sys, &pmx, "A=1\n").unwrap();
        assert!(
            out.contains("published fabric.conf gen 1 (4 bytes)"),
            "{out}"
        );
        assert_eq!(std::fs::read_to_string(pmx.conf_path()).unwrap(), "A=1\n");
        assert_eq!(pmx.read_gen().unwrap(), 1);
        assert!(!dir.path().join("priv/lock/cfab-conf").exists());
        let out = publish(&mut sys, &pmx, "A=2\n").unwrap();
        assert!(out.contains("gen 2"), "{out}");
    }

    #[test]
    fn publish_cleans_ack_dirs_older_than_previous_gen() {
        let dir = clustered_root();
        let pmx = Pmxcfs::at(dir.path());
        std::fs::create_dir_all(pmx.cfab_dir()).unwrap();
        std::fs::write(pmx.gen_path(), "4\n").unwrap();
        for g in 1..=4u64 {
            std::fs::create_dir_all(pmx.acks_dir(g)).unwrap();
            std::fs::write(pmx.ack_path(g, "pve1-tb"), "pve1-tb 0\n").unwrap();
        }
        std::fs::create_dir_all(pmx.cfab_dir().join("acks/not-a-gen")).unwrap();
        let mut sys = MockSys::default();
        let out = publish(&mut sys, &pmx, "A=1\n").unwrap();
        assert!(out.contains("gen 5"), "{out}");
        // g < N-1 removed; N-1 kept (a slow member may still be on it); non-numeric left.
        assert!(!pmx.acks_dir(1).exists());
        assert!(!pmx.acks_dir(2).exists());
        assert!(!pmx.acks_dir(3).exists());
        assert!(pmx.acks_dir(4).exists());
        assert!(pmx.cfab_dir().join("acks/not-a-gen").exists());
    }
}
