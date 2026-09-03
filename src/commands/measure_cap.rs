//! `cfab measure-cap <dev> <peer> [secs]` — active calibration: measure achieved throughput to a
//! fabric peer on ONE physical NIC and write the cap file the shape derivation prefers over the
//! declared link_speed table. The UDP flood is built in: N threads, connected sockets, coarse
//! pacing, no self-limit below the qdisc — the pacing target is ABOVE line rate so the wire is
//! the binding constraint.

use std::time::Duration;

use crate::cluster::Pmxcfs;
use crate::derive::View;
use crate::error::{Error, Result};
use crate::sys::Sys;

pub struct FloodSpec {
    pub peer: String,
    pub port: u16,
    pub payload: usize,
    pub secs: u64,
    pub threads: usize,
    pub rate_mbit: u64,
}

pub fn run(
    sys: &mut dyn Sys,
    view: &View,
    pmx: &Pmxcfs,
    dev: &str,
    peer: &str,
    secs: u64,
    flood: &dyn Fn(&FloodSpec) -> Result<()>,
) -> Result<String> {
    let f = view.fabric;
    let mut out = String::new();

    // Prove ownership / fail loud: only measure a dev that is actually a fabric wire.
    let sub_ifs: Vec<String> = view
        .class_rows()
        .into_iter()
        .filter(|r| r.wire == dev)
        .map(|r| r.ifname)
        .collect();
    if sub_ifs.is_empty() {
        return Err(Error::fatal(format!(
            "measure-cap: '{dev}' is not a wire in CLASS_TABLE — refusing to measure"
        )));
    }
    if view.admin_if() == Some(dev) {
        out.push_str(&format!(
            "measure-cap: '{dev}' is the admin NIC (ADMIN_IF): the admin session shares it for the next {secs}s (paced flood)\n"
        ));
    }

    // A shaper anywhere on the egress path bounds the flood and gets recorded as the wire's
    // capacity. Refuse.
    let mut shaped = Vec::new();
    for x in std::iter::once(dev.to_string()).chain(sub_ifs) {
        let q = sys.run(&["tc", "qdisc", "show", "dev", &x])?.stdout;
        let kind = q
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("");
        if matches!(kind, "htb" | "tbf" | "cbq" | "hfsc") {
            shaped.push(x);
        }
    }
    if !shaped.is_empty() {
        return Err(Error::fatal(format!(
            "measure-cap: a shaper is on the egress path of '{dev}' (qdisc root on: {}) — the \
             flood would measure the shaper, not the wire. Remove it first (tc qdisc replace dev \
             <if> root fq_codel) and re-run",
            shaped.join(" ")
        )));
    }

    // Pacing target: ~1.2x THIS host's declared speed, so the offered load saturates the wire
    // without swamping the switch far beyond it.
    let declared = view.link_speed(dev)?;
    let rate = declared as u64 * 12 / 10;

    let statfile = format!("/sys/class/net/{dev}/statistics/tx_bytes");
    let before_bytes: u64 = sys
        .read(&statfile)
        .map_err(|_| {
            Error::fatal(format!(
                "measure-cap: cannot read {statfile} — is '{dev}' a real interface on this host?"
            ))
        })?
        .trim()
        .parse()
        .map_err(|_| Error::fatal(format!("measure-cap: {statfile} is not a number")))?;

    let bfd_count = |sys: &mut dyn Sys| -> Result<Option<usize>> {
        let o = sys.run(&["vtysh", "-c", "show bfd peers brief"])?;
        Ok(o.ok()
            .then(|| o.stdout.lines().filter(|l| l.contains(" up ")).count()))
    };
    if let Some(n) = bfd_count(sys)? {
        out.push_str(&format!(
            "measure-cap: BFD up-count before: {n} (warn-only sanity check)\n"
        ));
    }

    // Measurement lease: one flood at a time cluster-wide (two concurrent floods would measure
    // each other's congestion, not the wires). Not clustered → no lease, run as always. A
    // crashed holder's lease expires cluster-wide 120 s after its mtime (pmxcfs priv/lock/).
    let clustered = pmx.probe()?.is_some_and(|m| m.cluster.is_some());
    let lease = if clustered {
        Some(pmx.lock(sys, "measure").map_err(|e| {
            // The inner error already carries the FATAL prefix; strip it so the user sees
            // one prefix, not a nested pair.
            let inner = e.to_string();
            let inner = inner.strip_prefix("FATAL: ").unwrap_or(&inner);
            Error::fatal(format!(
                "measure-cap: another member is measuring (cluster lease cfab-measure held); \
                 retry shortly — {inner}"
            ))
        })?)
    } else {
        None
    };

    let flooded = flood(&FloodSpec {
        peer: peer.to_string(),
        port: 9999,
        payload: 1400,
        secs,
        threads: 6,
        rate_mbit: rate,
    });
    // Release even when the flood failed; report the flood's error first.
    let released = match lease {
        Some(guard) => guard.release(),
        None => Ok(()),
    };
    flooded?;
    released?;

    if let Some(n) = bfd_count(sys)? {
        out.push_str(&format!(
            "measure-cap: BFD up-count after: {n} (warn-only sanity check)\n"
        ));
    }

    let after_bytes: u64 = sys.read(&statfile)?.trim().parse().unwrap_or(before_bytes);
    let delta = after_bytes.saturating_sub(before_bytes);
    let mbps = (delta * 8) / 1_000_000 / secs;

    let cap_dir = crate::caps::cap_dir(&f.run_dir);
    sys.mkdir_p(&cap_dir)?;
    let cap_file = format!("{cap_dir}/cap-{dev}");
    let content = format!("{mbps}\n");
    sys.write(&cap_file, &content)?;
    out.push_str(&format!(
        "measure-cap: dev={dev} peer={peer} secs={secs} offered={rate}Mb/s measured={mbps}Mb/s -> {cap_file}"
    ));
    // Cap publication (additive layer): share the measurement cluster-wide so a member whose
    // tmpfs run_dir lost the local file can fall back to it. Failure is a warning, never a
    // measurement failure — the local cap file is already written.
    if clustered {
        let target = pmx.cap_path(&view.member.name, dev);
        let published = std::fs::create_dir_all(pmx.member_caps_dir(&view.member.name))
            .map_err(|e| {
                Error::fatal(format!(
                    "cannot create {}: {e}",
                    pmx.member_caps_dir(&view.member.name).display()
                ))
            })
            .and_then(|()| pmx.publish(&target, &content));
        match published {
            Ok(()) => out.push_str(&format!(
                "\nmeasure-cap: cap published to {}",
                target.display()
            )),
            Err(e) => eprintln!(
                "measure-cap: warning: cannot publish the cap to {}: {e} — \
                 the local cap file is written; the measurement stands",
                target.display()
            ),
        }
    }
    Ok(out)
}

/// The native flood: N threads, each a connected blocking UDP socket sending `payload`-byte
/// datagrams with coarse pacing to rate_mbit/threads. tos is left at the default (best-effort:
/// a calibration flood must never ride the protected class). ENOBUFS/EAGAIN when the qdisc
/// backs up = retry.
pub fn native_flood(spec: &FloodSpec) -> Result<()> {
    use std::net::UdpSocket;
    use std::time::Instant;
    let per_thread_bps = spec.rate_mbit as f64 * 1e6 / 8.0 / spec.threads as f64;
    let deadline = Instant::now() + Duration::from_secs(spec.secs);
    let addr = format!("{}:{}", spec.peer, spec.port);
    let mut handles = Vec::new();
    for _ in 0..spec.threads {
        let addr = addr.clone();
        let payload = vec![0u8; spec.payload];
        handles.push(std::thread::spawn(move || -> Result<u64> {
            let sock = UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| Error::fatal(format!("measure-cap: bind: {e}")))?;
            sock.connect(&addr)
                .map_err(|e| Error::fatal(format!("measure-cap: connect {addr}: {e}")))?;
            let start = Instant::now();
            let mut sent: u64 = 0;
            while Instant::now() < deadline {
                match sock.send(&payload) {
                    Ok(n) => sent += n as u64,
                    Err(_) => { /* ENOBUFS/EAGAIN when the qdisc backs up — just retry */ }
                }
                if per_thread_bps > 0.0 {
                    let ahead = sent as f64 / per_thread_bps - start.elapsed().as_secs_f64();
                    if ahead > 0.0002 {
                        std::thread::sleep(Duration::from_secs_f64(ahead));
                    }
                }
            }
            Ok(sent)
        }));
    }
    let mut total = 0u64;
    for h in handles {
        total += h
            .join()
            .map_err(|_| Error::fatal("measure-cap: flood thread panicked"))??;
    }
    eprintln!(
        "measure-cap: offered {:.0} Mbit/s at the sockets ({} threads, payload {})",
        (total * 8) as f64 / 1e6 / spec.secs as f64,
        spec.threads,
        spec.payload
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    const CLUSTERED: &str = r#"{
      "nodename": "pve1-tb", "version": 7,
      "cluster": {"name": "cfab-test", "version": 3, "nodes": 3, "quorate": 1},
      "nodelist": {"pve1-tb": {"id": 1, "online": 1, "ip": "10.249.0.1"}}
    }"#;

    /// A tempdir standing in for /etc/pve (clustered when `clustered`).
    fn pmx_root(clustered: bool) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        if clustered {
            std::fs::write(dir.path().join(".members"), CLUSTERED).unwrap();
        }
        dir
    }

    /// MockSys wired for a clean eth9 measurement.
    fn measurable_sys() -> MockSys {
        MockSys::default()
            .on_stdout(
                &["tc", "qdisc", "show"],
                "qdisc fq_codel 0: root refcnt 9\n",
            )
            .file("/sys/class/net/eth9/statistics/tx_bytes", "1000\n")
    }

    #[test]
    fn refuses_non_fabric_wire() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let dir = pmx_root(false);
        let mut sys = MockSys::default();
        let err = run(
            &mut sys,
            &view,
            &Pmxcfs::at(dir.path()),
            "eth5",
            "10.99.1.2",
            1,
            &|_| Ok(()),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not a wire in CLASS_TABLE"),
            "{err}"
        );
    }

    #[test]
    fn refuses_shaped_egress() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let dir = pmx_root(false);
        let mut sys = MockSys::default().on_stdout(
            &["tc", "qdisc", "show", "dev", "eth9"],
            "qdisc htb 1: root refcnt 9\n",
        );
        let err = run(
            &mut sys,
            &view,
            &Pmxcfs::at(dir.path()),
            "eth9",
            "10.99.1.2",
            1,
            &|_| Ok(()),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("a shaper is on the egress path"),
            "{err}"
        );
    }

    #[test]
    fn measures_and_writes_cap_file_not_clustered() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let dir = pmx_root(false);
        let pmx = Pmxcfs::at(dir.path());
        // 6s at ~3 Gb/s: delta = 2_250_000_000 bytes
        let mut sys = measurable_sys();
        let report = run(&mut sys, &view, &pmx, "eth9", "10.99.1.2", 6, &|spec| {
            assert_eq!(spec.rate_mbit, 6000, "1.2x the declared 5000");
            assert_eq!(spec.threads, 6);
            Ok(())
        })
        // MockSys files are immutable during run, so the delta is 0 — assert the plumbing.
        .unwrap();
        assert!(report.contains("offered=6000Mb/s"), "{report}");
        assert!(report.contains("-> "), "{report}");
        assert_eq!(
            sys.writes_to("/run/cfab/cap-eth9").map(str::trim),
            Some("0")
        );
        // Not clustered: no lease taken, nothing published.
        assert!(!dir.path().join("priv").exists());
        assert!(!pmx.caps_dir().exists());
        assert!(!report.contains("published"), "{report}");
    }

    #[test]
    fn clustered_lease_held_during_flood_and_cap_published() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let dir = pmx_root(true);
        let pmx = Pmxcfs::at(dir.path());
        let lock_dir = dir.path().join("priv/lock/cfab-measure");
        let lock_dir_probe = lock_dir.clone();
        let mut sys = measurable_sys();
        let report = run(&mut sys, &view, &pmx, "eth9", "10.99.1.2", 6, &|_| {
            assert!(lock_dir_probe.is_dir(), "lease held while flooding");
            Ok(())
        })
        .unwrap();
        assert!(!lock_dir.exists(), "lease released after the flood");
        let published = pmx.cap_path("pve1-tb", "eth9");
        assert_eq!(std::fs::read_to_string(&published).unwrap(), "0\n");
        assert!(report.contains("cap published to"), "{report}");
    }

    #[test]
    fn lease_released_when_flood_fails() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let dir = pmx_root(true);
        let pmx = Pmxcfs::at(dir.path());
        let mut sys = measurable_sys();
        let err = run(&mut sys, &view, &pmx, "eth9", "10.99.1.2", 6, &|_| {
            Err(crate::error::Error::fatal("flood blew up"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("flood blew up"), "{err}");
        assert!(
            !dir.path().join("priv/lock/cfab-measure").exists(),
            "lease released on the flood's error path"
        );
        assert!(
            !pmx.caps_dir().exists(),
            "no cap published for a failed run"
        );
    }

    #[test]
    fn refuses_when_lease_held_elsewhere() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let dir = pmx_root(true);
        // A fresh-mtime lock = another member is measuring right now.
        std::fs::create_dir_all(dir.path().join("priv/lock/cfab-measure")).unwrap();
        let mut sys = measurable_sys();
        let err = run(
            &mut sys,
            &view,
            &Pmxcfs::at(dir.path()),
            "eth9",
            "10.99.1.2",
            6,
            &|_| {
                unreachable!("the flood must not start without the lease");
            },
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(
                "another member is measuring (cluster lease cfab-measure held); retry shortly"
            ),
            "{msg}"
        );
    }

    #[test]
    fn publish_failure_is_a_warning_not_a_measurement_failure() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let dir = pmx_root(true);
        let pmx = Pmxcfs::at(dir.path());
        // A FILE where the caps dir must go makes create_dir_all fail.
        std::fs::create_dir_all(pmx.cfab_dir()).unwrap();
        std::fs::write(pmx.caps_dir(), "in the way").unwrap();
        let mut sys = measurable_sys();
        let report = run(&mut sys, &view, &pmx, "eth9", "10.99.1.2", 6, &|_| Ok(())).unwrap();
        // The measurement stands: local cap written, publication line absent.
        assert_eq!(
            sys.writes_to("/run/cfab/cap-eth9").map(str::trim),
            Some("0")
        );
        assert!(!report.contains("cap published to"), "{report}");
        assert!(
            !dir.path().join("priv/lock/cfab-measure").exists(),
            "lease still released"
        );
    }
}
