//! `cfab shape-daemon` — membership-reactive shaping; runs as cfab-shape.service on a host.
//! Watches link events for the fabric wires and regenerates+applies each UP wire's
//! HTB tree with an authoritative up-set. On a link down, a bulk zone's full floor re-derives
//! onto its next-preferred surviving wire; on return it re-derives back. Control keeps its full
//! floor on every wire, so its failover needs NO shaping re-derivation.
//!
//! On ANY exit (stop/signal) restores fq_codel on every fabric wire: the service being down =
//! no floors, which `cfab verify` reports. Touches ONLY the CLASS_TABLE wires.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::derive::View;
use crate::emit;
use crate::error::{Error, Result};
use crate::sys::{Sys, run_ignore};

/// The debounced event loop, separated from process wiring for testability: `events` yields
/// `ip monitor link` lines; `stop` polled each tick; `apply` runs once per quiet gap after a
/// burst that touched a fabric wire (it gets `sys` so the caller's closure can act on it).
pub fn event_loop(
    events: &Receiver<String>,
    devs: &[String],
    debounce: Duration,
    stop: &dyn Fn() -> bool,
    apply: &mut dyn FnMut(&mut dyn Sys),
    sys: &mut dyn Sys,
) {
    let mut pending = false;
    loop {
        if stop() {
            return;
        }
        match events.recv_timeout(debounce) {
            Ok(line) => {
                if devs
                    .iter()
                    .any(|d| line.contains(&format!("{d}:")) || line.contains(&format!("{d}@")))
                {
                    pending = true;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if pending {
                    pending = false;
                    apply(sys);
                }
            }
            Err(RecvTimeoutError::Disconnected) => return, // ip monitor died; teardown follows
        }
    }
}

/// One reconvergence: read the up-set, derive and apply each up wire's tree.
pub fn reconverge(sys: &mut dyn Sys, view: &View, devs: &[String]) -> Result<String> {
    let up: Vec<String> = devs
        .iter()
        .filter(|d| {
            sys.read(&format!("/sys/class/net/{d}/carrier"))
                .map(|s| s.trim() == "1")
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let t0 = Instant::now();
    for dev in &up {
        let measured = read_cap(sys, view, dev);
        let up_ref = &up;
        let in_up = move |w: &str| up_ref.iter().any(|u| u == w);
        let derivation = match emit::shape::derive(view, dev, measured, &in_up) {
            Ok(d) => d,
            Err(e) => {
                // A wire that cannot derive (e.g. cap file corrupt AND no declared speed) is
                // skipped loudly rather than killing the daemon: the other wires keep floors.
                eprintln!("shape-daemon: {dev}: {e}");
                continue;
            }
        };
        for (argv, ignore_err) in derivation.tc_argv() {
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            let out = sys.run(&argv_refs)?;
            if !out.ok() && !ignore_err {
                eprintln!(
                    "shape-daemon: {}: exit {} — {}",
                    argv.join(" "),
                    out.status,
                    out.stderr.trim()
                );
            }
        }
    }
    let dt = t0.elapsed().as_millis();
    Ok(format!(
        "shape-daemon: reconverge dt={dt}ms up=[{}]",
        up.join(" ")
    ))
}

/// The shared cap chain (local file → cluster-published → declared). The cluster fallback
/// caches back to the local file, so its message fires once, not per reconverge.
fn read_cap(sys: &mut dyn Sys, view: &View, dev: &str) -> Option<u64> {
    crate::caps::read_cap(
        sys,
        &crate::cluster::Pmxcfs::new(),
        &view.member.name,
        &view.fabric.run_dir,
        dev,
    )
}

/// Restore fq_codel on every fabric wire (the exit path — floors gone, verify reports it).
pub fn teardown(sys: &mut dyn Sys, devs: &[String]) -> Result<()> {
    for d in devs {
        run_ignore(sys, &["tc", "qdisc", "del", "dev", d, "root"])?;
        run_ignore(
            sys,
            &["tc", "qdisc", "replace", "dev", d, "root", "fq_codel"],
        )?;
    }
    Ok(())
}

/// The real daemon: spawn `ip monitor link`, loop until SIGTERM/SIGINT, tear down on exit.
pub fn run(sys: &mut dyn Sys, view: &View, debounce: Duration) -> Result<()> {
    let devs = view.wires();
    if devs.is_empty() {
        return Err(Error::fatal("shape-daemon: no wires in CLASS_TABLE"));
    }
    println!(
        "shape-daemon: start devs=[{}] debounce={}s",
        devs.join(" "),
        debounce.as_secs_f64()
    );
    match reconverge(sys, view, &devs) {
        Ok(msg) => println!("{msg}"),
        Err(e) => eprintln!("shape-daemon: initial reconverge failed: {e}"),
    }

    let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let f = stop_flag.clone();
        ctrlc::set_handler(move || f.store(true, std::sync::atomic::Ordering::SeqCst))
            .map_err(|e| Error::fatal(format!("cannot install signal handler: {e}")))?;
    }

    let mut child = std::process::Command::new("ip")
        .args(["monitor", "link"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::fatal(format!("cannot spawn ip monitor link: {e}")))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(|l| l.ok())
        {
            if tx.send(line).is_err() {
                return;
            }
        }
    });

    let stop = {
        let f = stop_flag.clone();
        move || f.load(std::sync::atomic::Ordering::SeqCst)
    };
    event_loop(
        &rx,
        &devs,
        debounce,
        &stop,
        &mut |sys: &mut dyn Sys| match reconverge(sys, view, &devs) {
            Ok(msg) => println!("{msg}"),
            Err(e) => eprintln!("shape-daemon: reconverge failed: {e}"),
        },
        sys,
    );
    let _ = child.kill();
    let _ = child.wait();
    teardown(sys, &devs)?;
    println!(
        "shape-daemon: TEARDOWN — fabric NICs restored to fq_codel ({})",
        devs.join(" ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;
    use std::sync::mpsc::channel;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    #[test]
    fn event_burst_debounces_to_one_reconverge() {
        let (tx, rx) = channel();
        let devs = vec!["eth9".to_string(), "eth1".to_string()];
        for _ in 0..5 {
            tx.send("3: eth9: <BROADCAST> state DOWN".to_string())
                .unwrap();
        }
        let mut count = 0;
        let calls = std::cell::Cell::new(0);
        let mut sys = MockSys::default();
        event_loop(
            &rx,
            &devs,
            Duration::from_millis(20),
            &|| {
                calls.set(calls.get() + 1);
                calls.get() > 50 // safety stop
            },
            &mut |_| count += 1,
            &mut sys,
        );
        drop(tx);
        assert_eq!(count, 1, "5 events in one burst = 1 reconverge");
    }

    #[test]
    fn unrelated_interface_events_do_not_reconverge() {
        let (tx, rx) = channel();
        let devs = vec!["eth9".to_string()];
        tx.send("7: docker0: <BROADCAST> state UP".to_string())
            .unwrap();
        drop(tx); // loop exits on disconnect after the debounce drain
        let mut count = 0;
        let mut sys = MockSys::default();
        event_loop(
            &rx,
            &devs,
            Duration::from_millis(10),
            &|| false,
            &mut |_| count += 1,
            &mut sys,
        );
        assert_eq!(count, 0);
    }

    #[test]
    fn reconverge_applies_trees_only_to_up_wires() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default()
            .file("/sys/class/net/eth9/carrier", "1\n")
            .file("/sys/class/net/eth1/carrier", "0\n")
            .file("/sys/class/net/eth0/carrier", "1\n");
        let msg = reconverge(&mut sys, &view, &view.wires()).unwrap();
        assert!(msg.contains("up=[eth0 eth9]"), "{msg}"); // wires() is sorted
        assert!(sys.ran("tc qdisc add dev eth9 root handle 1: htb"));
        assert!(sys.ran("tc qdisc add dev eth0 root handle 1: htb"));
        assert!(
            !sys.ran("tc qdisc add dev eth1 root handle 1: htb"),
            "down wire left alone"
        );
    }

    #[test]
    fn teardown_restores_fq_codel() {
        let mut sys = MockSys::default();
        teardown(&mut sys, &["eth9".to_string(), "eth0".to_string()]).unwrap();
        assert!(sys.ran("tc qdisc del dev eth9 root"));
        assert!(sys.ran("tc qdisc replace dev eth9 root fq_codel"));
        assert!(sys.ran("tc qdisc replace dev eth0 root fq_codel"));
    }
}
