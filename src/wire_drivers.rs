//! A wire's driver: what `up` records at apply, and what `status` and the forwarding watchdog
//! read back.
//!
//! NIC feature quirks (offloads that lock up a given adapter under load) are the host's
//! business now — a udev rule fired on the netdev-add event — not a cfab actuator. What cfab
//! still owns is the fact a returned netdev may not be the same ADAPTER as the one `up` found:
//! the driver each present wire had at apply is recorded here, so the watchdog can report a
//! wire that comes back under a different driver instead of silently trusting it.
//!
//! Every read in this module degrades instead of failing: `ethtool` is a read-only diagnostic
//! dependency (`Recommends`, not `Depends`), and its absence — or a single device erroring — is
//! not a reason to fail a bringup, a teardown, or a status gather.

use crate::sys::Sys;

/// The driver `ethtool -i <dev>` reports, or `None` when it cannot be read: ethtool is not
/// installed, or this device errored. cfab does not fail a caller over a read it cannot make.
pub fn driver_of(sys: &mut dyn Sys, dev: &str) -> Option<String> {
    let out = sys.run(&["ethtool", "-i", dev]).ok()?;
    if !out.ok() {
        return None;
    }
    Some(
        out.stdout
            .lines()
            .find_map(|l| l.strip_prefix("driver:"))
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
    )
}

/// `<run_dir>/wire-drivers`: the driver each present wire had when `up` ran.
pub fn drivers_path(run_dir: &str) -> String {
    format!("{}/wire-drivers", run_dir.trim_end_matches('/'))
}

pub fn render_drivers(rows: &[(String, String)]) -> String {
    rows.iter()
        .map(|(nic, drv)| format!("{nic} {drv}\n"))
        .collect()
}

/// The driver recorded for one wire, or `None` when there is no record to read (a run dir from
/// an older version, one wiped under a running fabric, or a wire `up` could not read the
/// driver of).
pub fn recorded_driver(sys: &mut dyn Sys, run_dir: &str, nic: &str) -> Option<String> {
    let text = sys.read(&drivers_path(run_dir)).ok()?;
    text.lines().find_map(|l| {
        let (n, drv) = l.split_once(' ')?;
        (n == nic).then(|| drv.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    #[test]
    fn the_driver_is_read_from_ethtool_i() {
        let mut sys = MockSys::default().on_stdout(
            &["ethtool", "-i", "eth9"],
            "driver: r8152\nversion: 6.12.0\n",
        );
        assert_eq!(driver_of(&mut sys, "eth9"), Some("r8152".to_string()));
    }

    /// ethtool absent entirely (the binary cannot exec): a read cfab cannot make, not a fatal
    /// error — the caller gets `None`, exactly as it would for a device-specific failure below.
    #[test]
    fn ethtool_absent_reads_as_none_not_an_error() {
        struct NoEthtool(MockSys);
        impl Sys for NoEthtool {
            fn bond_port_state(
                &mut self,
                p: &str,
            ) -> crate::error::Result<crate::netlink::PortState> {
                self.0.bond_port_state(p)
            }
            fn set_active_port(&mut self, b: &str, p: &str) -> crate::error::Result<()> {
                self.0.set_active_port(b, p)
            }
            fn run(&mut self, argv: &[&str]) -> crate::error::Result<crate::sys::Output> {
                if argv[0] == "ethtool" {
                    return Err(crate::error::Error::fatal("cannot exec ethtool"));
                }
                self.0.run(argv)
            }
            fn read(&self, p: &str) -> crate::error::Result<String> {
                self.0.read(p)
            }
            fn write(&mut self, p: &str, c: &str) -> crate::error::Result<()> {
                self.0.write(p, c)
            }
            fn exists(&self, p: &str) -> bool {
                self.0.exists(p)
            }
            fn is_writable(&self, p: &str) -> bool {
                self.0.is_writable(p)
            }
            fn list_dir(&self, p: &str) -> crate::error::Result<Vec<String>> {
                self.0.list_dir(p)
            }
            fn read_link(&self, p: &str) -> crate::error::Result<String> {
                self.0.read_link(p)
            }
            fn mkdir_p(&mut self, p: &str) -> crate::error::Result<()> {
                self.0.mkdir_p(p)
            }
            fn remove(&mut self, p: &str) -> crate::error::Result<()> {
                self.0.remove(p)
            }
            fn rename(&mut self, a: &str, b: &str) -> crate::error::Result<()> {
                self.0.rename(a, b)
            }
            fn sleep(&mut self, d: std::time::Duration) {
                self.0.sleep(d);
            }
            fn unix_request(&mut self, p: &str, l: &str) -> crate::error::Result<String> {
                self.0.unix_request(p, l)
            }
        }
        let mut sys = NoEthtool(MockSys::default());
        assert_eq!(driver_of(&mut sys, "eth9"), None);
    }

    /// A nonzero exit (device error) is the same "cannot read" as an exec failure: `None`,
    /// never a fatal error propagated up through a bringup or a status gather.
    #[test]
    fn a_nonzero_exit_reads_as_none() {
        let mut sys = MockSys::default().on_fail(&["ethtool", "-i", "eth9"], 1, "no such device");
        assert_eq!(driver_of(&mut sys, "eth9"), None);
    }

    #[test]
    fn the_records_round_trip() {
        let drivers = vec![
            ("eth9".to_string(), "r8152".to_string()),
            ("eth1".to_string(), "igb".to_string()),
        ];
        let mut sys =
            MockSys::default().file(&drivers_path("/run/cfab"), &render_drivers(&drivers));
        assert_eq!(
            recorded_driver(&mut sys, "/run/cfab", "eth9"),
            Some("r8152".to_string())
        );
        assert_eq!(recorded_driver(&mut sys, "/run/cfab", "eth0"), None);
    }

    /// A run dir with no record (an older version, a wiped dir) is not an error: nothing to
    /// compare against, exactly as `mark.backend` reads.
    #[test]
    fn a_missing_record_is_none_not_an_error() {
        let mut sys = MockSys::default();
        assert_eq!(recorded_driver(&mut sys, "/run/cfab", "eth9"), None);
    }
}
