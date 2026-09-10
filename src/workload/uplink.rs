//! Uplink identification over sysfs (`Sys`): the declared bridge's ports, the uplink
//! recursion, and STP forwarding state. `emit::workload::bridge_table` renders the ARP
//! guard text from what this module finds; everything here is read-only I/O over `dyn Sys`.

use std::collections::BTreeSet;

use crate::sys::Sys;

/// The uplink of a workload's bridge: the declared bridge, the declared VLAN id its leg
/// carries, and the bridge port(s) that reach off-host (a physical NIC, a bond, or a VLAN
/// sub-interface — anything with a `device` link, found directly or through `lower_*` links).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uplink {
    pub bridge: String,
    pub vid: u16,
    pub ports: Vec<String>,
}

/// A depth cap on the `lower_*` recursion: real stacks (VLAN-on-bond, bond-of-VLANs) are one or
/// two deep; this only guards against a symlink cycle or a pathological declaration.
const MAX_LOWER_DEPTH: u32 = 8;

/// The `lower_*` links of a netdev (`/sys/class/net/<dev>/lower_<name>`), name only. A netdev
/// that does not exist (or has none) has none — the caller's own checks name that condition.
fn lower_of(sys: &dyn Sys, dev: &str) -> Vec<String> {
    sys.list_dir(&format!("/sys/class/net/{dev}/"))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|name| name.strip_prefix("lower_").map(str::to_string))
        .collect()
}

/// Does `port` reach off-host? A `device` link (or, on `MockSys`, an exact `device` file key)
/// answers directly for a physical NIC; a bond or a VLAN sub-interface has none of its own and
/// answers through its `lower_*` links instead.
fn is_uplink_port(sys: &dyn Sys, port: &str, depth: u32) -> bool {
    if depth > MAX_LOWER_DEPTH {
        return false;
    }
    let device = format!("/sys/class/net/{port}/device");
    if sys.read_link(&device).is_ok() || sys.exists(&device) {
        return true;
    }
    lower_of(sys, port)
        .iter()
        .any(|lower| is_uplink_port(sys, lower, depth + 1))
}

/// Is `bridge` a bridge on this host right now? A bridge has a `brif/` directory (its ports)
/// and a `bridge/` directory of its own settings; a netdev that is not a bridge, and a netdev
/// that does not exist at all, both answer false.
///
/// The deferral gate: a `[[workload]]` row whose declared `uplink` is not (yet) a bridge is
/// deferred by its caller, in the caller's own words, rather than refused here — which is why
/// `identify_declared` below does not repeat the check.
pub fn bridge_present(sys: &dyn Sys, bridge: &str) -> bool {
    !ports_of(sys, bridge).is_empty()
        || sys.exists(&format!("/sys/class/net/{bridge}/bridge/stp_state"))
}

/// The bridge port names of `bridge` (`/sys/class/net/<bridge>/brif/`). A netdev that is not a
/// bridge, or is not there at all, has none.
fn ports_of(sys: &dyn Sys, bridge: &str) -> Vec<String> {
    sys.list_dir(&format!("/sys/class/net/{bridge}/brif/"))
        .unwrap_or_default()
}

/// The uplink ports of the DECLARED bridge, for the DECLARED vid. cfab creates the leg itself
/// (`cfab-work-<name>` on `uplink`), so nothing here reads the leg: no `/proc/net/vlan` entry
/// (the leg may not exist yet) and no `lower_*` walk from it (the declaration already says
/// which bridge it sits on). The `lower_*` walk survives one level down, deciding whether a
/// bridge PORT reaches off-host.
///
/// Callers gate on `bridge_present` first (an absent bridge is a deferral, not a refusal); a
/// bridge that is absent anyway reaches the "no uplink port" refusal with an empty port list.
pub fn identify_declared(sys: &dyn Sys, bridge: &str, vid: u16) -> Result<Uplink, String> {
    let ports = ports_of(sys, bridge);
    let uplink_ports: Vec<String> = ports
        .iter()
        .filter(|p| is_uplink_port(sys, p, 0))
        .cloned()
        .collect();
    if uplink_ports.is_empty() {
        let listed = if ports.is_empty() {
            "(none)".to_string()
        } else {
            ports.join(", ")
        };
        return Err(format!(
            "bridge {bridge} has no uplink port (no port has a /sys/class/net/<port>/device, \
             directly or through lower links); ports: {listed}"
        ));
    }
    Ok(Uplink {
        bridge: bridge.to_string(),
        vid,
        ports: uplink_ports,
    })
}

/// Is `port` (a bridge port of `bridge`) in STP forwarding state (`BR_STATE_FORWARDING` = 3)?
/// A missing state file names the bridge and port and the sysfs path it expected. Returns the
/// raw (trimmed) state text alongside the bool so a caller building a "not forwarding yet"
/// message can name the state without re-reading the same sysfs file a second time.
pub fn stp_forwarding(sys: &dyn Sys, bridge: &str, port: &str) -> Result<(bool, String), String> {
    let path = format!("/sys/class/net/{bridge}/brif/{port}/state");
    let state = sys
        .read(&path)
        .map_err(|_| format!("bridge {bridge}: port {port} has no {path}"))?;
    let state = state.trim().to_string();
    Ok((state == "3", state))
}

/// The ifindexes of every port on `up`'s bridge that is NOT one of its uplink ports (the VM taps
/// and any other non-uplink ports) — the set the announcer scans, excluding the uplink itself. A
/// port that no longer has an `ifindex` file at all has vanished mid-scan (the tap was torn
/// down) and is skipped, not an error; a port whose `ifindex` file exists but cannot be read or
/// does not parse is a fault worth naming (something is wrong with that specific netdev, not
/// "it went away"), so it fails the whole scan rather than silently under-reporting the set.
pub fn non_uplink_ifindexes(sys: &dyn Sys, up: &Uplink) -> Result<BTreeSet<u32>, String> {
    let mut out = BTreeSet::new();
    for port in sys
        .list_dir(&format!("/sys/class/net/{}/brif/", up.bridge))
        .unwrap_or_default()
    {
        if up.ports.contains(&port) {
            continue;
        }
        let path = format!("/sys/class/net/{port}/ifindex");
        if !sys.exists(&path) {
            continue;
        }
        let ifindex = sys
            .read(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .ok_or_else(|| format!("port {port}: cannot read ifindex from {path}"))?;
        out.insert(ifindex);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    /// pve1 shape (R8): primary = vlan-aware bridge, ports eth0 (physical), tap100i0, veth101i0,
    /// fwpr102p0 (veth to the firewall bridge); cfab's leg sits on it as vid 3.
    fn pve1() -> MockSys {
        MockSys::default()
            .file("/sys/class/net/primary/bridge/stp_state", "0\n")
            .file("/sys/class/net/primary/brif/eth0/state", "3\n")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .file("/sys/class/net/primary/brif/veth101i0/state", "3\n")
            .file("/sys/class/net/primary/brif/fwpr102p0/state", "3\n")
            .link("/sys/class/net/eth0/device", "../../../0000:01:00.0")
            .file("/sys/class/net/eth0/ifindex", "2\n")
            .file("/sys/class/net/tap100i0/ifindex", "10\n")
            .file("/sys/class/net/veth101i0/ifindex", "11\n")
            .file("/sys/class/net/fwpr102p0/ifindex", "12\n")
    }

    #[test]
    fn the_declared_uplink_is_read_from_the_bridge_alone() {
        let sys = MockSys::default()
            .file("/sys/class/net/primary/bridge/stp_state", "0\n")
            .file("/sys/class/net/primary/brif/eth0/state", "3\n")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .link("/sys/class/net/eth0/device", "../../../0000:01:00.0")
            .file("/sys/class/net/eth0/ifindex", "2\n")
            .file("/sys/class/net/tap100i0/ifindex", "10\n");
        assert_eq!(
            identify_declared(&sys, "primary", 3).unwrap(),
            Uplink {
                bridge: "primary".into(),
                vid: 3,
                ports: vec!["eth0".into()]
            }
        );
        // The vid is the declaration's, carried through untouched — nothing reads it back off
        // a netdev, so a bridge that has not been given the vid yet identifies the same way.
        assert_eq!(identify_declared(&sys, "primary", 7).unwrap().vid, 7);
    }

    #[test]
    fn a_bond_port_is_an_uplink_of_the_declared_bridge_through_its_lower_links() {
        let sys = MockSys::default() // bond0 is the port; eth0/eth1 are its lower links
            .file("/sys/class/net/primary/brif/bond0/state", "3\n")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .link("/sys/class/net/bond0/lower_eth0", "../../eth0")
            .link("/sys/class/net/eth0/device", "../../../0000:01:00.0");
        assert_eq!(
            identify_declared(&sys, "primary", 3).unwrap().ports,
            vec!["bond0"]
        );
    }

    #[test]
    fn a_declared_uplink_with_no_off_host_port_is_refused_by_name() {
        let no_uplink = MockSys::default()
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .file("/sys/class/net/tap100i0/ifindex", "10\n");
        assert_eq!(
            identify_declared(&no_uplink, "primary", 3).unwrap_err(),
            "bridge primary has no uplink port (no port has a /sys/class/net/<port>/device, \
             directly or through lower links); ports: tap100i0"
        );
        // A bridge that is not there at all reaches the same refusal (its caller gated on
        // `bridge_present` and deferred instead) — with no port list to name.
        assert_eq!(
            identify_declared(&MockSys::default(), "primary", 3).unwrap_err(),
            "bridge primary has no uplink port (no port has a /sys/class/net/<port>/device, \
             directly or through lower links); ports: (none)"
        );
    }

    #[test]
    fn a_bridge_is_present_by_its_ports_or_its_own_settings_directory() {
        let with_ports = MockSys::default().file("/sys/class/net/primary/brif/eth0/state", "3\n");
        assert!(bridge_present(&with_ports, "primary"));
        // A vlan-aware bridge with no port yet is still a bridge.
        let no_ports = MockSys::default().file("/sys/class/net/primary/bridge/stp_state", "0\n");
        assert!(bridge_present(&no_ports, "primary"));
        // A plain NIC named `primary`, and a `primary` that does not exist: neither is one.
        let nic = MockSys::default().link("/sys/class/net/primary/device", "../../../0000:01:00.0");
        assert!(!bridge_present(&nic, "primary"));
        assert!(!bridge_present(&MockSys::default(), "primary"));
    }

    #[test]
    fn a_port_that_vanished_mid_scan_is_skipped() {
        let sys = MockSys::default()
            .file("/sys/class/net/primary/brif/eth0/state", "3\n")
            .file("/sys/class/net/primary/brif/goner/state", "3\n")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .file("/sys/class/net/tap100i0/ifindex", "10\n");
        // "goner" is a bridge port with no /sys/class/net/goner/ifindex at all: it was torn
        // down between the brif/ listing and the ifindex read. The live tap beside it proves
        // the skip is surgical, not total.
        let up = Uplink {
            bridge: "primary".into(),
            vid: 3,
            ports: vec!["eth0".into()],
        };
        assert_eq!(
            non_uplink_ifindexes(&sys, &up).unwrap(),
            BTreeSet::from([10])
        );
    }

    #[test]
    fn unparseable_ifindex_content_is_a_named_error() {
        let sys = MockSys::default()
            .file("/sys/class/net/primary/brif/eth0/state", "3\n")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .file("/sys/class/net/tap100i0/ifindex", "not-a-number\n");
        let up = Uplink {
            bridge: "primary".into(),
            vid: 3,
            ports: vec!["eth0".into()],
        };
        assert_eq!(
            non_uplink_ifindexes(&sys, &up).unwrap_err(),
            "port tap100i0: cannot read ifindex from /sys/class/net/tap100i0/ifindex"
        );
    }

    #[test]
    fn stp_state_forwarding_is_3_and_anything_else_is_named() {
        assert_eq!(
            stp_forwarding(&pve1(), "primary", "eth0").unwrap(),
            (true, "3".to_string())
        );
        let listening = pve1().file("/sys/class/net/primary/brif/eth0/state", "1\n");
        assert_eq!(
            stp_forwarding(&listening, "primary", "eth0"),
            Ok((false, "1".to_string()))
        );
        assert_eq!(
            stp_forwarding(&MockSys::default(), "primary", "eth0").unwrap_err(),
            "bridge primary: port eth0 has no /sys/class/net/primary/brif/eth0/state"
        );
    }
}
