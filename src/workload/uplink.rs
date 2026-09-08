//! Uplink identification over sysfs (`Sys`): the bridge of a workload interface, its ports, the
//! uplink recursion, and STP forwarding state. `emit::workload::bridge_table` renders the ARP
//! guard text from what this module finds; everything here is read-only I/O over `dyn Sys`.

use std::collections::BTreeSet;

use crate::sys::Sys;

/// The uplink of a workload's bridge: the bridge itself, the VLAN id carried on the workload's
/// sub-interface, and the bridge port(s) that reach off-host (a physical NIC, a bond, or a VLAN
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

/// The `VID: <n>` field of `/proc/net/vlan/<ifname>` (8021q's per-device proc file). VERIFIED
/// format (pve1-tb, 2026-09-08 22:10 UTC): `"<name>  VID: <n>\t REORDER_HDR: …"` — a TAB follows
/// the id, so the id is taken as the first whitespace-delimited token after `VID:` rather than
/// assumed to end at a fixed character.
fn parse_vid(text: &str) -> Option<u16> {
    let after = text.split("VID:").nth(1)?;
    after.split_whitespace().next()?.parse().ok()
}

/// Identify the uplink of the bridge that `ifname` (a workload VLAN sub-interface, e.g.
/// `primary.3`) sits on. Every failure names the object and the remedy (fail loud, never
/// degrade): a missing or ambiguous lower link, a lower link that is not a bridge, a bridge with
/// no uplink port, a `/proc/net/vlan` entry without a VID, or a workload interface that is not
/// itself an 802.1Q sub-interface.
pub fn identify(sys: &dyn Sys, ifname: &str) -> Result<Uplink, String> {
    let lowers = lower_of(sys, ifname);
    let bridge = match lowers.as_slice() {
        [] => {
            return Err(format!(
                "workload interface {ifname} is not a VLAN sub-interface of a bridge (no lower link in /sys/class/net/{ifname})"
            ));
        }
        [bridge] => bridge.clone(),
        many => {
            return Err(format!(
                "{} lower links in /sys/class/net/{ifname}; expected exactly one",
                many.len()
            ));
        }
    };

    let ports = sys
        .list_dir(&format!("/sys/class/net/{bridge}/brif/"))
        .unwrap_or_default();
    let is_bridge =
        !ports.is_empty() || sys.exists(&format!("/sys/class/net/{bridge}/bridge/stp_state"));
    if !is_bridge {
        return Err(format!(
            "workload interface {ifname} sits on {bridge}, which is not a bridge (phase 1 needs a bridge port for the VMs)"
        ));
    }

    let uplink_ports: Vec<String> = ports
        .iter()
        .filter(|p| is_uplink_port(sys, p, 0))
        .cloned()
        .collect();
    if uplink_ports.is_empty() {
        return Err(format!(
            "bridge {bridge} has no uplink port (no port has a /sys/class/net/<port>/device, directly or through lower links); ports: {}",
            ports.join(", ")
        ));
    }

    let vlan_proc = format!("/proc/net/vlan/{ifname}");
    let vlan_text = sys.read(&vlan_proc).map_err(|_| {
        format!("workload interface {ifname} is not an 802.1Q sub-interface (no {vlan_proc})")
    })?;
    let vid = parse_vid(&vlan_text).ok_or_else(|| {
        format!("workload interface {ifname}: {vlan_proc} has no VID field")
    })?;

    Ok(Uplink {
        bridge,
        vid,
        ports: uplink_ports,
    })
}

/// Is `port` (a bridge port of `bridge`) in STP forwarding state (`BR_STATE_FORWARDING` = 3)?
/// A missing state file names the bridge and port and the sysfs path it expected.
pub fn stp_forwarding(sys: &dyn Sys, bridge: &str, port: &str) -> Result<bool, String> {
    let path = format!("/sys/class/net/{bridge}/brif/{port}/state");
    let state = sys
        .read(&path)
        .map_err(|_| format!("bridge {bridge}: port {port} has no {path}"))?;
    Ok(state.trim() == "3")
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
    /// fwpr102p0 (veth to the firewall bridge); primary.3 is the vlan sub-interface on it.
    fn pve1() -> MockSys {
        MockSys::default()
            .link("/sys/class/net/primary.3/lower_primary", "../../primary")
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
            .file(
                "/proc/net/vlan/primary.3",
                "primary.3  VID: 3\t REORDER_HDR: 1  dev->priv_flags: 1021\n",
            )
    }

    #[test]
    fn the_uplink_is_the_port_with_a_device_and_the_vid_comes_from_the_sub_interface() {
        let up = identify(&pve1(), "primary.3").unwrap();
        assert_eq!(
            up,
            Uplink {
                bridge: "primary".into(),
                vid: 3,
                ports: vec!["eth0".into()]
            }
        );
        assert_eq!(
            non_uplink_ifindexes(&pve1(), &up).unwrap(),
            [10, 11, 12].into_iter().collect()
        );
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
        assert_eq!(non_uplink_ifindexes(&sys, &up).unwrap(), BTreeSet::from([10]));
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
    fn a_bond_or_vlan_port_is_an_uplink_through_its_lower_links() {
        let sys = MockSys::default() // bond0 is the port; eth0/eth1 are its lower links
            .link("/sys/class/net/primary.3/lower_primary", "../../primary")
            .file("/sys/class/net/primary/brif/bond0/state", "3\n")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .link("/sys/class/net/bond0/lower_eth0", "../../eth0")
            .link("/sys/class/net/bond0/lower_eth1", "../../eth1")
            .link("/sys/class/net/eth0/device", "../../../0000:01:00.0")
            .link("/sys/class/net/eth1/device", "../../../0000:02:00.0")
            .file("/sys/class/net/bond0/ifindex", "3\n")
            .file("/sys/class/net/tap100i0/ifindex", "10\n")
            .file(
                "/proc/net/vlan/primary.3",
                "primary.3  VID: 3\t REORDER_HDR: 1  dev->priv_flags: 1021\n",
            );
        assert_eq!(identify(&sys, "primary.3").unwrap().ports, vec!["bond0"]);
        let vlan_port = MockSys::default()
            .link("/sys/class/net/primary.3/lower_primary", "../../primary")
            .file("/sys/class/net/primary/brif/eth0.7/state", "3\n")
            .link("/sys/class/net/eth0.7/lower_eth0", "../../eth0")
            .link("/sys/class/net/eth0/device", "../../../0000:01:00.0")
            .file("/sys/class/net/eth0.7/ifindex", "4\n")
            .file(
                "/proc/net/vlan/primary.3",
                "primary.3  VID: 3\t REORDER_HDR: 1  dev->priv_flags: 1021\n",
            );
        assert_eq!(
            identify(&vlan_port, "primary.3").unwrap().ports,
            vec!["eth0.7"]
        );
    }

    #[test]
    fn refusals_name_the_object_and_the_remedy() {
        let no_lower = MockSys::default();
        assert_eq!(
            identify(&no_lower, "primary.3").unwrap_err(),
            "workload interface primary.3 is not a VLAN sub-interface of a bridge (no lower link in /sys/class/net/primary.3)"
        );
        let no_bridge =
            MockSys::default().link("/sys/class/net/primary.3/lower_eth0", "../../eth0");
        assert_eq!(
            identify(&no_bridge, "primary.3").unwrap_err(),
            "workload interface primary.3 sits on eth0, which is not a bridge (phase 1 needs a bridge port for the VMs)"
        );
        let no_uplink = MockSys::default()
            .link("/sys/class/net/primary.3/lower_primary", "../../primary")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .file("/sys/class/net/tap100i0/ifindex", "10\n")
            .file(
                "/proc/net/vlan/primary.3",
                "primary.3  VID: 3\t REORDER_HDR: 1  dev->priv_flags: 1021\n",
            );
        assert_eq!(
            identify(&no_uplink, "primary.3").unwrap_err(),
            "bridge primary has no uplink port (no port has a /sys/class/net/<port>/device, directly or through lower links); ports: tap100i0"
        );
        let mut no_vid = pve1();
        no_vid.files.remove("/proc/net/vlan/primary.3");
        assert_eq!(
            identify(&no_vid, "primary.3").unwrap_err(),
            "workload interface primary.3 is not an 802.1Q sub-interface (no /proc/net/vlan/primary.3)"
        );
    }

    #[test]
    fn two_lower_links_is_its_own_refusal_naming_the_count() {
        let two_lowers = MockSys::default()
            .link("/sys/class/net/primary.3/lower_primary", "../../primary")
            .link("/sys/class/net/primary.3/lower_other", "../../other");
        assert_eq!(
            identify(&two_lowers, "primary.3").unwrap_err(),
            "2 lower links in /sys/class/net/primary.3; expected exactly one"
        );
    }

    #[test]
    fn stp_state_forwarding_is_3_and_anything_else_is_named() {
        assert!(stp_forwarding(&pve1(), "primary", "eth0").unwrap());
        let listening = pve1().file("/sys/class/net/primary/brif/eth0/state", "1\n");
        assert_eq!(stp_forwarding(&listening, "primary", "eth0"), Ok(false));
        assert_eq!(
            stp_forwarding(&MockSys::default(), "primary", "eth0").unwrap_err(),
            "bridge primary: port eth0 has no /sys/class/net/primary/brif/eth0/state"
        );
    }
}
