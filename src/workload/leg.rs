//! The workload leg: `cfab-work-<name>`, an 802.1Q sub-interface of the declared uplink bridge,
//! plus the bridge's own vid.
//!
//! A VLAN device on a vlan-aware bridge receives its tag only while the BRIDGE carries that vid
//! on itself (`bridge vlan add dev <bridge> vid <vid> self`) — VERIFIED on pve1-tb 2026-09-08
//! 22:38 UTC, where ifupdown2 adds it silently for a host-declared `<bridge>.<vid>` stanza.
//! cfab creates the leg, so cfab adds the vid when it is missing.
//!
//! Ownership of that vid is recorded, not guessed: `down` must remove a vid cfab added and
//! leave one that was already there (a host stanza, another tool), and nothing on the bridge
//! says who put it there. One line per `<bridge> <vid>` in `<run_dir>/workload-self-vid`, which
//! lives on tmpfs with the rest of the run state: after a reboot nothing cfab added survives
//! either, and the next `up` re-derives from a bridge in its baseline state.

use std::collections::BTreeSet;

use crate::commands::apply::{mk_vlan, vlan_marker};
use crate::commands::common::{link_exists, link_kind_is};
use crate::error::Result;
use crate::sys::{Sys, run_ok};

/// Where the vids cfab added to a bridge are recorded.
fn record_path(run_dir: &str) -> String {
    format!("{run_dir}/workload-self-vid")
}

/// One recorded vid, as it is written and matched: `<bridge> <vid>`.
fn record_line(bridge: &str, vid: u16) -> String {
    format!("{bridge} {vid}")
}

/// The vids `bridge` carries on ITSELF, from `bridge -j vlan show dev <bridge>`.
///
/// VERIFIED shape (pve1-tb, iproute2 6.15.0, 2026-09-10):
/// `[{"ifname":"primary","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]},{"vlan":3}]}]`
/// — the bridge's own entry is listed under its own ifname, and a device that does not exist
/// exits 255 (`Cannot find device`), which `run_ok` turns into the error it is.
pub fn self_vids(sys: &mut dyn Sys, bridge: &str) -> Result<BTreeSet<u16>> {
    let out = run_ok(sys, &["bridge", "-j", "vlan", "show", "dev", bridge])?;
    Ok(parse_self_vids(&out.stdout, bridge))
}

/// The `vlans` of `bridge`'s own entry. A range is `{"vlan":<first>,"vlanEnd":<last>}`;
/// anything unparsable is simply not a vid we have seen, and the caller's `add` is idempotent
/// enough to be safe (the kernel accepts adding a vid that is already there).
fn parse_self_vids(json: &str, bridge: &str) -> BTreeSet<u16> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        return BTreeSet::new();
    };
    let mut out = BTreeSet::new();
    for entry in doc.as_array().unwrap_or(&Vec::new()) {
        if entry.get("ifname").and_then(|v| v.as_str()) != Some(bridge) {
            continue;
        }
        for v in entry
            .get("vlans")
            .and_then(|v| v.as_array())
            .unwrap_or(&Vec::new())
        {
            let Some(first) = v.get("vlan").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let last = v
                .get("vlanEnd")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(first);
            for vid in first..=last {
                if let Ok(vid) = u16::try_from(vid) {
                    out.insert(vid);
                }
            }
        }
    }
    out
}

/// Create (or repair) the leg and give the bridge the vid if it lacks it.
///
/// `mk_vlan` is the same builder every other cfab leg uses, so a netdev of this name that is
/// NOT a vlan of this vid is replaced rather than trusted, and one that is is left where it is.
pub fn install(
    sys: &mut dyn Sys,
    run_dir: &str,
    leg: &str,
    uplink: &str,
    vid: u16,
    address: &str,
    qos_map: &[&str],
) -> Result<()> {
    mk_vlan(sys, leg, uplink, vid, Some(address), true, qos_map)?;
    ensure_self_vid(sys, run_dir, uplink, vid)?;
    Ok(())
}

/// Give the bridge the vid on ITSELF if it lacks it, recording that cfab is the one that added
/// it (`remove` reads that record back before it dares delete a vid). `Ok(true)` when this call
/// added it — the watchdog re-adds a vid an operator or an `ifreload` took away, and says so.
pub fn ensure_self_vid(sys: &mut dyn Sys, run_dir: &str, uplink: &str, vid: u16) -> Result<bool> {
    if self_vids(sys, uplink)?.contains(&vid) {
        return Ok(false);
    }
    run_ok(
        sys,
        &[
            "bridge",
            "vlan",
            "add",
            "dev",
            uplink,
            "vid",
            &vid.to_string(),
            "self",
        ],
    )?;
    let mut lines: BTreeSet<String> = read_record(sys, run_dir);
    lines.insert(record_line(uplink, vid));
    sys.write(
        &record_path(run_dir),
        &lines.into_iter().collect::<Vec<_>>().join("\n"),
    )?;
    Ok(true)
}

/// Is the leg there, and ours? A netdev of that name which is not a vlan of this vid is not
/// this leg — the caller rebuilds (`install` replaces it) rather than counting it present.
pub fn present(sys: &mut dyn Sys, leg: &str, vid: u16) -> Result<bool> {
    Ok(link_exists(sys, leg)? && link_kind_is(sys, leg, &vlan_marker(vid))?)
}

/// Remove the leg, and the bridge's vid if cfab is the one that added it.
///
/// Ownership is proven twice before anything is destroyed: the netdev must be a vlan of this
/// vid (a foreign netdev that happens to carry the name is left alone), and the vid must be in
/// cfab's own record (a vid the host had before cfab ran stays — VM ports keep their own vids
/// either way, this is only the bridge's self entry).
pub fn remove(sys: &mut dyn Sys, run_dir: &str, leg: &str, uplink: &str, vid: u16) -> Result<()> {
    if present(sys, leg, vid)? {
        run_ok(sys, &["ip", "link", "del", leg])?;
    }
    let mut lines = read_record(sys, run_dir);
    if !lines.remove(&record_line(uplink, vid)) {
        return Ok(());
    }
    run_ok(
        sys,
        &[
            "bridge",
            "vlan",
            "del",
            "dev",
            uplink,
            "vid",
            &vid.to_string(),
            "self",
        ],
    )?;
    if lines.is_empty() {
        sys.remove(&record_path(run_dir))
    } else {
        sys.write(
            &record_path(run_dir),
            &lines.into_iter().collect::<Vec<_>>().join("\n"),
        )
    }
}

/// The recorded `<bridge> <vid>` lines; an absent file is an empty record (nothing added yet,
/// or a reboot took the whole run dir with it).
fn read_record(sys: &dyn Sys, run_dir: &str) -> BTreeSet<String> {
    sys.read(&record_path(run_dir))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    /// The VERIFIED output shape (pve1-tb, iproute2 6.15.0): the bridge's own entry beside a
    /// port's, so the parser is proven to read the right one.
    const SHOW: &str = r#"[{"ifname":"eth0","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]},{"vlan":9}]},{"ifname":"primary","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]},{"vlan":3}]}]"#;

    fn sys_with_vlan_show(stdout: &str) -> MockSys {
        MockSys::default()
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .on_stdout(&["bridge", "-j", "vlan", "show", "dev", "primary"], stdout)
    }

    #[test]
    fn the_bridges_own_vids_are_read_from_its_own_entry_and_ranges_expand() {
        assert_eq!(parse_self_vids(SHOW, "primary"), BTreeSet::from([1, 3]));
        assert_eq!(parse_self_vids(SHOW, "eth0"), BTreeSet::from([1, 9]));
        assert_eq!(parse_self_vids("[]", "primary"), BTreeSet::new());
        assert_eq!(
            parse_self_vids(
                r#"[{"ifname":"primary","vlans":[{"vlan":10,"vlanEnd":12}]}]"#,
                "primary"
            ),
            BTreeSet::from([10, 11, 12])
        );
        // Not JSON at all (an iproute2 that answered on stderr): no vid is claimed present.
        assert_eq!(
            parse_self_vids("Cannot find device", "primary"),
            BTreeSet::new()
        );
    }

    #[test]
    fn install_creates_the_leg_with_the_member_address_and_adds_the_missing_self_vid() {
        let mut sys = sys_with_vlan_show(
            r#"[{"ifname":"primary","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]}]}]"#,
        );
        install(
            &mut sys,
            "/run/cfab",
            "cfab-work-vms",
            "primary",
            3,
            "192.168.20.2/24",
            &["0:0", "6:6"],
        )
        .unwrap();
        assert_eq!(
            sys.calls,
            vec![
                "ip link show cfab-work-vms",
                "ip link show cfab-work-vms",
                "ip link add link primary name cfab-work-vms type vlan id 3 egress-qos-map 0:0 6:6",
                "ip addr replace 192.168.20.2/24 dev cfab-work-vms",
                "ip link set cfab-work-vms up",
                "bridge -j vlan show dev primary",
                "bridge vlan add dev primary vid 3 self",
                "write /run/cfab/workload-self-vid",
            ]
        );
        assert_eq!(
            sys.writes_to("/run/cfab/workload-self-vid"),
            Some("primary 3")
        );
    }

    #[test]
    fn install_leaves_a_self_vid_the_host_already_had_and_records_nothing() {
        let mut sys = sys_with_vlan_show(SHOW);
        install(
            &mut sys,
            "/run/cfab",
            "cfab-work-vms",
            "primary",
            3,
            "192.168.20.2/24",
            &["0:0", "6:6"],
        )
        .unwrap();
        assert!(!sys.ran("bridge vlan add dev primary vid 3 self"));
        assert!(sys.writes_of("/run/cfab/workload-self-vid").is_empty());
    }

    #[test]
    fn down_removes_the_leg_and_only_a_self_vid_cfab_added() {
        // cfab added it: the record says so, so it comes off with the leg.
        let mut ours = MockSys::default()
            .on_stdout(
                &["ip", "link", "show", "cfab-work-vms"],
                "5: cfab-work-vms\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-work-vms"],
                "5: cfab-work-vms@primary: vlan protocol 802.1Q id 3 <REORDER_HDR>\n",
            )
            .file("/run/cfab/workload-self-vid", "primary 3\n");
        remove(&mut ours, "/run/cfab", "cfab-work-vms", "primary", 3).unwrap();
        assert!(ours.ran("ip link del cfab-work-vms"));
        assert!(ours.ran("bridge vlan del dev primary vid 3 self"));
        assert!(ours.ran("rm /run/cfab/workload-self-vid"));

        // The host had it before cfab ran (no record): the leg goes, the vid stays.
        let mut theirs = MockSys::default()
            .on_stdout(
                &["ip", "link", "show", "cfab-work-vms"],
                "5: cfab-work-vms\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-work-vms"],
                "5: cfab-work-vms@primary: vlan protocol 802.1Q id 3 <REORDER_HDR>\n",
            );
        remove(&mut theirs, "/run/cfab", "cfab-work-vms", "primary", 3).unwrap();
        assert!(theirs.ran("ip link del cfab-work-vms"));
        assert!(!theirs.ran("bridge vlan del dev primary vid 3 self"));
    }

    #[test]
    fn down_leaves_a_netdev_of_another_kind_wearing_the_legs_name_alone() {
        let mut foreign = MockSys::default()
            .on_stdout(
                &["ip", "link", "show", "cfab-work-vms"],
                "5: cfab-work-vms\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-work-vms"],
                "5: cfab-work-vms: <BROADCAST> ... bridge forward_delay 1500\n",
            );
        remove(&mut foreign, "/run/cfab", "cfab-work-vms", "primary", 3).unwrap();
        assert!(!foreign.ran("ip link del cfab-work-vms"));
        assert!(!present(&mut foreign, "cfab-work-vms", 3).unwrap());
    }

    #[test]
    fn a_record_with_two_bridges_keeps_the_other_line() {
        let mut sys = MockSys::default()
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .file("/run/cfab/workload-self-vid", "primary 3\nprimary2 4\n");
        remove(&mut sys, "/run/cfab", "cfab-work-vms", "primary", 3).unwrap();
        assert_eq!(
            sys.writes_to("/run/cfab/workload-self-vid"),
            Some("primary2 4")
        );
    }
}
