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

use crate::commands::apply::{mk_vlan, vlan_identity_is};
use crate::commands::common::link_exists;
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

/// The vids `bridge` carries on ITSELF. One reader for the bridge's own entry and for a
/// port's (`uplink::ports_carrying_vid` asks the same question of a port), so the two can
/// never drift apart on a future iproute2 output change.
pub fn self_vids(sys: &mut dyn Sys, bridge: &str) -> Result<BTreeSet<u16>> {
    crate::workload::uplink::vids_of(sys, bridge)
}

/// The netdev, if any, that already holds `vid` on `uplink` and is not our own `leg`.
///
/// The kernel allows exactly ONE 802.1Q device per (parent, vid): a host stanza that declares
/// `<bridge>.<vid>` (the pre-0.5.3 shape) takes the pair, and `ip link add … type vlan id <vid>`
/// then fails with `8021q: VLAN device already exists`. That failure used to take the whole
/// member down (apply errors, the supervisor exits 3, `RestartPreventExitStatus=3` keeps it
/// down), so the caller defers the row instead — which needs the holder's NAME, to say what to
/// remove. VERIFIED shape (pve1-tb, iproute2 6.15.0, 2026-09-10):
/// `[{"ifindex":661,"link":"eth9","ifname":"cfab-st",…,"linkinfo":{"info_kind":"vlan",
/// "info_data":{"protocol":"802.1Q","id":100,…}}}]`.
pub fn foreign_holder(
    sys: &mut dyn Sys,
    uplink: &str,
    vid: u16,
    leg: &str,
) -> Result<Option<String>> {
    let out = run_ok(sys, &["ip", "-d", "-j", "link", "show", "type", "vlan"])?;
    Ok(parse_foreign_holder(&out.stdout, uplink, vid, leg))
}

/// The `ifname` of the first entry whose parent is `uplink` and whose vlan id is `vid`, other
/// than `leg` itself. Anything unparsable — not JSON, a missing `link`/`ifname`/`id` — is simply
/// not a holder we can name, the same tolerance `parse_self_vids` takes: a false "no holder"
/// leaves the kernel to refuse the add as it did before, while a false holder would defer a row
/// that could have come up.
fn parse_foreign_holder(json: &str, uplink: &str, vid: u16, leg: &str) -> Option<String> {
    let doc = serde_json::from_str::<serde_json::Value>(json).ok()?;
    doc.as_array()?.iter().find_map(|entry| {
        let ifname = entry.get("ifname")?.as_str()?;
        if ifname == leg || entry.get("link")?.as_str()? != uplink {
            return None;
        }
        let id = entry
            .get("linkinfo")?
            .get("info_data")?
            .get("id")?
            .as_u64()?;
        (u16::try_from(id).ok()? == vid).then(|| ifname.to_string())
    })
}

/// One workload row's leg, as `install` builds it. A struct because the five facts travel
/// together everywhere (apply's ready row, the watchdog's rebuild) and a positional list of
/// them is a swap waiting to happen — the same shape `mk_bond_leg` takes.
#[derive(Debug, Clone, Copy)]
pub struct LegSpec<'a> {
    pub leg: &'a str,
    pub uplink: &'a str,
    pub vid: u16,
    /// This member's own address on the row, with the prefix's mask.
    pub address: &'a str,
    /// The anycast gateway. Not installed here (see `install`), only kept.
    pub gw_cidr: &'a str,
}

/// Create (or repair) the leg and give the bridge the vid if it lacks it.
///
/// `mk_vlan` is the same builder every other cfab leg uses, so a netdev of this name that is
/// not a vlan of this vid on THIS uplink is replaced rather than trusted, and one that is is
/// left where it is.
///
/// `gw_cidr` is not installed here — the callers add the anycast gw only after the bridge ARP
/// guard is up — but it is named here because this is where the leg's address list is
/// reconciled: a leg that outlives a supervisor stop can come back to a row whose `address`
/// changed meanwhile, and `ip addr replace` alone would leave BOTH on it.
pub fn install(sys: &mut dyn Sys, run_dir: &str, spec: &LegSpec, qos_map: &[&str]) -> Result<()> {
    let LegSpec {
        leg,
        uplink,
        vid,
        address,
        gw_cidr,
    } = *spec;
    mk_vlan(sys, leg, uplink, vid, Some(address), true, qos_map)?;
    prune_addresses(sys, leg, &[address, gw_cidr])?;
    // Address-then-vid on purpose, and momentarily: until the bridge carries the vid the leg
    // receives nothing, so the window is one where no traffic can arrive at the address anyway
    // (unlike the anycast `gw`, which apply/the watchdog deliberately install only after the
    // bridge ARP guard). Both steps are idempotent, so a failure here is repaired by the next
    // `install` rather than leaving a half-built leg that has to be unwound.
    ensure_self_vid(sys, run_dir, uplink, vid)?;
    Ok(())
}

/// Delete every IPv4 address on the leg other than the ones cfab means it to carry.
///
/// The leg is cfab's own netdev, created and named by cfab, so every address on it is cfab's to
/// manage — and there are exactly two: this member's declared `address` and the anycast `gw`.
/// This is scoped to the WORKLOAD leg, not to `mk_vlan`, because `mk_vlan`'s other callers do
/// not own their addresses the same way: the gw address arrives on the workload leg through a
/// separate `ip addr replace` AFTER the bridge ARP guard, so a prune inside `mk_vlan` would
/// delete and re-add the anycast gateway on every apply and every watchdog restore.
///
/// A read that fails prunes nothing: the address list is not a fact we have, and deleting on a
/// guess is the one thing this must never do. IPv6 never appears — `-4` asks for one family.
fn prune_addresses(sys: &mut dyn Sys, leg: &str, keep: &[&str]) -> Result<()> {
    let out = sys.run(&["ip", "-4", "-br", "addr", "show", "dev", leg])?;
    if !out.ok() {
        return Ok(());
    }
    for cidr in extra_addresses(&out.stdout, keep) {
        run_ok(sys, &["ip", "addr", "del", &cidr, "dev", leg])?;
    }
    Ok(())
}

/// The `<addr>/<len>` tokens of an `ip -4 -br addr show dev <leg>` line that are not in `keep`.
///
/// VERIFIED shape (pve1-tb, iproute2 6.15.0): `cfab-work-vms UP 192.168.20.2/24
/// 192.168.20.254/24` — ifname, state, then the addresses. Read by shape rather than by
/// position: a token counts only if it parses as `<IPv4>/<len>`, so neither the ifname nor a
/// state word (nor a future column) can ever be handed to `ip addr del`.
fn extra_addresses(brief: &str, keep: &[&str]) -> Vec<String> {
    brief
        .split_whitespace()
        .filter(|t| {
            t.split_once('/').is_some_and(|(a, len)| {
                a.parse::<std::net::Ipv4Addr>().is_ok() && len.parse::<u8>().is_ok_and(|n| n <= 32)
            })
        })
        .filter(|t| !keep.contains(t))
        .map(str::to_string)
        .collect()
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

/// Is the leg there, and ours? Same identity `mk_vlan` applies — kind vlan, this uplink, this
/// vid — so the watchdog and the builder can never disagree about what counts as present. A
/// netdev of that name failing any of the three is not this leg, and the caller rebuilds
/// (`install` replaces it) rather than counting it present.
pub fn present(sys: &mut dyn Sys, leg: &str, uplink: &str, vid: u16) -> Result<bool> {
    Ok(link_exists(sys, leg)? && vlan_identity_is(sys, leg, uplink, vid)?)
}

/// Remove the leg, and the bridge's vid if cfab is the one that added it.
///
/// Ownership is proven twice before anything is destroyed: the netdev must be a vlan of this
/// vid (a foreign netdev that happens to carry the name is left alone), and the vid must be in
/// cfab's own record (a vid the host had before cfab ran stays — VM ports keep their own vids
/// either way, this is only the bridge's self entry). The second proof is `release_vid`, which
/// a supervisor stop runs on its own: it keeps the netdev and gives the vid back.
pub fn remove(sys: &mut dyn Sys, run_dir: &str, leg: &str, uplink: &str, vid: u16) -> Result<()> {
    if present(sys, leg, uplink, vid)? {
        run_ok(sys, &["ip", "link", "del", leg])?;
    }
    release_vid(sys, run_dir, uplink, vid)
}

/// Give the bridge's self-vid back if — and only if — cfab's own record says cfab added it, and
/// forget the record either way. The netdev is not touched: this is the half of `remove` a
/// supervisor stop runs, and `install`'s `ensure_self_vid` is what puts the vid back at the
/// next `up`.
pub fn release_vid(sys: &mut dyn Sys, run_dir: &str, uplink: &str, vid: u16) -> Result<()> {
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

    /// The row every `install` test builds: `examples/fabric.toml`'s workload on pve1-tb.
    fn spec() -> LegSpec<'static> {
        LegSpec {
            leg: "cfab-work-vms",
            uplink: "primary",
            vid: 3,
            address: "192.168.20.2/24",
            gw_cidr: "192.168.20.254/24",
        }
    }

    fn sys_with_vlan_show(stdout: &str) -> MockSys {
        MockSys::default()
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .on_stdout(&["bridge", "-j", "vlan", "show", "dev", "primary"], stdout)
    }

    /// The VERIFIED output shape of `ip -d -j link show type vlan` (pve1-tb, iproute2 6.15),
    /// trimmed to the fields the walk reads: a foreign holder of vid 3 on `primary`, cfab's
    /// own storage leg on another parent, and cfab's own workload leg.
    const VLAN_SHOW: &str = r#"[{"ifindex":661,"link":"eth9","ifname":"cfab-st","linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":100}}},{"ifindex":662,"link":"primary","ifname":"primary.3","linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":3}}}]"#;

    #[test]
    fn a_foreign_vlan_device_holding_the_uplinks_vid_is_named() {
        assert_eq!(
            parse_foreign_holder(VLAN_SHOW, "primary", 3, "cfab-work-vms"),
            Some("primary.3".to_string())
        );
    }

    #[test]
    fn cfabs_own_leg_is_not_a_foreign_holder_of_its_own_vid() {
        let own = r#"[{"link":"primary","ifname":"cfab-work-vms","linkinfo":{"info_kind":"vlan","info_data":{"id":3}}}]"#;
        assert_eq!(
            parse_foreign_holder(own, "primary", 3, "cfab-work-vms"),
            None
        );
    }

    #[test]
    fn a_same_vid_device_on_a_different_parent_is_not_a_holder() {
        // vid 3 is only ever taken per (parent, vid): `primary2.3` does not block `primary`.
        let elsewhere = r#"[{"link":"primary2","ifname":"primary2.3","linkinfo":{"info_kind":"vlan","info_data":{"id":3}}}]"#;
        assert_eq!(
            parse_foreign_holder(elsewhere, "primary", 3, "cfab-work-vms"),
            None
        );
        // And a different vid on the right parent is not one either.
        assert_eq!(
            parse_foreign_holder(VLAN_SHOW, "primary", 4, "cfab-work-vms"),
            None
        );
    }

    #[test]
    fn unparsable_vlan_json_or_a_missing_field_claims_no_holder() {
        assert_eq!(
            parse_foreign_holder("Cannot find device", "primary", 3, "cfab-work-vms"),
            None
        );
        assert_eq!(
            parse_foreign_holder("[]", "primary", 3, "cfab-work-vms"),
            None
        );
        // Present but shapeless: no `link`, no `id`, no `ifname` — never a holder.
        let partial = r#"[{"ifname":"primary.3","linkinfo":{"info_kind":"vlan"}},{"link":"primary","linkinfo":{"info_kind":"vlan","info_data":{"id":3}}}]"#;
        assert_eq!(
            parse_foreign_holder(partial, "primary", 3, "cfab-work-vms"),
            None
        );
    }

    #[test]
    fn the_holder_probe_asks_the_kernel_for_vlan_devices() {
        let mut sys = MockSys::default().on_stdout(
            &["ip", "-d", "-j", "link", "show", "type", "vlan"],
            VLAN_SHOW,
        );
        assert_eq!(
            foreign_holder(&mut sys, "primary", 3, "cfab-work-vms").unwrap(),
            Some("primary.3".to_string())
        );
        assert!(sys.ran("ip -d -j link show type vlan"));
    }

    #[test]
    fn install_creates_the_leg_with_the_member_address_and_adds_the_missing_self_vid() {
        let mut sys = sys_with_vlan_show(
            r#"[{"ifname":"primary","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]}]}]"#,
        );
        install(&mut sys, "/run/cfab", &spec(), &["0:0", "6:6"]).unwrap();
        assert_eq!(
            sys.calls,
            vec![
                "ip link show cfab-work-vms",
                "ip link show cfab-work-vms",
                "ip link add link primary name cfab-work-vms type vlan id 3 egress-qos-map 0:0 6:6",
                "ip addr replace 192.168.20.2/24 dev cfab-work-vms",
                "ip link set cfab-work-vms up",
                "ip -4 -br addr show dev cfab-work-vms",
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
        install(&mut sys, "/run/cfab", &spec(), &["0:0", "6:6"]).unwrap();
        assert!(!sys.ran("bridge vlan add dev primary vid 3 self"));
        assert!(sys.writes_of("/run/cfab/workload-self-vid").is_empty());
    }

    /// A kept leg is judged by kind, PARENT and vid. A row whose `uplink` changed while cfab
    /// was stopped comes back to a netdev with the right name and the right vid on the wrong
    /// bridge; it is deleted and rebuilt, not trusted.
    #[test]
    fn a_kept_leg_on_the_wrong_uplink_is_rebuilt_and_one_on_the_right_uplink_is_left_alone() {
        let kept = |parent: &str| {
            sys_with_vlan_show(SHOW)
                .on_stdout(
                    &["ip", "link", "show", "cfab-work-vms"],
                    "9: cfab-work-vms\n",
                )
                .on_stdout(
                    &["ip", "-d", "link", "show", "cfab-work-vms"],
                    &format!("9: cfab-work-vms@{parent}: <UP> vlan protocol 802.1Q id 3 \n"),
                )
        };
        let mut moved = kept("oldbridge");
        install(&mut moved, "/run/cfab", &spec(), &["0:0", "6:6"]).unwrap();
        assert!(moved.ran("ip link del cfab-work-vms"));
        assert!(moved.ran(
            "ip link add link primary name cfab-work-vms type vlan id 3 egress-qos-map 0:0 6:6"
        ));

        // The teeth: the same leg on the declared bridge is never touched.
        let mut same = kept("primary");
        install(&mut same, "/run/cfab", &spec(), &["0:0", "6:6"]).unwrap();
        assert!(!same.ran("ip link del cfab-work-vms"));
        assert!(!same.calls.iter().any(|c| c.starts_with("ip link add")));
        assert!(!same.calls.iter().any(|c| c.starts_with("ip addr del")));

        // The watchdog reads the same identity, so it can never call a leg on the wrong bridge
        // present and skip the rebuild the builder would do.
        assert!(!present(&mut kept("oldbridge"), "cfab-work-vms", "primary", 3).unwrap());
        assert!(present(&mut kept("primary"), "cfab-work-vms", "primary", 3).unwrap());
    }

    /// A row whose `address` changed while cfab was stopped: `ip addr replace` adds the new one
    /// and leaves the old, so every other IPv4 address on the leg is deleted. The anycast `gw`
    /// is not "other" — the callers install it separately, after the bridge ARP guard.
    #[test]
    fn install_deletes_a_stale_address_the_kept_leg_still_carries_and_keeps_the_gw() {
        let mut sys = sys_with_vlan_show(SHOW)
            .on_stdout(
                &["ip", "link", "show", "cfab-work-vms"],
                "9: cfab-work-vms\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-work-vms"],
                "9: cfab-work-vms@primary: <UP> vlan protocol 802.1Q id 3 \n",
            )
            .on_stdout(
                &["ip", "-4", "-br", "addr", "show", "dev", "cfab-work-vms"],
                "cfab-work-vms UP 192.168.20.9/24 192.168.20.2/24 192.168.20.254/24\n",
            );
        install(&mut sys, "/run/cfab", &spec(), &["0:0", "6:6"]).unwrap();
        assert!(sys.ran("ip addr replace 192.168.20.2/24 dev cfab-work-vms"));
        assert!(sys.ran("ip addr del 192.168.20.9/24 dev cfab-work-vms"));
        assert_eq!(
            sys.calls
                .iter()
                .filter(|c| c.starts_with("ip addr del"))
                .count(),
            1,
            "the member address and the anycast gw both stay"
        );
    }

    #[test]
    fn the_address_list_is_read_by_shape_so_no_column_can_become_a_delete() {
        // ifname and state are not addresses, and neither is anything else without a valid
        // `<IPv4>/<len>`; an empty read (a leg with no address yet) deletes nothing.
        assert_eq!(
            extra_addresses(
                "cfab-work-vms UP 192.168.20.9/24 192.168.20.2/24",
                &["192.168.20.2/24"]
            ),
            vec!["192.168.20.9/24".to_string()]
        );
        assert!(extra_addresses("cfab-work-vms DOWN \n", &[]).is_empty());
        assert!(extra_addresses("", &[]).is_empty());
        assert!(extra_addresses("cfab-work-vms UP 192.168.20.2/99", &[]).is_empty());
        assert!(extra_addresses("cfab-work-vms UP fe80::1/64", &[]).is_empty());
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
        assert!(!present(&mut foreign, "cfab-work-vms", "primary", 3).unwrap());
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
