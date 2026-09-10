//! `cfab down` — remove the fabric from THIS member (a reboot does the same, harder).
//! Order matters: forwarding OFF first (fail closed even mid-teardown), then policy, then
//! netdevs. Prove-ownership: only deletes cfab-* netdevs of the expected kind.

use std::path::{Path, PathBuf};

use crate::commands::common::{
    conf_interfaces, drop_rules, has_ip_addr, link_exists, link_kind_is,
    remove_foreign_transit_accept,
};
use crate::commands::engine_ctl;
use crate::derive::{Port, View};
use crate::emit::ceiling_ipt::Backend as MarkBackend;
use crate::error::{Error, Result};
use crate::model::MemberKind;
use crate::sys::{Sys, UnixProbe, have_tool, run_ignore, run_ok};

/// Stage one of the teardown, callable alone: forwarding OFF, the forward policy off, and the
/// foreign-stack accept removed. Run before anything that can fail or block — this is what
/// lets the supervisor's stop sequence fail closed *first* (spec §13): everything after this
/// point can be `SIGKILL`ed by `TimeoutStopSec` without a packet transiting a half-torn-down
/// host.
///
/// Host-only (RULED, James 2026-09-05, on Gate A review finding 6/B4): a leaf has no global
/// forwarding to turn off, and its leak-guard `ip rule`s are its ONLY containment — dropping
/// them here would fail *open* for the rest of the teardown (netdevs, addresses and routes
/// all still present), the opposite of what "stage one, fail closed first" means. The leaf's
/// rules come off in the main body below, after its netdevs are gone.
pub fn forwarding_off(sys: &mut dyn Sys, view: &View) -> Result<()> {
    if view.kind() != MemberKind::Host {
        return Ok(());
    }
    for ifn in conf_interfaces(sys)? {
        if view.owns_if(&ifn) {
            sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
        }
    }
    if have_tool(sys, "nft")? {
        run_ignore(sys, &["nft", "delete", "table", "inet", "cfab-fwd"])?;
    }
    // custody: the accept `up` put in a foreign user hook is ours to remove, and only the
    // rule carrying our tag is touched
    remove_foreign_transit_accept(sys)?;
    Ok(())
}

/// `cfab down` from the command line. It is the out-of-band teardown — for a SIGKILLed
/// supervisor, stale state, or a host with no service — so it must never race the supervisor's
/// own stop sequence on the same netdevs (spec §10). If a supervisor answers on
/// `<run_dir>/cfab.sock`, refuse and name the remedy, changing nothing; otherwise tear down.
///
/// This is distinct from the `engine.lock` refusal in `run` below (spec §14): that one guards a
/// live *engine* still owning the run_dir; this one guards a live *supervisor* that owns the
/// whole stop sequence. The two conditions have their own spellings so an operator is never told
/// the wrong remedy.
pub fn run_cli(sys: &mut dyn Sys, view: &View) -> Result<String> {
    let sock = PathBuf::from(&view.fabric.run_dir).join("cfab.sock");
    match sys.unix_probe(&sock.to_string_lossy(), "components\n") {
        // Provably nobody home: this is the SIGKILLed-supervisor / no-service recovery path.
        UnixProbe::NotListening => run(sys, view),
        // A reply proves a supervisor owns the teardown — name its pid if we can read it.
        UnixProbe::Answered(reply) => Err(supervisor_refusal(&pid_of(&reply))),
        // Connected but silent (a live-but-slow supervisor, a read timeout). A successful
        // connect already proves a listener: refuse, never infer absence from a late reply.
        UnixProbe::Unreachable(_) => Err(supervisor_refusal("unknown")),
    }
}

/// The supervisor's pid from a `components` reply, or `unknown` when the reply does not parse or
/// omits the field — either way the supervisor is running, so the refusal still fires.
fn pid_of(reply: &str) -> String {
    serde_json::from_str::<serde_json::Value>(reply)
        .ok()
        .and_then(|v| v["supervisor"]["pid"].as_u64())
        .map_or_else(|| "unknown".to_string(), |p| p.to_string())
}

fn supervisor_refusal(pid: &str) -> Error {
    Error::fatal(format!(
        "REFUSING: a cfab supervisor is running (pid {pid}) — stop the service instead \
         (systemctl stop cfab, or docker stop <container>)"
    ))
}

/// The ingress leg's two shapes wear ONE name (`cfab-gw<id>`): a plain tagged sub-interface on
/// a single gw domain, an active-backup bond over every wire on scope `any`. Which one is on
/// the box is read FROM the box — a declaration flipped between the two says the wrong thing
/// about a leg the previous one built — and both `down` and `up` remove it through this one
/// function, so the flip can always be undone and always be applied.
///
/// Bond before ports: `ip link del <bond>` RELEASES its ports, it does not delete them, and
/// the port names come from this member's wires because the declaration stops listing them the
/// moment the scope flips. A netdev of neither shape is a stranger wearing our name and is
/// refused, never deleted.
///
/// Returns which shape was removed — for the caller's one log line — or `None` when the leg is
/// not on the box at all.
pub(crate) fn remove_gw_leg(
    sys: &mut dyn Sys,
    member: &crate::model::Member,
    ifname: &str,
) -> Result<Option<&'static str>> {
    if !link_exists(sys, ifname)? {
        return Ok(None);
    }
    if link_kind_is(sys, ifname, " bond ")? {
        run_ok(sys, &["ip", "link", "del", ifname])?;
        for s in crate::derive::ports_of(member, ifname) {
            if !link_exists(sys, &s.ifname)? {
                continue;
            }
            if !link_kind_is(sys, &s.ifname, " vlan ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {} exists but is not a vlan",
                    s.ifname
                )));
            }
            run_ok(sys, &["ip", "link", "del", &s.ifname])?;
        }
        return Ok(Some("bond"));
    }
    if !link_kind_is(sys, ifname, " vlan ")? {
        return Err(Error::fatal(format!(
            "REFUSING: {ifname} exists but is not a vlan"
        )));
    }
    run_ok(sys, &["ip", "link", "del", ifname])?;
    Ok(Some("sub-interface"))
}

pub fn run(sys: &mut dyn Sys, view: &View) -> Result<String> {
    let f = view.fabric;
    let mut notes = Vec::new();

    forwarding_off(sys, view)?;

    // The mark state (marking + the fallback control-egress ceiling) is installed on every
    // kind, so it comes off on every kind — through whichever backend `up` recorded. With no
    // record (a wiped run dir, a downgrade) BOTH are attempted: leaving a member's mark state
    // resident because we could not remember how it got there is the failure mode this
    // teardown exists to prevent. Each half is `have_tool`-guarded, keeping the
    // survive-a-changed-environment property the nft line already had.
    let backend = crate::emit::ceiling_ipt::recorded(sys, &f.run_dir);
    if backend != Some(MarkBackend::IptablesLegacy) && have_tool(sys, "nft")? {
        run_ignore(sys, &["nft", "delete", "table", "inet", "cfab"])?;
    }
    if backend != Some(MarkBackend::Nft) {
        crate::commands::common::remove_mark_ipt(sys)?;
    }
    // Workload bridge ARP guard, gw address, then the leg itself (the exact reverse of apply's
    // order): the guard table is one per member, not one per row, so it comes off once, gated
    // on the FIRST row (an empty `workload_rows()` skips this entirely — a member with no
    // `[[workload]]` row never ran `nft list table bridge cfab` at all). `forwarding_off` above
    // already covers the leg (it iterates `owned_forwarding()`, which lists every workload
    // row); `arp_ignore` is left exactly as `up` set it (ruling 11) — `down` never touches it.
    // `leg::remove` proves ownership twice before it destroys anything: the netdev must be a
    // vlan of this vid, and the vid on the bridge must be one cfab's own record says cfab
    // added. The UPLINK is the host's bridge and is never a delete candidate.
    if !view.workload_rows().is_empty() {
        // M2 (whole-branch review): `have_tool`-guarded like the mark removal above — a missing
        // nft must never abort `down` before the gw address and rule removal below it run.
        if have_tool(sys, "nft")? {
            let bridge_present = sys.run(&["nft", "list", "table", "bridge", "cfab"])?.ok();
            if bridge_present {
                run_ok(sys, &["nft", "delete", "table", "bridge", "cfab"])?;
            }
        }
        for row in view.workload_rows() {
            let ifname = &row.wl.leg_ifname();
            let gw_cidr = row.wl.gw_cidr();
            let addr = sys.run(&["ip", "-4", "-br", "addr", "show", "dev", ifname])?;
            if has_ip_addr(&addr.stdout, &gw_cidr) {
                run_ok(sys, &["ip", "addr", "del", &gw_cidr, "dev", ifname])?;
            }
            crate::workload::leg::remove(sys, &f.run_dir, ifname, &row.wl.uplink, row.wl.vid)?;
        }
    }
    // The engine stops (and its routes are swept) before any interface goes away, so it never
    // acts on vanished links. A zone's table now holds two things cfab owns: the engine's
    // routes (swept here with the engine) and, on a gw zone, cfab's own proto-205 return-path
    // default (deleted explicitly below). Anything else left in the table is not ours and is
    // left alone (the leftover-note loop says so).
    engine_ctl::stop_and_sweep(sys, f)?;
    // return-path rules (both kinds), plus the pref-2000 workload siblings (spec §5 item 4):
    // computed once, fabric-wide, then filtered per zone below — one `FabricRule` shape (tail-
    // only `.add`), so `drop_rules` (which prepends `ip rule del pref <pref>` itself) is the
    // only way any of these rules is added to or removed from the kernel.
    let workload_rules = crate::commands::common::workload_return_rules(view);
    for z in &f.zones {
        let blk = format!("{}.0.0/16", z.block());
        let id = z.id.to_string();
        drop_rules(
            sys,
            "2000",
            &format!("from {blk} to {blk} lookup main suppress_prefixlength 0"),
            &[
                "from",
                &blk,
                "to",
                &blk,
                "lookup",
                "main",
                "suppress_prefixlength",
                "0",
            ],
        )?;
        for r in workload_rules
            .iter()
            .filter(|r| r.needle.starts_with(&format!("from {blk} to ")))
        {
            let del: Vec<&str> = r.add.iter().map(String::as_str).collect();
            drop_rules(sys, &r.pref, &r.needle, &del)?;
        }
        drop_rules(
            sys,
            "2001",
            &format!("from {blk} lookup {id}"),
            &["from", &blk, "lookup", &id],
        )?;
        drop_rules(
            sys,
            "2002",
            &format!("from {blk} unreachable"),
            &["from", &blk, "unreachable"],
        )?;
    }
    // cfab's own return-path default (up installs it, proto 205): deleted by exact key
    // (prefix `default`, the zone's table, proto 205), never a broad pattern, so only the route
    // cfab owns is removed. Idempotent like the neighboring teardown (`run_ignore`): the leg's
    // netdev may already be gone, taking the route with it.
    let proto = crate::emit::engine::CFAB_PROTO.to_string();
    for r in view.gw_rows() {
        let z = f.zone(&r.zone)?;
        run_ignore(
            sys,
            &[
                "ip",
                "route",
                "del",
                "default",
                "table",
                &z.id.to_string(),
                "proto",
                &proto,
            ],
        )?;
    }

    // The additive host default (spec §6): the 250 route by its exact key, then the pref
    // 2099-2101 rules that reach it — the same function the unwind of a half-installed `up`
    // uses, and idempotent, so a member that never carried one tears down clean.
    crate::commands::common::remove_host_default(sys)?;

    // Review finding 11 (2026-09-05, escalated to blocking — B3): refuse before destroying
    // the run_dir if `engine.lock` is still held. `stop_and_sweep` above only signals a
    // systemd-managed engine; a detached (non-systemd) one has no stop mechanism in this
    // gate at all and may still be alive. Removing its socket/lock files here would let the
    // very next `cfab engine` take a FRESH, uncontended lock on a new inode — two live
    // engines, exactly the state the flock (spec §14) exists to make unrepresentable.
    // Checked directly against the real filesystem, matching `supervisor::lock` itself (not
    // through `Sys` — the flock is a kernel object, not something to mock), and only when
    // the run_dir exists at all: a member that was never applied has nothing to hold.
    let lock_path = PathBuf::from(&f.run_dir).join(crate::engine::LOCK_NAME);
    if Path::new(&f.run_dir).exists()
        && let Err(held) = crate::supervisor::lock::hold(&lock_path)
    {
        return Err(Error::fatal(format!(
            "an engine is still running (pid {} holds {}); stop it first — teardown refuses \
             to remove a run_dir a live engine still owns",
            held.pid.map_or("unknown".to_string(), |p| p.to_string()),
            lock_path.display()
        )));
    }
    // NIC features are the host's own business now (a udev rule on the netdev-add event): `up`
    // never sets one, so `down` has nothing to put back. The driver record (`wire-drivers`)
    // goes with the rest of the run dir below, unread — `down` never runs ethtool at all.
    sys.remove(&f.run_dir)?;

    // Netdevs, prove-ownership-before-destroy: expected kind or refuse.
    // Fallback legs, bonds before ports: `ip link del <bond>` RELEASES its ports, it does not
    // delete them, which is why the second loop exists. The engine is already stopped and its
    // routes swept above, so this order is ownership-proof clarity, nothing more.
    let fallback_rows = view.fallback_rows();
    let bond_legs: Vec<(&str, &[Port])> = fallback_rows
        .iter()
        .map(|r| (r.ifname.as_str(), r.ports.as_slice()))
        .collect();
    for (ifname, _) in &bond_legs {
        if link_exists(sys, ifname)? {
            if !link_kind_is(sys, ifname, " bond ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {ifname} exists but is not a bond"
                )));
            }
            run_ok(sys, &["ip", "link", "del", ifname])?;
        }
    }
    for s in bond_legs.iter().flat_map(|(_, ports)| *ports) {
        if link_exists(sys, &s.ifname)? {
            if !link_kind_is(sys, &s.ifname, " vlan ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {} exists but is not a vlan",
                    s.ifname
                )));
            }
            run_ok(sys, &["ip", "link", "del", &s.ifname])?;
        }
    }
    // The ingress leg, in whatever shape the box has it — see `remove_gw_leg`. After the
    // universal segments, so each leg reads as one unit: the bond, then the ports deleting it
    // released.
    for r in &view.gw_rows() {
        remove_gw_leg(sys, view.member, &r.ifname)?;
    }
    let ifnames: Vec<String> = view.class_rows().into_iter().map(|r| r.ifname).collect();
    for dev in &ifnames {
        if link_exists(sys, dev)? {
            if !link_kind_is(sys, dev, " vlan ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {dev} exists but is not a vlan"
                )));
            }
            run_ok(sys, &["ip", "link", "del", dev])?;
        }
    }
    for z in &f.zones {
        let dev = View::identity_if(z);
        if link_exists(sys, &dev)? {
            if !link_kind_is(sys, &dev, " veth ")? {
                return Err(Error::fatal(format!(
                    "REFUSING: {dev} exists but is not a veth"
                )));
            }
            run_ok(sys, &["ip", "link", "del", &dev])?; // deletes the pair
        }
        if link_exists(sys, &format!("{dev}-peer"))? {
            return Err(Error::fatal(format!(
                "REFUSING: {dev}-peer exists without {dev} (not ours)"
            )));
        }
        run_ignore(
            sys,
            &[
                "ip",
                "route",
                "del",
                "unreachable",
                &format!("{}.0.0/16", z.block()),
            ],
        )?;
        let left = sys.run(&["ip", "route", "show", "table", &z.id.to_string()])?;
        if !left.stdout.trim().is_empty() {
            notes.push(format!(
                "note: table {} still holds routes not ours (left alone): {}",
                z.id,
                left.stdout.trim()
            ));
        }
    }
    if view.kind() == MemberKind::Host {
        for dev in view.wires() {
            run_ignore(sys, &["tc", "qdisc", "del", "dev", &dev, "root"])?;
        }
    } else {
        // B4 (ruling): the leaf's leak-guard rules are its only containment, so they come
        // off here — after its netdevs are already gone — rather than in `forwarding_off`
        // (stage one), where removing them first would fail open for the rest of teardown.
        for z in &f.zones {
            let blk = format!("{}.0.0/16", z.block());
            drop_rules(
                sys,
                "1000",
                &format!("to {blk} iif lo lookup main"),
                &["to", &blk, "iif", "lo", "lookup", "main"],
            )?;
            drop_rules(
                sys,
                "1001",
                &format!("to {blk} unreachable"),
                &["to", &blk, "unreachable"],
            )?;
        }
    }
    let mut msg = notes.join("\n");
    if !msg.is_empty() {
        msg.push('\n');
    }
    msg.push_str(&format!("teardown OK on {}\n", view.member.name));
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::Declaration;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    fn wl_fabric() -> Fabric {
        Fabric::from_decl(
            &Declaration::parse(&crate::decl::fixtures::with_workload(
                &crate::decl::fixtures::example(),
            ))
            .unwrap(),
        )
        .unwrap()
    }

    /// The state `up` leaves: every other netdev absent (the `.on_fail(ip link show)` baseline
    /// the rest of this file's minimal-state tests share — there is no separate "healthy
    /// teardown" fixture here), the workload leg present and of the vid `up` built it with, the
    /// vid `up` gave the bridge recorded as cfab's, guard table present, gw on the leg, both
    /// 2000 rules.
    fn wl_down_sys() -> MockSys {
        MockSys::default()
            .on_fail(&["ip", "link", "show"], 1, "no")
            .on_stdout(
                &["ip", "link", "show", "cfab-work-vms"],
                "9: cfab-work-vms@primary: <UP>\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-work-vms"],
                "9: cfab-work-vms@primary: <UP> vlan protocol 802.1Q id 3 \n",
            )
            .file("/run/cfab/workload-self-vid", "primary 3")
            // The conf entry `up`'s `enable_forwarding` left on the leg —
            // `forwarding_off`'s `conf_interfaces` scan needs it present to find it.
            .file("/proc/sys/net/ipv4/conf/cfab-work-vms/forwarding", "1\n")
            .on_stdout(
                &["nft", "list", "table", "bridge", "cfab"],
                "table bridge cfab {\n}\n",
            )
            .on_stdout(
                &["ip", "-4", "-br", "addr", "show", "dev", "cfab-work-vms"],
                "cfab-work-vms UP 192.168.20.2/24 192.168.20.254/24\n",
            )
            .on_stdout(
                &["ip", "rule", "show", "pref", "2000"],
                "2000:\tfrom 10.99.0.0/16 to 10.99.0.0/16 lookup main suppress_prefixlength 0\n\
                 2000:\tfrom 10.99.0.0/16 to 192.168.20.0/24 lookup main\n",
            )
    }

    /// cfab creates the leg and gives the bridge the vid, so `down` takes both away again — and
    /// nothing else: the bridge is the host's, and its other vids (the untagged default, every
    /// VM port's) are none of cfab's business.
    #[test]
    fn down_removes_the_bridge_table_the_gw_address_the_sibling_rules_the_leg_and_the_self_vid() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wl_down_sys();
        run(&mut sys, &view).unwrap();
        assert!(sys.ran("nft delete table bridge cfab"));
        assert!(sys.ran("ip addr del 192.168.20.254/24 dev cfab-work-vms"));
        assert!(sys.ran("ip rule del pref 2000 from 10.99.0.0/16 to 192.168.20.0/24 lookup main"));
        assert_eq!(
            sys.writes_of("/proc/sys/net/ipv4/conf/cfab-work-vms/forwarding")
                .last(),
            Some(&"0")
        );
        assert!(sys.ran("ip link del cfab-work-vms"));
        assert!(sys.ran("bridge vlan del dev primary vid 3 self"));
        assert!(sys.ran("rm /run/cfab/workload-self-vid"));
        assert!(
            !sys.calls.iter().any(|c| c == "ip link del primary"),
            "the uplink is the host's: never deleted"
        );
        assert!(
            !sys.ran("bridge vlan del dev primary vid 1"),
            "only the vid cfab added"
        );
        assert!(
            sys.writes_of("/proc/sys/net/ipv4/conf/all/arp_ignore")
                .is_empty(),
            "down leaves arp_ignore (ruling 11)"
        );
    }

    /// Prove ownership before destroy, half one: a vid the HOST already had when cfab came up
    /// is not in cfab's record, so `down` leaves it on the bridge — deleting it would cut every
    /// VM on that vlan off from the rest of the world.
    #[test]
    fn down_leaves_a_self_vid_cfab_never_added() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wl_down_sys();
        sys.files.remove("/run/cfab/workload-self-vid");
        run(&mut sys, &view).unwrap();
        assert!(sys.ran("ip link del cfab-work-vms"));
        assert!(!sys.ran("bridge vlan del dev primary"));
    }

    /// Prove ownership before destroy, half two: a netdev carrying the leg's name that is NOT a
    /// vlan of this vid is somebody else's and is left where it is. The vid cfab recorded still
    /// comes off — cfab added that itself, whatever later happened to the name.
    #[test]
    fn down_leaves_a_foreign_netdev_that_only_carries_the_legs_name() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wl_down_sys().on_stdout(
            &["ip", "-d", "link", "show", "cfab-work-vms"],
            "9: cfab-work-vms: <UP> bond \n",
        );
        run(&mut sys, &view).unwrap();
        assert!(!sys.ran("ip link del cfab-work-vms"));
        assert!(sys.ran("bridge vlan del dev primary vid 3 self"));
    }

    #[test]
    fn down_skips_what_is_already_gone() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wl_down_sys()
            .on_fail(
                &["nft", "list", "table", "bridge", "cfab"],
                1,
                "Error: No such file or directory",
            )
            .on_stdout(
                &["ip", "-4", "-br", "addr", "show", "dev", "cfab-work-vms"],
                "cfab-work-vms UP 192.168.20.2/24\n",
            )
            .on_stdout(
                &["ip", "rule", "show", "pref", "2000"],
                "2000:\tfrom 10.99.0.0/16 to 10.99.0.0/16 lookup main suppress_prefixlength 0\n",
            );
        run(&mut sys, &view).unwrap();
        assert!(!sys.ran("nft delete table bridge cfab"));
        assert!(!sys.ran("ip addr del 192.168.20.254/24"));
        assert!(!sys.ran("ip rule del pref 2000 from 10.99.0.0/16 to 192.168.20.0/24"));
    }

    #[test]
    fn down_does_not_mistake_a_substring_collision_for_the_gw_address_being_present() {
        // 192.168.20.254/24 is a SUBSTRING of 1192.168.20.254/24; a `.contains()` check would
        // wrongly try to delete an address that was never applied.
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wl_down_sys().on_stdout(
            &["ip", "-4", "-br", "addr", "show", "dev", "cfab-work-vms"],
            "cfab-work-vms UP 192.168.20.2/24 1192.168.20.254/24\n",
        );
        run(&mut sys, &view).unwrap();
        assert!(!sys.ran("ip addr del 192.168.20.254/24 dev cfab-work-vms"));
    }

    // M2 (whole-branch review): the bridge-guard presence read used a bare `?`, unlike the
    // `have_tool`-guarded mark removal right above it — with nft removed, `RealSys::run` maps
    // the exec failure to `Err`, and `down` aborted BEFORE the gw address and rule removal below
    // it ever ran, leaving a half-torn-down host. `have_tool`-guard it the same way.
    #[test]
    fn down_continues_past_a_missing_nft_and_still_removes_the_gw_address_and_rules() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wl_down_sys().on_fail(&["/usr/bin/env", "sh", "-c", "command -v nft"], 1, "");
        run(&mut sys, &view).unwrap();
        assert!(!sys.ran("nft list table bridge cfab"));
        assert!(!sys.ran("nft delete table bridge cfab"));
        assert!(sys.ran("ip addr del 192.168.20.254/24 dev cfab-work-vms"));
        assert!(sys.ran("ip rule del pref 2000 from 10.99.0.0/16 to 192.168.20.0/24 lookup main"));
        assert_eq!(
            sys.writes_of("/proc/sys/net/ipv4/conf/cfab-work-vms/forwarding")
                .last(),
            Some(&"0")
        );
    }

    /// Every netdev absent except the fallback leg of the storage zone, correctly typed.
    fn sys_with_a_storage_fallback_leg() -> MockSys {
        MockSys::default()
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .on_stdout(&["ip", "link", "show", "cfab-st-fb"], "9: cfab-st-fb\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb"],
                "9: cfab-st-fb: bond \n",
            )
            .on_stdout(
                &["ip", "link", "show", "cfab-st-fb-a"],
                "10: cfab-st-fb-a\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb-a"],
                "10: cfab-st-fb-a@eth9: vlan protocol 802.1Q id 300 \n",
            )
    }

    /// A run dir from an OLDER cfab version may still carry the retired `wire-driver-features`
    /// record (features `up` used to change and `down` used to put back). NIC features are the
    /// host's own business now, so `down` never reads it: no ethtool call, nothing said about
    /// features, legacy record or not.
    #[test]
    fn down_ignores_a_legacy_wire_driver_features_record_and_runs_no_ethtool() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg()
            .file("/run/cfab/mark.backend", "nft\n")
            .file(
                "/run/cfab/wire-driver-features",
                "eth9 sg on\neth9 tso on\n",
            );
        let msg = run(&mut sys, &view).unwrap();
        assert!(!sys.ran("ethtool"), "{:?}", sys.calls);
        assert!(!msg.contains("driver features"), "{msg}");
    }

    /// The ordinary case, no legacy record at all: still no ethtool, still nothing said.
    #[test]
    fn down_without_any_feature_record_runs_no_ethtool() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg().file("/run/cfab/mark.backend", "nft\n");
        let msg = run(&mut sys, &view).unwrap();
        assert!(!sys.ran("ethtool"), "{:?}", sys.calls);
        assert!(!msg.contains("driver features"), "{msg}");
    }

    /// A mangle dump with our chains resident, plus a foreign chain that must survive.
    fn ipt_mangle_save() -> &'static str {
        "*mangle\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [9:600]\n:DOCKER-USER - [0:0]\n\
         :cfab-out - [0:0]\n:cfab-ceil-storage - [0:0]\n-A OUTPUT -j cfab-out\n\
         -A cfab-out -j cfab-ceil-storage\n-A cfab-ceil-storage -j DROP\nCOMMIT\n"
    }

    /// The recorded backend is the one torn down, and only that one: an nft member never
    /// runs iptables at all.
    #[test]
    fn down_on_the_nft_record_touches_only_nft() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg().file("/run/cfab/mark.backend", "nft\n");
        run(&mut sys, &view).unwrap();
        assert!(sys.ran("nft delete table inet cfab"), "{:?}", sys.calls);
        // (`iptables -S DOCKER-USER` is the foreign-transit-accept removal, unrelated to the
        // mark state and unchanged; the legacy binaries are what this backend never runs.)
        assert!(!sys.ran("iptables-legacy"), "{:?}", sys.calls);
    }

    /// The iptables-legacy record: the OUTPUT jump goes, then every `cfab-*` mangle chain the
    /// readback names — flushed before deleted, by exact name. The foreign chain in the same
    /// table is never touched, and nft is not consulted.
    #[test]
    fn down_on_the_iptables_record_removes_our_chains_by_exact_name() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg()
            .file("/run/cfab/mark.backend", "iptables-legacy\n")
            .on_stdout(&["iptables-legacy-save", "-t", "mangle"], ipt_mangle_save());
        run(&mut sys, &view).unwrap();
        let ipt: Vec<String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("iptables-legacy"))
            .cloned()
            .collect();
        assert_eq!(
            ipt,
            vec![
                "iptables-legacy-save -t mangle",
                "iptables-legacy -t mangle -D OUTPUT -j cfab-out",
                "iptables-legacy -t mangle -F cfab-out",
                "iptables-legacy -t mangle -F cfab-ceil-storage",
                "iptables-legacy -t mangle -X cfab-out",
                "iptables-legacy -t mangle -X cfab-ceil-storage",
            ],
            "{:?}",
            sys.calls
        );
        assert!(!sys.ran("DOCKER-USER"), "{:?}", sys.calls);
        assert!(!sys.ran("nft delete table inet cfab\n"), "{:?}", sys.calls);
    }

    /// No record at all — a wiped run dir, a downgrade from a version that never wrote one.
    /// BOTH backends are torn down: leaving a member policed by a mechanism we could not
    /// remember choosing is the failure this teardown exists to prevent.
    #[test]
    fn down_with_no_record_tears_down_both_backends() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg()
            .on_stdout(&["iptables-legacy-save", "-t", "mangle"], ipt_mangle_save());
        run(&mut sys, &view).unwrap();
        assert!(sys.ran("nft delete table inet cfab"), "{:?}", sys.calls);
        assert!(
            sys.ran("iptables-legacy -t mangle -X cfab-ceil-storage"),
            "{:?}",
            sys.calls
        );
    }

    /// ...and each half is guarded, so a member that no longer has the other backend's
    /// binaries still tears down cleanly instead of failing on an absent tool.
    #[test]
    fn down_with_no_record_survives_a_member_without_iptables() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg().on_fail(
            &["/usr/bin/env", "sh", "-c", "command -v iptables-legacy"],
            1,
            "",
        );
        run(&mut sys, &view).unwrap();
        assert!(sys.ran("nft delete table inet cfab"), "{:?}", sys.calls);
        assert!(!sys.ran("iptables-legacy -t"), "{:?}", sys.calls);
    }

    /// `ip link del <bond>` RELEASES its ports, it does not delete them — so the ports get
    /// their own deletes, and the bond goes first (ownership-proof clarity: the engine is
    /// already stopped and swept before any netdev is touched).
    #[test]
    fn down_deletes_a_fallback_bond_before_its_ports() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg();
        run(&mut sys, &view).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("ip link del"))
            .collect();
        assert_eq!(dels, ["ip link del cfab-st-fb", "ip link del cfab-st-fb-a"]);
    }

    /// Task 9: a migrating ingress leg is a bond, so it is torn down as one — bond first,
    /// then its ports. Deleting it in the plain sub-interface loop would REFUSE it
    /// ("not a vlan") and strand the leg on a `cfab down`. The ingress leg is now removed as
    /// one unit after the universal segments (`remove_gw_leg`, shared with `up`) rather than
    /// interleaved with them; the ordering was always "ownership-proof clarity, nothing more"
    /// — the engine is stopped and its routes swept long before any netdev is touched.
    #[test]
    fn down_deletes_a_migrating_gw_bond_before_its_ports() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg()
            .on_stdout(&["ip", "link", "show", "cfab-gw249"], "20: cfab-gw249\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249"],
                "20: cfab-gw249: bond \n",
            )
            .on_stdout(
                &["ip", "link", "show", "cfab-gw249-c"],
                "21: cfab-gw249-c\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249-c"],
                "21: cfab-gw249-c@eth0: vlan protocol 802.1Q id 249 \n",
            );
        run(&mut sys, &view).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("ip link del"))
            .collect();
        assert_eq!(
            dels,
            [
                "ip link del cfab-st-fb",
                "ip link del cfab-st-fb-a",
                "ip link del cfab-gw249",
                "ip link del cfab-gw249-c",
            ]
        );
    }

    /// The same declaration with the ingress leg pinned to one domain — the example ships
    /// scope `any`, the migrating leg.
    fn fabric_with_a_domain_gw() -> Fabric {
        let text = crate::decl::fixtures::with_a_domain_gw(&crate::decl::fixtures::example());
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    /// A live ingress BOND named by a declaration that now puts the gw on one domain, plus its
    /// three ports: what an operator has after flipping `any` -> a domain.
    fn sys_with_a_migrating_gw_leg() -> MockSys {
        let mut sys = sys_with_a_storage_fallback_leg()
            .on_stdout(&["ip", "link", "show", "cfab-gw249"], "20: cfab-gw249\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249"],
                "20: cfab-gw249: bond \n",
            );
        for (i, (port, wire)) in [
            ("cfab-gw249-a", "eth9"),
            ("cfab-gw249-b", "eth1"),
            ("cfab-gw249-c", "eth0"),
        ]
        .iter()
        .enumerate()
        {
            sys = sys
                .on_stdout(
                    &["ip", "link", "show", port],
                    &format!("{}: {port}\n", 21 + i),
                )
                .on_stdout(
                    &["ip", "-d", "link", "show", port],
                    &format!("{}: {port}@{wire}: vlan protocol 802.1Q id 249 \n", 21 + i),
                );
        }
        sys
    }

    /// The declaration on disk says the gw is on ONE domain; the running fabric wears the bond
    /// the PREVIOUS declaration built. `down` must remove what is really there — bond first,
    /// then every port — or the flip can be neither applied nor undone: the plain
    /// sub-interface loop refuses a bond ("not a vlan") and strands the leg.
    #[test]
    fn down_removes_an_ingress_bond_the_previous_declaration_built() {
        let f = fabric_with_a_domain_gw();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_migrating_gw_leg();
        run(&mut sys, &view).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("ip link del"))
            .collect();
        assert_eq!(
            dels,
            [
                "ip link del cfab-st-fb",
                "ip link del cfab-st-fb-a",
                "ip link del cfab-gw249",
                "ip link del cfab-gw249-a",
                "ip link del cfab-gw249-b",
                "ip link del cfab-gw249-c",
            ]
        );
    }

    /// The other direction: the declaration says `any`, the box wears the plain sub-interface
    /// the previous one built. The bond loop refused it ("not a bond"); it must be deleted.
    #[test]
    fn down_removes_a_plain_ingress_leg_after_a_flip_to_any() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg()
            .on_stdout(&["ip", "link", "show", "cfab-gw249"], "20: cfab-gw249\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249"],
                "20: cfab-gw249@eth0: vlan protocol 802.1Q id 249 \n",
            );
        run(&mut sys, &view).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("ip link del"))
            .collect();
        assert_eq!(
            dels,
            [
                "ip link del cfab-st-fb",
                "ip link del cfab-st-fb-a",
                "ip link del cfab-gw249"
            ]
        );
    }

    /// Reading the shape off the box is not a licence to delete anything wearing the name: a
    /// netdev that is neither of the ingress leg's two shapes is still refused.
    #[test]
    fn down_refuses_a_stranger_wearing_the_ingress_legs_name() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = sys_with_a_storage_fallback_leg()
            .on_stdout(&["ip", "link", "show", "cfab-gw249"], "20: cfab-gw249\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249"],
                "20: cfab-gw249: bridge \n",
            );
        let e = run(&mut sys, &view).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-gw249 exists but is not a vlan"),
            "{e}"
        );
        assert!(!sys.ran("ip link del cfab-gw249"), "{:?}", sys.calls);
    }

    /// Prove ownership before destroy: a stranger wearing the bond's name is refused, and a
    /// port name carrying something that is not a vlan is refused too.
    #[test]
    fn down_refuses_a_fallback_netdev_of_the_wrong_kind() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();

        let mut sys = sys_with_a_storage_fallback_leg().on_stdout(
            &["ip", "-d", "link", "show", "cfab-st-fb"],
            "9: cfab-st-fb: bridge \n",
        );
        let e = run(&mut sys, &view).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-fb exists but is not a bond"),
            "{e}"
        );
        assert!(!sys.ran("ip link del cfab-st-fb"));

        let mut sys = sys_with_a_storage_fallback_leg().on_stdout(
            &["ip", "-d", "link", "show", "cfab-st-fb-a"],
            "10: cfab-st-fb-a: macvlan \n",
        );
        let e = run(&mut sys, &view).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-fb-a exists but is not a vlan"),
            "{e}"
        );
        assert!(!sys.ran("ip link del cfab-st-fb-a"));
    }

    /// Routes the engine left behind (a crash) are swept by `down`, one delete per route,
    /// before the first interface is deleted.
    #[test]
    fn down_sweeps_private_proto_routes() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        // No netdevs left but one identity veth, so exactly one `ip link del` follows the sweep.
        let mut sys = MockSys::default()
            .on_stdout(
                &["ip", "-4", "route", "show", "table", "all", "proto", "201"],
                "10.99.0.1 via 10.99.1.1 dev cfab-st proto 201 metric 20\n\
                 10.199.0.1 via 10.199.1.1 dev cfab-cl proto 201 metric 20\n",
            )
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .on_stdout(
                &["ip", "link", "show", "cfab-id99"],
                "5: cfab-id99@cfab-id99-peer\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-id99"],
                "5: cfab-id99: veth \n",
            );
        run(&mut sys, &view).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.contains("proto 201"))
            .filter(|c| c.starts_with("ip route del"))
            .collect();
        assert_eq!(
            dels,
            [
                "ip route del 10.99.0.1 metric 20 proto 201",
                "ip route del 10.199.0.1 metric 20 proto 201"
            ]
        );
        let last_del = sys
            .calls
            .iter()
            .rposition(|c| c.starts_with("ip route del") && c.contains("proto 201"))
            .unwrap();
        let first_link_del = sys
            .calls
            .iter()
            .position(|c| c.starts_with("ip link del"))
            .unwrap();
        assert!(
            last_del < first_link_del,
            "sweep precedes interface deletion"
        );
    }

    /// `down` deletes cfab's own return-path default by exact key (prefix `default`, the zone's
    /// table, proto 205) — never a broad pattern — for the gw zone this member carries.
    #[test]
    fn down_deletes_the_return_path_default_by_exact_key() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default().on_fail(&["ip", "link", "show"], 1, "no");
        run(&mut sys, &view).unwrap();
        assert!(
            sys.ran("ip route del default table 249 proto 205"),
            "{:?}",
            sys.calls
                .iter()
                .filter(|c| c.contains("route del default"))
                .collect::<Vec<_>>()
        );
    }

    /// The pref-2000 workload sibling (spec §5 item 4) comes off when it is there, and `down`
    /// issues no delete for it when it is not — the same idempotent shape as every other
    /// `drop_rules` caller here.
    #[test]
    fn teardown_drops_the_workload_sibling_rule() {
        let f = wl_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();

        let mut present = MockSys::default()
            .on_fail(&["ip", "link", "show"], 1, "no")
            .on_stdout(
                &["ip", "rule", "show", "pref", "2000"],
                "100:\tfrom 10.99.0.0/16 to 192.168.20.0/24 lookup main\n",
            );
        run(&mut present, &view).unwrap();
        assert!(
            present.ran("rule del pref 2000 from 10.99.0.0/16 to 192.168.20.0/24 lookup main"),
            "{:?}",
            present.calls
        );

        let mut absent = MockSys::default().on_fail(&["ip", "link", "show"], 1, "no");
        run(&mut absent, &view).unwrap();
        assert!(
            !absent.ran("rule del pref 2000 from 10.99.0.0/16 to 192.168.20.0/24"),
            "{:?}",
            absent.calls
        );
    }

    /// `up` installs `table inet cfab` on every kind, so `down` removes it on every kind — a
    /// leaf that tore the fabric down must not be left dropping its own OSPF at a ceiling
    /// derived for a fabric that is gone. The forward policy stays host-only (a leaf never
    /// installs `cfab-fwd`).
    #[test]
    fn down_removes_the_mark_table_on_a_leaf_and_never_the_forward_policy() {
        let f = fabric();
        for (host, kind) in [("pve1-tb", "host"), ("pve3-tb", "leaf")] {
            let view = View::new(&f, host).unwrap();
            let mut sys = MockSys::default().on_fail(&["ip", "link", "show"], 1, "no");
            run(&mut sys, &view).unwrap();
            assert_eq!(
                sys.calls
                    .iter()
                    .filter(|c| c.as_str() == "nft delete table inet cfab")
                    .count(),
                1,
                "{kind}: {:?}",
                sys.calls
            );
            let fwd = sys
                .calls
                .iter()
                .filter(|c| c.as_str() == "nft delete table inet cfab-fwd")
                .count();
            assert_eq!(fwd, usize::from(kind == "host"), "{kind}: {:?}", sys.calls);
        }
    }

    /// Review finding 11 / B3 (escalated to blocking, 2026-09-05): a still-running engine
    /// (holding `engine.lock`) makes teardown refuse rather than remove the run_dir out from
    /// under it — the two-live-engines state spec §14's flock exists to make unrepresentable.
    #[test]
    fn down_refuses_while_the_engine_lock_is_held() {
        let mut f = fabric();
        let dir = tempfile::tempdir().unwrap();
        f.run_dir = dir.path().to_str().unwrap().to_string();
        let view = View::new(&f, "pve1-tb").unwrap();
        let lock_path = dir.path().join(crate::engine::LOCK_NAME);
        let _held = crate::supervisor::lock::hold(&lock_path).unwrap();
        let mut sys = MockSys::default().on_fail(&["ip", "link", "show"], 1, "no");
        let err = run(&mut sys, &view).unwrap_err().to_string();
        assert!(err.contains("an engine is still running"), "{err}");
        assert!(
            !sys.ran(&format!("rm {}", f.run_dir)),
            "the run_dir must not be removed while its lock is held: {:?}",
            sys.calls
        );
    }

    /// With nobody holding the lock (or no run_dir at all yet — a member never applied),
    /// teardown proceeds and does remove the run_dir.
    #[test]
    fn down_proceeds_when_the_engine_lock_is_free() {
        let mut f = fabric();
        let dir = tempfile::tempdir().unwrap();
        f.run_dir = dir.path().to_str().unwrap().to_string();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default().on_fail(&["ip", "link", "show"], 1, "no");
        run(&mut sys, &view).unwrap();
        assert!(sys.ran(&format!("rm {}", f.run_dir)));
    }

    /// Spec §10: `cfab down` is the out-of-band teardown and must never race the supervisor's
    /// own stop sequence — so if a supervisor answers on `<run_dir>/cfab.sock`, `run_cli`
    /// refuses, names the running pid and the remedy, and changes nothing (no `ip link del`).
    #[test]
    fn down_refuses_while_a_supervisor_answers() {
        let f = fabric(); // `[runtime] run_dir`=/run/cfab
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default()
            .socket(
                "/run/cfab/cfab.sock",
                "{\"supervisor\":{\"pid\":42},\"components\":[]}\n",
            )
            .on_fail(&["ip", "link", "show"], 1, "no");
        let err = run_cli(&mut sys, &view).unwrap_err().to_string();
        assert!(
            err.contains("REFUSING: a cfab supervisor is running (pid 42)"),
            "{err}"
        );
        assert!(err.contains("systemctl stop cfab"), "{err}");
        assert!(
            sys.calls.iter().all(|c| !c.starts_with("ip link del")),
            "a refusal must change nothing: {:?}",
            sys.calls
        );
        assert!(
            !sys.ran(&format!("rm {}", f.run_dir)),
            "the run_dir must not be removed on a refusal: {:?}",
            sys.calls
        );
    }

    /// With nothing listening on `cfab.sock` (an unregistered socket probes as `NotListening`),
    /// `run_cli` proceeds to the real teardown — this is the SIGKILLed-supervisor / no-service
    /// recovery path the verb exists for.
    #[test]
    fn down_proceeds_when_no_supervisor_answers() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default().on_fail(&["ip", "link", "show"], 1, "no");
        run_cli(&mut sys, &view).unwrap();
        assert!(sys.ran(&format!("rm {}", f.run_dir)));
    }

    /// A LIVE-but-slow supervisor accepts the connection but does not answer in time (a read
    /// timeout). `RealSys::unix_probe` reports that as `Unreachable`, not `NotListening`, because
    /// a successful `connect(2)` already proves a listener owns the socket. `run_cli` MUST refuse
    /// — with pid `unknown`, since it never read one — and tear NOTHING down. Folding a
    /// post-connect failure to "no supervisor" is the double-teardown race this guards.
    #[test]
    fn down_refuses_when_the_supervisor_connects_but_does_not_answer() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default()
            .socket_unreachable("/run/cfab/cfab.sock")
            .on_fail(&["ip", "link", "show"], 1, "no");
        let err = run_cli(&mut sys, &view).unwrap_err().to_string();
        assert!(
            err.contains("REFUSING: a cfab supervisor is running (pid unknown)"),
            "{err}"
        );
        assert!(err.contains("systemctl stop cfab"), "{err}");
        assert!(
            sys.calls.iter().all(|c| !c.starts_with("ip link del")),
            "a live-but-slow supervisor must not be torn down under: {:?}",
            sys.calls
        );
        assert!(
            !sys.ran(&format!("rm {}", f.run_dir)),
            "the run_dir must not be removed on a refusal: {:?}",
            sys.calls
        );
    }

    /// B4 (RULING, James 2026-09-05, on Gate A review finding 6): `forwarding_off` alone must
    /// not remove a leaf's leak-guard rules — they are its only containment, and stage one's
    /// whole point is to fail closed before anything that can be `SIGKILL`ed later.
    #[test]
    fn a_leafs_leak_guard_survives_forwarding_off_alone() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        // Deliberately no `ip rule show pref …` mock at all: `forwarding_off` on a leaf must
        // not even QUERY the leak-guard rules, let alone delete one — that whole action moved
        // to the main teardown body (B4). (A rule mocked as persistently present would loop
        // forever under a regression that still calls `drop_rules` here, since the mock
        // never reflects a `del`; asserting "never even asked" avoids that hazard and is the
        // stronger claim anyway.)
        let mut sys = MockSys::default();
        forwarding_off(&mut sys, &view).unwrap();
        assert!(!sys.ran("ip rule show pref 1000"), "{:?}", sys.calls);
        assert!(!sys.ran("ip rule show pref 1001"), "{:?}", sys.calls);
        assert!(!sys.ran("ip rule del"), "{:?}", sys.calls);
    }

    /// Spec §6: `down` removes the additive host default whole — the 250 route by prefix +
    /// table + proto (never a flush of the table), and the three rule prefs, idempotently.
    #[test]
    fn down_removes_the_host_default_route_and_all_three_rule_prefs() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default()
            .on_fail(&["ip", "link", "show"], 1, "no")
            .on_stdout(
                &["ip", "rule", "show", "pref", "2099"],
                "2099:\tfrom 192.168.10.1 iif lo lookup main\n",
            )
            // ...and empty from the second read on, so `drop_rules`'s loop terminates the way a
            // real kernel's does once the rule is gone.
            .on_stdout(&["ip", "rule", "show", "pref", "2099"], "");
        run(&mut sys, &view).unwrap();
        assert!(sys.ran("ip route del default table 250 proto 206"));
        for pref in ["2099", "2100", "2101"] {
            assert!(
                sys.ran(&format!("ip rule show pref {pref}")),
                "pref {pref} was never examined: {:?}",
                sys.calls
            );
        }
        assert!(
            !sys.calls.iter().any(|c| c.contains("ip route flush")),
            "the table is never flushed: {:?}",
            sys.calls
        );
    }

    /// A leaf never installed one; `down` still asks, because the objects are cfab's whether or
    /// not the current declaration would install them (a gw zone removed since `up`).
    #[test]
    fn down_on_a_leaf_still_asks_for_the_host_default_objects_and_finds_none() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = MockSys::default().on_fail(&["ip", "link", "show"], 1, "no");
        run(&mut sys, &view).unwrap();
        assert!(sys.ran("ip route del default table 250 proto 206"));
        assert!(
            !sys.calls
                .iter()
                .any(|c| c.starts_with("ip rule del pref 21")),
            "nothing to delete: {:?}",
            sys.calls
        );
    }
}
