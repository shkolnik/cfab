//! `cfab apply` — apply the fabric on THIS member. Idempotent, root. The order is
//! load-bearing: preconditions → own the NICs → sysctls → per-class netdevs → return
//! path → policy + per-interface forwarding (or the leaf leak guard) → marking + the
//! fallback ceiling → qos. Starting the routing engine, the shape daemon, conf-sync and
//! the fail-closed watchdog is the supervisor's job (`cfab run`), not this function's.

use std::collections::BTreeSet;

use crate::commands::check;
use crate::commands::common;
use crate::commands::common::{
    conf_interfaces, ensure_foreign_transit_accept, link_exists, link_kind_is, proc_sysctl,
};
use crate::commands::teardown;
use crate::derive::{GwRow, Port, View};
use crate::emit;
use crate::emit::ceiling_ipt::Backend as MarkBackend;
use crate::error::{Error, Result};
use crate::model::MemberKind;
use crate::sys::{Sys, have_tool, run_ignore, run_ok};
use crate::wire_drivers;
use crate::workload::{leg, uplink};

pub struct ApplyOpts {
    /// pmxcfs mount root probed to decide whether to start conf-sync (/etc/pve in
    /// production; a tempdir in tests). Unused by `apply::run` itself in this gate — kept on
    /// the type for the supervisor, which reads it to decide whether to spawn conf-sync;
    /// conf-sync itself is spawned by the supervisor, never by `apply`.
    pub pmxcfs_root: String,
}

/// The set of declared wires with no netdev (James's ruling, 2026-09-05): the rest of the
/// apply consults this set and touches none of them — no sub-if, no bond port, no
/// per-interface sysctl. `own_wires` is the one place that decides membership.
pub type AbsentWires = BTreeSet<String>;

/// The exact wording for an absent wire (spec §6/§9 string table): the operator must be able
/// to tell it apart from a present-but-carrierless wire, one spelling per condition.
fn absent_wire_warning(dev: &str) -> String {
    format!(
        "wire {dev} absent (no such netdev) — its segments are not configured; the fabric is \
         up on the rest"
    )
}

/// "uplink" for one port, "uplinks" for more than one (a bond uplink of a workload's bridge)
/// — a message naming a list of ports should agree with it in number.
fn uplink_word(ports: &[String]) -> &'static str {
    if ports.len() > 1 { "uplinks" } else { "uplink" }
}

/// The three legacy binaries, by name. `iptables-legacy-restore` loads the ceiling atomically,
/// `iptables-legacy-save` is both readback halves (drift and counters), `iptables-legacy` adds
/// the OUTPUT jump and sweeps stale chains.
const IPT: [&str; 3] = [
    "iptables-legacy",
    "iptables-legacy-save",
    "iptables-legacy-restore",
];

/// Which backend a leaf's mark state goes through, decided at `up` on the kernel's own
/// refusal and never inferred from a distro, a kind or a knob.
///
/// The probe is a BARE table add, and must stay one forever: EOPNOTSUPP from a probe that grew
/// a rule would mean "that expression is unsupported", not "this kernel has no nf_tables", and
/// would route a perfectly capable member onto the ceiling-only backend.
fn mark_backend_for_leaf(sys: &mut dyn Sys) -> Result<MarkBackend> {
    let have_nft = have_tool(sys, "nft")?;
    if !have_nft {
        for t in IPT {
            if !have_tool(sys, t)? {
                return Err(Error::fatal(format!(
                    "neither nft nor {t} is installed — a leaf needs one of them for the \
                     fallback control-egress ceiling"
                )));
            }
        }
        return Ok(MarkBackend::IptablesLegacy);
    }
    // `LC_ALL=C`: strerror is localized, and the fallback is taken on this one exact text.
    let probe = sys.run(&[
        "/usr/bin/env",
        "LC_ALL=C",
        "nft",
        "add",
        "table",
        "inet",
        "cfabprobe",
    ])?;
    // Delete unconditionally, errors ignored: a failed delete must never strand the table.
    run_ignore(sys, &["nft", "delete", "table", "inet", "cfabprobe"])?;
    if probe.ok() {
        return Ok(MarkBackend::Nft);
    }
    if !probe.stderr.contains("Operation not supported") {
        // Any other failure — a broken nftables install, a seccomp/AppArmor EPERM, an
        // nfnetlink init failure — is NOT "this kernel has no nf_tables". Refuse with the
        // kernel's own words rather than silently policing with a weaker backend.
        return Err(Error::fatal(format!(
            "nft is installed but unusable here: {}",
            probe.stderr.trim()
        )));
    }
    for t in IPT {
        if !have_tool(sys, t)? {
            return Err(Error::fatal(format!(
                "this kernel has no nf_tables (nft: Operation not supported) and {t} is not \
                 installed — a leaf needs one of them for the fallback control-egress ceiling"
            )));
        }
    }
    Ok(MarkBackend::IptablesLegacy)
}

/// Remove whatever the OTHER backend left behind, before this one installs. A member that gains
/// nf_tables (a DSM upgrade), loses it, or is redeclared from `leaf` to `host` must never end up
/// policed by both, or by neither with stale chains still resident — so this runs on EVERY kind,
/// not only the one that can choose. Each half is `have_tool`-guarded, so a host that has never
/// had the legacy binaries runs no extra command at all.
fn remove_other_mark_backend(
    sys: &mut dyn Sys,
    f: &crate::model::Fabric,
    chosen: MarkBackend,
) -> Result<()> {
    match chosen {
        MarkBackend::Nft => {
            common::remove_mark_ipt(sys)?;
            sys.remove(&format!("{}/mark.ipt", f.run_dir))?;
        }
        MarkBackend::IptablesLegacy => {
            if have_tool(sys, "nft")? {
                run_ignore(sys, &["nft", "delete", "table", "inet", "cfab"])?;
            }
            sys.remove(&format!("{}/mark.nft", f.run_dir))?;
        }
    }
    Ok(())
}

/// Install the mark state through the iptables-legacy backend: ceiling only, no bulk clamp
/// (the kernel this runs on has no `-j DSCP` target at all — `status` says so).
fn install_mark_ipt(sys: &mut dyn Sys, view: &View) -> Result<()> {
    let f = view.fabric;
    let path = format!("{}/mark.ipt", f.run_dir);
    let rendered = emit::ceiling_ipt::generate(view)?;
    sys.write(&path, &rendered)?;
    // A filename argument, not stdin: `Sys` runs argv vectors, never a shell.
    run_ok(sys, &["iptables-legacy-restore", "--noflush", &path])?;
    // The jump, idempotently: `-C` is the only way to ask "is it already there?".
    if !sys
        .run(&[
            "iptables-legacy",
            "-t",
            "mangle",
            "-C",
            "OUTPUT",
            "-j",
            emit::ceiling_ipt::OUT_CHAIN,
        ])?
        .ok()
    {
        run_ok(
            sys,
            &[
                "iptables-legacy",
                "-t",
                "mangle",
                "-A",
                "OUTPUT",
                "-j",
                emit::ceiling_ipt::OUT_CHAIN,
            ],
        )?;
    }
    let mut save = run_ok(sys, &["iptables-legacy-save", "-t", "mangle"])?.stdout;
    // A zone that lost its fallback row leaves an empty chain behind: the restore's `-F
    // cfab-out` unhooked it, but the chain is still resident. Delete it by the exact name the
    // readback gave us — never by pattern over chains that are not ours.
    let wanted: Vec<String> = emit::ceiling_ipt::chains_in(&rendered);
    let stale: Vec<String> = emit::ceiling_ipt::chains_in(&save)
        .into_iter()
        .filter(|c| !wanted.contains(c))
        .collect();
    if !stale.is_empty() {
        for chain in &stale {
            run_ignore(sys, &["iptables-legacy", "-t", "mangle", "-F", chain])?;
            run_ignore(sys, &["iptables-legacy", "-t", "mangle", "-X", chain])?;
        }
        save = run_ok(sys, &["iptables-legacy-save", "-t", "mangle"])?.stdout;
    }
    sys.write(
        &format!("{}/mark.applied", f.run_dir),
        &emit::ceiling_ipt::ours(&save),
    )?;
    Ok(())
}

/// Bring up every declared wire, releasing it from a manager it does not belong to. Absence
/// is decided by `link_exists` (the netdev genuinely does not exist) — RULED (James,
/// 2026-09-05) to be a warning, never a refusal, because under a supervisor the old refusal
/// would leave an unattended host with no supervisor at all. A wire that DOES exist but
/// cannot be brought up (EPERM, EBUSY, a wedged driver) is a different condition — still a
/// refusal, not silently dropped from the apply and not misreported as absent.
fn own_wires(sys: &mut dyn Sys, view: &View) -> Result<AbsentWires> {
    let mut absent = AbsentWires::new();
    for dev in &view.wires() {
        if !link_exists(sys, dev)? {
            absent.insert(dev.clone());
            continue;
        }
        run_ok(sys, &["ip", "link", "set", dev, "up"])?;
    }
    Ok(absent)
}

/// A bond leg's ports, minus any on an absent wire; if the leg's declared `home` wire is one
/// of them, the first surviving port takes over as home (any survivor is a legal `primary`;
/// `mk_bond_leg` only needs ONE that matches). `None` when every wire under the leg is absent
/// — nothing to build, and the caller skips it with a warning of its own.
fn present_ports<'a>(
    ports: &'a [Port],
    home: &'a str,
    absent: &AbsentWires,
) -> Option<(Vec<Port>, String)> {
    let kept: Vec<Port> = ports
        .iter()
        .filter(|s| !absent.contains(&s.wire))
        .cloned()
        .collect();
    if kept.is_empty() {
        return None;
    }
    let new_home = if absent.contains(home) {
        kept[0].wire.clone()
    } else {
        home.to_string()
    };
    Some((kept, new_home))
}

pub fn run(sys: &mut dyn Sys, view: &View, _opts: &ApplyOpts) -> Result<Vec<String>> {
    let f = view.fabric;
    let kind = view.kind();
    let n = view.node();
    let host = &view.member.name;
    let class_rows = view.class_rows();
    let gw_rows = view.gw_rows();
    let wires = view.wires();
    let admin_ifs = view.admin_ifs();

    // ---- preconditions: fail loud, never degrade -------------------------------
    // A host requires `nft`: it installs the whole `table inet cfab` (bulk DSCP clamp + the
    // fallback control-egress ceiling), and a no-nft kernel is a hard refusal for that kind —
    // there is no iptables path for a forwarding member. `tc` stays host-only — a leaf shapes
    // nothing, its wires' qdiscs belonging to its own OS. `ethtool` is NOT a precondition for
    // either kind any more: it is a read-only diagnostic dependency (Debian `Recommends`), and
    // its absence degrades the per-wire driver record below rather than refusing `up`.
    let mut tools: Vec<&str> = vec!["ip"];
    if kind == MemberKind::Host {
        tools.push("nft");
        tools.push("tc");
        if f.host_forward {
            tools.push("logger");
        }
    }
    for tool in tools {
        if !have_tool(sys, tool)? {
            return Err(Error::fatal(format!("{tool} not installed")));
        }
    }
    // A leaf takes either backend: `nft`, or all three legacy binaries. ALWAYS the `-legacy`
    // names — on trixie the unqualified `iptables`/`-save`/`-restore` are alternatives
    // defaulting to the nft backend, which fails with the same EOPNOTSUPP on the one kernel
    // this path exists for.
    let mark_backend = if kind == MemberKind::Leaf {
        mark_backend_for_leaf(sys)?
    } else {
        MarkBackend::Nft
    };
    // Lockout guard: at least one wire must carry an untagged IPv4 address BEFORE we touch
    // anything — the admin session rides the untagged path of some wire, and bringup
    // deliberately never assigns or flushes any of them. Every wire is an admin wire on a
    // host, so the bar is "one of them is reachable", not "all of them are addressed".
    if !admin_ifs.is_empty() {
        let mut addressed: Vec<&str> = Vec::new();
        for admin in &admin_ifs {
            let out = sys.run(&["ip", "-4", "-br", "addr", "show", "dev", admin])?;
            if out.stdout.lines().any(|l| {
                l.split_whitespace()
                    .skip(2)
                    .any(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
            }) {
                addressed.push(admin);
            }
        }
        if addressed.is_empty() {
            return Err(Error::fatal(format!(
                "no wire ({}) has an untagged IPv4 address — the admin path would be unreachable",
                admin_ifs.join(" ")
            )));
        }
    }
    // A leaf writes per-interface sysctls on netdevs it creates; in a container that needs a
    // writable /proc/sys (Docker: --privileged; NET_ADMIN alone leaves it read-only).
    if !sys.is_writable("/proc/sys/net/ipv4/conf/all/rp_filter") {
        return Err(Error::fatal(
            "/proc/sys is read-only here — run the container privileged (Docker: --privileged; \
             Synology Container Manager: 'high privilege')",
        ));
    }
    sys.mkdir_p(&f.run_dir)?;

    // ---- own the fabric NICs ---------------------------------------------------
    // Release the wires from their manager — leftover DHCP state on a fabric NIC is a fight
    // for its addresses. The admin NIC's UNTAGGED L3 is the admin path: only tagged sub-ifs
    // are added on it, never a flush. An absent wire (§6, RULED) is warned about, not
    // refused: `own_wires` decides membership once, here, and nothing below re-derives it.
    let absent = own_wires(sys, view)?;
    let mut warnings: Vec<String> = absent.iter().map(|dev| absent_wire_warning(dev)).collect();
    // Nothing is taken over here any more. Until 2026-09-06 `up` released each non-admin wire
    // from NetworkManager, refused a wire a dhcp client held, and flushed its addresses. Under
    // the ruling that the UNTAGGED path of EVERY host wire is the admin plane, there is no
    // non-admin wire left to take: cfab adds tagged sub-interfaces and never touches a wire's
    // own L3, so NM and DHCP keep every wire they had. `up` proves it by never running those
    // commands (`up_never_takes_a_wire_from_its_manager`).
    // ---- per-wire driver record --------------------------------------------------------
    // cfab sets no NIC feature any more (that is the host's own udev rule now); what it still
    // records is which driver each present wire had at apply, so the forwarding watchdog can
    // tell a re-enumerated wire from a swapped adapter. `ethtool` is read-only and optional
    // (Debian `Recommends`): probed once, and its absence writes an empty record with a
    // warning rather than failing the bringup — a leaf without ethtool used to fail here
    // ungracefully with no precondition to explain why; it no longer does.
    // `?` would let a plain exec failure (never observed off `/usr/bin/env` itself, but not
    // provably impossible) fail the whole bringup over a diagnostic dependency it doesn't have
    // — `unwrap_or(false)` folds it into the ordinary "not on PATH" answer instead.
    let have_ethtool = have_tool(sys, "ethtool").unwrap_or(false);
    if !have_ethtool {
        warnings.push("WARNING: ethtool not installed: wire drivers unrecorded".to_string());
    }
    let mut drivers: Vec<(String, String)> = Vec::new();
    if have_ethtool {
        for w in view
            .member
            .wires
            .iter()
            .filter(|w| !absent.contains(w.name.as_str()))
        {
            match wire_drivers::driver_of(sys, &w.name) {
                Some(drv) => drivers.push((w.name.clone(), drv)),
                // `driver_of` returns None both for a device-specific refusal (a nonzero exit,
                // e.g. "Operation not supported") and for an exec failure (ethtool removed
                // between the `have_tool` probe above and this call) — either way this wire
                // gets no driver record, named per wire rather than silently skipped, so the
                // watchdog's later "different driver" report isn't the first anyone hears of it.
                None => warnings.push(format!("WARNING: ethtool -i {}: driver unrecorded", w.name)),
            }
        }
    }
    sys.write(
        &wire_drivers::drivers_path(&f.run_dir),
        &wire_drivers::render_drivers(&drivers),
    )?;

    // ---- sysctls (host-only: GLOBAL; a leaf shares its kernel with an external owner) --------
    if kind == MemberKind::Host {
        sys.write(
            "/proc/sys/net/ipv4/conf/all/ignore_routes_with_linkdown",
            "1",
        )?;
        // Redirects: a hairpin through a fabric host redirects a dumb endpoint straight at a
        // neighbor's segment address; the cached entry outlives that neighbor's wire (measured).
        sys.write("/proc/sys/net/ipv4/conf/all/send_redirects", "0")?;
        sys.write("/proc/sys/net/ipv4/conf/default/send_redirects", "0")?;
        // Forwarding starts OFF on every cfab interface (the kernel checks the PER-INTERFACE
        // flag); it is turned on — per class-table interface only — after the policy is loaded.
        // Interfaces cfab does not own are left alone (scoped posture).
        sys.write("/proc/sys/net/ipv4/conf/default/forwarding", "0")?;
        for ifn in conf_interfaces(sys)? {
            if view.owns_if(&ifn) {
                sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
            }
        }
    }

    // ---- workload preconditions (spec §5.1 pass 1 — pure reads, no state change) ------------
    // cfab creates the leg now, so nothing here is about an interface the operator was
    // supposed to declare. What is left is (a) a host fact no amount of creating fixes — an
    // uplink bridge that is not vlan-aware, refused in `check`'s words so an operator meets
    // one spelling wherever they meet it — and (b) three availability deferrals: no bridge
    // yet, no identifiable uplink, an uplink not yet STP-forwarding. Each defers that ONE row
    // to the watchdog and lets every other row's apply through (James's ruling 2026-09-09,
    // "bias towards availability"), which deviates from spec §5.1 item 1 by that ruling.
    //
    // `ready` collects what the netdev pass builds and pass 3 addresses; `workload_uplinks`
    // also gets an entry for a row whose uplink WAS identified but is not yet forwarding — the
    // guard rule is harmless to install before the address exists — but not for one whose
    // uplink could not be identified at all (there is no bridge/port to guard).
    check::host_preflight(&*sys, view)?;
    struct ReadyWorkload {
        leg: String,
        uplink: String,
        vid: u16,
        address: String,
        gw_cidr: String,
    }
    let mut workload_uplinks: Vec<(std::net::Ipv4Addr, uplink::Uplink)> = Vec::new();
    let mut workload_descs: Vec<String> = Vec::new();
    let mut ready: Vec<ReadyWorkload> = Vec::new();
    let mut deferred_names: Vec<String> = Vec::new();
    for row in view.workload_rows() {
        let leg = row.wl.leg_ifname();
        let name = &row.wl.name;
        let bridge = row.wl.uplink.as_str();
        if !uplink::bridge_present(sys, bridge) {
            // The bridge is the host's: it may be seconds behind cfab at boot, or renamed by
            // an operator mid-flight. Either way this row waits and the rest of the member
            // comes up (branch-review C1's class of fault, same ruling).
            warnings.push(format!("workload {name}: waiting for bridge {bridge}"));
            deferred_names.push(name.clone());
            continue;
        }
        let up = match uplink::identify_declared(sys, bridge, row.wl.vid) {
            Ok(up) => up,
            Err(e) => {
                warnings.push(format!(
                    "workload {name}: uplink not identified: {e}; row deferred to the watchdog"
                ));
                deferred_names.push(name.clone());
                continue;
            }
        };
        let mut not_forwarding: Option<String> = None;
        for port in &up.ports {
            match uplink::stp_forwarding(sys, &up.bridge, port) {
                Ok((true, _)) => {}
                Ok((false, state)) => {
                    not_forwarding = Some(format!(
                        "workload {name}: uplink {port} not forwarding (STP state {state}); \
                         row deferred to the watchdog"
                    ));
                    break;
                }
                Err(e) => {
                    not_forwarding = Some(format!(
                        "workload {name}: uplink {port} not forwarding ({e}); row deferred to \
                         the watchdog"
                    ));
                    break;
                }
            }
        }
        if let Some(warning) = not_forwarding {
            warnings.push(warning);
            deferred_names.push(name.clone());
            workload_uplinks.push((row.wl.gw, up)); // guard is harmless before the leg exists
            continue;
        }
        workload_descs.push(format!(
            "{name} on {leg} ({} {})",
            uplink_word(&up.ports),
            up.ports.join(", ")
        ));
        ready.push(ReadyWorkload {
            leg,
            uplink: bridge.to_string(),
            vid: row.wl.vid,
            address: row.address.clone(),
            gw_cidr: row.wl.gw_cidr(),
        });
        workload_uplinks.push((row.wl.gw, up));
    }

    // ---- per-class netdevs -----------------------------------------------------
    for z in &f.zones {
        mk_identity(
            sys,
            &View::identity_if(z),
            &format!("{}/32", view.identity_addr(z)),
        )?;
        // Fabric blocks must never fall through to the default route (identity traffic leaking
        // onto the management LAN during a peer's routing-engine restart).
        run_ok(
            sys,
            &[
                "ip",
                "route",
                "replace",
                "unreachable",
                &format!("{}.0.0/16", z.block()),
            ],
        )?;
    }
    for r in class_rows.iter().filter(|r| !absent.contains(&r.wire)) {
        build_class_leg(sys, view, r)?;
    }
    // The ingress leg: the router's VLAN, this node's address in the router's /24. Same
    // sysctls as a backup segment; nothing else about it is a segment. On a gw domain of
    // `any` the leg is the same bond a fallback segment is, so it migrates between wires
    // instead of dying with its domain — one leg, one BGP session (James 2026-09-04).
    for r in &gw_rows {
        let z = f.zone(&r.zone)?;
        let gw = z.gw.as_ref().expect("gw_rows lists gw zones");
        let cidr = gw.leg_cidr(n);
        let qos_map = qos_map(f, z);
        let qos_map: Vec<&str> = qos_map.iter().map(String::as_str).collect();
        replace_a_wrong_shape_gw_leg(sys, view, r, &mut warnings)?;
        if r.migrates() {
            let Some((ports, home)) = present_ports(&r.ports, &r.home, &absent) else {
                continue; // every wire under this leg is absent; already warned above
            };
            mk_bond_leg(
                sys,
                &BondLeg {
                    ifname: &r.ifname,
                    vid: r.vid,
                    home: &home,
                    ports: &ports,
                    cidr: &cidr,
                },
                &qos_map,
            )?;
        } else if !absent.contains(&r.home) {
            build_gw_vlan_leg(sys, view, r)?;
        }
        // cfab's own return-path default: a reply sourced from an identity address must leave
        // through the ingress leg (proto 205, this member's own id), never untagged out of the
        // main default. The FRR build got this from `ip route 0.0.0.0/0 <router> table <id>`;
        // the embedded engine's static path cannot — holo installs a static only when its
        // nexthop names an interface, and the fork has no `table` augment — so cfab owns it,
        // torn down by exact key in `down`. proto 205 is outside the engine's swept 201..204
        // range, so neither the startup purge nor `down`'s engine sweep removes it. The watchdog
        // restores it after a leg flap (the kernel drops a dev-scoped route on link-down and
        // never re-adds it), via the same `GwReturnDefault` so the two spellings cannot drift.
        common::GwReturnDefault {
            table: z.id.to_string(),
            via: gw.router.clone(),
            dev: r.ifname.clone(),
        }
        .install(sys)?;
    }
    // The fallback leg: one active-backup bond per zone over a tagged sub-interface of every
    // wire, so the member keeps a path in the zone when the physical domains are disjointly
    // isolated. Not a class row and not a wire: nothing that treats a segment as a wire (the
    // shaper, the qdisc sweep, status's link-speed checks) ever sees it.
    for r in &view.fallback_rows() {
        let z = f.zone(&r.zone)?;
        let Some((ports, home)) = present_ports(&r.ports, &r.home, &absent) else {
            continue; // every wire under this fallback leg is absent; already warned above
        };
        mk_bond_leg(
            sys,
            &BondLeg {
                ifname: &r.ifname,
                vid: r.vid,
                home: &home,
                ports: &ports,
                cidr: &format!("{}/24", view.segment_addr(z, r.seg)),
            },
            &qos_map(f, z).iter().map(String::as_str).collect::<Vec<_>>(),
        )?;
    }

    // The workload leg: `cfab-work-<name>` on the declared bridge, tagged `vid`, carrying this
    // member's own address — plus the vid on the bridge itself, without which the leg receives
    // nothing (VERIFIED 2026-09-08 22:38 UTC). A deferred row builds nothing: the watchdog
    // creates its leg when the condition that deferred it clears.
    let wl_qos = workload_qos(f);
    let wl_qos: Vec<&str> = wl_qos.iter().map(String::as_str).collect();
    for r in &ready {
        leg::install(
            sys, &f.run_dir, &r.leg, &r.uplink, r.vid, &r.address, &wl_qos,
        )?;
    }

    // ---- return path (`[[zone]]` gw): identity-sourced traffic never leaves untagged ---------
    for r in common::return_path_rules(view) {
        common::ensure_fabric_rule(sys, &r)?;
    }

    // ---- forward policy + per-interface forwarding ------------------------------
    if kind == MemberKind::Leaf {
        leaf_guard(sys, view)?;
    } else if f.host_forward {
        let built: Vec<&str> = ready.iter().map(|r| r.leg.as_str()).collect();
        enable_forwarding(sys, view, &absent, &built)?;
    } else {
        run_ignore(sys, &["nft", "delete", "table", "inet", "cfab-fwd"])?;
        sys.remove(&format!("{}/policy.nft", f.run_dir))?;
        sys.remove(&format!("{}/policy.applied", f.run_dir))?;
    }

    // ---- workload bridge ARP guard (after forwarding is up, before the mark table: the
    // announcer only starts once `apply` returns, so ordering here is about the guard being in
    // place before anything else touches the mark table, not a race with the announcer) --------
    if !workload_uplinks.is_empty() {
        let bridge_nft = emit::workload::bridge_table(&workload_uplinks);
        let bridge_path = format!("{}/workload-bridge.nft", f.run_dir);
        sys.write(&bridge_path, &bridge_nft)?;
        run_ok(sys, &["nft", "-f", &bridge_path])?; // one transaction: atomic replace
        let applied = run_ok(sys, &["nft", "-s", "list", "table", "bridge", "cfab"])?;
        sys.write(
            &format!("{}/workload-bridge.applied", f.run_dir),
            &applied.stdout,
        )?;
    }

    // ---- workload gw address + arp_ignore (spec §5.1 pass 3, review item 1: the guard above is
    // in place BEFORE any gw address goes live — closes the window where the address was
    // reachable with no ARP-guard protection) + deferred-row bookkeeping for the watchdog -------
    if view.workload_rows().is_empty() {
        // A declaration that dropped its last `[[workload]]` row (or never had one) must not
        // leave a prior apply's stale deferred name behind — `remove` is already absent-safe.
        sys.remove(&format!("{}/workload-deferred", f.run_dir))?;
    } else {
        sys.write(
            &format!("{}/workload-deferred", f.run_dir),
            &deferred_names.join("\n"),
        )?;
    }
    for plan in &ready {
        run_ok(
            sys,
            &["ip", "addr", "replace", &plan.gw_cidr, "dev", &plan.leg],
        )?;
    }
    // Matches the watchdog's own restore condition (`restore_workloads`): arp_ignore is
    // member-wide, not per-row, and is set whenever ANY workload row is declared at all — ready
    // or still deferred — never gated on this apply having a ready row of its own.
    if !view.workload_rows().is_empty() {
        sys.write("/proc/sys/net/ipv4/conf/all/arp_ignore", "1")?;
    }

    // ---- marking + the fallback ceiling (EVERY kind) ----------------------------------------
    // `table inet cfab` is derived from the class table alone — `oifname` groups over this
    // member's own `cfab-*` segments, bonds and ingress legs, which a leaf creates exactly as a
    // host does. Nothing in it reads a wire, a qdisc or the forwarding posture, so there is one
    // code path and no `kind` branch: a leaf marks its own egress and, more to the point, gets
    // the fallback control-egress ceiling. A containment one member class escapes is half a
    // containment: a leaf sources a fallback-segment control storm at the same measured rate a
    // host does (149 k pkt/s and 3.5 cores, all three members alike), and the leaf is the
    // member most likely to be a 4-core NAS.
    //
    // Which mechanism carries it is the kernel's call, not the declaration's: a leaf on a
    // kernel without nf_tables (the NAS) gets the ceiling through iptables-legacy and no bulk
    // DSCP clamp at all — that kernel has no `-j DSCP` target. The choice is recorded so
    // `status` and `down` read it instead of re-probing, and so a member that GAINS nf_tables
    // (or changes kind) does not leave the other backend's state resident.
    sys.write(
        &emit::ceiling_ipt::record_path(&f.run_dir),
        &format!("{}\n", mark_backend.as_str()),
    )?;
    remove_other_mark_backend(sys, f, mark_backend)?;
    match mark_backend {
        MarkBackend::Nft => {
            let mark = emit::mark::generate(view)?;
            let mark_path = format!("{}/mark.nft", f.run_dir);
            sys.write(&mark_path, &mark)?;
            run_ok(sys, &["nft", "-f", &mark_path])?; // one transaction: atomic replace
            let applied = run_ok(sys, &["nft", "-s", "list", "table", "inet", "cfab"])?;
            sys.write(&format!("{}/mark.applied", f.run_dir), &applied.stdout)?;
        }
        MarkBackend::IptablesLegacy => {
            install_mark_ipt(sys, view)?;
            // Only the degraded backend is worth a line here: it is a real, named loss of the
            // bulk clamp. `mark: nft` is the ordinary case and belongs to `status` alone.
            warnings.push(mark_backend.status_line().to_string());
        }
    }

    // ---- qos (host only: a leaf shapes nothing; its wires' qdiscs belong to its OS) ----------
    if kind == MemberKind::Host {
        for dev in wires.iter().filter(|d| !absent.contains(d.as_str())) {
            run_ok(
                sys,
                &["tc", "qdisc", "replace", "dev", dev, "root", "fq_codel"],
            )?;
        }
    }

    // The routing engine, shape daemon, fail-closed watchdog and conf-sync are the
    // supervisor's job (`cfab run`), not this idempotent apply's. `describe_down` stays
    // exported for it.
    if kind == MemberKind::Host {
        warnings.push(format!(
            "apply OK on {host} (node {n}, host); forward={} shape={} wires",
            u8::from(f.host_forward),
            wires.len() - absent.len()
        ));
    } else {
        warnings.push(format!(
            "apply OK on {host} (node {n}, leaf); no transit (cost +{}, forwarding=0, leak guard)",
            f.leaf_cost_offset
        ));
    }
    if !workload_descs.is_empty()
        && let Some(last) = warnings.last_mut()
    {
        last.push_str(&format!("; workloads: {}", workload_descs.join(", ")));
    }
    Ok(warnings)
}

/// An always-up netdev holding a /32: a veth pair (on every kernel that runs Docker; `dummy` is
/// not — absent on DSM 7.3's 4.4 kernel). Both ends inherit conf/default, and on a kernel whose
/// owner keeps ip_forward=1 that means forwarding=1 — set 0 explicitly on both.
fn mk_identity(sys: &mut dyn Sys, name: &str, cidr: &str) -> Result<()> {
    if link_exists(sys, name)? && !link_kind_is(sys, name, " veth ")? {
        // transition: a same-named netdev of the wrong kind (ours by the cfab- name)
        run_ok(sys, &["ip", "link", "del", name])?;
    }
    let peer = format!("{name}-peer");
    if !link_exists(sys, name)? {
        run_ok(
            sys,
            &[
                "ip", "link", "add", name, "type", "veth", "peer", "name", &peer,
            ],
        )?;
    }
    run_ok(sys, &["ip", "addr", "replace", cidr, "dev", name])?;
    for d in [name, peer.as_str()] {
        proc_sysctl(sys, d, "forwarding", "0")?;
        proc_sysctl(sys, d, "send_redirects", "0")?;
    }
    run_ok(sys, &["ip", "link", "set", &peer, "up"])?;
    run_ok(sys, &["ip", "link", "set", name, "up"])?;
    Ok(())
}

/// A tagged sub-interface on `lower`. `addr` is `None` for a link that carries no L3 of its
/// own (a fallback bond's port: the bond holds the address), and `bring_up` is false for a link
/// something else brings up later (adding a port wants it down first).
/// The `ip -d link show` marker that proves a netdev is a vlan sub-interface of this vid.
pub(crate) fn vlan_marker(vid: u16) -> String {
    format!("vlan protocol 802.1Q id {vid} ")
}

pub(crate) fn mk_vlan(
    sys: &mut dyn Sys,
    name: &str,
    lower: &str,
    vid: u16,
    addr: Option<&str>,
    bring_up: bool,
    qos_map: &[&str],
) -> Result<()> {
    let vid_s = vid.to_string();
    if link_exists(sys, name)? && !link_kind_is(sys, name, &vlan_marker(vid))? {
        run_ok(sys, &["ip", "link", "del", name])?;
    }
    if !link_exists(sys, name)? {
        let mut argv = vec![
            "ip",
            "link",
            "add",
            "link",
            lower,
            "name",
            name,
            "type",
            "vlan",
            "id",
            &vid_s,
            "egress-qos-map",
        ];
        argv.extend_from_slice(qos_map);
        run_ok(sys, &argv)?;
    }
    if let Some(cidr) = addr {
        run_ok(sys, &["ip", "addr", "replace", cidr, "dev", name])?;
    }
    if bring_up {
        run_ok(sys, &["ip", "link", "set", name, "up"])?;
    }
    Ok(())
}

/// The `egress-qos-map` every leg of a zone is created with: the zone's own PCP for untagged
/// priority, and the control PCP mapped to itself. One definition — `apply` builds a leg with
/// it and the forwarding watchdog rebuilds one with it, so the two cannot drift.
pub(crate) fn qos_map(f: &crate::model::Fabric, z: &crate::model::Zone) -> [String; 2] {
    [
        format!("0:{}", z.pcp),
        format!("{}:{}", f.pcp_ctrl, f.pcp_ctrl),
    ]
}

/// The `egress-qos-map` a workload leg is created with. A workload belongs to no zone, so
/// unmarked traffic keeps pcp 0 and only control-marked traffic keeps its pcp. One definition —
/// `apply` builds the leg with it and the forwarding watchdog rebuilds one with it, so the two
/// cannot drift.
pub(crate) fn workload_qos(f: &crate::model::Fabric) -> [String; 2] {
    ["0:0".to_string(), format!("{p}:{p}", p = f.pcp_ctrl)]
}

/// One class-segment leg, exactly as the per-class-netdevs section builds it: the tagged
/// sub-interface with this member's segment address, then the segment sysctls (which leave
/// `forwarding=0`; `enable_forwarding` raises it later on a transiting host).
pub(crate) fn build_class_leg(
    sys: &mut dyn Sys,
    view: &View,
    r: &crate::derive::ClassRow,
) -> Result<()> {
    let f = view.fabric;
    let z = f.zone(&r.zone)?;
    let qm = qos_map(f, z);
    mk_vlan(
        sys,
        &r.ifname,
        &r.wire,
        r.vid,
        Some(&format!("{}/24", view.segment_addr(z, r.seg))),
        true,
        &qm.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    class_sysctls(sys, &r.ifname)
}

/// One NON-migrating ingress leg (a gw on a physical domain): a plain tagged sub-interface on
/// the leg's `home` wire, addressed in the router's /24. The return-path default is installed
/// by the caller — `apply` does it for every gw row, the watchdog through
/// `restore_gw_return_defaults`.
pub(crate) fn build_gw_vlan_leg(sys: &mut dyn Sys, view: &View, r: &GwRow) -> Result<()> {
    let f = view.fabric;
    let z = f.zone(&r.zone)?;
    let gw = z.gw.as_ref().expect("gw_rows lists gw zones");
    let qm = qos_map(f, z);
    mk_vlan(
        sys,
        &r.ifname,
        &r.home,
        r.vid,
        Some(&gw.leg_cidr(view.node())),
        true,
        &qm.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    class_sysctls(sys, &r.ifname)
}

/// Bond `updelay` in ms — how long a returning wire must hold carrier before it is reselected.
/// **500 is MEASURED, not a target** (sweep of 0/200/500, n=1 per value, container fixture on a
/// three-member testbed): it costs a 0.574 s window after a *legitimate* return in which
/// `status` reads UP-DEGRADED (0.074 s at 0), with **zero**
/// packets lost at every value, and it buys a 10x reduction in migrations on a bouncing wire —
/// 2 versus 20 active-port switches over ten 250 ms flaps, each avoided switch an avoided GARP
/// burst and MAC move on every switch in the path. `updelay` never delays the failover AWAY from
/// a dead wire (0.026-0.042 s at every value), so it cannot lengthen an outage. It takes effect on
/// an EXISTING member only after a `down`/`up` — `mk_bond_leg` never rewrites a live bond; it
/// refuses when the running value diverges from this one and names that remedy.
const FALLBACK_UPDELAY_MS: &str = "500";
/// `fail_over_mac`. **`none` is the build default** — measured nil difference against `active`
/// on veth, and it keeps one MAC across a migration. A real NIC must accept the bond MAC in its
/// unicast filter (INFERRED); Task 7's hardware step measures that and flips this to `active`
/// if it does not. One line, deliberately not a config knob.
const FALLBACK_FAIL_OVER_MAC: &str = "none";
/// Bonding mode. Active-backup is the whole point of the leg: one wire carries it at a time, and
/// a migration is invisible above L2. Not writable on a live bond — only `ip link add` sets it.
const FALLBACK_BOND_MODE: &str = "active-backup";
/// Carrier poll, ms: measured switch at +0.014…0.059 s after carrier loss through the VLAN.
const FALLBACK_MIIMON_MS: &str = "100";
/// Gratuitous ARPs per migration: measured exactly 3, at +0.050/+0.050/+0.152 s.
const FALLBACK_NUM_GRAT_ARP: &str = "3";
/// Return to the home wire whenever it comes back — a deterministic steady state `status` can
/// expect. The return migration is lossless (measured), so it costs nothing.
const FALLBACK_PRIMARY_RESELECT: &str = "always";

/// A migrating leg to build: a universal segment, or an ingress leg on gw scope `any`. The two
/// are the same netdev shape, so they are the same code — only the address differs.
pub(crate) struct BondLeg<'a> {
    pub(crate) ifname: &'a str,
    pub(crate) vid: u16,
    /// The wire whose port the bond takes as `primary`.
    pub(crate) home: &'a str,
    pub(crate) ports: &'a [Port],
    /// The bond is the L3 interface; its ports carry no address.
    pub(crate) cidr: &'a str,
}

/// Every bond parameter this build creates a leg with, in `bonding/` sysfs spelling: the file
/// name and the value `ip link add` was given. Read back on an existing bond so a changed
/// constant cannot silently miss a member that already has the leg.
const FALLBACK_BOND_PARAMS: [(&str, &str); 5] = [
    ("mode", FALLBACK_BOND_MODE),
    ("miimon", FALLBACK_MIIMON_MS),
    ("updelay", FALLBACK_UPDELAY_MS),
    ("num_grat_arp", FALLBACK_NUM_GRAT_ARP),
    ("fail_over_mac", FALLBACK_FAIL_OVER_MAC),
];

/// An existing bond keeps whatever `ip link add` gave it: nothing in `up` re-asserts the
/// parameters, so a changed constant would reach a fresh member and silently miss every member
/// that already has the leg. Refuse on divergence rather than rewrite — `mode` and
/// `fail_over_mac` are not writable on a live bond at all, and a partial rewrite is a degraded
/// leg nobody asked for. `cfab down` deletes the bond before its ports, so down/up is a proven
/// rebuild.
///
/// sysfs spells the enumerated parameters `<name> <index>` ("active-backup 1", "none 0") and the
/// numeric ones as a bare integer; compare on the first whitespace-separated token. An
/// unreadable file is not health — it is an unproven bond — so it refuses too.
fn bond_params_match(sys: &dyn Sys, ifname: &str) -> Result<()> {
    let mut diverged: Vec<String> = Vec::new();
    for (param, want) in FALLBACK_BOND_PARAMS {
        let path = format!("/sys/class/net/{ifname}/bonding/{param}");
        let Ok(raw) = sys.read(&path) else {
            return Err(Error::fatal(format!(
                "REFUSING: {ifname} exists but {path} cannot be read, so its bond parameters \
                 cannot be proven; run `cfab down` then `cfab up` to rebuild the leg"
            )));
        };
        let got = raw.split_whitespace().next().unwrap_or("");
        if got != want {
            diverged.push(format!("{param} want {want} got {got}"));
        }
    }
    if !diverged.is_empty() {
        return Err(Error::fatal(format!(
            "REFUSING: {ifname} exists with bond parameters this build did not create it with \
             ({}); cfab never rewrites a live bond (mode and fail_over_mac are not writable on \
             one), so run `cfab down` then `cfab up` to rebuild the leg",
            diverged.join(", ")
        )));
    }
    Ok(())
}

/// One migrating leg: an active-backup bond over a tagged sub-interface of every wire this
/// member has, addressed like a segment. Idempotent, and refuse-unless-ours on every netdev
/// it touches.
pub(crate) fn mk_bond_leg(sys: &mut dyn Sys, r: &BondLeg, qos_map: &[&str]) -> Result<()> {
    // (1) the bond. Unlike a vlan of the wrong id, a same-named foreign netdev here is not
    // ours to delete — refuse and say so.
    if link_exists(sys, r.ifname)? {
        if !link_kind_is(sys, r.ifname, " bond ")? {
            return Err(Error::fatal(not_a_bond(r.ifname)));
        }
        bond_params_match(sys, r.ifname)?;
    } else {
        run_ok(
            sys,
            &[
                "ip",
                "link",
                "add",
                r.ifname,
                "type",
                "bond",
                "mode",
                FALLBACK_BOND_MODE,
                "miimon",
                FALLBACK_MIIMON_MS,
                "num_grat_arp",
                FALLBACK_NUM_GRAT_ARP,
                "updelay",
                FALLBACK_UPDELAY_MS,
                "fail_over_mac",
                FALLBACK_FAIL_OVER_MAC,
            ],
        )?;
    }
    // (2) the ports: created DOWN and with no address — the bond holds the L3, and adding
    // a link the kernel is bringing up is a race. The egress-qos map lives HERE: the tag is
    // applied on the port, and PCP is per frame, so control on the fallback path is queued like
    // control anywhere.
    for s in r.ports {
        add_bond_port(sys, r.ifname, s, r.vid, qos_map)?;
    }
    // (4) AFTER the ports exist: `primary` names a PORT, and at `ip link add` time no port
    // exists yet, so setting it there is a silent no-op.
    let home = home_port(r.ifname, r.ports, r.home)?;
    set_bond_primary(sys, r.ifname, &home.ifname)?;
    // (5) the bond is the segment: address, segment sysctls, up.
    run_ok(sys, &["ip", "addr", "replace", r.cidr, "dev", r.ifname])?;
    class_sysctls(sys, r.ifname)?;
    run_ok(sys, &["ip", "link", "set", r.ifname, "up"])?;
    Ok(())
}

/// One port of a bond leg, exactly as `mk_bond_leg` builds it: the tagged sub-interface DOWN
/// and address-less with the leg's qos map, added as a port (never re-added — that is EBUSY), up,
/// and `forwarding=0` written explicitly. Callable for ONE port so the forwarding watchdog can
/// put back the legs a re-enumerated wire took with it, in the same argv as `apply`.
pub(crate) fn add_bond_port(
    sys: &mut dyn Sys,
    bond: &str,
    s: &Port,
    vid: u16,
    qos_map: &[&str],
) -> Result<()> {
    mk_vlan(sys, &s.ifname, &s.wire, vid, None, false, qos_map)?;
    // (3) `ip link set <port> master <bond>` on a port already in that bond is EBUSY, so
    // the second `up` must not re-issue it. sysfs answers "a port at all"; `ip -d` says
    // to whom (the master link cannot be read as a file — it is a symlink to a directory).
    let is_port_anywhere = sys.exists(&format!("/sys/class/net/{}/master", s.ifname));
    let is_port_here =
        is_port_anywhere && link_kind_is(sys, &s.ifname, &format!(" master {bond} "))?;
    if is_port_anywhere && !is_port_here {
        // A port already, but not of us. The kernel would answer the `master` set with a bare
        // EBUSY; say what is actually wrong instead.
        return Err(Error::fatal(port_elsewhere(&s.ifname)));
    }
    if !is_port_here {
        run_ok(sys, &["ip", "link", "set", &s.ifname, "master", bond])?;
    }
    run_ok(sys, &["ip", "link", "set", &s.ifname, "up"])?;
    // A port inherits conf/default, and on a kernel whose owner keeps ip_forward=1 that
    // means forwarding=1 — the same hazard `mk_identity` guards against. `up` only zeroes
    // conf/default on a HOST; a LEAF has fallback rows and is deliberately left alone there,
    // so the explicit write is the only thing that holds `owned_forwarding()`'s false.
    proc_sysctl(sys, &s.ifname, "forwarding", "0")
}

/// Re-assert the bond's `primary` and `primary_reselect`. Idempotent, and the ONLY way to set
/// `primary` — it names a port, so at `ip link add` time it is a silent no-op.
pub(crate) fn set_bond_primary(sys: &mut dyn Sys, bond: &str, home_port: &str) -> Result<()> {
    run_ok(
        sys,
        &[
            "ip",
            "link",
            "set",
            bond,
            "type",
            "bond",
            "primary",
            home_port,
            "primary_reselect",
            FALLBACK_PRIMARY_RESELECT,
        ],
    )?;
    Ok(())
}

/// The port carrying a bond leg's `home` wire — the one `primary` names.
pub(crate) fn home_port<'a>(bond: &str, ports: &'a [Port], home: &str) -> Result<&'a Port> {
    ports.iter().find(|s| s.wire == home).ok_or_else(|| {
        Error::fatal(format!(
            "{bond}: home wire {home} carries no port of this bond"
        ))
    })
}

/// The ingress leg's two shapes wear ONE name: `cfab-gw<id>` is a plain tagged sub-interface on
/// a single gw domain and an active-backup bond over every wire on scope `any`. A leg in the
/// OTHER shape is state a previous declaration left — after a crash, and also after a clean
/// stop whose teardown partially failed, which the supervisor logs and exits 0 on — so `up`
/// REMOVES it and builds the declared shape (James 2026-09-07). Refusing protected nothing: the
/// daemon is already down by the time `up` runs, and the refusal's exit 3 is on the unit's
/// `RestartPreventExitStatus`, so systemd would never retry it.
///
/// Removal goes through `teardown::remove_gw_leg`, the very code `cfab down` runs — the bond
/// before the ports that deleting it RELEASES rather than deletes, so nothing is orphaned, and
/// one spelling of "what a stale ingress leg is" for both verbs.
///
/// Only the other CFAB shape is handled here. A netdev of neither is a stranger wearing the
/// name and keeps the builders' own refusals, unchanged: `up` never deletes what it cannot
/// prove is ours.
fn replace_a_wrong_shape_gw_leg(
    sys: &mut dyn Sys,
    view: &View,
    r: &GwRow,
    warnings: &mut Vec<String>,
) -> Result<()> {
    if !link_exists(sys, &r.ifname)? {
        return Ok(());
    }
    let wrong_shape = if r.migrates() {
        link_kind_is(sys, &r.ifname, " vlan ")?
    } else {
        link_kind_is(sys, &r.ifname, " bond ")?
    };
    if !wrong_shape {
        return Ok(());
    }
    let Some(removed) = teardown::remove_gw_leg(sys, view.member, &r.ifname)? else {
        return Ok(());
    };
    warnings.push(gw_leg_shape_replaced(&r.ifname, removed, r.migrates()));
    Ok(())
}

/// One spelling for both directions: what was removed, and why this run wanted the other shape.
fn gw_leg_shape_replaced(ifname: &str, removed: &str, migrates: bool) -> String {
    let declared = if migrates {
        "scope `any`"
    } else {
        "one domain"
    };
    format!(
        "{ifname}: removed the {removed} a previous declaration left — this one puts the \
         ingress leg on {declared} — and rebuilt the leg"
    )
}

/// One spelling per condition (spec §9 string table), shared by `apply` and the forwarding
/// watchdog's rebuild step so the operator sees the same sentence whichever found it.
pub(crate) fn not_a_bond(ifname: &str) -> String {
    format!("REFUSING: {ifname} exists but is not a bond")
}

pub(crate) fn port_elsewhere(ifname: &str) -> String {
    format!("REFUSING: {ifname} is a port on another bond")
}

/// A netdev holding a cfab VLAN leg's name but of another kind. `apply` DELETES such a netdev
/// and re-creates it (it is cfab's by name, and an `up` is an operator-driven act); the
/// forwarding watchdog will not delete a live netdev on a three-second tick, so it says this
/// instead and leaves the leg unbuilt.
pub(crate) fn not_our_vlan(ifname: &str, lower: &str, vid: u16) -> String {
    format!(
        "REFUSING: {ifname} exists but is not a vlan id {vid} sub-interface of {lower} — the \
         watchdog never deletes a live netdev; re-run cfab up"
    )
}

/// Render `settled_down_ifs`'s `zone/ifname` entries for the operator. A fallback bond is not a
/// wire: it is `down` exactly when not one of its ports has carrier, so the warning must name
/// that condition — "ip -br link show cfab-st-fb" would only show an interface that is UP.
pub fn describe_down(view: &View, down: &[String]) -> Vec<String> {
    let fallback: Vec<String> = view
        .fallback_rows()
        .into_iter()
        .map(|r| r.ifname)
        .chain(
            view.gw_rows()
                .into_iter()
                .filter(GwRow::migrates)
                .map(|r| r.ifname),
        )
        .collect();
    down.iter()
        .map(|entry| {
            let ifname = entry.rsplit('/').next().unwrap_or(entry);
            if fallback.iter().any(|r| r == ifname) {
                format!("{entry} (no wire with carrier under it)")
            } else {
                entry.clone()
            }
        })
        .collect()
}

/// Measured live: arp_ignore=1 (NOT arp_filter — it flaps BFD); rp_filter LOOSE on every
/// segment (strict on a primary black-holed control for ~5 s when all links returned at once).
pub(crate) fn class_sysctls(sys: &mut dyn Sys, ifname: &str) -> Result<()> {
    proc_sysctl(sys, ifname, "arp_ignore", "1")?;
    proc_sysctl(sys, ifname, "rp_filter", "2")?;
    proc_sysctl(sys, ifname, "send_redirects", "0")?;
    proc_sysctl(sys, ifname, "forwarding", "0")?;
    Ok(())
}

/// Whether a gw or fallback leg was actually built by the per-class-netdevs section above,
/// given the same `absent` set and the same rule that section used to skip it: a migrating
/// (bond) leg needs `present_ports` to find a survivor; a non-migrating leg just needs its
/// one `home` wire present. Anything this returns `false` for has no netdev at all — a
/// per-interface sysctl on it would fail loud on real Linux (`RealSys::write` maps ENOENT to
/// `Error::fatal`) even though the mock accepts any path unconditionally.
fn leg_was_built(migrates: bool, ports: &[Port], home: &str, absent: &AbsentWires) -> bool {
    if migrates {
        present_ports(ports, home, absent).is_some()
    } else {
        !absent.contains(home)
    }
}

/// Load the policy atomically, read it back, and only then enable forwarding — on exactly the
/// class-table interfaces and workload `legs` that were actually built, never an absent wire's
/// segment, never a wire itself, never the untagged admin NIC.
fn enable_forwarding(
    sys: &mut dyn Sys,
    view: &View,
    absent: &AbsentWires,
    legs: &[&str],
) -> Result<()> {
    let f = view.fabric;
    let policy = emit::policy::generate(view)?;
    let path = format!("{}/policy.nft", f.run_dir);
    sys.write(&path, &policy)?;
    run_ok(sys, &["nft", "-f", &path])?; // one transaction: atomic replace
    let chain = run_ok(
        sys,
        &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
    )?;
    if !chain.stdout.contains("policy drop;") {
        return Err(Error::fatal(
            "policy loaded but chain forward is not 'policy drop' — not enabling forwarding",
        ));
    }
    let applied = run_ok(sys, &["nft", "-s", "list", "table", "inet", "cfab-fwd"])?;
    sys.write(&format!("{}/policy.applied", f.run_dir), &applied.stdout)?; // status drift baseline
    for r in view
        .class_rows()
        .iter()
        .filter(|r| !absent.contains(&r.wire))
    {
        proc_sysctl(sys, &r.ifname, "forwarding", "1")?;
    }
    for r in view
        .gw_rows()
        .iter()
        .filter(|r| leg_was_built(r.migrates(), &r.ports, &r.home, absent))
    {
        proc_sysctl(sys, &r.ifname, "forwarding", "1")?;
    }
    // The bond, never its ports: a port carries no L3 and the flag on it is meaningless.
    // `status` and the watchdog grade against `owned_forwarding()`, which lists the bond as
    // transit — leaving it out here would make every `up` report UP-DEGRADED three seconds later.
    for r in view
        .fallback_rows()
        .iter()
        .filter(|r| leg_was_built(true, &r.ports, &r.home, absent))
    {
        proc_sysctl(sys, &r.ifname, "forwarding", "1")?;
    }
    for admin in view.admin_ifs() {
        proc_sysctl(sys, admin, "forwarding", "0")?; // belt (the policy's admin rules = braces)
    }
    // A workload VLAN's whole point is routing VM traffic to its allowed zones. Only the legs
    // this apply actually built: a deferred row has no netdev, and a per-interface sysctl on a
    // netdev that does not exist fails loud on real Linux (`RealSys::write` maps ENOENT to
    // `Error::fatal`) even though the mock accepts any path. The watchdog sets it with the leg
    // it creates.
    for l in legs {
        proc_sysctl(sys, l, "forwarding", "1")?;
    }
    // A foreign stack's forward-hook policy drop kills transit that cfab accepts, and cfab
    // cannot out-accept it. Where the stack offers a user hook (Docker's DOCKER-USER), ask it
    // to pass cfab transit; `down` removes exactly this rule again.
    ensure_foreign_transit_accept(sys)?;
    Ok(())
}

/// Leaf leak guard (the braces; per-interface forwarding=0 is the belt): traffic to a fabric
/// block is looked up in main ONLY when locally originated; anything arriving on another
/// interface bound for a fabric block is refused. Routing rules, not netfilter: the guard is a
/// property of the routing table it protects. (`nft` is required on every kind for `table inet
/// cfab`; a member without it fails loud at the tool probe. The guard stays rule-based because
/// a second mechanism for the same invariant is a second thing to keep in step.)
fn leaf_guard(sys: &mut dyn Sys, view: &View) -> Result<()> {
    for r in common::leak_guard_rules(view) {
        common::ensure_fabric_rule(sys, &r)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
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

    #[test]
    fn uplink_word_agrees_in_number_with_the_port_list() {
        assert_eq!(uplink_word(&["eth0".to_string()]), "uplink");
        assert_eq!(
            uplink_word(&["eth0".to_string(), "eth1".to_string()]),
            "uplinks"
        );
        assert_eq!(uplink_word(&[]), "uplink");
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

    /// pve1-tb with TWO workload rows on TWO bridges: "vms" on `primary` (row 1, healthy per
    /// `wl_sys`) and "vms2" on `primary2` (row 2, refusable on its own) — for proving pass 1
    /// is pure reads: a hard refusal partway through must leave no write from an earlier row
    /// applied.
    fn two_row_wl_fabric() -> Fabric {
        let t = crate::decl::fixtures::with_prefs(
            &crate::decl::fixtures::example(),
            "pve1-tb",
            "workloads = [{ name = \"vms\", address = \"192.168.20.2/24\" }, { name = \"vms2\", address = \"192.168.30.2/24\" }]",
        );
        let blocks = format!(
            "{}\n[[workload]]\nname = \"vms2\"\nuplink = \"primary2\"\nvid = 4\nprefix = \"192.168.30.0/24\"\ngw = \"192.168.30.254\"\nrouter = \"192.168.30.1\"\nallow = [\"storage\"]\n",
            crate::decl::fixtures::WORKLOAD_BLOCK
        );
        Fabric::from_decl(&Declaration::parse(&format!("{t}{blocks}")).unwrap()).unwrap()
    }

    /// Task 5: the engine start, the shape daemon, the watchdog and conf-sync all moved to
    /// the (not-yet-built) supervisor. `apply` itself must launch no daemon at all — no
    /// `systemd-run`, no `systemctl`, no `spawn_detached` — and must name no unit.
    #[test]
    fn apply_starts_no_daemon_and_names_no_unit() {
        let (mut sys, view) = up_sys_and_view();
        run(&mut sys, &view, &opts()).unwrap();
        for c in &sys.calls {
            assert!(!c.contains("systemd-run"), "{c}");
            assert!(!c.contains("systemctl"), "{c}");
            assert!(!c.starts_with("spawn_detached"), "{c}");
        }
    }

    /// Task 5b (RULED, James 2026-09-05): the netdev does not exist. Today this refuses the
    /// whole apply; it must warn instead, skip that wire entirely, and say WHICH condition it
    /// hit. Review finding 1 (2026-09-05): the skip must reach the forwarding sysctls too —
    /// `write_fail` on the segment's forwarding path stands in for the real ENOENT a deleted
    /// VLAN sub-interface's `/proc/sys/net/ipv4/conf/<if>` gives on real Linux; a missed
    /// filter anywhere in `enable_forwarding` now fails this test instead of passing silently
    /// (the previous version of this test could not catch it: `MockSys::write` succeeded for
    /// any path).
    #[test]
    fn an_absent_wire_warns_and_the_apply_continues() {
        let (mut sys, view) = up_sys_and_view();
        // Genuine absence per `link_exists`: `ip link show eth9` itself reports no such
        // device (the last-added `on_fail` rule wins over `up_sys`'s default success).
        // `fabric()` (examples/fabric.toml) already declares `[forward] enabled`=1 for pve1-tb, so
        // this exercises the exact motivating scenario: a forwarding host with an absent wire.
        assert!(
            view.fabric.host_forward,
            "test assumes `[forward] enabled`=1"
        );
        sys = sys
            .on_fail(&["ip", "link", "show", "eth9"], 1, "Device does not exist")
            .write_fail("/proc/sys/net/ipv4/conf/cfab-st/forwarding");
        let warnings = run(&mut sys, &view, &opts()).unwrap();
        assert!(
            warnings.iter().any(|w| w
                == "wire eth9 absent (no such netdev) — its segments are not configured; the \
                    fabric is up on the rest"),
            "{warnings:?}"
        );
        // Nothing else may touch it: no sub-if, no bond port, no sysctl, no forwarding write —
        // checked by exact ifname token, not substring (a zone's `segments` reuses "cfab-st" as a
        // PREFIX for segments that live on other wires entirely: cfab-st-bk is domain cl,
        // cfab-st-b2 is domain mg — only cfab-st itself is eth9's segment).
        for c in sys
            .calls
            .iter()
            .skip_while(|c| !c.contains("ip link show eth9"))
            .skip(1)
        {
            let words: Vec<&str> = c.split_whitespace().collect();
            assert!(
                !words.contains(&"eth9") && !words.contains(&"cfab-st"),
                "the apply kept using an absent wire: {c}"
            );
        }
        // And the other wires were still configured.
        assert!(sys.ran("ip link add link eth0"));
    }

    /// Review finding 2 (2026-09-05): a wire that genuinely exists but cannot be brought up
    /// (EPERM, EBUSY, a wedged driver) is a DIFFERENT condition from absence — still a
    /// refusal, and the message must not claim the netdev does not exist (that would disagree
    /// with `status`, which reads `/sys/class/net/<wire>` and would show the wire present).
    #[test]
    fn a_present_wire_that_cannot_be_brought_up_still_refuses() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys.on_fail(
            &["ip", "link", "set", "eth9", "up"],
            1,
            "Operation not permitted",
        );
        let err = run(&mut sys, &view, &opts()).unwrap_err().to_string();
        assert!(!err.contains("absent (no such netdev)"), "{err}");
    }

    /// The untagged path of every host wire is the admin plane (James 2026-09-06), so `up`
    /// must never take a wire from whatever manages it: no NetworkManager release, no dhcp
    /// client kill, and above all no `ip addr flush` — that address IS the admin session. This
    /// replaces the two NetworkManager-release tests: the code they covered is gone, and this
    /// is the invariant that made it go.
    #[test]
    fn up_never_takes_a_wire_from_its_manager() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys.on_stdout(
            &["/usr/bin/env", "sh", "-c", "command -v nmcli"],
            "/usr/bin/nmcli\n",
        );
        run(&mut sys, &view, &opts()).unwrap();
        for wire in ["eth9", "eth1", "eth0"] {
            assert!(
                !sys.ran(&format!("nmcli device set {wire} managed no")),
                "{wire} was released from NetworkManager"
            );
            assert!(
                !sys.ran(&format!("ip addr flush dev {wire}")),
                "{wire}'s untagged admin address was flushed"
            );
            assert!(!sys.ran(&format!("dhcpcd -k {wire}")), "{wire}");
        }
    }

    /// Every netdev absent but the three wires (the from-scratch `up`), the admin NIC
    /// addressed, and the forward chain readable — the shape a first bringup sees.
    fn up_sys(_view: &View) -> MockSys {
        MockSys::default()
            .file("/proc/sys/net/ipv4/conf/all/rp_filter", "1\n")
            .on_fail(&["ip", "link", "show"], 1, "Device does not exist")
            .on_stdout(&["ip", "link", "show", "eth0"], "2: eth0: <UP>\n")
            .on_stdout(&["ip", "link", "show", "eth1"], "3: eth1: <UP>\n")
            .on_stdout(&["ip", "link", "show", "eth9"], "4: eth9: <UP>\n")
            .on_stdout(
                &["ip", "-4", "-br", "addr", "show", "dev", "eth0"],
                "eth0 UP 192.168.10.1/24\n",
            )
            .on_stdout(
                &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
                "table inet cfab-fwd {\n chain forward {\n type filter hook forward priority 0; policy drop;\n}\n}\n",
            )
    }

    /// `fabric()` + the `pve1-tb` view + `up_sys`'s fixture, combined for the common case
    /// (a fresh `apply` from scratch on a host). Leaks the `Fabric` (test-only, one per
    /// call): `View` borrows it, and a helper returning both needs a `'static` owner.
    fn up_sys_and_view() -> (MockSys, View<'static>) {
        let f: &'static Fabric = Box::leak(Box::new(fabric()));
        let view = View::new(f, "pve1-tb").unwrap();
        let sys = up_sys(&view);
        (sys, view)
    }

    /// The older mocks answer every `ip link show` with success, so a fallback bond would look
    /// present and of an unknown kind — a refusal. Mark the bonds absent: a fresh member.
    fn absent_fallback_netdevs(mut sys: MockSys, view: &View) -> MockSys {
        for r in view.fallback_rows() {
            sys = sys.on_fail(
                &["ip", "link", "show", &r.ifname],
                1,
                "Device does not exist",
            );
        }
        sys
    }

    pub(crate) fn opts() -> ApplyOpts {
        ApplyOpts {
            pmxcfs_root: "/nonexistent/pve".to_string(),
        }
    }

    /// pve1-tb with the workload row: `up_sys` plus the pve1 bridge — vlan-aware, one uplink
    /// port, one tap, and no self vid yet (cfab adds it). The leg itself does not exist: every
    /// `ip link show` fails in `up_sys`, which is what a first `up` finds.
    fn wl_sys(view: &View) -> MockSys {
        up_sys(view)
            .file("/sys/class/net/primary/bridge/stp_state", "0\n")
            .file("/sys/class/net/primary/bridge/vlan_filtering", "1\n")
            .file("/sys/class/net/primary/brif/eth0/state", "3\n")
            .file("/sys/class/net/primary/brif/tap100i0/state", "3\n")
            .link("/sys/class/net/eth0/device", "../../../0000:01:00.0")
            .file("/sys/class/net/eth0/ifindex", "2\n")
            .file("/sys/class/net/tap100i0/ifindex", "10\n")
            .file("/proc/sys/net/ipv4/conf/all/arp_ignore", "0\n")
            .on_stdout(
                &["bridge", "-j", "vlan", "show", "dev", "primary"],
                r#"[{"ifname":"primary","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]}]}]"#,
            )
    }

    pub(crate) fn wl_sys_and_view(member: &str) -> (MockSys, View<'static>) {
        let f: &'static Fabric = Box::leak(Box::new(wl_fabric()));
        let view = View::new(f, member).unwrap();
        let sys = wl_sys(&view);
        (sys, view)
    }

    #[test]
    fn up_with_a_workload_adds_gw_forwarding_arp_ignore_and_the_bridge_guard_before_the_mark_table()
    {
        let (mut sys, view) = wl_sys_and_view("pve1-tb");
        run(&mut sys, &view, &opts()).unwrap();
        assert!(sys.ran("ip addr replace 192.168.20.254/24 dev cfab-work-vms"));
        assert_eq!(
            sys.writes_of("/proc/sys/net/ipv4/conf/all/arp_ignore"),
            vec!["1"]
        );
        assert_eq!(
            sys.writes_of("/proc/sys/net/ipv4/conf/cfab-work-vms/forwarding")
                .last(),
            Some(&"1")
        );
        assert!(sys.ran("nft -f /run/cfab/workload-bridge.nft"));
        assert!(sys.ran("nft -s list table bridge cfab"));
        let pos = |needle: &str| {
            sys.calls
                .iter()
                .position(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not run: {:#?}", sys.calls))
        };
        assert!(
            pos("nft -f /run/cfab/policy.nft")
                < sys
                    .calls
                    .iter()
                    .rposition(|c| c == "write /proc/sys/net/ipv4/conf/cfab-work-vms/forwarding")
                    .unwrap(),
            "forwarding=1 follows the policy load (enable_forwarding)"
        );
        assert!(
            pos("nft -f /run/cfab/workload-bridge.nft") < pos("nft -f /run/cfab/mark.nft"),
            "guard before the mark table; the announcer starts after apply returns"
        );
        assert!(
            pos("nft -f /run/cfab/workload-bridge.nft")
                < pos("ip addr replace 192.168.20.254/24 dev cfab-work-vms"),
            "review item 1: the ARP guard is loaded before the gw address goes live, never after"
        );
        assert!(!sys.ran("ip link del cfab-work-vms"));
    }

    /// The leg is cfab's now: `up` builds it on the declared bridge, gives the bridge the vid
    /// it lacks, and puts BOTH addresses on it — the member's own and the anycast `gw`.
    #[test]
    fn up_creates_the_leg_the_self_vid_and_both_addresses() {
        let (mut sys, view) = wl_sys_and_view("pve1-tb");
        run(&mut sys, &view, &opts()).unwrap();
        assert!(sys.ran(
            "ip link add link primary name cfab-work-vms type vlan id 3 egress-qos-map 0:0 6:6"
        ));
        assert!(sys.ran("ip addr replace 192.168.20.2/24 dev cfab-work-vms"));
        assert!(sys.ran("ip link set cfab-work-vms up"));
        assert!(sys.ran("bridge vlan add dev primary vid 3 self"));
        assert_eq!(
            sys.writes_to("/run/cfab/workload-self-vid"),
            Some("primary 3")
        );
        assert!(sys.ran("ip addr replace 192.168.20.254/24 dev cfab-work-vms"));
        // The uplink bridge is the host's: cfab never creates or deletes it.
        assert!(!sys.ran("ip link del primary"));
        assert!(!sys.ran("ip link add link  name primary"));
    }

    /// The bridge is the host's and may be seconds behind cfab at boot (or renamed): that row
    /// waits, every other row and everything else on the member still applies.
    #[test]
    fn up_defers_a_row_whose_bridge_is_not_there_yet() {
        let (sys, view) = wl_sys_and_view("pve1-tb");
        let mut nobridge = MockSys {
            files: sys
                .files
                .iter()
                .filter(|(k, _)| !k.starts_with("/sys/class/net/primary/"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            ..sys
        };
        let warnings = run(&mut nobridge, &view, &opts()).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w == "workload vms: waiting for bridge primary"),
            "{warnings:#?}"
        );
        assert!(!nobridge.ran("ip link add link primary name cfab-work-vms"));
        assert!(!nobridge.ran("ip addr replace 192.168.20.254/24 dev cfab-work-vms"));
        assert_eq!(
            nobridge.writes_of(&format!("{}/workload-deferred", view.fabric.run_dir)),
            vec!["vms"]
        );
        // Everything else still applies: the policy loaded, forwarding still went on.
        assert!(nobridge.ran("nft -f /run/cfab/policy.nft"));
    }

    /// A bridge that is not vlan-aware cannot carry the leg's tag, and no amount of waiting
    /// fixes it: `apply` refuses in `check::host_preflight`'s words, one spelling for both.
    #[test]
    fn up_refuses_an_uplink_bridge_that_is_not_vlan_aware() {
        let (sys, view) = wl_sys_and_view("pve1-tb");
        let mut flat = sys.file("/sys/class/net/primary/bridge/vlan_filtering", "0\n");
        assert_eq!(
            run(&mut flat, &view, &opts()).unwrap_err().to_string(),
            "FATAL: workload vms: bridge primary is not vlan-aware (bridge-vlan-aware yes in \
             /etc/network/interfaces)"
        );
    }

    #[test]
    fn a_refusal_on_the_second_workload_row_leaves_nothing_from_the_first_applied() {
        let f: &'static Fabric = Box::leak(Box::new(two_row_wl_fabric()));
        let view = View::new(f, "pve1-tb").unwrap();
        // Row 2's bridge exists but is not vlan-aware: a refusal, not a deferral.
        let mut sys = wl_sys(&view)
            .file("/sys/class/net/primary2/bridge/stp_state", "0\n")
            .file("/sys/class/net/primary2/bridge/vlan_filtering", "0\n")
            .file("/sys/class/net/primary2/brif/eth1/state", "3\n")
            .link("/sys/class/net/eth1/device", "../../../0000:01:00.1");
        let err = run(&mut sys, &view, &opts()).unwrap_err().to_string();
        assert_eq!(
            err,
            "FATAL: workload vms2: bridge primary2 is not vlan-aware (bridge-vlan-aware yes in \
             /etc/network/interfaces)"
        );
        // Pass 1 is pure reads: row 1 ("vms") was fully valid, but nothing workload-shaped was
        // written for it — the hard refusal on row 2 happens before the leg is built, before
        // pass 2 (bridge table) and before pass 3 (the gw address + arp_ignore writes).
        assert!(!sys.ran("ip link add link primary name cfab-work-vms"));
        assert!(!sys.ran("ip addr replace 192.168.20.254/24 dev cfab-work-vms"));
        assert!(!sys.ran("nft -f /run/cfab/workload-bridge.nft"));
        assert!(
            sys.writes_of("/proc/sys/net/ipv4/conf/all/arp_ignore")
                .is_empty()
        );
        assert!(
            sys.writes_of(&format!("{}/workload-deferred", view.fabric.run_dir))
                .is_empty()
        );
    }

    // James's ruling 2026-09-09 ("bias towards availability"): an uplink that is not yet
    // STP-forwarding, or that cannot be identified at all, no longer refuses the whole apply
    // (spec §5.1 item 1) — it defers that one row to the watchdog and applies everything else.
    #[test]
    fn up_defers_a_not_yet_forwarding_uplink_instead_of_refusing_the_whole_apply() {
        let (sys, view) = wl_sys_and_view("pve1-tb");
        let mut listening = sys.file("/sys/class/net/primary/brif/eth0/state", "1\n");
        let warnings = run(&mut listening, &view, &opts()).unwrap();
        assert!(
            warnings.iter().any(|w| w
                == "workload vms: uplink eth0 not forwarding (STP state 1); row deferred to \
                    the watchdog"),
            "{warnings:#?}"
        );
        assert!(!listening.ran("ip addr replace 192.168.20.254/24 dev cfab-work-vms"));
        // MINOR 1 (re-review): arp_ignore matches the watchdog's own restore condition — set
        // whenever ANY workload row is declared, ready or not, never gated on this row alone.
        // Every row on this member is deferred here (there is only the one, "vms"), so this is
        // also the all-rows-deferred case.
        assert_eq!(
            listening.writes_of("/proc/sys/net/ipv4/conf/all/arp_ignore"),
            vec!["1"]
        );
        assert_eq!(
            listening.writes_of(&format!("{}/workload-deferred", view.fabric.run_dir)),
            vec!["vms"]
        );
        // Everything else still applies: the policy loaded, forwarding still went on.
        assert!(listening.ran("nft -f /run/cfab/policy.nft"));
    }

    #[test]
    fn up_defers_an_unidentifiable_uplink_instead_of_refusing_the_whole_apply() {
        let (sys, view) = wl_sys_and_view("pve1-tb");
        let mut no_uplink = sys;
        no_uplink.links.remove("/sys/class/net/eth0/device");
        let warnings = run(&mut no_uplink, &view, &opts()).unwrap();
        let warning = warnings
            .iter()
            .find(|w| w.starts_with("workload vms: uplink not identified: "))
            .unwrap_or_else(|| panic!("{warnings:#?}"));
        assert!(
            warning.contains("bridge primary has no uplink port"),
            "{warning}"
        );
        assert!(
            warning.ends_with("; row deferred to the watchdog"),
            "{warning}"
        );
        assert!(!no_uplink.ran("ip addr replace 192.168.20.254/24 dev cfab-work-vms"));
        assert!(
            !no_uplink.ran("nft -f /run/cfab/workload-bridge.nft"),
            "no uplink to guard"
        );
    }

    #[test]
    fn up_with_a_workload_elsewhere_does_not_touch_arp_ignore_on_a_member_without_one() {
        let (mut sys, view) = wl_sys_and_view("pve3-tb"); // wl_sys adds facts pve3 never reads; harmless
        let mut sys = absent_fallback_netdevs(std::mem::take(&mut sys), &view);
        run(&mut sys, &view, &opts()).unwrap();
        assert!(
            sys.writes_of("/proc/sys/net/ipv4/conf/all/arp_ignore")
                .is_empty()
        );
        assert!(
            sys.ran("ip rule add pref 2000 from 10.99.0.0/16 to 192.168.20.0/24 lookup main"),
            "the leaf gets the sibling"
        );
    }

    #[test]
    fn up_with_zero_workload_rows_removes_a_stale_deferred_file() {
        // MINOR 2 (re-review): a declaration that dropped its last `[[workload]]` row (or never
        // had one) must not leave a prior `apply`'s workload-deferred file behind for a stale
        // name the watchdog would otherwise keep trying to install forever.
        let (mut sys, view) = up_sys_and_view();
        run(&mut sys, &view, &opts()).unwrap();
        assert!(sys.ran(&format!("rm {}/workload-deferred", view.fabric.run_dir)));
    }

    #[test]
    fn the_workload_apply_sequence_is_pinned() {
        let (mut sys, view) = wl_sys_and_view("pve1-tb");
        run(&mut sys, &view, &opts()).unwrap();
        let got = format!("{}\n", sys.calls.join("\n"));
        let path = format!(
            "{}/tests/fixtures/apply-argv-workload-pve1-tb.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let want = std::fs::read_to_string(&path).unwrap_or_default();
        if got != want {
            std::fs::write(format!("{path}.actual"), &got).unwrap();
            panic!("the workload apply sequence changed; see {path}.actual");
        }
    }

    fn calls_for(sys: &MockSys, needle: &str) -> Vec<String> {
        sys.calls
            .iter()
            .filter(|c| c.contains(needle))
            .cloned()
            .collect()
    }

    /// Calls naming exactly this device (token equality: `cfab-st` never matches `cfab-st-bk`).
    fn calls_for_dev(sys: &MockSys, dev: &str) -> Vec<String> {
        sys.calls
            .iter()
            .filter(|c| c.split_whitespace().any(|t| t == dev))
            .cloned()
            .collect()
    }

    /// The whole fallback leg for one zone, argv by argv, on a member with three wires: the bond
    /// first, each port created DOWN and address-less then added and brought up, `primary`
    /// only AFTER the ports exist (at `add` time it is a silent no-op), then the address,
    /// the segment sysctls and the bond up. storage's home wire is eth9 (its cheapest class
    /// row is on the st domain), so `primary` names the st PORT, never the wire.
    #[test]
    fn a_fallback_leg_is_built_bond_ports_primary_address() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view);
        let o = opts();
        run(&mut sys, &view, &o).unwrap();
        assert_eq!(
            calls_for(&sys, "cfab-st-fb"),
            [
                "ip link show cfab-st-fb",
                "ip link add cfab-st-fb type bond mode active-backup miimon 100 num_grat_arp 3 updelay 500 fail_over_mac none",
                "ip link show cfab-st-fb-a",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-fb-a",
                "ip link add link eth9 name cfab-st-fb-a type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-fb-a master cfab-st-fb",
                "ip link set cfab-st-fb-a up",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb-a/forwarding",
                "ip link show cfab-st-fb-b",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-fb-b",
                "ip link add link eth1 name cfab-st-fb-b type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-fb-b master cfab-st-fb",
                "ip link set cfab-st-fb-b up",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb-b/forwarding",
                "ip link show cfab-st-fb-c",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-fb-c",
                "ip link add link eth0 name cfab-st-fb-c type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-fb-c master cfab-st-fb",
                "ip link set cfab-st-fb-c up",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb-c/forwarding",
                "ip link set cfab-st-fb type bond primary cfab-st-fb-a primary_reselect always",
                "ip addr replace 10.99.9.1/24 dev cfab-st-fb",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb/arp_ignore",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb/send_redirects",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb/forwarding",
                "ip link set cfab-st-fb up",
                // enable_forwarding, after the policy is loaded and read back
                "write /proc/sys/net/ipv4/conf/cfab-st-fb/forwarding",
            ]
        );
    }

    /// A port already in OUR bond is not re-added: `ip link set <port> master <bond>` on
    /// it is EBUSY, so the second `up` would fail outright. A port that is not gets added.
    #[test]
    fn a_second_up_does_not_re_add_a_port_already_in_the_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        // An existing bond must also present its bonding/ sysfs: `up` proves the parameters
        // before it touches a bond it did not just create.
        let sys = bond_sysfs(up_sys(&view), "cfab-st-fb", &healthy_bond_params());
        let mut sys = sys
            .file("/sys/class/net/cfab-st-fb-a/master", "")
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
                "10: cfab-st-fb-a@eth9: master cfab-st-fb state UP vlan protocol 802.1Q id 300 \n",
            );
        run(&mut sys, &view, &o).unwrap();
        assert!(
            !sys.ran("ip link set cfab-st-fb-a master"),
            "{:?}",
            calls_for(&sys, "cfab-st-fb-a")
        );
        assert!(!sys.ran("ip link add cfab-st-fb type bond"), "bond kept");
        // and the ones that are not ports yet still are
        assert!(sys.ran("ip link set cfab-st-fb-b master cfab-st-fb"));
    }

    /// A port name that is already a port SOMEWHERE ELSE: the kernel would answer the
    /// `master` set with a bare "Device or resource busy". Refuse in cfab's own wording.
    #[test]
    fn up_refuses_a_fallback_port_already_on_a_foreign_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let mut sys = up_sys(&view)
            .file("/sys/class/net/cfab-st-fb-a/master", "")
            .on_stdout(
                &["ip", "link", "show", "cfab-st-fb-a"],
                "10: cfab-st-fb-a\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb-a"],
                "10: cfab-st-fb-a@eth9: master br0 state UP vlan protocol 802.1Q id 300 \n",
            );
        let e = run(&mut sys, &view, &o).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-fb-a is a port on another bond"),
            "{e}"
        );
        assert!(
            !sys.ran("ip link set cfab-st-fb-a master"),
            "never fights the kernel for it"
        );
    }

    /// A netdev already carrying a fallback bond's name but of another kind is not ours to
    /// delete (unlike a vlan of the wrong id, which cfab created and can recreate): refuse.
    #[test]
    fn up_refuses_a_foreign_netdev_named_like_a_fallback_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let mut sys = up_sys(&view)
            .on_stdout(&["ip", "link", "show", "cfab-st-fb"], "9: cfab-st-fb\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb"],
                "9: cfab-st-fb: bridge \n",
            );
        let e = run(&mut sys, &view, &o).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-fb exists but is not a bond"),
            "{e}"
        );
        assert!(
            !sys.ran("ip link del cfab-st-fb"),
            "never deletes a stranger"
        );
    }

    /// An existing fallback bond, correctly typed, with every bonding parameter as this build
    /// wants it — the steady state a second `up` meets.
    fn existing_fallback_bond(sys: MockSys, params: &[(&str, &str)]) -> MockSys {
        let sys = sys
            .on_stdout(
                &["ip", "link", "show", "cfab-st-fb"],
                "9: cfab-st-fb: <UP>\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb"],
                "9: cfab-st-fb: bond mode active-backup \n",
            );
        bond_sysfs(sys, "cfab-st-fb", params)
    }

    /// A bond's `bonding/` sysfs as the kernel spells it, parameter by parameter.
    fn bond_sysfs(mut sys: MockSys, ifname: &str, params: &[(&str, &str)]) -> MockSys {
        for (name, value) in params {
            sys = sys.file(&format!("/sys/class/net/{ifname}/bonding/{name}"), value);
        }
        sys
    }

    /// Exactly what this build creates a bond with, in sysfs spelling.
    fn healthy_bond_params() -> Vec<(&'static str, &'static str)> {
        vec![
            ("mode", "active-backup 1\n"),
            ("miimon", "100\n"),
            ("updelay", "500\n"),
            ("num_grat_arp", "3\n"),
            ("fail_over_mac", "none 0\n"),
        ]
    }

    /// Bond parameters are only set at `ip link add`, so an existing bond keeps whatever it
    /// was created with — this branch's own `updelay` 0 -> 500 would never reach a member
    /// that already has the leg. `up` refuses instead of rewriting a live bond (`mode` and
    /// `fail_over_mac` are not writable on one at all) and names the remedy.
    #[test]
    fn up_refuses_an_existing_fallback_bond_whose_parameters_diverge() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let mut params = healthy_bond_params();
        params[2] = ("updelay", "0\n");
        let mut sys = existing_fallback_bond(up_sys(&view), &params);
        let e = run(&mut sys, &view, &o).unwrap_err().to_string();
        assert!(e.contains("cfab-st-fb"), "{e}");
        assert!(e.contains("updelay want 500 got 0"), "{e}");
        assert!(e.contains("cfab down"), "{e}");
        assert!(
            !sys.ran("ip link set cfab-st-fb type bond updelay"),
            "never rewrites a live bond: {:?}",
            sys.calls
        );
    }

    /// Every diverging parameter is named in one message, not just the first.
    #[test]
    fn a_diverging_bond_names_every_parameter_with_want_and_got() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let params = [
            ("mode", "balance-rr 0\n"),
            ("miimon", "100\n"),
            ("updelay", "0\n"),
            ("num_grat_arp", "1\n"),
            ("fail_over_mac", "active 1\n"),
        ];
        let mut sys = existing_fallback_bond(up_sys(&view), &params);
        let e = run(&mut sys, &view, &o).unwrap_err().to_string();
        for want in [
            "mode want active-backup got balance-rr",
            "updelay want 500 got 0",
            "num_grat_arp want 3 got 1",
            "fail_over_mac want none got active",
        ] {
            assert!(e.contains(want), "{want} missing from: {e}");
        }
        assert!(
            !e.contains("miimon want"),
            "the matching one is not named: {e}"
        );
    }

    /// The steady state: a bond that is already exactly right is accepted, `ip link add` is
    /// not re-issued, and `up` goes on to the ports.
    #[test]
    fn an_existing_fallback_bond_with_matching_parameters_is_accepted() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let mut sys = existing_fallback_bond(up_sys(&view), &healthy_bond_params());
        run(&mut sys, &view, &o).unwrap();
        assert!(
            !sys.ran("ip link add cfab-st-fb type bond"),
            "an existing bond is never recreated"
        );
        assert!(sys.ran("ip link set cfab-st-fb-a master cfab-st-fb"));
        assert!(sys.ran("ip link set cfab-st-fb up"));
    }

    /// An unreadable bonding file is not health: it is an unproven bond. Refuse, and say
    /// which file could not be read.
    #[test]
    fn an_unreadable_bonding_file_is_refused_by_name() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let params: Vec<_> = healthy_bond_params()
            .into_iter()
            .filter(|(n, _)| *n != "num_grat_arp")
            .collect();
        let mut sys = existing_fallback_bond(up_sys(&view), &params);
        let e = run(&mut sys, &view, &o).unwrap_err().to_string();
        assert!(
            e.contains("/sys/class/net/cfab-st-fb/bonding/num_grat_arp"),
            "{e}"
        );
        assert!(e.contains("cfab down"), "{e}");
    }

    /// 3.1b: `enable_forwarding` loops the rows, not `owned_forwarding()` — a fallback bond left
    /// out of it would leave every `up` UP-DEGRADED and make the watchdog "correct" a flag cfab
    /// never set. The ports are written 0 EXPLICITLY: they carry no L3, and inheriting
    /// conf/default (1 on a leaf whose external owner keeps ip_forward=1) would contradict
    /// `owned_forwarding()` with nothing in `up` to correct it.
    #[test]
    fn fallback_bonds_forward_and_their_ports_never_do() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let mut sys = up_sys(&view);
        run(&mut sys, &view, &o).unwrap();
        for zone_if in ["cfab-st-fb", "cfab-cl-fb", "cfab-mg-fb"] {
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{zone_if}/forwarding")),
                Some("1"),
                "{zone_if}"
            );
        }
        for port in ["cfab-st-fb-a", "cfab-st-fb-b", "cfab-st-fb-c"] {
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{port}/forwarding")),
                Some("0"),
                "{port} is L2 only"
            );
        }
    }

    /// `up` records the driver of every present wire so the forwarding watchdog can spot a
    /// swapped adapter later. NIC features are the host's own business now (a udev rule on the
    /// netdev-add event): no code path in `up` runs `ethtool -k` or `ethtool -K` at all.
    #[test]
    fn up_records_every_present_wires_driver_and_sets_no_nic_feature() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys
            .on_stdout(&["ethtool", "-i", "eth9"], "driver: r8152\n")
            .on_stdout(&["ethtool", "-i", "eth1"], "driver: igb\n")
            .on_stdout(&["ethtool", "-i", "eth0"], "driver: igb\n");
        run(&mut sys, &view, &opts()).unwrap();
        assert_eq!(
            sys.writes_to("/run/cfab/wire-drivers"),
            Some("eth9 r8152\neth1 igb\neth0 igb\n")
        );
        assert!(calls_for(&sys, "ethtool -K").is_empty(), "{:?}", sys.calls);
        assert!(calls_for(&sys, "ethtool -k").is_empty(), "{:?}", sys.calls);
    }

    /// ethtool is on PATH, but one present wire refuses the read (a device-specific nonzero
    /// exit, e.g. "Operation not supported"): that wire is silently left out of the driver
    /// record — same as before — but now names itself in a per-wire warning rather than
    /// vanishing without a trace. The other wires still record normally.
    #[test]
    fn a_device_specific_ethtool_failure_warns_by_name_and_still_records_the_rest() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys
            .on_fail(&["ethtool", "-i", "eth9"], 1, "Operation not supported")
            .on_stdout(&["ethtool", "-i", "eth1"], "driver: igb\n")
            .on_stdout(&["ethtool", "-i", "eth0"], "driver: igb\n");
        let warnings = run(&mut sys, &view, &opts()).unwrap();
        assert_eq!(
            sys.writes_to("/run/cfab/wire-drivers"),
            Some("eth1 igb\neth0 igb\n")
        );
        assert!(
            warnings.contains(&"WARNING: ethtool -i eth9: driver unrecorded".to_string()),
            "{warnings:?}"
        );
        assert!(
            !warnings.iter().any(|w| w.contains("not installed")),
            "a device's own refusal must not read as ethtool being uninstalled: {warnings:?}"
        );
    }

    /// An absent wire is not probed and not recorded — same rule the rest of `up` follows.
    #[test]
    fn an_absent_wire_gets_no_driver_probe_and_no_record() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys
            .on_fail(&["ip", "link", "show", "eth9"], 1, "Device does not exist")
            .on_stdout(&["ethtool", "-i", "eth1"], "driver: igb\n")
            .on_stdout(&["ethtool", "-i", "eth0"], "driver: igb\n");
        run(&mut sys, &view, &opts()).unwrap();
        assert!(!sys.ran("ethtool -i eth9"), "{:?}", sys.calls);
        assert_eq!(
            sys.writes_to("/run/cfab/wire-drivers"),
            Some("eth1 igb\neth0 igb\n")
        );
    }

    /// ethtool is a read-only, OPTIONAL dependency (Debian `Recommends`): absent entirely, `up`
    /// still succeeds, writes an empty driver record (nothing to compare the watchdog against
    /// later), and says so once — never a fatal precondition, and never one probe per wire once
    /// the tool is known missing.
    #[test]
    fn ethtool_absent_writes_an_empty_record_and_warns_once() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys.on_fail(&["/usr/bin/env", "sh", "-c", "command -v ethtool"], 1, "");
        let warnings = run(&mut sys, &view, &opts()).unwrap();
        assert!(!sys.ran("ethtool -i"), "{:?}", sys.calls);
        assert_eq!(sys.writes_to("/run/cfab/wire-drivers"), Some(""));
        assert_eq!(
            warnings
                .iter()
                .filter(|w| w.contains("ethtool not installed"))
                .count(),
            1,
            "{warnings:?}"
        );
        assert!(
            warnings
                .contains(&"WARNING: ethtool not installed: wire drivers unrecorded".to_string()),
            "{warnings:?}"
        );
    }

    /// The same declaration with the ingress leg pinned to one domain — the example ships
    /// scope `any`, the migrating leg.
    fn fabric_with_a_domain_gw() -> Fabric {
        let text = crate::decl::fixtures::with_a_domain_gw(&crate::decl::fixtures::example());
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    /// Task 9: a gw domain of `any` builds the ingress leg as the very same bond a fallback
    /// leg is — same parameters, same port-add order, same `primary`-after-ports
    /// rule — addressed with the router's /24 leg address, not a segment address. mgmt's
    /// cheapest segment is on the mg domain, so `primary` names the mg PORT.
    #[test]
    fn a_migrating_gw_leg_is_built_as_a_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view);
        let o = opts();
        run(&mut sys, &view, &o).unwrap();
        assert_eq!(
            calls_for(&sys, "cfab-gw249"),
            [
                // the shape guard's own probe (`gw_leg_shape_ok`), then mk_bond_leg's
                "ip link show cfab-gw249",
                "ip link show cfab-gw249",
                "ip link add cfab-gw249 type bond mode active-backup miimon 100 num_grat_arp 3 updelay 500 fail_over_mac none",
                "ip link show cfab-gw249-a",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-gw249-a",
                "ip link add link eth9 name cfab-gw249-a type vlan id 249 egress-qos-map 0:2 6:6",
                "ip link set cfab-gw249-a master cfab-gw249",
                "ip link set cfab-gw249-a up",
                "write /proc/sys/net/ipv4/conf/cfab-gw249-a/forwarding",
                "ip link show cfab-gw249-b",
                "ip link show cfab-gw249-b",
                "ip link add link eth1 name cfab-gw249-b type vlan id 249 egress-qos-map 0:2 6:6",
                "ip link set cfab-gw249-b master cfab-gw249",
                "ip link set cfab-gw249-b up",
                "write /proc/sys/net/ipv4/conf/cfab-gw249-b/forwarding",
                "ip link show cfab-gw249-c",
                "ip link show cfab-gw249-c",
                "ip link add link eth0 name cfab-gw249-c type vlan id 249 egress-qos-map 0:2 6:6",
                "ip link set cfab-gw249-c master cfab-gw249",
                "ip link set cfab-gw249-c up",
                "write /proc/sys/net/ipv4/conf/cfab-gw249-c/forwarding",
                "ip link set cfab-gw249 type bond primary cfab-gw249-c primary_reselect always",
                "ip addr replace 192.168.249.1/24 dev cfab-gw249",
                "write /proc/sys/net/ipv4/conf/cfab-gw249/arp_ignore",
                "write /proc/sys/net/ipv4/conf/cfab-gw249/rp_filter",
                "write /proc/sys/net/ipv4/conf/cfab-gw249/send_redirects",
                "write /proc/sys/net/ipv4/conf/cfab-gw249/forwarding",
                "ip link set cfab-gw249 up",
                // The per-zone return-path default lands as part of building the leg (E2.2).
                "ip route replace default via 192.168.249.254 dev cfab-gw249 table 249 proto 205",
                "write /proc/sys/net/ipv4/conf/cfab-gw249/forwarding",
            ]
        );
    }

    /// Every `ip link del` the run issued, in order.
    fn dels(sys: &MockSys) -> Vec<&String> {
        sys.calls
            .iter()
            .filter(|c| c.starts_with("ip link del"))
            .collect()
    }

    /// The index of the first call equal to `argv`.
    fn call_at(sys: &MockSys, argv: &str) -> usize {
        sys.calls
            .iter()
            .position(|c| c == argv)
            .unwrap_or_else(|| panic!("{argv} never ran: {:?}", sys.calls))
    }

    /// A migrating ingress leg with one tagged port per wire, live on the box — what a
    /// previous `any` declaration left behind.
    fn a_live_gw_bond(mut sys: MockSys) -> MockSys {
        sys = sys
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

    /// The ingress leg's two shapes wear the SAME name: a plain tagged sub-interface on a
    /// single gw domain, an active-backup bond on scope `any`. A plain `cfab up` on a flipped
    /// declaration meets the shape the PREVIOUS declaration built — after a crash, and also
    /// after a clean exit whose teardown partially failed (the supervisor logs that and exits
    /// 0). James 2026-09-07: refusing protects nothing with the daemon already down, and exit
    /// 3 is on `RestartPreventExitStatus`, so systemd would never retry. `up` removes the old
    /// shape through the same code `cfab down` runs — the bond BEFORE the ports it releases
    /// rather than deletes — says so in one line, and builds the declared shape.
    #[test]
    fn up_replaces_an_ingress_leg_the_previous_declaration_built_as_a_bond() {
        let f = fabric_with_a_domain_gw();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = a_live_gw_bond(up_sys(&view));
        let warnings = run(&mut sys, &view, &opts()).unwrap();
        assert_eq!(
            dels(&sys),
            [
                "ip link del cfab-gw249",
                "ip link del cfab-gw249-a",
                "ip link del cfab-gw249-b",
                "ip link del cfab-gw249-c",
            ]
        );
        assert!(
            call_at(&sys, "ip link del cfab-gw249-c")
                < call_at(
                    &sys,
                    "ip link add link eth0 name cfab-gw249 type vlan id 249 egress-qos-map 0:2 6:6"
                ),
            "the declared shape is built after the old one is gone: {:?}",
            sys.calls
        );
        assert!(
            warnings.contains(
                &"cfab-gw249: removed the bond a previous declaration left — this one puts the \
                  ingress leg on one domain — and rebuilt the leg"
                    .to_string()
            ),
            "{warnings:?}"
        );
    }

    /// The other direction, in the same words: the box wears the plain sub-interface and the
    /// declaration now says `any`. The stale leg had no ports, so exactly one delete.
    #[test]
    fn up_replaces_an_ingress_leg_the_previous_declaration_built_as_a_sub_interface() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view)
            .on_stdout(&["ip", "link", "show", "cfab-gw249"], "20: cfab-gw249\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249"],
                "20: cfab-gw249@eth0: vlan protocol 802.1Q id 249 \n",
            );
        let warnings = run(&mut sys, &view, &opts()).unwrap();
        assert_eq!(dels(&sys), ["ip link del cfab-gw249"]);
        assert!(
            call_at(&sys, "ip link del cfab-gw249")
                < call_at(
                    &sys,
                    "ip link add cfab-gw249 type bond mode active-backup miimon 100 \
                     num_grat_arp 3 updelay 500 fail_over_mac none"
                ),
            "the declared shape is built after the old one is gone: {:?}",
            sys.calls
        );
        assert!(
            warnings.contains(
                &"cfab-gw249: removed the sub-interface a previous declaration left — this one \
                  puts the ingress leg on scope `any` — and rebuilt the leg"
                    .to_string()
            ),
            "{warnings:?}"
        );
    }

    /// A netdev of NEITHER shape wearing the leg's name is not the flip: it keeps the builders'
    /// own refusals, which do not offer a remedy `down` cannot perform on a stranger.
    #[test]
    fn up_still_refuses_a_stranger_wearing_the_ingress_legs_name() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view)
            .on_stdout(&["ip", "link", "show", "cfab-gw249"], "20: cfab-gw249\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-gw249"],
                "20: cfab-gw249: bridge \n",
            );
        let e = run(&mut sys, &view, &opts()).unwrap_err().to_string();
        assert_eq!(e, "FATAL: REFUSING: cfab-gw249 exists but is not a bond");
    }

    /// The per-zone return-path default (task E2.2): after the ingress leg is addressed, `up`
    /// installs cfab's own default in the zone's table, via the router, through the leg, under
    /// proto 205 (cfab's own id, outside the engine's swept range). Exact argv.
    #[test]
    fn up_installs_the_return_path_default_through_the_ingress_leg() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view);
        let o = opts();
        run(&mut sys, &view, &o).unwrap();
        assert!(
            sys.ran(
                "ip route replace default via 192.168.249.254 dev cfab-gw249 table 249 proto 205"
            ),
            "{:?}",
            calls_for(&sys, "route replace default")
        );
    }

    /// The bond forwards (it is the L3 leg); its ports never do, and `up` writes that
    /// explicitly rather than inheriting conf/default.
    #[test]
    fn a_migrating_gw_bond_forwards_and_its_ports_never_do() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view);
        let o = opts();
        run(&mut sys, &view, &o).unwrap();
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-gw249/forwarding"),
            Some("1")
        );
        for port in ["cfab-gw249-a", "cfab-gw249-b", "cfab-gw249-c"] {
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{port}/forwarding")),
                Some("0"),
                "{port} is L2 only"
            );
        }
    }

    /// A migrating ingress leg is a bond too, so the settle warning must name the real
    /// condition for it as well.
    #[test]
    fn a_down_migrating_gw_bond_is_reported_as_no_wire_with_carrier() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let got = describe_down(&view, &["mgmt/cfab-gw249".to_string()]);
        assert_eq!(
            got,
            ["mgmt/cfab-gw249 (no wire with carrier under it)".to_string()]
        );
    }

    /// The WHOLE recorded sequence of a from-scratch `apply`, argv by argv and write by write,
    /// for a forwarding host and for a leaf. The per-leg builders below are shared with the
    /// forwarding watchdog's rebuild step (`fwd_watchdog::restore_missing_legs`), which exists
    /// precisely so the two spellings cannot drift — this pins the other half of that bargain:
    /// factoring a builder out must not move one byte of what `apply` issues, in what order.
    #[test]
    fn the_whole_apply_sequence_is_pinned() {
        for member in ["pve1-tb", "pve3-tb"] {
            let f = fabric();
            let view = View::new(&f, member).unwrap();
            let mut sys = absent_fallback_netdevs(up_sys(&view), &view);
            run(&mut sys, &view, &opts()).unwrap();
            let got = format!("{}\n", sys.calls.join("\n"));
            let path = format!(
                "{}/tests/fixtures/apply-argv-{member}.txt",
                env!("CARGO_MANIFEST_DIR")
            );
            let want = std::fs::read_to_string(&path).unwrap_or_default();
            if got != want {
                std::fs::write(format!("{path}.actual"), &got).unwrap();
                panic!("the apply sequence for {member} changed; see {path}.actual");
            }
        }
    }

    /// VRRP was deleted (the NAS is a fabric leaf, James 2026-09-02): a forwarding host's
    /// `up` must create no macvlan at all — the storage VIP netdev was the only one cfab ever
    /// made. The example fabric declares ``[forward] enabled`=1`, the case that used to build it.
    #[test]
    fn a_forwarding_host_creates_no_macvlan() {
        let f = fabric();
        assert!(f.host_forward);
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let mut sys = up_sys(&view);
        run(&mut sys, &view, &o).unwrap();
        assert_eq!(calls_for(&sys, "macvlan"), Vec::<String>::new());
        assert_eq!(calls_for(&sys, "cfab-st-vr"), Vec::<String>::new());
    }

    /// The fallback leg extended `mk_vlan` with `addr`/`bring_up`. A class row and an ingress
    /// leg must still produce exactly the argv they produced before it — this pins them.
    #[test]
    fn class_and_gw_sub_interfaces_are_created_exactly_as_before() {
        let f = fabric_with_a_domain_gw();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let mut sys = up_sys(&view);
        run(&mut sys, &view, &o).unwrap();
        assert_eq!(
            calls_for_dev(&sys, "cfab-st"),
            [
                "ip link show cfab-st",
                "ip link show cfab-st",
                "ip link add link eth9 name cfab-st type vlan id 100 egress-qos-map 0:0 6:6",
                "ip addr replace 10.99.1.1/24 dev cfab-st",
                "ip link set cfab-st up",
            ]
        );
        assert_eq!(
            calls_for_dev(&sys, "cfab-gw249"),
            [
                // the shape guard's own probe (`gw_leg_shape_ok`), then mk_vlan's two
                "ip link show cfab-gw249",
                "ip link show cfab-gw249",
                "ip link show cfab-gw249",
                "ip link add link eth0 name cfab-gw249 type vlan id 249 egress-qos-map 0:2 6:6",
                "ip addr replace 192.168.249.1/24 dev cfab-gw249",
                "ip link set cfab-gw249 up",
                // The per-zone return-path default lands as part of building the leg (E2.2).
                "ip route replace default via 192.168.249.254 dev cfab-gw249 table 249 proto 205",
            ]
        );
    }

    /// 3.3: a bond with no carrier is a bond whose every port lost carrier. Naming the bond
    /// alone would send the operator to `ip -br link show cfab-st-fb`, which shows it UP.
    #[test]
    fn a_down_fallback_bond_is_reported_as_no_wire_with_carrier() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let got = describe_down(
            &view,
            &[
                "storage/cfab-st".to_string(),
                "storage/cfab-st-fb".to_string(),
            ],
        );
        assert_eq!(
            got,
            [
                "storage/cfab-st".to_string(),
                "storage/cfab-st-fb (no wire with carrier under it)".to_string(),
            ]
        );
    }

    /// The pref-2000 workload sibling (spec §5 item 4) is installed on a leaf too — it is
    /// fabric-wide, not host-only, because a leaf must be able to answer `ip route get <vm>
    /// from <identity>`. The host case (a member that itself carries the workload row) is
    /// deferred to Task 7a: forwarding for a workload needs the uplink refusal that task adds,
    /// and this apply fixture does not build it.
    #[test]
    fn apply_adds_the_workload_sibling_rule_on_a_leaf() {
        let f: &'static Fabric = Box::leak(Box::new(wl_fabric()));
        let view = View::new(f, "pve3-tb").unwrap();
        let mut sys = absent_fallback_netdevs(up_sys(&view), &view);
        run(&mut sys, &view, &opts()).unwrap();
        assert!(
            sys.ran("rule add pref 2000 from 10.99.0.0/16 to 192.168.20.0/24 lookup main"),
            "{:?}",
            sys.calls
        );
    }

    /// A leaf installs `table inet cfab` exactly as a host does: the generated file, the one
    /// `nft -f` transaction, and the `-s` readback stored for `status`'s drift check. The
    /// containment the table carries (the fallback control-egress ceiling) is worthless if the
    /// one member class that is not a Proxmox host escapes it.
    #[test]
    fn a_leaf_installs_the_mark_table_with_its_ceilings() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = absent_fallback_netdevs(up_sys(&view), &view).on_stdout(
            &["nft", "-s", "list", "table", "inet", "cfab"],
            "table inet cfab\n",
        );
        let opts = opts();
        run(&mut sys, &view, &opts).unwrap();

        let want = emit::mark::generate(&view).unwrap();
        assert!(
            want.contains("comment \"ceiling-storage\""),
            "the leaf's table carries no ceiling: {want}"
        );
        assert_eq!(sys.files.get("/run/cfab/mark.nft"), Some(&want));
        assert_eq!(
            sys.files.get("/run/cfab/mark.applied"),
            Some(&"table inet cfab\n".to_string())
        );
        assert_eq!(
            calls_for(&sys, "nft -f"),
            vec!["nft -f /run/cfab/mark.nft".to_string()]
        );
        // ...and only the mark table: a leaf still shapes nothing and filters nothing.
        assert!(calls_for(&sys, "tc ").is_empty(), "{:?}", sys.calls);
        assert!(calls_for(&sys, "policy.nft").is_empty(), "{:?}", sys.calls);
    }

    /// The `iptables-legacy-save -t mangle` dump of a member whose ceiling is installed:
    /// mangle's built-ins, a foreign chain that must be left alone, and OUR chains and rules
    /// taken verbatim from the render — so the fixture can never drift from what `up` loads.
    fn ipt_save(view: &View) -> String {
        let rendered = emit::ceiling_ipt::generate(view).unwrap();
        let mut out = String::from(
            "# Generated by iptables-save\n*mangle\n:PREROUTING ACCEPT [0:0]\n\
             :OUTPUT ACCEPT [12:800]\n:DOCKER-USER - [0:0]\n",
        );
        for l in rendered.lines().filter(|l| l.starts_with(':')) {
            out.push_str(l);
            out.push('\n');
        }
        out.push_str("-A OUTPUT -j cfab-out\n-A DOCKER-USER -j RETURN\n");
        for l in rendered.lines().filter(|l| l.starts_with("-A ")) {
            out.push_str(l);
            out.push('\n');
        }
        out.push_str("COMMIT\n");
        out
    }

    /// A leaf whose kernel refuses nf_tables with the one text that means "this kernel has
    /// none" takes the ceiling-only backend — the whole sequence, argv by argv: the probe
    /// under LC_ALL=C, the probe table deleted whatever happened, the three legacy binaries
    /// checked BY THEIR -legacy NAMES (the unqualified ones are the nft backend on trixie and
    /// would fail the same way), the nft backend's state removed, the ceiling restored
    /// atomically, the OUTPUT jump added because it was not there, and the readback stored.
    #[test]
    fn a_leaf_on_a_kernel_without_nf_tables_installs_the_ceiling_with_iptables_legacy() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = absent_fallback_netdevs(up_sys(&view), &view)
            .on_fail(
                &[
                    "/usr/bin/env",
                    "LC_ALL=C",
                    "nft",
                    "add",
                    "table",
                    "inet",
                    "cfabprobe",
                ],
                1,
                "Error: Could not process rule: Operation not supported",
            )
            .on_fail(
                &["iptables-legacy", "-t", "mangle", "-C", "OUTPUT"],
                1,
                "iptables: Bad rule (does a matching rule exist in that chain?).",
            )
            .on_stdout(&["iptables-legacy-save", "-t", "mangle"], &ipt_save(&view));
        let opts = opts();
        let warnings = run(&mut sys, &view, &opts).unwrap();

        let marky: Vec<String> = sys
            .calls
            .iter()
            .filter(|c| c.contains("nft") || c.contains("iptables") || c.contains("mark."))
            .cloned()
            .collect();
        assert_eq!(
            marky,
            vec![
                "/usr/bin/env sh -c command -v nft",
                "/usr/bin/env LC_ALL=C nft add table inet cfabprobe",
                "nft delete table inet cfabprobe",
                "/usr/bin/env sh -c command -v iptables-legacy",
                "/usr/bin/env sh -c command -v iptables-legacy-save",
                "/usr/bin/env sh -c command -v iptables-legacy-restore",
                "write /run/cfab/mark.backend",
                "/usr/bin/env sh -c command -v nft",
                "nft delete table inet cfab",
                "rm /run/cfab/mark.nft",
                "write /run/cfab/mark.ipt",
                "iptables-legacy-restore --noflush /run/cfab/mark.ipt",
                "iptables-legacy -t mangle -C OUTPUT -j cfab-out",
                "iptables-legacy -t mangle -A OUTPUT -j cfab-out",
                "iptables-legacy-save -t mangle",
                "write /run/cfab/mark.applied",
            ],
            "{:?}",
            sys.calls
        );
        // The recorded choice, the restore input, and the readback `status` diffs against.
        assert_eq!(
            sys.files.get("/run/cfab/mark.backend"),
            Some(&"iptables-legacy\n".to_string())
        );
        assert_eq!(
            sys.files.get("/run/cfab/mark.ipt"),
            Some(&emit::ceiling_ipt::generate(&view).unwrap())
        );
        assert_eq!(
            sys.files.get("/run/cfab/mark.applied"),
            Some(&emit::ceiling_ipt::ours(&ipt_save(&view)))
        );
        // No nft table was rendered or loaded on this member...
        assert!(!sys.files.contains_key("/run/cfab/mark.nft"));
        assert!(!sys.ran("nft -f"));
        // ...and the condition is said in `up` too, in the one spelling `status` uses.
        assert!(
            warnings.iter().any(|w| w
                == "mark: iptables-legacy (ceiling only; bulk DSCP clamp unavailable on \
                    this kernel)"),
            "{warnings:?}"
        );
    }

    /// Any OTHER nft failure is not "this kernel has no nf_tables" — a broken install, an
    /// EPERM from seccomp/AppArmor, an nfnetlink init failure. Refuse with the kernel's own
    /// words rather than silently policing with the weaker backend.
    #[test]
    fn a_leaf_whose_nft_fails_for_any_other_reason_is_refused_with_the_real_text() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = absent_fallback_netdevs(up_sys(&view), &view).on_fail(
            &[
                "/usr/bin/env",
                "LC_ALL=C",
                "nft",
                "add",
                "table",
                "inet",
                "cfabprobe",
            ],
            1,
            "Error: Could not process rule: Operation not permitted",
        );
        let opts = opts();
        let err = run(&mut sys, &view, &opts).unwrap_err().to_string();
        assert!(
            err.contains("nft is installed but unusable here")
                && err.contains("Operation not permitted"),
            "{err}"
        );
        assert!(!sys.ran("iptables"), "{:?}", sys.calls);
        assert!(!sys.files.contains_key("/run/cfab/mark.ipt"));
    }

    /// A host never probes, and on a host that has never had the legacy binaries the mark
    /// path is nft byte for byte — no probe, no iptables, no extra command. The two things
    /// that are new on every kind are file operations, not commands: the `mark.backend`
    /// record and the removal of any stale `mark.ipt`.
    #[test]
    fn a_host_without_iptables_runs_the_nft_mark_path_and_nothing_else() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys
            .on_stdout(
                &["nft", "-s", "list", "table", "inet", "cfab"],
                "table inet cfab\n",
            )
            .on_fail(
                &["/usr/bin/env", "sh", "-c", "command -v iptables-legacy"],
                1,
                "",
            );
        run(&mut sys, &view, &opts()).unwrap();
        assert!(!sys.ran("cfabprobe"), "{:?}", sys.calls);
        assert!(!sys.ran("iptables-legacy -"), "{:?}", sys.calls);
        assert!(!sys.ran("iptables-legacy-save"), "{:?}", sys.calls);
        // The precondition list, in its old order: `iptables-legacy` is looked for only by
        // the guarded sweep, never as a host precondition. `ethtool` is not a precondition at
        // all now — its probe is the per-wire driver record's own `have_tool`, which runs
        // after the wires are owned, hence last. (The trailing `nmcli` probes are the per-wire
        // release, unchanged.)
        let mut probes = calls_for(&sys, "command -v");
        probes.retain(|c| !c.ends_with("nmcli") && !c.contains("iptables"));
        assert_eq!(
            probes,
            vec![
                "/usr/bin/env sh -c command -v ip",
                "/usr/bin/env sh -c command -v nft",
                "/usr/bin/env sh -c command -v tc",
                "/usr/bin/env sh -c command -v logger",
                "/usr/bin/env sh -c command -v ethtool",
            ],
            "{:?}",
            sys.calls
        );
        assert!(!sys.ran("nft delete table inet cfab"), "{:?}", sys.calls);
        assert_eq!(
            sys.calls
                .iter()
                .filter(|c| c.contains("mark."))
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "write /run/cfab/mark.backend",
                "rm /run/cfab/mark.ipt",
                "write /run/cfab/mark.nft",
                "nft -f /run/cfab/mark.nft",
                "write /run/cfab/mark.applied",
            ],
            "{:?}",
            sys.calls
        );
        assert_eq!(
            sys.files.get("/run/cfab/mark.nft"),
            Some(&emit::mark::generate(&view).unwrap())
        );
        assert_eq!(
            sys.files.get("/run/cfab/mark.applied"),
            Some(&"table inet cfab\n".to_string())
        );
        assert_eq!(
            sys.files.get("/run/cfab/mark.backend"),
            Some(&"nft\n".to_string())
        );
    }

    /// ...and a member redeclared from `leaf` to `host` while its ceiling chains are still
    /// resident IS swept: the sweep runs on every kind, guarded on the binaries existing, so
    /// nothing is ever policed by two mechanisms at once.
    #[test]
    fn a_host_with_the_legacy_binaries_still_sweeps_resident_ceiling_chains() {
        let (mut sys, view) = up_sys_and_view();
        let leaf_view = {
            let f: &'static Fabric = Box::leak(Box::new(fabric()));
            View::new(f, "pve3-tb").unwrap()
        };
        sys = sys
            .on_stdout(
                &["nft", "-s", "list", "table", "inet", "cfab"],
                "table inet cfab\n",
            )
            .on_stdout(
                &["iptables-legacy-save", "-t", "mangle"],
                &ipt_save(&leaf_view),
            );
        run(&mut sys, &view, &opts()).unwrap();
        assert!(
            sys.ran("iptables-legacy -t mangle -X cfab-ceil-storage"),
            "{:?}",
            sys.calls
        );
        assert!(!sys.ran("DOCKER-USER -j"), "{:?}", sys.calls);
        // ...and the nft path still ran, unchanged.
        assert!(sys.ran("nft -f /run/cfab/mark.nft"), "{:?}", sys.calls);
    }

    /// `iptables-restore --noflush` does not flush an existing user chain, so a second `up`
    /// would append a second copy of every rule if the render did not carry its own `-F`
    /// lines. Twice through: identical input, identical readback, and the OUTPUT jump added
    /// exactly once — the first `up` finds no jump (`-C` fails), the second finds the one it
    /// installed (`-C` succeeds), which is the live sequence this claim rests on.
    #[test]
    fn a_second_up_on_the_iptables_backend_renders_and_applies_the_same_thing() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = absent_fallback_netdevs(up_sys(&view), &view)
            .on_fail(
                &[
                    "/usr/bin/env",
                    "LC_ALL=C",
                    "nft",
                    "add",
                    "table",
                    "inet",
                    "cfabprobe",
                ],
                1,
                "Operation not supported",
            )
            .on_stdout(&["iptables-legacy-save", "-t", "mangle"], &ipt_save(&view))
            // First `up`: nothing is hooked from OUTPUT yet.
            .on_fail(
                &["iptables-legacy", "-t", "mangle", "-C", "OUTPUT"],
                1,
                "iptables: Bad rule (does a matching rule exist in that chain?).",
            );
        let opts = opts();
        run(&mut sys, &view, &opts).unwrap();
        let first = sys.files.get("/run/cfab/mark.ipt").cloned().unwrap();
        let applied = sys.files.get("/run/cfab/mark.applied").cloned().unwrap();
        assert!(first.contains("-F cfab-out\n"), "{first}");
        // Second `up`: the jump the first one installed is now there (a later mock rule wins).
        sys = sys.on_stdout(&["iptables-legacy", "-t", "mangle", "-C", "OUTPUT"], "");
        run(&mut sys, &view, &opts).unwrap();
        assert_eq!(sys.files.get("/run/cfab/mark.ipt"), Some(&first));
        assert_eq!(sys.files.get("/run/cfab/mark.applied"), Some(&applied));
        assert_eq!(
            calls_for(&sys, "-A OUTPUT"),
            vec!["iptables-legacy -t mangle -A OUTPUT -j cfab-out"],
            "the jump must be installed once across both runs: {:?}",
            sys.calls
        );
    }

    /// The mirror case: a leaf whose kernel HAS nf_tables (a DSM upgrade, a kind change) but
    /// whose run dir records the ceiling-only backend. `up` takes nft and must leave no
    /// iptables state behind — the chains are swept by the exact names the readback gives,
    /// the foreign chain beside them is untouched, and the record is rewritten.
    #[test]
    fn a_leaf_that_gains_nf_tables_sweeps_the_iptables_chains_it_used_to_have() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = absent_fallback_netdevs(up_sys(&view), &view)
            // The probe succeeds: this kernel has nf_tables now.
            .file("/run/cfab/mark.backend", "iptables-legacy\n")
            .file("/run/cfab/mark.ipt", "*mangle\nCOMMIT\n")
            .on_stdout(&["iptables-legacy-save", "-t", "mangle"], &ipt_save(&view))
            .on_stdout(
                &["nft", "-s", "list", "table", "inet", "cfab"],
                "table inet cfab\n",
            );
        let opts = opts();
        let warnings = run(&mut sys, &view, &opts).unwrap();

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
                "iptables-legacy -t mangle -F cfab-ceil-cluster",
                "iptables-legacy -t mangle -F cfab-ceil-mgmt",
                "iptables-legacy -t mangle -X cfab-out",
                "iptables-legacy -t mangle -X cfab-ceil-storage",
                "iptables-legacy -t mangle -X cfab-ceil-cluster",
                "iptables-legacy -t mangle -X cfab-ceil-mgmt",
            ],
            "{:?}",
            sys.calls
        );
        // Nothing foreign in the same table was touched.
        assert!(!sys.ran("DOCKER-USER"), "{:?}", sys.calls);
        // The record now says nft, the stale restore input is gone, and the nft table is in.
        assert_eq!(
            sys.files.get("/run/cfab/mark.backend"),
            Some(&"nft\n".to_string())
        );
        assert!(!sys.files.contains_key("/run/cfab/mark.ipt"));
        assert_eq!(
            sys.files.get("/run/cfab/mark.nft"),
            Some(&emit::mark::generate(&view).unwrap())
        );
        assert!(sys.ran("nft -f /run/cfab/mark.nft"), "{:?}", sys.calls);
        // The ordinary backend is not worth a line at `up`: only the degraded one is.
        assert!(
            !warnings.iter().any(|w| w.starts_with("mark:")),
            "{warnings:?}"
        );
    }

    /// A zone that lost its fallback row leaves an unhooked but resident chain behind. It is
    /// deleted by the exact name the readback gave — the mangle table is shared with Docker
    /// and with the member's own rules, so nothing is matched by pattern.
    #[test]
    fn a_ceiling_chain_from_a_previous_zone_set_is_deleted_by_exact_name() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let stale = ipt_save(&view).replace(
            ":cfab-out - [0:0]\n",
            ":cfab-out - [0:0]\n:cfab-ceil-backup - [0:0]\n",
        );
        let mut sys = absent_fallback_netdevs(up_sys(&view), &view)
            .on_fail(
                &[
                    "/usr/bin/env",
                    "LC_ALL=C",
                    "nft",
                    "add",
                    "table",
                    "inet",
                    "cfabprobe",
                ],
                1,
                "Operation not supported",
            )
            .on_stdout(&["iptables-legacy-save", "-t", "mangle"], &stale);
        let opts = opts();
        run(&mut sys, &view, &opts).unwrap();
        assert_eq!(
            calls_for(&sys, "mangle -F"),
            vec!["iptables-legacy -t mangle -F cfab-ceil-backup"],
            "{:?}",
            sys.calls
        );
        assert_eq!(
            calls_for(&sys, "mangle -X"),
            vec!["iptables-legacy -t mangle -X cfab-ceil-backup"],
            "{:?}",
            sys.calls
        );
        // Nothing foreign was touched, and the live chains were left alone.
        assert!(!sys.ran("DOCKER-USER"), "{:?}", sys.calls);
        assert!(!sys.ran("-X cfab-ceil-storage"), "{:?}", sys.calls);
    }

    /// A leaf takes either backend, so it is refused only when it has NEITHER — by name,
    /// before anything is applied. Never a member silently running without the ceiling.
    #[test]
    fn a_leaf_with_neither_backend_is_refused_by_name() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = absent_fallback_netdevs(up_sys(&view), &view)
            .on_fail(&["/usr/bin/env", "sh", "-c", "command -v nft"], 1, "")
            .on_fail(
                &[
                    "/usr/bin/env",
                    "sh",
                    "-c",
                    "command -v iptables-legacy-save",
                ],
                1,
                "",
            );
        let opts = opts();
        let err = run(&mut sys, &view, &opts).unwrap_err().to_string();
        assert!(
            err.contains("neither nft nor iptables-legacy-save is installed"),
            "{err}"
        );
        assert!(
            !sys.files.contains_key("/run/cfab/mark.nft"),
            "refused after applying: {:?}",
            sys.calls
        );
    }
}
