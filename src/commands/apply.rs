//! `cfab apply` — apply the fabric on THIS member. Idempotent, root. The order is
//! load-bearing: preconditions → own the NICs → sysctls → per-class netdevs → return
//! path → policy + per-interface forwarding (or the leaf leak guard) → marking + the
//! fallback ceiling → qos. Starting the routing engine, the shape daemon, conf-sync and
//! the fail-closed watchdog is the supervisor's job (`cfab run`), not this function's.

use std::collections::BTreeSet;

use crate::commands::common;
use crate::commands::common::{
    conf_interfaces, ensure_foreign_transit_accept, link_exists, link_kind_is, proc_sysctl,
};
use crate::derive::{GwRow, Slave, View};
use crate::emit;
use crate::emit::ceiling_ipt::Backend as MarkBackend;
use crate::error::{Error, Result};
use crate::model::{MemberKind, Role};
use crate::sys::{Sys, have_tool, run_ignore, run_ok};

pub struct ApplyOpts {
    /// pmxcfs mount root probed to decide whether to start conf-sync (/etc/pve in
    /// production; a tempdir in tests). Unused by `apply::run` itself in this gate — kept on
    /// the type for the supervisor, which reads it to decide whether to spawn conf-sync;
    /// conf-sync itself is spawned by the supervisor, never by `apply`.
    pub pmxcfs_root: String,
}

/// The set of declared wires with no netdev (James's ruling, 2026-09-05): the rest of the
/// apply consults this set and touches none of them — no sub-if, no bond slave, no
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

/// Remove whatever the OTHER backend left behind, before this one installs. A leaf that gains
/// nf_tables (a DSM upgrade) or loses it must never end up policed by both, or by neither with
/// stale chains still resident. Each half is `have_tool`-guarded, so a member that no longer
/// has the other backend's binaries still applies.
fn remove_other_mark_backend(
    sys: &mut dyn Sys,
    f: &crate::model::Fabric,
    chosen: MarkBackend,
) -> Result<()> {
    match chosen {
        MarkBackend::Nft => {
            if have_tool(sys, "iptables-legacy")? && have_tool(sys, "iptables-legacy-save")? {
                let save = sys.run(&["iptables-legacy-save", "-t", "mangle"])?;
                for chain in emit::ceiling_ipt::chains_in(&save.stdout) {
                    if chain == emit::ceiling_ipt::OUT_CHAIN {
                        run_ignore(
                            sys,
                            &[
                                "iptables-legacy",
                                "-t",
                                "mangle",
                                "-D",
                                "OUTPUT",
                                "-j",
                                &chain,
                            ],
                        )?;
                    }
                    run_ignore(sys, &["iptables-legacy", "-t", "mangle", "-F", &chain])?;
                }
                for chain in emit::ceiling_ipt::chains_in(&save.stdout) {
                    run_ignore(sys, &["iptables-legacy", "-t", "mangle", "-X", &chain])?;
                }
            }
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
    sys.write(&path, &emit::ceiling_ipt::generate(view)?)?;
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
    let wanted: Vec<String> = emit::ceiling_ipt::chains_in(&emit::ceiling_ipt::generate(view)?);
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

/// A bond leg's slaves, minus any on an absent wire; if the leg's declared `home` wire is one
/// of them, the first surviving slave takes over as home (any survivor is a legal `primary`;
/// `mk_bond_leg` only needs ONE that matches). `None` when every wire under the leg is absent
/// — nothing to build, and the caller skips it with a warning of its own.
fn present_slaves<'a>(
    slaves: &'a [Slave],
    home: &'a str,
    absent: &AbsentWires,
) -> Option<(Vec<Slave>, String)> {
    let kept: Vec<Slave> = slaves
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
    let admin_if = view.admin_if();

    // ---- preconditions: fail loud, never degrade -------------------------------
    // A host requires `nft`: it installs the whole `table inet cfab` (bulk DSCP clamp + the
    // fallback control-egress ceiling), and a no-nft kernel is a hard refusal for that kind —
    // there is no iptables path for a forwarding member. `tc`/`ethtool` stay host-only — a
    // leaf shapes nothing and its wires' qdiscs and offloads belong to its OS.
    let mut tools: Vec<&str> = vec!["ip"];
    if kind == MemberKind::Host {
        tools.push("nft");
        tools.extend(["tc", "ethtool"]);
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
    if f.fabric_mode != "tagged" {
        return Err(Error::fatal(format!(
            "FABRIC_MODE='{}' (expected tagged)",
            f.fabric_mode
        )));
    }
    // Lockout guard: the admin NIC must carry an IPv4 address BEFORE we touch anything — the
    // admin session rides it untagged, and bringup deliberately never assigns or flushes it.
    if let Some(admin) = admin_if {
        let out = sys.run(&["ip", "-4", "-br", "addr", "show", "dev", admin])?;
        let has_v4 = out.stdout.lines().any(|l| {
            l.split_whitespace()
                .skip(2)
                .any(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
        });
        if !has_v4 {
            return Err(Error::fatal(format!(
                "admin NIC '{admin}' (ADMIN_IF) has no IPv4 address — admin path would be unreachable"
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
    for dev in wires.iter().filter(|d| !absent.contains(d.as_str())) {
        if kind != MemberKind::Host {
            continue; // a leaf never owns a wire's L3 (DSM does)
        }
        if admin_if == Some(dev.as_str()) {
            continue;
        }
        if sys.run(&["pgrep", "-f", &format!("dhcpcd.*{dev}")])?.ok() {
            run_ignore(sys, &["dhcpcd", "-k", dev])?;
        }
        // Review finding 3 (2026-09-05): the predicate that used to gate this was "is
        // NetworkManager RUNNING" (`systemctl is-active`), which Task 5 had to drop (no
        // systemd probe in apply); "is nmcli INSTALLED" is a different, weaker condition —
        // a host with NM installed but masked would now run a command that fails every
        // apply. Ask NM itself instead of systemd or the binary's mere presence.
        //
        // Round 2 (RULED, 2026-09-05): a refusal here strands an unattended host with NO
        // supervisor at all — strictly worse than a wire NM keeps fighting us for. ALWAYS
        // attempt the release when nmcli is installed; the RUNNING probe words the warning
        // only (not-running vs. running-but-refused), it never gates the attempt, and a
        // failure is a WARNING, never a refusal.
        if have_tool(sys, "nmcli")? {
            let nm = sys.run(&["nmcli", "-t", "-f", "RUNNING", "general"])?;
            let out = sys.run(&["nmcli", "device", "set", dev, "managed", "no"])?;
            if !out.ok() {
                warnings.push(if nm.stdout.trim() == "running" {
                    format!(
                        "WARNING: NetworkManager is running and refused to release {dev} \
                         ({}) — it may keep fighting cfab for this wire's addresses; check \
                         `nmcli device show {dev}`",
                        out.stderr.trim()
                    )
                } else {
                    format!(
                        "WARNING: nmcli is installed but NetworkManager is not running, and \
                         releasing {dev} still failed ({}) — check `nmcli device show {dev}`",
                        out.stderr.trim()
                    )
                });
            }
        }
        let dhcp = sys.run(&["pgrep", "-af", "dhclient|udhcpc"])?;
        if dhcp
            .stdout
            .lines()
            .any(|l| l.split_whitespace().any(|w| w == dev.as_str()))
        {
            return Err(Error::fatal(format!(
                "a dhcp client holds fabric NIC {dev} — investigate before bringup"
            )));
        }
        run_ok(sys, &["ip", "addr", "flush", "dev", dev])?;
    }

    // ---- NIC safe mode ---------------------------------------------------------
    for (_, dev) in f
        .usb_nics
        .iter()
        .filter(|(m, dev)| m == host && !absent.contains(dev.as_str()))
    {
        let out = run_ok(sys, &["ethtool", "-i", dev])?;
        let drv = out
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix("driver:"))
            .map(str::trim)
            .unwrap_or("");
        if drv == "r8152" {
            // RTL8157 SG-lockup mitigation
            run_ok(
                sys,
                &[
                    "ethtool", "-K", dev, "sg", "off", "tso", "off", "gso", "off",
                ],
            )?;
        } else {
            warnings.push(format!(
                "WARNING: {dev} on {host} is driven by '{drv}', not r8152 (RTL8157 re-enumerated \
                 as CDC?) — SG mitigation skipped, link speed unverified"
            ));
        }
    }

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
        let z = f.zone(&r.zone)?;
        mk_vlan(
            sys,
            &r.ifname,
            &r.wire,
            r.vid,
            Some(&format!("{}/24", view.segment_addr(z, r.seg))),
            true,
            &[
                &format!("0:{}", z.pcp),
                &format!("{}:{}", f.pcp_ctrl, f.pcp_ctrl),
            ],
        )?;
        class_sysctls(sys, &r.ifname, r.role)?;
    }
    // The ingress leg: the router's VLAN, this node's address in the router's /24. Same
    // sysctls as a backup segment; nothing else about it is a segment. On a gw island of
    // `any` the leg is the same bond a fallback segment is, so it migrates between wires
    // instead of dying with its island — one leg, one BGP session (James 2026-09-04).
    for r in &gw_rows {
        let z = f.zone(&r.zone)?;
        let gw = z.gw.as_ref().expect("gw_rows lists gw zones");
        let cidr = gw.leg_cidr(n);
        let qos_map = [
            format!("0:{}", z.pcp),
            format!("{}:{}", f.pcp_ctrl, f.pcp_ctrl),
        ];
        let qos_map: Vec<&str> = qos_map.iter().map(String::as_str).collect();
        if r.migrates() {
            let Some((slaves, home)) = present_slaves(&r.slaves, &r.home, &absent) else {
                continue; // every wire under this leg is absent; already warned above
            };
            mk_bond_leg(
                sys,
                &BondLeg {
                    ifname: &r.ifname,
                    vid: r.vid,
                    home: &home,
                    slaves: &slaves,
                    cidr: &cidr,
                    role: Role::Backup,
                },
                &qos_map,
            )?;
        } else if !absent.contains(&r.home) {
            mk_vlan(sys, &r.ifname, &r.home, r.vid, Some(&cidr), true, &qos_map)?;
            class_sysctls(sys, &r.ifname, Role::Backup)?;
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
    // wire, so the member keeps a path in the zone when the physical islands are disjointly
    // isolated. Not a class row and not a wire: nothing that treats a segment as a wire (the
    // shaper, the qdisc sweep, status's link-speed checks) ever sees it.
    for r in &view.fallback_rows() {
        let z = f.zone(&r.zone)?;
        let Some((slaves, home)) = present_slaves(&r.slaves, &r.home, &absent) else {
            continue; // every wire under this fallback leg is absent; already warned above
        };
        mk_bond_leg(
            sys,
            &BondLeg {
                ifname: &r.ifname,
                vid: r.vid,
                home: &home,
                slaves: &slaves,
                cidr: &format!("{}/24", view.segment_addr(z, r.seg)),
                role: Role::Fallback,
            },
            &[
                &format!("0:{}", z.pcp),
                &format!("{}:{}", f.pcp_ctrl, f.pcp_ctrl),
            ],
        )?;
    }

    // ---- return path (ZONE_TABLE gw): identity-sourced traffic never leaves untagged ---------
    for r in common::return_path_rules(view) {
        common::ensure_fabric_rule(sys, &r)?;
    }

    // ---- forward policy + per-interface forwarding ------------------------------
    if kind == MemberKind::Leaf {
        leaf_guard(sys, view)?;
    } else if f.host_forward {
        enable_forwarding(sys, view, &absent)?;
    } else {
        run_ignore(sys, &["nft", "delete", "table", "inet", "cfab-fwd"])?;
        sys.remove(&format!("{}/policy.nft", f.run_dir))?;
        sys.remove(&format!("{}/policy.applied", f.run_dir))?;
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
    if kind == MemberKind::Leaf {
        remove_other_mark_backend(sys, f, mark_backend)?;
    }
    match mark_backend {
        MarkBackend::Nft => {
            let mark = emit::mark::generate(view)?;
            let mark_path = format!("{}/mark.nft", f.run_dir);
            sys.write(&mark_path, &mark)?;
            run_ok(sys, &["nft", "-f", &mark_path])?; // one transaction: atomic replace
            let applied = run_ok(sys, &["nft", "-s", "list", "table", "inet", "cfab"])?;
            sys.write(&format!("{}/mark.applied", f.run_dir), &applied.stdout)?;
        }
        MarkBackend::IptablesLegacy => install_mark_ipt(sys, view)?,
    }
    warnings.push(mark_backend.status_line().to_string());

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
/// own (a fallback bond's slave: the bond holds the address), and `bring_up` is false for a link
/// something else brings up later (enslaving wants the slave down first).
fn mk_vlan(
    sys: &mut dyn Sys,
    name: &str,
    lower: &str,
    vid: u16,
    addr: Option<&str>,
    bring_up: bool,
    qos_map: &[&str],
) -> Result<()> {
    let vid_s = vid.to_string();
    if link_exists(sys, name)?
        && !link_kind_is(sys, name, &format!("vlan protocol 802.1Q id {vid} "))?
    {
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

/// Bond `updelay` in ms — how long a returning wire must hold carrier before it is reselected.
/// **500 is MEASURED, not a target** (sweep of 0/200/500, n=1 per value, container fixture on a
/// three-member testbed): it costs a 0.574 s window after a *legitimate* return in which
/// `status` reads UP-DEGRADED (0.074 s at 0), with **zero**
/// packets lost at every value, and it buys a 10x reduction in migrations on a bouncing wire —
/// 2 versus 20 active-slave switches over ten 250 ms flaps, each avoided switch an avoided GARP
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

/// A migrating leg to build: a fallback segment, or an ingress leg on gw island `any`. The two
/// are the same netdev shape, so they are the same code — only the address and the (unused)
/// role differ.
struct BondLeg<'a> {
    ifname: &'a str,
    vid: u16,
    /// The wire whose slave the bond takes as `primary`.
    home: &'a str,
    slaves: &'a [Slave],
    /// The bond is the L3 interface; its slaves carry no address.
    cidr: &'a str,
    role: Role,
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
/// leg nobody asked for. `cfab down` deletes the bond before its slaves, so down/up is a proven
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
fn mk_bond_leg(sys: &mut dyn Sys, r: &BondLeg, qos_map: &[&str]) -> Result<()> {
    // (1) the bond. Unlike a vlan of the wrong id, a same-named foreign netdev here is not
    // ours to delete — refuse and say so.
    if link_exists(sys, r.ifname)? {
        if !link_kind_is(sys, r.ifname, " bond ")? {
            return Err(Error::fatal(format!(
                "REFUSING: {} exists but is not a bond",
                r.ifname
            )));
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
    // (2) the slaves: created DOWN and with no address — the bond holds the L3, and enslaving
    // a link the kernel is bringing up is a race. The egress-qos map lives HERE: the tag is
    // applied on the slave, and PCP is per frame, so control on the fallback path is queued like
    // control anywhere.
    for s in r.slaves {
        mk_vlan(sys, &s.ifname, &s.wire, r.vid, None, false, qos_map)?;
        // (3) `ip link set <slave> master <bond>` on a slave already in that bond is EBUSY, so
        // the second `up` must not re-issue it. sysfs answers "enslaved at all"; `ip -d` says
        // to whom (the master link cannot be read as a file — it is a symlink to a directory).
        let enslaved_anywhere = sys.exists(&format!("/sys/class/net/{}/master", s.ifname));
        let enslaved_here =
            enslaved_anywhere && link_kind_is(sys, &s.ifname, &format!(" master {} ", r.ifname))?;
        if enslaved_anywhere && !enslaved_here {
            // Enslaved, but not to us. The kernel would answer the `master` set with a bare
            // EBUSY; say what is actually wrong instead.
            return Err(Error::fatal(format!(
                "REFUSING: {} is enslaved to another bond",
                s.ifname
            )));
        }
        if !enslaved_here {
            run_ok(sys, &["ip", "link", "set", &s.ifname, "master", r.ifname])?;
        }
        run_ok(sys, &["ip", "link", "set", &s.ifname, "up"])?;
        // A slave inherits conf/default, and on a kernel whose owner keeps ip_forward=1 that
        // means forwarding=1 — the same hazard `mk_identity` guards against. `up` only zeroes
        // conf/default on a HOST; a LEAF has fallback rows and is deliberately left alone there,
        // so the explicit write is the only thing that holds `owned_forwarding()`'s false.
        proc_sysctl(sys, &s.ifname, "forwarding", "0")?;
    }
    // (4) AFTER the slaves exist: `primary` names a SLAVE, and at `ip link add` time no slave
    // exists yet, so setting it there is a silent no-op.
    let home = r.slaves.iter().find(|s| s.wire == r.home).ok_or_else(|| {
        Error::fatal(format!(
            "{}: home wire {} carries no slave of this bond",
            r.ifname, r.home
        ))
    })?;
    run_ok(
        sys,
        &[
            "ip",
            "link",
            "set",
            r.ifname,
            "type",
            "bond",
            "primary",
            &home.ifname,
            "primary_reselect",
            FALLBACK_PRIMARY_RESELECT,
        ],
    )?;
    // (5) the bond is the segment: address, segment sysctls, up.
    run_ok(sys, &["ip", "addr", "replace", r.cidr, "dev", r.ifname])?;
    class_sysctls(sys, r.ifname, r.role)?;
    run_ok(sys, &["ip", "link", "set", r.ifname, "up"])?;
    Ok(())
}

/// Render `settled_down_ifs`'s `zone/ifname` entries for the operator. A fallback bond is not a
/// wire: it is `down` exactly when not one of its slaves has carrier, so the warning must name
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

/// Measured live: arp_ignore=1 (NOT arp_filter — it flaps BFD); rp_filter LOOSE on every role
/// (strict on a primary black-holed control for ~5 s when all links returned at once).
fn class_sysctls(sys: &mut dyn Sys, ifname: &str, _role: Role) -> Result<()> {
    proc_sysctl(sys, ifname, "arp_ignore", "1")?;
    proc_sysctl(sys, ifname, "rp_filter", "2")?;
    proc_sysctl(sys, ifname, "send_redirects", "0")?;
    proc_sysctl(sys, ifname, "forwarding", "0")?;
    Ok(())
}

/// Whether a gw or fallback leg was actually built by the per-class-netdevs section above,
/// given the same `absent` set and the same rule that section used to skip it: a migrating
/// (bond) leg needs `present_slaves` to find a survivor; a non-migrating leg just needs its
/// one `home` wire present. Anything this returns `false` for has no netdev at all — a
/// per-interface sysctl on it would fail loud on real Linux (`RealSys::write` maps ENOENT to
/// `Error::fatal`) even though the mock accepts any path unconditionally.
fn leg_was_built(migrates: bool, slaves: &[Slave], home: &str, absent: &AbsentWires) -> bool {
    if migrates {
        present_slaves(slaves, home, absent).is_some()
    } else {
        !absent.contains(home)
    }
}

/// Load the policy atomically, read it back, and only then enable forwarding — on exactly the
/// class-table interfaces that were actually built, never an absent wire's segment, never a
/// wire itself, never the untagged admin NIC.
fn enable_forwarding(sys: &mut dyn Sys, view: &View, absent: &AbsentWires) -> Result<()> {
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
        .filter(|r| leg_was_built(r.migrates(), &r.slaves, &r.home, absent))
    {
        proc_sysctl(sys, &r.ifname, "forwarding", "1")?;
    }
    // The bond, never its slaves: a slave carries no L3 and the flag on it is meaningless.
    // `status` and the watchdog grade against `owned_forwarding()`, which lists the bond as
    // transit — leaving it out here would make every `up` report UP-DEGRADED three seconds later.
    for r in view
        .fallback_rows()
        .iter()
        .filter(|r| leg_was_built(true, &r.slaves, &r.home, absent))
    {
        proc_sysctl(sys, &r.ifname, "forwarding", "1")?;
    }
    if let Some(admin) = view.admin_if() {
        proc_sysctl(sys, admin, "forwarding", "0")?; // belt (the policy's admin rules = braces)
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
        // `fabric()` (examples/fabric.conf) already declares HOST_FORWARD=1 for pve1-tb, so
        // this exercises the exact motivating scenario: a forwarding host with an absent wire.
        assert!(view.fabric.host_forward, "test assumes HOST_FORWARD=1");
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
        // Nothing else may touch it: no sub-if, no bond slave, no sysctl, no forwarding write —
        // checked by exact ifname token, not substring (CLASS_TABLE reuses "cfab-st" as a
        // PREFIX for segments that live on other wires entirely: cfab-st-bk is island cl,
        // cfab-st-b2 is island mg — only cfab-st itself is eth9's segment).
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

    /// Round 2 (RULED, 2026-09-05): a refusal here would strand an unattended host with no
    /// supervisor at all — strictly worse than a wire NM keeps fighting us for. A running NM
    /// that refuses to release the wire is a WARNING, never a refusal, and the apply succeeds;
    /// the release is still ATTEMPTED (the reviewer's real point: the condition is no longer
    /// silent).
    #[test]
    fn a_running_nm_that_refuses_to_release_a_wire_warns_and_the_apply_still_succeeds() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys
            .on_stdout(
                &["/usr/bin/env", "sh", "-c", "command -v nmcli"],
                "/usr/bin/nmcli\n",
            )
            .on_stdout(&["nmcli", "-t", "-f", "RUNNING", "general"], "running\n")
            .on_fail(
                &["nmcli", "device", "set", "eth1", "managed", "no"],
                1,
                "Error: Device 'eth0' not managed.",
            );
        let warnings = run(&mut sys, &view, &opts()).unwrap();
        assert!(sys.ran("nmcli device set eth1 managed no"));
        assert!(
            warnings.iter().any(|w| w
                .contains("NetworkManager is running and refused to release eth1")
                && w.contains("Error: Device 'eth0' not managed.")),
            "{warnings:?}"
        );
    }

    /// nmcli installed but NetworkManager not running (masked, stopped): the release is still
    /// attempted (round 2 drops the RUNNING probe as a gate on whether to try), it succeeds
    /// (nmcli manages the release fine with NM down), and no warning is raised.
    #[test]
    fn an_installed_but_not_running_networkmanager_release_is_attempted_and_clean() {
        let (mut sys, view) = up_sys_and_view();
        sys = sys.on_stdout(
            &["/usr/bin/env", "sh", "-c", "command -v nmcli"],
            "/usr/bin/nmcli\n",
        );
        let warnings = run(&mut sys, &view, &opts()).unwrap();
        assert!(sys.ran("nmcli device set eth1 managed no"));
        assert!(
            !warnings.iter().any(|w| w.contains("NetworkManager")),
            "{warnings:?}"
        );
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

    fn opts() -> ApplyOpts {
        ApplyOpts {
            pmxcfs_root: "/nonexistent/pve".to_string(),
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
    /// first, each slave created DOWN and address-less then enslaved and brought up, `primary`
    /// only AFTER the slaves exist (at `add` time it is a silent no-op), then the address,
    /// the segment sysctls and the bond up. storage's home wire is eth9 (its cheapest class
    /// row is on the st island), so `primary` names the st SLAVE, never the wire.
    #[test]
    fn a_fallback_leg_is_built_bond_slaves_primary_address() {
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
                "ip link show cfab-st-fb-st",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-fb-st",
                "ip link add link eth9 name cfab-st-fb-st type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-fb-st master cfab-st-fb",
                "ip link set cfab-st-fb-st up",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb-st/forwarding",
                "ip link show cfab-st-fb-cl",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-fb-cl",
                "ip link add link eth1 name cfab-st-fb-cl type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-fb-cl master cfab-st-fb",
                "ip link set cfab-st-fb-cl up",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb-cl/forwarding",
                "ip link show cfab-st-fb-mg",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-fb-mg",
                "ip link add link eth0 name cfab-st-fb-mg type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-fb-mg master cfab-st-fb",
                "ip link set cfab-st-fb-mg up",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb-mg/forwarding",
                "ip link set cfab-st-fb type bond primary cfab-st-fb-st primary_reselect always",
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

    /// A slave already in OUR bond is not re-enslaved: `ip link set <slave> master <bond>` on
    /// it is EBUSY, so the second `up` would fail outright. A slave that is not gets enslaved.
    #[test]
    fn a_second_up_does_not_re_enslave_a_slave_already_in_the_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        // An existing bond must also present its bonding/ sysfs: `up` proves the parameters
        // before it touches a bond it did not just create.
        let sys = bond_sysfs(up_sys(&view), "cfab-st-fb", &healthy_bond_params());
        let mut sys = sys
            .file("/sys/class/net/cfab-st-fb-st/master", "")
            .on_stdout(&["ip", "link", "show", "cfab-st-fb"], "9: cfab-st-fb\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb"],
                "9: cfab-st-fb: bond \n",
            )
            .on_stdout(
                &["ip", "link", "show", "cfab-st-fb-st"],
                "10: cfab-st-fb-st\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb-st"],
                "10: cfab-st-fb-st@eth9: master cfab-st-fb state UP vlan protocol 802.1Q id 300 \n",
            );
        run(&mut sys, &view, &o).unwrap();
        assert!(
            !sys.ran("ip link set cfab-st-fb-st master"),
            "{:?}",
            calls_for(&sys, "cfab-st-fb-st")
        );
        assert!(!sys.ran("ip link add cfab-st-fb type bond"), "bond kept");
        // and the ones that are not enslaved still are
        assert!(sys.ran("ip link set cfab-st-fb-cl master cfab-st-fb"));
    }

    /// A slave name that is already enslaved SOMEWHERE ELSE: the kernel would answer the
    /// `master` set with a bare "Device or resource busy". Refuse in cfab's own wording.
    #[test]
    fn up_refuses_a_fallback_slave_enslaved_to_a_foreign_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let o = opts();
        let mut sys = up_sys(&view)
            .file("/sys/class/net/cfab-st-fb-st/master", "")
            .on_stdout(
                &["ip", "link", "show", "cfab-st-fb-st"],
                "10: cfab-st-fb-st\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-fb-st"],
                "10: cfab-st-fb-st@eth9: master br0 state UP vlan protocol 802.1Q id 300 \n",
            );
        let e = run(&mut sys, &view, &o).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-fb-st is enslaved to another bond"),
            "{e}"
        );
        assert!(
            !sys.ran("ip link set cfab-st-fb-st master"),
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
    /// not re-issued, and `up` goes on to the slaves.
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
        assert!(sys.ran("ip link set cfab-st-fb-st master cfab-st-fb"));
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
    /// never set. The slaves are written 0 EXPLICITLY: they carry no L3, and inheriting
    /// conf/default (1 on a leaf whose external owner keeps ip_forward=1) would contradict
    /// `owned_forwarding()` with nothing in `up` to correct it.
    #[test]
    fn fallback_bonds_forward_and_their_slaves_never_do() {
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
        for slave in ["cfab-st-fb-st", "cfab-st-fb-cl", "cfab-st-fb-mg"] {
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{slave}/forwarding")),
                Some("0"),
                "{slave} is L2 only"
            );
        }
    }

    /// The same declaration with the ingress leg on island `any`.
    fn fabric_with_a_migrating_gw() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace("mg:249:", "any:249:");
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// Task 9: a gw island of `any` builds the ingress leg as the very same bond a fallback
    /// leg is — same parameters, same slave-then-enslave order, same `primary`-after-slaves
    /// rule — addressed with the router's /24 leg address, not a segment address. mgmt's
    /// cheapest segment is on the mg island, so `primary` names the mg SLAVE.
    #[test]
    fn a_migrating_gw_leg_is_built_as_a_bond() {
        let f = fabric_with_a_migrating_gw();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view);
        let o = opts();
        run(&mut sys, &view, &o).unwrap();
        assert_eq!(
            calls_for(&sys, "cfab-gw249"),
            [
                "ip link show cfab-gw249",
                "ip link add cfab-gw249 type bond mode active-backup miimon 100 num_grat_arp 3 updelay 500 fail_over_mac none",
                "ip link show cfab-gw249-st",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-gw249-st",
                "ip link add link eth9 name cfab-gw249-st type vlan id 249 egress-qos-map 0:2 6:6",
                "ip link set cfab-gw249-st master cfab-gw249",
                "ip link set cfab-gw249-st up",
                "write /proc/sys/net/ipv4/conf/cfab-gw249-st/forwarding",
                "ip link show cfab-gw249-cl",
                "ip link show cfab-gw249-cl",
                "ip link add link eth1 name cfab-gw249-cl type vlan id 249 egress-qos-map 0:2 6:6",
                "ip link set cfab-gw249-cl master cfab-gw249",
                "ip link set cfab-gw249-cl up",
                "write /proc/sys/net/ipv4/conf/cfab-gw249-cl/forwarding",
                "ip link show cfab-gw249-mg",
                "ip link show cfab-gw249-mg",
                "ip link add link eth0 name cfab-gw249-mg type vlan id 249 egress-qos-map 0:2 6:6",
                "ip link set cfab-gw249-mg master cfab-gw249",
                "ip link set cfab-gw249-mg up",
                "write /proc/sys/net/ipv4/conf/cfab-gw249-mg/forwarding",
                "ip link set cfab-gw249 type bond primary cfab-gw249-mg primary_reselect always",
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

    /// The bond forwards (it is the L3 leg); its slaves never do, and `up` writes that
    /// explicitly rather than inheriting conf/default.
    #[test]
    fn a_migrating_gw_bond_forwards_and_its_slaves_never_do() {
        let f = fabric_with_a_migrating_gw();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view);
        let o = opts();
        run(&mut sys, &view, &o).unwrap();
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-gw249/forwarding"),
            Some("1")
        );
        for slave in ["cfab-gw249-st", "cfab-gw249-cl", "cfab-gw249-mg"] {
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{slave}/forwarding")),
                Some("0"),
                "{slave} is L2 only"
            );
        }
    }

    /// A migrating ingress leg is a bond too, so the settle warning must name the real
    /// condition for it as well.
    #[test]
    fn a_down_migrating_gw_bond_is_reported_as_no_wire_with_carrier() {
        let f = fabric_with_a_migrating_gw();
        let view = View::new(&f, "pve1-tb").unwrap();
        let got = describe_down(&view, &["mgmt/cfab-gw249".to_string()]);
        assert_eq!(
            got,
            ["mgmt/cfab-gw249 (no wire with carrier under it)".to_string()]
        );
    }

    /// VRRP was deleted (the NAS is a fabric leaf, James 2026-09-02): a forwarding host's
    /// `up` must create no macvlan at all — the storage VIP netdev was the only one cfab ever
    /// made. The example fabric declares `HOST_FORWARD=1`, the case that used to build it.
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
        let f = fabric();
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

    /// 3.3: a bond with no carrier is a bond whose every slave lost carrier. Naming the bond
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
