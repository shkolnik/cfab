//! `cfab up` — apply the fabric on THIS member. Idempotent, root. The order is load-bearing:
//! preconditions → own the NICs → sysctls → per-class netdevs → return path → VRRP netdev →
//! policy + per-interface forwarding (or the leaf leak guard) → qos + shape daemon → routing
//! engine (restart + readback) → fail-closed watchdog.

use crate::commands::common::{
    conf_interfaces, ensure_foreign_transit_accept, ensure_rule, link_exists, link_kind_is,
    proc_sysctl,
};
use crate::commands::engine_ctl;
use crate::derive::{RescueRow, View};
use crate::emit;
use crate::error::{Error, Result};
use crate::model::{MemberKind, Role};
use crate::sys::{Sys, have_tool, run_ignore, run_ok};

pub struct UpOpts {
    /// Absolute path to this binary (re-exec'd as the shape daemon / watchdog).
    pub exe: String,
    /// Absolute path to fabric.conf (passed to the re-exec'd units).
    pub config: String,
    /// pmxcfs mount root probed to decide whether to start conf-sync (/etc/pve in
    /// production; a tempdir in tests).
    pub pmxcfs_root: String,
}

pub fn run(sys: &mut dyn Sys, view: &View, opts: &UpOpts) -> Result<String> {
    let f = view.fabric;
    let kind = view.kind();
    let n = view.node();
    let host = &view.member.name;
    let class_rows = view.class_rows();
    let gw_rows = view.gw_rows();
    let wires = view.wires();
    let admin_if = view.admin_if();

    // ---- preconditions: fail loud, never degrade -------------------------------
    for dev in &wires {
        if !link_exists(sys, dev)? {
            return Err(Error::fatal(format!("{dev} missing")));
        }
    }
    // The engine runs as a transient unit where systemd is (probed, like the other daemons);
    // a container leaf detaches it with setsid (`Sys::spawn_detached`) and stops it by pid.
    let mut tools: Vec<&str> = vec!["ip"];
    if sys.exists("/run/systemd/system") {
        tools.push("systemd-run");
    } else {
        tools.extend(["setsid", "kill"]);
    }
    if kind == MemberKind::Host {
        tools.extend(["tc", "ethtool", "nft"]);
        if f.host_forward {
            tools.push("logger");
        }
    }
    for tool in tools {
        if !have_tool(sys, tool)? {
            return Err(Error::fatal(format!("{tool} not installed")));
        }
    }
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
    // are added on it, never a flush.
    for dev in &wires {
        run_ok(sys, &["ip", "link", "set", dev, "up"])?;
        if kind != MemberKind::Host {
            continue; // a leaf never owns a wire's L3 (DSM does)
        }
        if admin_if == Some(dev.as_str()) {
            continue;
        }
        if sys.run(&["pgrep", "-f", &format!("dhcpcd.*{dev}")])?.ok() {
            run_ignore(sys, &["dhcpcd", "-k", dev])?;
        }
        if sys
            .run(&["systemctl", "is-active", "-q", "NetworkManager"])?
            .ok()
        {
            run_ok(sys, &["nmcli", "device", "set", dev, "managed", "no"])?;
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
    let mut warnings = Vec::new();
    for (_, dev) in f.usb_nics.iter().filter(|(m, _)| m == host) {
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
    for r in &class_rows {
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
    // The ingress leg: the router's VLAN on this wire, this node's address in the router's /24.
    // Same sysctls as a backup segment; nothing else about it is a segment.
    for r in &gw_rows {
        let z = f.zone(&r.zone)?;
        let gw = z.gw.as_ref().expect("gw_rows lists gw zones");
        mk_vlan(
            sys,
            &r.ifname,
            &r.wire,
            r.vid,
            Some(&gw.leg_cidr(n)),
            true,
            &[
                &format!("0:{}", z.pcp),
                &format!("{}:{}", f.pcp_ctrl, f.pcp_ctrl),
            ],
        )?;
        class_sysctls(sys, &r.ifname, Role::Backup)?;
    }
    // The rescue leg: one active-backup bond per zone over a tagged sub-interface of every
    // wire, so the member keeps a path in the zone when the physical islands are disjointly
    // isolated. Not a class row and not a wire: nothing that treats a segment as a wire (the
    // shaper, the qdisc sweep, verify's link-speed checks) ever sees it.
    for r in &view.rescue_rows() {
        let z = f.zone(&r.zone)?;
        mk_rescue(
            sys,
            r,
            &format!("{}/24", view.segment_addr(z, r.seg)),
            &[
                &format!("0:{}", z.pcp),
                &format!("{}:{}", f.pcp_ctrl, f.pcp_ctrl),
            ],
        )?;
    }

    // ---- return path (ZONE_TABLE gw): identity-sourced traffic never leaves untagged ---------
    for z in &f.zones {
        let blk = format!("{}.0.0/16", z.block());
        let id = z.id.to_string();
        ensure_rule(
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
        // The substring "lookup <id>" is unique within this pref's rules.
        ensure_rule(
            sys,
            "2001",
            &format!("from {blk} lookup {id}"),
            &["from", &blk, "lookup", &id],
        )?;
        ensure_rule(
            sys,
            "2002",
            &format!("from {blk} unreachable"),
            &["from", &blk, "unreachable"],
        )?;
    }

    // ---- floating storage gateway netdev ---------------------------------------
    if kind == MemberKind::Host && f.vrrp_gw {
        if !f.host_forward {
            return Err(Error::fatal(
                "VRRP_GW=1 needs HOST_FORWARD=1 (a gateway that does not forward)",
            ));
        }
        let vmac = format!("00:00:5e:00:01:{:02x}", f.vrrp_vrid);
        let vr_parent = class_rows
            .iter()
            .find(|r| r.zone == "storage" && r.role == Role::Primary)
            .map(|r| r.ifname.clone())
            .ok_or_else(|| {
                Error::fatal("VRRP_GW=1 but no storage primary segment on this member")
            })?;
        if !link_exists(sys, &f.vrrp_if)? {
            run_ok(
                sys,
                &[
                    "ip", "link", "add", &f.vrrp_if, "link", &vr_parent, "type", "macvlan", "mode",
                    "bridge",
                ],
            )?;
        }
        run_ok(
            sys,
            &["ip", "link", "set", "dev", &f.vrrp_if, "address", &vmac],
        )?;
        // noprefixroute: a second connected route here made the host source its own OSPF/BFD
        // from the VIP after a link cycle (measured root cause).
        let vip = format!("{}/24", view.vrrp_vip()?);
        run_ok(
            sys,
            &[
                "ip",
                "addr",
                "replace",
                &vip,
                "dev",
                &f.vrrp_if,
                "noprefixroute",
            ],
        )?;
        proc_sysctl(sys, &f.vrrp_if, "arp_ignore", "1")?;
        proc_sysctl(sys, &f.vrrp_if, "send_redirects", "0")?;
        proc_sysctl(sys, &f.vrrp_if, "forwarding", "0")?;
        // NAS traffic enters on this macvlan but the reverse route is via the parent sub-if, so
        // strict rpf would drop every packet the gateway exists to carry.
        proc_sysctl(sys, &f.vrrp_if, "rp_filter", "2")?;
        run_ok(sys, &["ip", "link", "set", &f.vrrp_if, "up"])?; // vrrpd holds the backup's macvlan down
    }

    // ---- forward policy + per-interface forwarding ------------------------------
    if kind == MemberKind::Leaf {
        leaf_guard(sys, view)?;
    } else if f.host_forward {
        enable_forwarding(sys, view)?;
    } else {
        run_ignore(sys, &["nft", "delete", "table", "inet", "cfab-fwd"])?;
        run_ignore(sys, &["systemctl", "stop", "cfab-fwd-watchdog.timer"])?;
        sys.remove(&format!("{}/policy.nft", f.run_dir))?;
        sys.remove(&format!("{}/policy.applied", f.run_dir))?;
    }

    // ---- qos (host only: a leaf shapes nothing; its wires' qdiscs belong to its OS) ----------
    if kind == MemberKind::Host {
        for dev in &wires {
            run_ok(
                sys,
                &["tc", "qdisc", "replace", "dev", dev, "root", "fq_codel"],
            )?;
        }
        let mark = emit::mark::generate(view)?;
        let mark_path = format!("{}/mark.nft", f.run_dir);
        sys.write(&mark_path, &mark)?;
        run_ok(sys, &["nft", "-f", &mark_path])?; // one transaction: atomic replace
        let applied = run_ok(sys, &["nft", "-s", "list", "table", "inet", "cfab"])?;
        sys.write(&format!("{}/mark.applied", f.run_dir), &applied.stdout)?;
        // Floor+borrow shaping: the daemon re-derives each up wire's HTB tree on link events.
        run_ignore(sys, &["systemctl", "stop", "cfab-shape.service"])?;
        run_ignore(sys, &["systemctl", "reset-failed", "cfab-shape.service"])?;
        run_ok(
            sys,
            &[
                "systemd-run",
                "--quiet",
                "--unit=cfab-shape",
                "-p",
                "KillMode=mixed",
                &opts.exe,
                "--config",
                &opts.config,
                "--host",
                host,
                "shape-daemon",
            ],
        )?;
    }

    // ---- routing engine ----------------------------------------------------------
    // A fresh start on every `up`: the engine has no config file and no state to replay, so
    // stop → sweep its routes → start → wait for ready is the whole apply. `ready` alone is
    // not proof the providers took the tree: the readback checks every instance.
    engine_ctl::stop_and_sweep(sys, f)?;
    let doc = engine_ctl::start_and_wait(sys, f, &opts.exe, &opts.config, host)?;
    engine_ctl::readback(view, &doc)?;
    // Operationally down is a warning, never a refusal: one wire without carrier must not
    // cost the host the fabric it can still have on the others.
    let down = describe_down(view, &engine_ctl::settled_down_ifs(sys, view, &doc)?);
    if !down.is_empty() {
        eprintln!(
            "cfab: warn: ospf interfaces still down after {}s: {} — no adjacency forms on them \
             and nothing routes over those wires. Usual cause is no carrier on the wire \
             underneath (ip -br link show). The fabric is up on the rest; cfab verify grades \
             this degraded",
            engine_ctl::SETTLE_MS / 1000,
            down.join(", ")
        );
    }

    // ---- fail-closed watchdog ---------------------------------------------------
    if kind == MemberKind::Host && f.host_forward {
        run_ignore(
            sys,
            &[
                "systemctl",
                "stop",
                "cfab-fwd-watchdog.timer",
                "cfab-fwd-watchdog.service",
            ],
        )?;
        run_ignore(
            sys,
            &[
                "systemctl",
                "reset-failed",
                "cfab-fwd-watchdog.timer",
                "cfab-fwd-watchdog.service",
            ],
        )?;
        run_ok(
            sys,
            &[
                "systemd-run",
                "--quiet",
                "--unit=cfab-fwd-watchdog",
                "--on-active=3",
                "--on-unit-active=3",
                "--timer-property=AccuracySec=1s",
                &opts.exe,
                "--config",
                &opts.config,
                "--host",
                host,
                "fwd-watchdog",
            ],
        )?;
    }

    // ---- cluster conf-sync daemon (additive: only when pmxcfs reports clustered) ----------
    let clustered = crate::cluster::Pmxcfs::at(&opts.pmxcfs_root)
        .probe()?
        .is_some_and(|m| m.cluster.is_some());
    if clustered {
        // The daemon re-execs this very `up` on each cluster apply/revert; stopping the unit
        // here would kill that daemon mid-protocol (systemd stops the whole cgroup, this
        // process included) — a running daemon is left alone.
        if !sys
            .run(&["systemctl", "is-active", "-q", "cfab-conf-sync.service"])?
            .ok()
        {
            run_ignore(
                sys,
                &["systemctl", "reset-failed", "cfab-conf-sync.service"],
            )?;
            run_ok(
                sys,
                &[
                    "systemd-run",
                    "--quiet",
                    "--unit=cfab-conf-sync",
                    "-p",
                    "KillMode=mixed",
                    &opts.exe,
                    "--config",
                    &opts.config,
                    "--host",
                    host,
                    "conf-sync",
                ],
            )?;
        }
    }

    let mut msg = warnings.join("\n");
    if !msg.is_empty() {
        msg.push('\n');
    }
    if kind == MemberKind::Host {
        msg.push_str(&format!(
            "up OK on {host} (node {n}, host); forward={} vrrp={} shape={} wires; run cfab verify\n",
            u8::from(f.host_forward),
            u8::from(f.vrrp_gw),
            wires.len()
        ));
    } else {
        msg.push_str(&format!(
            "up OK on {host} (node {n}, leaf); no transit (cost +{}, forwarding=0, leak guard); run cfab verify\n",
            f.leaf_cost_offset
        ));
    }
    Ok(msg)
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
/// own (a rescue bond's slave: the bond holds the address), and `bring_up` is false for a link
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

/// Bond `updelay` in ms. **0 is the measured configuration** (the spike migrated losslessly
/// four times per `fail_over_mac` mode at this value). 500 ms is the target James accepted, but
/// it is INFERRED — Task 7.2(d) sweeps 0/200/500 on hardware and decides; this constant is the
/// one line that changes. Note it takes effect on an EXISTING member only after a `down`/`up`:
/// `mk_rescue` skips `ip link add` when the bond is already there and does not re-assert the
/// bond parameters, so the sweep must tear the leg down between values.
const RESCUE_UPDELAY_MS: &str = "0";
/// `fail_over_mac`. **`none` is the build default** — measured nil difference against `active`
/// on veth, and it keeps one MAC across a migration. A real NIC must accept the bond MAC in its
/// unicast filter (INFERRED); Task 7's hardware step measures that and flips this to `active`
/// if it does not. One line, deliberately not a config knob.
const RESCUE_FAIL_OVER_MAC: &str = "none";
/// Carrier poll, ms: measured switch at +0.014…0.059 s after carrier loss through the VLAN.
const RESCUE_MIIMON_MS: &str = "100";
/// Gratuitous ARPs per migration: measured exactly 3, at +0.050/+0.050/+0.152 s.
const RESCUE_NUM_GRAT_ARP: &str = "3";
/// Return to the home wire whenever it comes back — a deterministic steady state `verify` can
/// expect. The return migration is lossless (measured), so it costs nothing.
const RESCUE_PRIMARY_RESELECT: &str = "always";

/// One rescue leg: an active-backup bond over a tagged sub-interface of every wire this member
/// has, addressed like a segment. Idempotent, and refuse-unless-ours on every netdev it touches.
fn mk_rescue(sys: &mut dyn Sys, r: &RescueRow, cidr: &str, qos_map: &[&str]) -> Result<()> {
    // (1) the bond. Unlike a vlan of the wrong id, a same-named foreign netdev here is not
    // ours to delete — refuse and say so.
    if link_exists(sys, &r.ifname)? {
        if !link_kind_is(sys, &r.ifname, " bond ")? {
            return Err(Error::fatal(format!(
                "REFUSING: {} exists but is not a bond",
                r.ifname
            )));
        }
    } else {
        run_ok(
            sys,
            &[
                "ip",
                "link",
                "add",
                &r.ifname,
                "type",
                "bond",
                "mode",
                "active-backup",
                "miimon",
                RESCUE_MIIMON_MS,
                "num_grat_arp",
                RESCUE_NUM_GRAT_ARP,
                "updelay",
                RESCUE_UPDELAY_MS,
                "fail_over_mac",
                RESCUE_FAIL_OVER_MAC,
            ],
        )?;
    }
    // (2) the slaves: created DOWN and with no address — the bond holds the L3, and enslaving
    // a link the kernel is bringing up is a race. The egress-qos map lives HERE: the tag is
    // applied on the slave, and PCP is per frame, so control on the rescue path is queued like
    // control anywhere.
    for s in &r.slaves {
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
            run_ok(sys, &["ip", "link", "set", &s.ifname, "master", &r.ifname])?;
        }
        run_ok(sys, &["ip", "link", "set", &s.ifname, "up"])?;
        // A slave inherits conf/default, and on a kernel whose owner keeps ip_forward=1 that
        // means forwarding=1 — the same hazard `mk_identity` guards against. `up` only zeroes
        // conf/default on a HOST; a LEAF has rescue rows and is deliberately left alone there,
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
            &r.ifname,
            "type",
            "bond",
            "primary",
            &home.ifname,
            "primary_reselect",
            RESCUE_PRIMARY_RESELECT,
        ],
    )?;
    // (5) the bond is the segment: address, segment sysctls, up.
    run_ok(sys, &["ip", "addr", "replace", cidr, "dev", &r.ifname])?;
    class_sysctls(sys, &r.ifname, Role::Rescue)?;
    run_ok(sys, &["ip", "link", "set", &r.ifname, "up"])?;
    Ok(())
}

/// Render `settled_down_ifs`'s `zone/ifname` entries for the operator. A rescue bond is not a
/// wire: it is `down` exactly when not one of its slaves has carrier, so the warning must name
/// that condition — "ip -br link show cfab-st-rs" would only show an interface that is UP.
fn describe_down(view: &View, down: &[String]) -> Vec<String> {
    let rescue: Vec<String> = view.rescue_rows().into_iter().map(|r| r.ifname).collect();
    down.iter()
        .map(|entry| {
            let ifname = entry.rsplit('/').next().unwrap_or(entry);
            if rescue.iter().any(|r| r == ifname) {
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

/// Load the policy atomically, read it back, and only then enable forwarding — on exactly the
/// class-table interfaces (+ the VRRP macvlan), never a wire, never the untagged admin NIC.
fn enable_forwarding(sys: &mut dyn Sys, view: &View) -> Result<()> {
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
    sys.write(&format!("{}/policy.applied", f.run_dir), &applied.stdout)?; // verify drift baseline
    for r in view.class_rows() {
        proc_sysctl(sys, &r.ifname, "forwarding", "1")?;
    }
    for r in view.gw_rows() {
        proc_sysctl(sys, &r.ifname, "forwarding", "1")?;
    }
    // The bond, never its slaves: a slave carries no L3 and the flag on it is meaningless.
    // `verify` and the watchdog grade against `owned_forwarding()`, which lists the bond as
    // transit — leaving it out here would make every `up` report DEGRADED three seconds later.
    for r in view.rescue_rows() {
        proc_sysctl(sys, &r.ifname, "forwarding", "1")?;
    }
    if f.vrrp_gw {
        proc_sysctl(sys, &f.vrrp_if, "forwarding", "1")?;
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
/// interface bound for a fabric block is refused — no netfilter needed (DSM kernels may lack
/// nf_tables).
fn leaf_guard(sys: &mut dyn Sys, view: &View) -> Result<()> {
    for z in &view.fabric.zones {
        let blk = format!("{}.0.0/16", z.block());
        ensure_rule(
            sys,
            "1000",
            &format!("to {blk} iif lo lookup main"),
            &["to", &blk, "iif", "lo", "lookup", "main"],
        )?;
        ensure_rule(
            sys,
            "1001",
            &format!("to {blk} unreachable"),
            &["to", &blk, "unreachable"],
        )?;
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

    /// A leaf whose engine came up ready but took only two of the three zones: `up` must
    /// refuse, naming the third, instead of trusting `ready`.
    #[test]
    fn up_refuses_when_readback_misses_an_instance() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_ctl::tests::healthy_doc(&view);
        doc["ospf"].as_object_mut().unwrap().remove("mgmt");
        let mut sys = absent_rescue_netdevs(
            MockSys::default()
                .socket("/run/cfab/engine.sock", &doc.to_string())
                .file("/proc/sys/net/ipv4/conf/all/rp_filter", "1\n"),
            &view,
        );
        let pmxcfs = tempfile::tempdir().unwrap();
        let opts = UpOpts {
            exe: "/usr/bin/cfab".into(),
            config: "/etc/cfab/fabric.conf".into(),
            pmxcfs_root: pmxcfs.path().to_string_lossy().into_owned(),
        };
        let e = run(&mut sys, &view, &opts).unwrap_err().to_string();
        assert!(e.contains("ospf instance 'mgmt' missing"), "{e}");
        assert!(sys.ran(
            "spawn_detached /usr/bin/cfab --config /etc/cfab/fabric.conf --host pve3-tb engine"
        ));
        // Sweep before start, every id of the private range.
        let first_sweep = sys
            .calls
            .iter()
            .position(|c| c.contains("route show table all proto 201"))
            .unwrap();
        let start = sys
            .calls
            .iter()
            .position(|c| c.starts_with("spawn_detached"))
            .unwrap();
        assert!(first_sweep < start);
    }

    /// Every netdev absent but the three wires (the from-scratch `up`), the admin NIC
    /// addressed, and the forward chain readable — the shape a first bringup sees.
    fn up_sys(view: &View) -> MockSys {
        let doc = engine_ctl::tests::healthy_doc(view);
        MockSys::default()
            .socket("/run/cfab/engine.sock", &doc.to_string())
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

    /// The older mocks answer every `ip link show` with success, so a rescue bond would look
    /// present and of an unknown kind — a refusal. Mark the bonds absent: a fresh member.
    fn absent_rescue_netdevs(mut sys: MockSys, view: &View) -> MockSys {
        for r in view.rescue_rows() {
            sys = sys.on_fail(
                &["ip", "link", "show", &r.ifname],
                1,
                "Device does not exist",
            );
        }
        sys
    }

    fn opts() -> (tempfile::TempDir, UpOpts) {
        let pmxcfs = tempfile::tempdir().unwrap();
        let o = UpOpts {
            exe: "/usr/bin/cfab".into(),
            config: "/etc/cfab/fabric.conf".into(),
            pmxcfs_root: pmxcfs.path().to_string_lossy().into_owned(),
        };
        (pmxcfs, o)
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

    /// The whole rescue leg for one zone, argv by argv, on a member with three wires: the bond
    /// first, each slave created DOWN and address-less then enslaved and brought up, `primary`
    /// only AFTER the slaves exist (at `add` time it is a silent no-op), then the address,
    /// the segment sysctls and the bond up. storage's home wire is eth9 (its cheapest class
    /// row is on the st island), so `primary` names the st SLAVE, never the wire.
    #[test]
    fn a_rescue_leg_is_built_bond_slaves_primary_address() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = up_sys(&view);
        let (_tmp, o) = opts();
        run(&mut sys, &view, &o).unwrap();
        assert_eq!(
            calls_for(&sys, "cfab-st-rs"),
            [
                "ip link show cfab-st-rs",
                "ip link add cfab-st-rs type bond mode active-backup miimon 100 num_grat_arp 3 updelay 0 fail_over_mac none",
                "ip link show cfab-st-rs-st",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-rs-st",
                "ip link add link eth9 name cfab-st-rs-st type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-rs-st master cfab-st-rs",
                "ip link set cfab-st-rs-st up",
                "write /proc/sys/net/ipv4/conf/cfab-st-rs-st/forwarding",
                "ip link show cfab-st-rs-cl",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-rs-cl",
                "ip link add link eth1 name cfab-st-rs-cl type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-rs-cl master cfab-st-rs",
                "ip link set cfab-st-rs-cl up",
                "write /proc/sys/net/ipv4/conf/cfab-st-rs-cl/forwarding",
                "ip link show cfab-st-rs-mg",
                // mk_vlan probes twice: kind-check, then create (unchanged, pre-existing)
                "ip link show cfab-st-rs-mg",
                "ip link add link eth0 name cfab-st-rs-mg type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-rs-mg master cfab-st-rs",
                "ip link set cfab-st-rs-mg up",
                "write /proc/sys/net/ipv4/conf/cfab-st-rs-mg/forwarding",
                "ip link set cfab-st-rs type bond primary cfab-st-rs-st primary_reselect always",
                "ip addr replace 10.99.9.1/24 dev cfab-st-rs",
                "write /proc/sys/net/ipv4/conf/cfab-st-rs/arp_ignore",
                "write /proc/sys/net/ipv4/conf/cfab-st-rs/rp_filter",
                "write /proc/sys/net/ipv4/conf/cfab-st-rs/send_redirects",
                "write /proc/sys/net/ipv4/conf/cfab-st-rs/forwarding",
                "ip link set cfab-st-rs up",
                // enable_forwarding, after the policy is loaded and read back
                "write /proc/sys/net/ipv4/conf/cfab-st-rs/forwarding",
            ]
        );
    }

    /// A slave already in OUR bond is not re-enslaved: `ip link set <slave> master <bond>` on
    /// it is EBUSY, so the second `up` would fail outright. A slave that is not gets enslaved.
    #[test]
    fn a_second_up_does_not_re_enslave_a_slave_already_in_the_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let (_tmp, o) = opts();
        let mut sys = up_sys(&view)
            .file("/sys/class/net/cfab-st-rs-st/master", "")
            .on_stdout(&["ip", "link", "show", "cfab-st-rs"], "9: cfab-st-rs\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-rs"],
                "9: cfab-st-rs: bond \n",
            )
            .on_stdout(
                &["ip", "link", "show", "cfab-st-rs-st"],
                "10: cfab-st-rs-st\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-rs-st"],
                "10: cfab-st-rs-st@eth9: master cfab-st-rs state UP vlan protocol 802.1Q id 300 \n",
            );
        run(&mut sys, &view, &o).unwrap();
        assert!(
            !sys.ran("ip link set cfab-st-rs-st master"),
            "{:?}",
            calls_for(&sys, "cfab-st-rs-st")
        );
        assert!(!sys.ran("ip link add cfab-st-rs type bond"), "bond kept");
        // and the ones that are not enslaved still are
        assert!(sys.ran("ip link set cfab-st-rs-cl master cfab-st-rs"));
    }

    /// A slave name that is already enslaved SOMEWHERE ELSE: the kernel would answer the
    /// `master` set with a bare "Device or resource busy". Refuse in cfab's own wording.
    #[test]
    fn up_refuses_a_rescue_slave_enslaved_to_a_foreign_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let (_tmp, o) = opts();
        let mut sys = up_sys(&view)
            .file("/sys/class/net/cfab-st-rs-st/master", "")
            .on_stdout(
                &["ip", "link", "show", "cfab-st-rs-st"],
                "10: cfab-st-rs-st\n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-rs-st"],
                "10: cfab-st-rs-st@eth9: master br0 state UP vlan protocol 802.1Q id 300 \n",
            );
        let e = run(&mut sys, &view, &o).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-rs-st is enslaved to another bond"),
            "{e}"
        );
        assert!(
            !sys.ran("ip link set cfab-st-rs-st master"),
            "never fights the kernel for it"
        );
    }

    /// A netdev already carrying a rescue bond's name but of another kind is not ours to
    /// delete (unlike a vlan of the wrong id, which cfab created and can recreate): refuse.
    #[test]
    fn up_refuses_a_foreign_netdev_named_like_a_rescue_bond() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let (_tmp, o) = opts();
        let mut sys = up_sys(&view)
            .on_stdout(&["ip", "link", "show", "cfab-st-rs"], "9: cfab-st-rs\n")
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st-rs"],
                "9: cfab-st-rs: bridge \n",
            );
        let e = run(&mut sys, &view, &o).unwrap_err().to_string();
        assert!(
            e.contains("REFUSING: cfab-st-rs exists but is not a bond"),
            "{e}"
        );
        assert!(
            !sys.ran("ip link del cfab-st-rs"),
            "never deletes a stranger"
        );
    }

    /// 3.1b: `enable_forwarding` loops the rows, not `owned_forwarding()` — a rescue bond left
    /// out of it would leave every `up` DEGRADED and make the watchdog "correct" a flag cfab
    /// never set. The slaves are written 0 EXPLICITLY: they carry no L3, and inheriting
    /// conf/default (1 on a leaf whose external owner keeps ip_forward=1) would contradict
    /// `owned_forwarding()` with nothing in `up` to correct it.
    #[test]
    fn rescue_bonds_forward_and_their_slaves_never_do() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let (_tmp, o) = opts();
        let mut sys = up_sys(&view);
        run(&mut sys, &view, &o).unwrap();
        for zone_if in ["cfab-st-rs", "cfab-cl-rs", "cfab-mg-rs"] {
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{zone_if}/forwarding")),
                Some("1"),
                "{zone_if}"
            );
        }
        for slave in ["cfab-st-rs-st", "cfab-st-rs-cl", "cfab-st-rs-mg"] {
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{slave}/forwarding")),
                Some("0"),
                "{slave} is L2 only"
            );
        }
    }

    /// The rescue leg extended `mk_vlan` with `addr`/`bring_up`. A class row and an ingress
    /// leg must still produce exactly the argv they produced before it — this pins them.
    #[test]
    fn class_and_gw_sub_interfaces_are_created_exactly_as_before() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let (_tmp, o) = opts();
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
                // the VRRP macvlan hangs off the storage primary — not a mk_vlan call
                "ip link add cfab-st-vr link cfab-st type macvlan mode bridge",
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
            ]
        );
    }

    /// 3.3: a bond with no carrier is a bond whose every slave lost carrier. Naming the bond
    /// alone would send the operator to `ip -br link show cfab-st-rs`, which shows it UP.
    #[test]
    fn a_down_rescue_bond_is_reported_as_no_wire_with_carrier() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let got = describe_down(
            &view,
            &[
                "storage/cfab-st".to_string(),
                "storage/cfab-st-rs".to_string(),
            ],
        );
        assert_eq!(
            got,
            [
                "storage/cfab-st".to_string(),
                "storage/cfab-st-rs (no wire with carrier under it)".to_string(),
            ]
        );
    }

    /// Availability-first: a segment wire with no carrier at `up` time is a real OSPF `down`,
    /// and must not cost the host its whole fabric. `up` completes (warning on stderr); the
    /// loss is `verify`'s to grade degraded.
    #[test]
    fn up_completes_when_a_segment_interface_is_down() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_ctl::tests::healthy_doc(&view);
        doc["ospf"]["storage"]["interfaces"]["cfab-st"]["state"] = serde_json::json!("down");
        let mut sys = absent_rescue_netdevs(
            MockSys::default()
                .socket("/run/cfab/engine.sock", &doc.to_string())
                .file("/proc/sys/net/ipv4/conf/all/rp_filter", "1\n"),
            &view,
        );
        let pmxcfs = tempfile::tempdir().unwrap();
        let opts = UpOpts {
            exe: "/usr/bin/cfab".into(),
            config: "/etc/cfab/fabric.conf".into(),
            pmxcfs_root: pmxcfs.path().to_string_lossy().into_owned(),
        };
        run(&mut sys, &view, &opts).unwrap();
    }
}
