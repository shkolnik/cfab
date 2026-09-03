//! `cfab up` — apply the fabric on THIS member. Idempotent, root. The order is load-bearing:
//! preconditions → own the NICs → sysctls → per-class netdevs → return path → VRRP netdev →
//! policy + per-interface forwarding (or the leaf leak guard) → qos + shape daemon → FRR →
//! read-backs → fail-closed watchdog.

use crate::commands::common::{
    conf_interfaces, ensure_rule, frr_ctl, frr_interface_block, link_exists, link_kind_is,
    proc_sysctl,
};
use crate::derive::View;
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
    let mut tools: Vec<&str> = vec!["vtysh", "ip"];
    if kind == MemberKind::Host {
        tools.extend(["tc", "ethtool", "nft"]);
        if f.host_forward {
            tools.extend(["systemd-run", "logger"]);
        }
    }
    for tool in tools {
        if !have_tool(sys, tool)? {
            return Err(Error::fatal(format!("{tool} not installed")));
        }
    }
    if !sys.exists("/etc/frr") {
        return Err(Error::fatal("/etc/frr missing (frr not installed?)"));
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
        // Forwarding starts OFF everywhere (the kernel checks the PER-INTERFACE flag); it is
        // turned on — per class-table interface only — after the policy is loaded.
        sys.write("/proc/sys/net/ipv4/conf/default/forwarding", "0")?;
        for ifn in conf_interfaces(sys)? {
            sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
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
        // onto the management LAN during a peer's FRR restart).
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
            &format!("{}/24", view.segment_addr(z, r.seg)),
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
            &gw.leg_cidr(n),
            &[
                &format!("0:{}", z.pcp),
                &format!("{}:{}", f.pcp_ctrl, f.pcp_ctrl),
            ],
        )?;
        class_sysctls(sys, &r.ifname, Role::Backup)?;
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

    // ---- FRR -------------------------------------------------------------------
    if sys.exists("/etc/frr/frr.conf") && !sys.exists("/etc/frr/frr.conf.pre-cfab") {
        let orig = sys.read("/etc/frr/frr.conf")?;
        sys.write("/etc/frr/frr.conf.pre-cfab", &orig)?;
    }
    edit_daemons(sys, view)?;
    let frr_conf = emit::frr::generate(view)?;
    sys.write("/etc/frr/frr.conf", &frr_conf)?;
    frr_ctl(sys, "restart")?;

    // ---- read-backs: the load-bearing config must be in the daemons ------------
    sys.sleep(std::time::Duration::from_secs(2));
    let running = run_ok(sys, &["vtysh", "-c", "show running-config"])?.stdout;
    if !running
        .lines()
        .any(|l| l == "ip protocol ospf route-map CFAB_SRC")
    {
        return Err(Error::fatal(
            "zebra dropped 'ip protocol ospf route-map CFAB_SRC'",
        ));
    }
    if kind == MemberKind::Host && f.vrrp_gw {
        let vrrp = run_ok(sys, &["vtysh", "-c", "show vrrp"])?.stdout;
        let want = format!("Virtual Router ID {}", f.vrrp_vrid);
        let seen = vrrp.lines().any(|l| {
            l.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains(&want)
        });
        if !seen {
            return Err(Error::fatal(format!(
                "vrrpd did not take the VRRP {} config",
                f.vrrp_vrid
            )));
        }
    }
    for r in &gw_rows {
        // ingress is load-bearing: bgpd must hold the session config
        let z = f.zone(&r.zone)?;
        let gw = z.gw.as_ref().expect("gw zone");
        let want = format!(" neighbor {} remote-as {}", gw.router, f.bgp_as);
        if !running.lines().any(|l| l == want) {
            return Err(Error::fatal(format!(
                "bgpd dropped 'neighbor {} remote-as {}' ({} ingress)",
                gw.router, f.bgp_as, r.zone
            )));
        }
    }
    for z in &f.zones {
        // the return path is load-bearing: a gw zone's static must be in staticd
        let Some(gw) = &z.gw else { continue };
        let want = format!("ip route 0.0.0.0/0 {} table {}", gw.router, z.id);
        if !running.lines().any(|l| l == want) {
            return Err(Error::fatal(format!(
                "staticd dropped 'ip route 0.0.0.0/0 {} table {}' ({} return path)",
                gw.router, z.id, z.name
            )));
        }
    }
    if kind == MemberKind::Leaf {
        // never-a-transit is load-bearing: every transit link this leaf advertises must carry
        // the offset (read back from the running config; the LSA follows it)
        for r in &class_rows {
            let want_cost = r.ospf_cost + f.leaf_cost_offset;
            let block = frr_interface_block(&running, &r.ifname);
            if !block
                .iter()
                .any(|l| *l == format!(" ip ospf cost {want_cost}"))
            {
                return Err(Error::fatal(format!(
                    "{}: ospfd did not take cost {want_cost} (leaf offset)",
                    r.ifname
                )));
            }
        }
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

fn mk_vlan(
    sys: &mut dyn Sys,
    name: &str,
    lower: &str,
    vid: u16,
    cidr: &str,
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
    run_ok(sys, &["ip", "addr", "replace", cidr, "dev", name])?;
    run_ok(sys, &["ip", "link", "set", name, "up"])?;
    Ok(())
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
    if f.vrrp_gw {
        proc_sysctl(sys, &f.vrrp_if, "forwarding", "1")?;
    }
    if let Some(admin) = view.admin_if() {
        proc_sysctl(sys, admin, "forwarding", "0")?; // belt (the policy's admin rules = braces)
    }
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

/// /etc/frr/daemons: enable ospfd+bfdd, vrrpd/bgpd per role, one ospfd instance per zone.
fn edit_daemons(sys: &mut dyn Sys, view: &View) -> Result<()> {
    let f = view.fabric;
    let path = "/etc/frr/daemons";
    let text = sys.read(path)?;
    let want_vrrp = view.kind() == MemberKind::Host && f.vrrp_gw;
    let want_bgp = !view.gw_rows().is_empty();
    let instances = f
        .zones
        .iter()
        .map(|z| z.id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut saw_instances = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|line| {
            if line == "ospfd=no" {
                "ospfd=yes".to_string()
            } else if line == "bfdd=no" {
                "bfdd=yes".to_string()
            } else if line.starts_with("vrrpd=") {
                format!("vrrpd={}", if want_vrrp { "yes" } else { "no" })
            } else if line.starts_with("bgpd=") {
                format!("bgpd={}", if want_bgp { "yes" } else { "no" })
            } else if line.starts_with("ospfd_instances=") {
                saw_instances = true;
                format!("ospfd_instances=\"{instances}\"")
            } else {
                line.to_string()
            }
        })
        .collect();
    if !saw_instances {
        out.push(format!("ospfd_instances=\"{instances}\""));
    }
    sys.write(path, &(out.join("\n") + "\n"))
}
