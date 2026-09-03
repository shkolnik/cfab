//! `cfab verify` — the health gate for THIS member. Exit 0 = fully converged and the posture
//! holds; exit 2 = converged DEGRADED (every peer's identity reachable in every zone with a
//! pinned src and ≥1 BFD-up segment, but some declared segment is down — listed, loudly — or a
//! zone's gw is unreachable); exit 1 = not converged, or a posture check failed.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Duration;

use crate::commands::common::conf_interfaces;
use crate::derive::{View, segments_of};
use crate::emit;
use crate::error::Result;
use crate::model::MemberKind;
use crate::sys::Sys;

pub struct VerifyReport {
    /// 0 = OK, 2 = DEGRADED, 1 = failed.
    pub code: u8,
    pub output: String,
}

struct Ctx {
    out: String,
    fails: u32,
    degraded: Vec<String>,
}

impl Ctx {
    fn bad(&mut self, msg: &str) {
        let _ = writeln!(self.out, "  FAIL: {msg}");
        self.fails += 1;
    }
    fn warn(&mut self, msg: &str) {
        let _ = writeln!(self.out, "  warn: {msg}");
    }
    fn say(&mut self, msg: &str) {
        let _ = writeln!(self.out, "{msg}");
    }
}

pub fn run(sys: &mut dyn Sys, view: &View, timeout_s: u64) -> Result<VerifyReport> {
    let f = view.fabric;
    let kind = view.kind();
    let host = &view.member.name;
    let kind_s = match kind {
        MemberKind::Host => "host",
        MemberKind::Leaf => "leaf",
    };
    let mut c = Ctx {
        out: String::new(),
        fails: 0,
        degraded: Vec::new(),
    };

    posture(sys, view, &mut c)?;
    return_path_and_ingress(sys, view, &mut c)?;
    mark_drift(sys, view, &mut c)?;
    shape_posture(sys, view, &mut c)?;
    link_speeds(sys, view, &mut c)?;

    // ---- convergence (waits) -----------------------------------------------------
    // One BFD session per (zone, segment) shared with each peer, keyed by the peer's segment
    // address — exact for a heterogeneous membership and per session, so a dark segment is
    // named, not just counted.
    let mut expected: Vec<(u8, String, u8, String)> = Vec::new(); // (peer, zone, seg, addr)
    let ours = segments_of(f, view.member);
    for m in &f.members {
        if m.name == *host {
            continue;
        }
        let theirs = segments_of(f, m);
        for shared in ours.intersection(&theirs) {
            let (z, seg) = shared.split_once(':').expect("zone:seg");
            let zone = f.zone(z)?;
            let seg: u8 = seg.parse().expect("seg number");
            expected.push((
                m.node,
                z.to_string(),
                seg,
                format!("{}.{seg}.{}", zone.block(), m.node),
            ));
        }
    }
    let expect_bfd = expected.len();

    let mut t = 0u64;
    let mut since_degraded: Option<u64> = None;
    let mut last_why = String::new();
    let mut down: Vec<String>;
    loop {
        let (rc, why, d) = check(sys, view, &expected)?;
        if why != last_why {
            if !why.is_empty() {
                c.out.push_str(&why);
            }
            last_why = why;
        }
        down = d;
        if rc == 0 {
            break;
        }
        if rc == 2 {
            // converged degraded: give the missing sessions a moment (a live segment comes up
            // within seconds of its siblings; a dark one never will), then report.
            let since = *since_degraded.get_or_insert(t);
            if t - since >= 10 {
                break;
            }
        }
        t += 2;
        if t >= timeout_s {
            c.say(&format!(
                "verify FAILED on {host}: not converged after {timeout_s}s (posture fails: {})",
                c.fails
            ));
            return Ok(VerifyReport {
                code: 1,
                output: c.out,
            });
        }
        sys.sleep(Duration::from_secs(2));
    }
    if kind == MemberKind::Host && f.vrrp_gw {
        let vrrp = sys.run(&["vtysh", "-c", "show vrrp"])?.stdout;
        let st = vrrp
            .lines()
            .find(|l| l.contains("Status (v4)"))
            // " Status (v4)   Master" → whitespace fields [Status, (v4), Master]
            .and_then(|l| l.split_whitespace().nth(2))
            .unwrap_or("?")
            .to_string();
        c.say(&format!(
            "  vrrp {}: {st} (prio {})",
            f.vrrp_vrid,
            view.vrrp_prio()?
        ));
    }
    if c.fails > 0 {
        let fails = c.fails;
        c.say(&format!(
            "verify FAILED on {host}: converged but {fails} posture check(s) failed"
        ));
        return Ok(VerifyReport {
            code: 1,
            output: c.out,
        });
    }
    if !down.is_empty() || !c.degraded.is_empty() {
        if !down.is_empty() {
            c.say(&format!(
                "  DOWN segments (zone:seg:peer): {}",
                down.join(" ")
            ));
        }
        let gw_note = if c.degraded.is_empty() {
            String::new()
        } else {
            format!("; gw unreachable: {}", c.degraded.join(" "))
        };
        c.say(&format!(
            "verify DEGRADED on {host} ({kind_s}): {}/{} BFD up; every identity reachable, src pinned; posture ok{}",
            expect_bfd - down.len(),
            expect_bfd,
            gw_note
        ));
        return Ok(VerifyReport {
            code: 2,
            output: c.out,
        });
    }
    c.say(&format!(
        "verify OK on {host} ({kind_s}): {expect_bfd} BFD up; identities via primaries, src pinned; posture ok"
    ));
    Ok(VerifyReport {
        code: 0,
        output: c.out,
    })
}

fn posture(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    let f = view.fabric;
    for r in view.class_rows() {
        let got = sys
            .read(&format!("/proc/sys/net/ipv4/conf/{}/rp_filter", r.ifname))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "missing".to_string());
        if got != "2" {
            c.bad(&format!(
                "{} rp_filter={got} (want 2 = loose, every role)",
                r.ifname
            ));
        }
    }

    match view.kind() {
        MemberKind::Leaf => {
            let mut ifs: Vec<String> = view.class_rows().into_iter().map(|r| r.ifname).collect();
            for z in &f.zones {
                let id = View::identity_if(z);
                ifs.push(id.clone());
                ifs.push(format!("{id}-peer"));
            }
            for ifn in ifs {
                let v = sys
                    .read(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if v != "0" {
                    c.bad(&format!("{ifn} forwarding!=0 (a leaf never transits)"));
                }
            }
            for z in &f.zones {
                let blk = format!("{}.0.0/16", z.block());
                let r1000 = sys.run(&["ip", "rule", "show", "pref", "1000"])?.stdout;
                if !r1000.contains(&format!("to {blk} iif lo lookup main")) {
                    c.bad(&format!(
                        "leak guard: 'pref 1000 to {blk} iif lo lookup main' missing"
                    ));
                }
                let r1001 = sys.run(&["ip", "rule", "show", "pref", "1001"])?.stdout;
                if !r1001.contains(&format!("to {blk} unreachable")) {
                    c.bad(&format!(
                        "leak guard: 'pref 1001 to {blk} unreachable' missing"
                    ));
                }
            }
            // never-a-transit: every transit link in our self-originated router LSA carries
            // the offset
            for z in &f.zones {
                let lsa = sys
                    .run(&[
                        "vtysh",
                        "-c",
                        &format!("show ip ospf {} database router self-originate", z.id),
                    ])?
                    .stdout;
                let mut in_transit = false;
                let mut below = false;
                for line in lsa.lines() {
                    if line.contains("Link connected to: a Transit") {
                        in_transit = true;
                    } else if in_transit && line.contains("TOS 0 Metric") {
                        let metric: u64 = line
                            .split_whitespace()
                            .next_back()
                            .and_then(|w| w.parse().ok())
                            .unwrap_or(0);
                        if metric < f.leaf_cost_offset as u64 {
                            below = true;
                        }
                        in_transit = false;
                    }
                }
                if below {
                    c.bad(&format!(
                        "ospf {}: a transit link in our router LSA is advertised below \
                         LEAF_COST_OFFSET={} (we could be chosen as a transit)",
                        z.id, f.leaf_cost_offset
                    ));
                }
            }
            c.say(&format!(
                "  leaf posture: forwarding=0 on fabric netdevs, leak guard present, transit links advertised at +{}",
                f.leaf_cost_offset
            ));
        }
        MemberKind::Host if f.host_forward => {
            let want_policy = emit::policy::generate(view)?;
            let loaded = sys
                .read(&format!("{}/policy.nft", f.run_dir))
                .unwrap_or_default();
            if want_policy != loaded {
                c.bad("policy drift: fabric.conf now generates a different policy than `up` loaded (re-run cfab up)");
            }
            let live = sys.run(&["nft", "-s", "list", "table", "inet", "cfab-fwd"])?;
            let applied = sys
                .read(&format!("{}/policy.applied", f.run_dir))
                .unwrap_or_default();
            if !live.ok() || live.stdout != applied {
                c.bad("ruleset drift: live table inet cfab-fwd differs from what `up` loaded");
            }
            let chain = sys
                .run(&["nft", "list", "chain", "inet", "cfab-fwd", "forward"])?
                .stdout;
            if !chain.contains("policy drop;") {
                c.bad("chain forward is not policy drop");
            }
            if let Some(admin) = view.admin_if() {
                for counter in ["I4-admin-in", "I4-admin-out"] {
                    match counter_packets(&chain, counter) {
                        Some(0) => {}
                        Some(n) => c.bad(&format!(
                            "{counter} counter = {n} (something tried to transit {admin})"
                        )),
                        None => c.bad(&format!(
                            "{counter} counter = absent (something tried to transit {admin})"
                        )),
                    }
                }
                let v = sys.read(&format!("/proc/sys/net/ipv4/conf/{admin}/forwarding"))?;
                if v.trim() != "0" {
                    c.bad(&format!("{admin} forwarding=1"));
                }
            }
            let mut allowed: BTreeSet<String> =
                view.class_rows().into_iter().map(|r| r.ifname).collect();
            allowed.extend(view.gw_rows().into_iter().map(|r| r.ifname));
            if f.vrrp_gw {
                allowed.insert(f.vrrp_if.clone());
            }
            for ifn in conf_interfaces(sys)? {
                if matches!(ifn.as_str(), "all" | "default" | "lo") {
                    continue;
                }
                let v = sys.read(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"))?;
                let v = v.trim();
                if allowed.contains(&ifn) {
                    if v != "1" {
                        c.bad(&format!(
                            "{ifn} forwarding=0 (class-table interface should forward)"
                        ));
                    }
                } else if v != "0" {
                    c.bad(&format!("{ifn} forwarding=1 (not a class-table interface)"));
                }
            }
            if !sys
                .run(&["systemctl", "is-active", "-q", "cfab-fwd-watchdog.timer"])?
                .ok()
            {
                c.bad("cfab-fwd-watchdog.timer not active");
            }
            let deny = counter_packets(&chain, "default-deny")
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string());
            c.say(&format!(
                "  policy: ok, default-deny counter={deny} (nonzero = something was refused; see nft counters)"
            ));
        }
        MemberKind::Host => {
            if sys.run(&["nft", "list", "table", "inet", "cfab-fwd"])?.ok() {
                c.bad("HOST_FORWARD=0 but table inet cfab-fwd is loaded");
            }
            for ifn in conf_interfaces(sys)? {
                let path = format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding");
                if sys.read(&path)?.trim() != "0" {
                    c.bad(&format!("{path} = 1 with HOST_FORWARD=0"));
                }
            }
        }
    }
    Ok(())
}

/// Return-path rules per zone; a gw zone's table must hold FRR's default, its leg must carry
/// the address, and the router must be peering.
fn return_path_and_ingress(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    let f = view.fabric;
    let n = view.node();
    for z in &f.zones {
        let blk = format!("{}.0.0/16", z.block());
        let id = z.id.to_string();
        let r2000 = sys.run(&["ip", "rule", "show", "pref", "2000"])?.stdout;
        if !r2000.contains(&format!(
            "from {blk} to {blk} lookup main suppress_prefixlength 0"
        )) {
            c.bad(&format!(
                "return path: 'pref 2000 from {blk} to {blk} lookup main suppress_prefixlength 0' missing"
            ));
        }
        let r2001 = sys.run(&["ip", "rule", "show", "pref", "2001"])?.stdout;
        if !r2001
            .lines()
            .any(|l| l.trim_end().ends_with(&format!("from {blk} lookup {id}")))
        {
            c.bad(&format!(
                "return path: 'pref 2001 from {blk} lookup {id}' missing"
            ));
        }
        let r2002 = sys.run(&["ip", "rule", "show", "pref", "2002"])?.stdout;
        if !r2002.contains(&format!("from {blk} unreachable")) {
            c.bad(&format!(
                "return path: 'pref 2002 from {blk} unreachable' missing"
            ));
        }
        let Some(gw) = &z.gw else { continue };
        let table = sys.run(&["ip", "route", "show", "table", &id])?.stdout;
        if !table.lines().any(|l| l.starts_with("default ")) {
            c.warn(&format!(
                "{}: gw {} unreachable — table {id} has no default; identity replies to the outside are refused",
                z.name, gw.router
            ));
            c.degraded.push(format!("{}:gw", z.name));
        }
        // ingress leg + session (members carrying the leg): the router must be peering, else
        // the outside cannot reach this zone's identities
        let Some(leg) = view.gw_rows().into_iter().find(|r| r.zone == z.name) else {
            continue;
        };
        let cidr = gw.leg_cidr(n);
        let addr = sys
            .run(&["ip", "-4", "-br", "addr", "show", "dev", &leg.ifname])?
            .stdout;
        if !addr.contains(&format!(" {cidr}")) {
            c.bad(&format!(
                "{} ingress leg {} missing or not {cidr}",
                z.name, leg.ifname
            ));
        }
        let nbr = sys
            .run(&["vtysh", "-c", &format!("show bgp neighbors {}", gw.router)])?
            .stdout;
        let state = nbr
            .lines()
            .find_map(|l| l.split("BGP state = ").nth(1))
            .and_then(|rest| rest.split([',', ' ']).next())
            .unwrap_or("absent")
            .to_string();
        if state == "Established" {
            let prefixes = find_prefix_counts(&nbr).unwrap_or_default();
            c.say(&format!(
                "  {} ingress: bgp {} Established ({prefixes})",
                z.name, gw.router
            ));
        } else {
            c.warn(&format!(
                "{} ingress: bgp {} {state} (not Established — the router is not learning this zone's identities)",
                z.name, gw.router
            ));
            c.degraded.push(format!("{}:bgp", z.name));
        }
    }
    Ok(())
}

fn mark_drift(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    // Host only: a leaf marks nothing. The DSCP plane is a queueing switch's actual isolation
    // mechanism, so drift is a posture failure, not cosmetic.
    if view.kind() != MemberKind::Host {
        return Ok(());
    }
    let f = view.fabric;
    let want = emit::mark::generate(view)?;
    let loaded = sys
        .read(&format!("{}/mark.nft", f.run_dir))
        .unwrap_or_default();
    if want != loaded {
        c.bad("mark drift: fabric.conf now generates a different table inet cfab than `up` loaded (re-run cfab up)");
    }
    let live = sys.run(&["nft", "-s", "list", "table", "inet", "cfab"])?;
    let applied = sys
        .read(&format!("{}/mark.applied", f.run_dir))
        .unwrap_or_default();
    if !live.ok() || live.stdout != applied {
        c.bad("mark ruleset drift: live table inet cfab differs from what `up` loaded");
    }
    Ok(())
}

/// The daemon must be alive, and every wire with carrier must carry exactly the tree the shape
/// derivation gives for the current up-set. A wire without carrier may hold a stale tree
/// (left alone).
fn shape_posture(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    if view.kind() != MemberKind::Host {
        return Ok(());
    }
    if !sys
        .run(&["systemctl", "is-active", "-q", "cfab-shape.service"])?
        .ok()
    {
        c.bad("cfab-shape.service not active (floor+borrow shaping is down: no floors, plain fq_codel at best)");
    }
    let wires = view.wires();
    let carrier_up: Vec<bool> = wires
        .iter()
        .map(|w| {
            sys.read(&format!("/sys/class/net/{w}/carrier"))
                .map(|s| s.trim() == "1")
                .unwrap_or(false)
        })
        .collect();
    for (dev, up_now) in wires.iter().zip(&carrier_up) {
        if !up_now {
            continue;
        }
        let measured = read_cap(sys, view, dev);
        let carrier = |w: &str| {
            sys.read(&format!("/sys/class/net/{w}/carrier"))
                .map(|s| s.trim() == "1")
                .unwrap_or(true)
        };
        let derivation = match emit::shape::derive(view, dev, measured, &carrier) {
            Ok(d) => d,
            Err(e) => {
                c.bad(&format!("shape derivation for {dev} failed: {e}"));
                continue;
            }
        };
        let live = sys.run(&["tc", "class", "show", "dev", dev])?.stdout;
        for b in &derivation.bands {
            let want = if b.eff >= 1000 && b.eff % 1000 == 0 {
                format!("rate {}Gbit", b.eff / 1000)
            } else if b.eff >= 1 {
                format!("rate {}Mbit", b.eff)
            } else {
                "rate 1Kbit".to_string()
            };
            let cid = format!("1:{}", b.minor);
            let hit = live.lines().any(|l| {
                l.contains(&format!("class htb {cid} ")) && l.contains(&format!(" {want} "))
            });
            if !hit {
                let live_line = live
                    .lines()
                    .find(|l| l.contains(&format!("class htb {cid} ")))
                    .unwrap_or("absent");
                c.bad(&format!(
                    "shape on {dev}: class {cid} should have '{want}' (live: {live_line})"
                ));
            }
        }
    }
    Ok(())
}

fn link_speeds(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    for wire in view.wires() {
        let decl = view.link_speed(&wire)?.to_string();
        let obs = sys
            .read(&format!("/sys/class/net/{wire}/speed"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "-1".to_string());
        let carrier = sys
            .read(&format!("/sys/class/net/{wire}/carrier"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if carrier && obs != decl {
            let drv = sys.run(&["ethtool", "-i", &wire])?.stdout;
            let driver = drv
                .lines()
                .find_map(|l| l.strip_prefix("driver:"))
                .map(str::trim)
                .unwrap_or("?");
            c.warn(&format!(
                "{wire}: observed link speed {obs} Mb/s != declared {decl} (driver {driver})"
            ));
        }
    }
    Ok(())
}

/// One convergence pass: 0 = full, 2 = degraded (returns the down sessions), 1 = not converged
/// (the reason text says why).
fn check(
    sys: &mut dyn Sys,
    view: &View,
    expected: &[(u8, String, u8, String)],
) -> Result<(u8, String, Vec<String>)> {
    let f = view.fabric;
    let host = &view.member.name;
    let up_addrs: BTreeSet<String> = sys
        .run(&["vtysh", "-c", "show bfd peers brief"])?
        .stdout
        .lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            (w.len() >= 4 && w[3] == "up").then(|| w[2].to_string())
        })
        .collect();
    let mut down: Vec<String> = Vec::new();
    let mut alive: BTreeSet<(u8, String)> = BTreeSet::new();
    let mut pairs: BTreeSet<(u8, String)> = BTreeSet::new();
    for (p, z, seg, addr) in expected {
        pairs.insert((*p, z.clone()));
        if up_addrs.contains(addr) {
            alive.insert((*p, z.clone()));
        } else {
            down.push(format!("{z}:{seg}:.{p}"));
        }
    }
    for (p, z) in &pairs {
        if !alive.contains(&(*p, z.clone())) {
            return Ok((1, format!("  {z}: no BFD-up segment to .{p}\n"), down));
        }
    }
    let ours = segments_of(f, view.member);
    for m in &f.members {
        if m.name == *host {
            continue;
        }
        let p = m.node;
        let theirs = segments_of(f, m);
        for z in &f.zones {
            let target = format!("{}.0.{p}", z.block());
            let ifs = view.zone_ifs(&z.name);
            // the peer must be reached over the cheapest segment we SHARE with it (the NAS
            // shape: a leaf with no wire on the zone's primary island)
            let shared: BTreeSet<u8> = ours
                .intersection(&theirs)
                .filter_map(|s| {
                    let (sz, seg) = s.split_once(':')?;
                    (sz == z.name).then(|| seg.parse().ok()).flatten()
                })
                .collect();
            let mut candidates: Vec<(u32, String)> = view
                .class_rows()
                .into_iter()
                .filter(|r| r.zone == z.name && shared.contains(&r.seg))
                .map(|r| (r.ospf_cost, r.ifname))
                .collect();
            candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            let prim = candidates
                .first()
                .map(|(_, i)| i.clone())
                .unwrap_or_default();
            let route = sys.run(&["ip", "route", "get", &target])?.stdout;
            let route_line = route.lines().next().unwrap_or("").trim().to_string();
            let words: Vec<&str> = route_line.split_whitespace().collect();
            let dev = words
                .iter()
                .position(|w| *w == "dev")
                .and_then(|i| words.get(i + 1))
                .map(|s| s.to_string())
                .unwrap_or_default();
            if !ifs.contains(&dev) {
                return Ok((
                    1,
                    format!(
                        "  {} id .0.{p} not via a {} sub-if: [{route_line}]\n",
                        z.name, z.name
                    ),
                    down,
                ));
            }
            if !route_line.contains(&format!("src {}.0.{}", z.block(), view.node())) {
                return Ok((
                    1,
                    format!("  {} id .0.{p} src not pinned: [{route_line}]\n", z.name),
                    down,
                ));
            }
            if down.is_empty() && dev != prim {
                return Ok((
                    1,
                    format!(
                        "  {} id .0.{p} via {dev}, not primary {prim}: [{route_line}]\n",
                        z.name
                    ),
                    down,
                ));
            }
        }
    }
    if down.is_empty() {
        Ok((0, String::new(), down))
    } else {
        Ok((2, String::new(), down))
    }
}

/// `counter packets N bytes M … comment "<name>"` → N.
fn counter_packets(chain: &str, comment: &str) -> Option<u64> {
    let line = chain
        .lines()
        .find(|l| l.contains(&format!("comment \"{comment}\"")))?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let i = words.iter().position(|w| *w == "packets")?;
    words.get(i + 1)?.parse().ok()
}

/// First "N accepted, M sent prefixes" in a `show bgp neighbors` output.
fn find_prefix_counts(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(pos) = line.find(" accepted, ") {
            let before = &line[..pos];
            let accepted: String = before
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
            let accepted: String = accepted.chars().rev().collect();
            let after = &line[pos + " accepted, ".len()..];
            let sent: String = after.chars().take_while(char::is_ascii_digit).collect();
            if !accepted.is_empty()
                && !sent.is_empty()
                && after[sent.len()..].starts_with(" sent prefixes")
            {
                return Some(format!("{accepted} accepted, {sent} sent prefixes"));
            }
        }
    }
    None
}

/// The cap the shape derivation prefers over the declared link speed: the shared chain (local
/// cap file → cluster-published cap, cached back locally → declared).
fn read_cap(sys: &mut dyn Sys, view: &View, dev: &str) -> Option<u64> {
    crate::caps::read_cap(
        sys,
        &crate::cluster::Pmxcfs::new(),
        &view.member.name,
        &view.fabric.run_dir,
        dev,
    )
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

    #[test]
    fn counter_parse() {
        let chain = "    iifname @admin counter packets 0 bytes 0 drop comment \"I4-admin-in\"\n\
                     counter packets 42 bytes 999 comment \"default-deny\"";
        assert_eq!(counter_packets(chain, "I4-admin-in"), Some(0));
        assert_eq!(counter_packets(chain, "default-deny"), Some(42));
        assert_eq!(counter_packets(chain, "nope"), None);
    }

    #[test]
    fn prefix_counts_parse() {
        let out = "  3 accepted, 0 filtered, 5 sent prefixes on this session\n";
        // "0 filtered," breaks contiguity — the parser needs "accepted, N sent" adjacent.
        assert_eq!(find_prefix_counts(out), None);
        let out2 = "  0 accepted, 3 sent prefixes\n";
        assert_eq!(
            find_prefix_counts(out2).as_deref(),
            Some("0 accepted, 3 sent prefixes")
        );
    }

    /// A leaf whose whole environment is healthy reports OK with the right session count.
    #[test]
    fn leaf_verify_ok_end_to_end_mocked() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = MockSys::default();
        // sysctls all correct
        for r in view.class_rows() {
            sys = sys
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", r.ifname),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                    "0\n",
                );
        }
        for z in &f.zones {
            let id = View::identity_if(z);
            sys = sys
                .file(&format!("/proc/sys/net/ipv4/conf/{id}/forwarding"), "0\n")
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{id}-peer/forwarding"),
                    "0\n",
                );
        }
        // leak guard + return path rules
        sys = sys
            .on_stdout(&["ip", "rule", "show", "pref", "1000"],
                "1000: from all to 10.99.0.0/16 iif lo lookup main\n1000: from all to 10.199.0.0/16 iif lo lookup main\n1000: from all to 10.249.0.0/16 iif lo lookup main\n")
            .on_stdout(&["ip", "rule", "show", "pref", "1001"],
                "1001: from all to 10.99.0.0/16 unreachable\n1001: from all to 10.199.0.0/16 unreachable\n1001: from all to 10.249.0.0/16 unreachable\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2000"],
                "2000: from 10.99.0.0/16 to 10.99.0.0/16 lookup main suppress_prefixlength 0\n2000: from 10.199.0.0/16 to 10.199.0.0/16 lookup main suppress_prefixlength 0\n2000: from 10.249.0.0/16 to 10.249.0.0/16 lookup main suppress_prefixlength 0\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2001"],
                "2001: from 10.99.0.0/16 lookup 99\n2001: from 10.199.0.0/16 lookup 199\n2001: from 10.249.0.0/16 lookup 249\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2002"],
                "2002: from 10.99.0.0/16 unreachable\n2002: from 10.199.0.0/16 unreachable\n2002: from 10.249.0.0/16 unreachable\n")
            // gw zone (mgmt): the leaf learns the ingress default via OSPF from the hosts
            .on_stdout(&["ip", "route", "show", "table", "249"],
                "default via 10.249.3.1 dev cfab-mg proto ospf metric 20\n");
        // LSA: transit links at offset cost
        for z in &f.zones {
            sys = sys.on_stdout(
                &[
                    "vtysh",
                    "-c",
                    &format!("show ip ospf {} database router self-originate", z.id),
                ],
                "  Link connected to: a Transit Network\n    TOS 0 Metric: 30010\n",
            );
        }
        // BFD: every expected session up (peer segment addresses for nodes 1 and 2)
        let mut bfd = String::new();
        for p in [1u8, 2u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    bfd.push_str(&format!("1 local {}.{seg}.{p} up\n", z.block()));
                }
            }
        }
        sys = sys.on_stdout(&["vtysh", "-c", "show bfd peers brief"], &bfd);
        // routes: each identity via the zone's primary with pinned src
        for p in [1u8, 2u8] {
            for z in &f.zones {
                let prim = view
                    .class_rows()
                    .into_iter()
                    .filter(|r| r.zone == z.name)
                    .min_by_key(|r| r.ospf_cost)
                    .unwrap()
                    .ifname;
                sys = sys.on_stdout(
                    &["ip", "route", "get", &format!("{}.0.{p}", z.block())],
                    &format!(
                        "{}.0.{p} via {}.1.{p} dev {prim} src {}.0.3 uid 0\n",
                        z.block(),
                        z.block(),
                        z.block()
                    ),
                );
            }
        }
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 0, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("verify OK on pve3-tb (leaf): 18 BFD up"),
            "{}",
            report.output
        );
    }

    /// Pull one segment (dark) → DEGRADED with the session named.
    #[test]
    fn leaf_verify_degraded_names_the_down_segment() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = MockSys::default();
        for r in view.class_rows() {
            sys = sys
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", r.ifname),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                    "0\n",
                );
        }
        for z in &f.zones {
            let id = View::identity_if(z);
            sys = sys
                .file(&format!("/proc/sys/net/ipv4/conf/{id}/forwarding"), "0\n")
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{id}-peer/forwarding"),
                    "0\n",
                );
        }
        sys = sys
            .on_stdout(&["ip", "rule", "show", "pref", "1000"],
                "to 10.99.0.0/16 iif lo lookup main\nto 10.199.0.0/16 iif lo lookup main\nto 10.249.0.0/16 iif lo lookup main\n")
            .on_stdout(&["ip", "rule", "show", "pref", "1001"],
                "to 10.99.0.0/16 unreachable\nto 10.199.0.0/16 unreachable\nto 10.249.0.0/16 unreachable\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2000"],
                "from 10.99.0.0/16 to 10.99.0.0/16 lookup main suppress_prefixlength 0\nfrom 10.199.0.0/16 to 10.199.0.0/16 lookup main suppress_prefixlength 0\nfrom 10.249.0.0/16 to 10.249.0.0/16 lookup main suppress_prefixlength 0\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2001"],
                "from 10.99.0.0/16 lookup 99\nfrom 10.199.0.0/16 lookup 199\nfrom 10.249.0.0/16 lookup 249\n")
            .on_stdout(&["ip", "rule", "show", "pref", "2002"],
                "from 10.99.0.0/16 unreachable\nfrom 10.199.0.0/16 unreachable\nfrom 10.249.0.0/16 unreachable\n");
        for z in &f.zones {
            sys = sys.on_stdout(
                &[
                    "vtysh",
                    "-c",
                    &format!("show ip ospf {} database router self-originate", z.id),
                ],
                "  Link connected to: a Transit Network\n    TOS 0 Metric: 30010\n",
            );
        }
        // BFD: all up EXCEPT storage seg 1 to node 1 (10.99.1.1)
        let mut bfd = String::new();
        for p in [1u8, 2u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    if p == 1 && z.name == "storage" && seg == 1 {
                        continue;
                    }
                    bfd.push_str(&format!("1 local {}.{seg}.{p} up\n", z.block()));
                }
            }
        }
        sys = sys.on_stdout(&["vtysh", "-c", "show bfd peers brief"], &bfd);
        for p in [1u8, 2u8] {
            for z in &f.zones {
                // identity to node 1 in storage now rides the backup; that's allowed while a
                // segment is down (the primary check is skipped when down is nonempty)
                let dev = if p == 1 && z.name == "storage" {
                    "cfab-st-bk"
                } else {
                    &view
                        .class_rows()
                        .into_iter()
                        .filter(|r| r.zone == z.name)
                        .min_by_key(|r| r.ospf_cost)
                        .unwrap()
                        .ifname
                        .clone()
                };
                sys = sys.on_stdout(
                    &["ip", "route", "get", &format!("{}.0.{p}", z.block())],
                    &format!(
                        "{}.0.{p} dev {dev} src {}.0.3 uid 0\n",
                        z.block(),
                        z.block()
                    ),
                );
            }
        }
        let report = run(&mut sys, &view, 30).unwrap();
        assert_eq!(report.code, 2, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("DOWN segments (zone:seg:peer): storage:1:.1"),
            "{}",
            report.output
        );
        assert!(
            report
                .output
                .contains("verify DEGRADED on pve3-tb (leaf): 17/18 BFD up"),
            "{}",
            report.output
        );
    }
}
