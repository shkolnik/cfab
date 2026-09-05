//! `cfab verify` — the health gate for THIS member. Exit 0 = fully converged and the posture
//! holds; exit 2 = converged DEGRADED (every peer's identity reachable in every zone with a
//! pinned src and ≥1 BFD-up segment, but some declared segment is down — listed, loudly — or a
//! zone's gw is unreachable); exit 1 = not converged, or a posture check failed.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Duration;

use crate::commands::common::{conf_interfaces, foreign_forward_remedy, unresolved_forward_drops};
use crate::commands::engine_ctl;
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
    /// Zones whose ingress is unreachable — `<zone>:gw` / `<zone>:bgp`.
    degraded: Vec<String>,
    /// Rescue-segment conditions — `<zone>:rescue-leg` / `<zone>:rescue-nbr` /
    /// `<zone>:rescue-path`. Kept apart from `degraded` so neither headline note has to
    /// describe the other's condition.
    rescue: Vec<String>,
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
        rescue: Vec::new(),
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
    rescue(sys, view, &mut c)?;
    if kind == MemberKind::Host && f.vrrp_gw {
        let doc = engine_ctl::state(sys, f)?;
        let inst = doc["vrrp"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|v| v["vrid"] == f.vrrp_vrid);
        match inst {
            Some(v) => {
                let st = v["state"].as_str().unwrap_or("?").to_string();
                c.say(&format!(
                    "  vrrp {}: {st} (prio {})",
                    f.vrrp_vrid,
                    view.vrrp_prio()?
                ));
            }
            None => c.bad("vrrp: no instance in engine state"),
        }
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
    if !down.is_empty() || !c.degraded.is_empty() || !c.rescue.is_empty() {
        if !down.is_empty() {
            c.say(&format!(
                "  DOWN segments (zone:seg:peer): {}",
                down.join(" ")
            ));
        }
        let gw_note = if c.degraded.is_empty() {
            String::new()
        } else {
            format!("; gw unreachable: {}", once_each(&c.degraded).join(" "))
        };
        let rescue_note = if c.rescue.is_empty() {
            String::new()
        } else {
            format!("; rescue degraded: {}", once_each(&c.rescue).join(" "))
        };
        c.say(&format!(
            "verify DEGRADED on {host} ({kind_s}): {}/{} BFD up; every identity reachable, src pinned; posture ok{}{}",
            expect_bfd - down.len(),
            expect_bfd,
            gw_note,
            rescue_note
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
    // The rescue bond is a segment here: it carries L3 and takes the same loose rp_filter.
    // Its slaves never appear — they are L2 only.
    let l3: Vec<String> = view
        .class_rows()
        .into_iter()
        .map(|r| r.ifname)
        .chain(view.rescue_rows().into_iter().map(|r| r.ifname))
        .collect();
    for ifname in &l3 {
        let got = sys
            .read(&format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "missing".to_string());
        if got != "2" {
            c.bad(&format!(
                "{ifname} rp_filter={got} (want 2 = loose, every role)"
            ));
        }
    }

    match view.kind() {
        MemberKind::Leaf => {
            let mut ifs: Vec<String> = l3.clone();
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
            // the offset — exactly cost + offset for a link from one of our segment
            // addresses, at least the offset for any other
            let doc = engine_ctl::state(sys, f)?;
            for z in &f.zones {
                // Segments AND the rescue bond as `(seg, cost)`: the bond addresses and
                // advertises exactly like a segment (`10.<id>.<seg>.<node>`), so a
                // class-rows-only list leaves its transit link owned by nobody and the
                // check silently weakens to "at least the offset" for it.
                let rows: Vec<(u8, u32)> = view
                    .class_rows()
                    .into_iter()
                    .filter(|r| r.zone == z.name)
                    .map(|r| (r.seg, r.ospf_cost))
                    .chain(
                        view.rescue_rows()
                            .into_iter()
                            .filter(|r| r.zone == z.name)
                            .map(|r| (r.seg, r.ospf_cost)),
                    )
                    .collect();
                let mut below = false;
                for link in doc["ospf"][&z.name]["self_lsa_links"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|l| engine_ctl::is_transit(&l["type"]))
                {
                    let metric = link["metric"].as_u64().unwrap_or(0);
                    let addr = link["if"].as_str().unwrap_or("");
                    let want = rows
                        .iter()
                        .find(|(seg, _)| view.segment_addr(z, *seg) == addr)
                        .map(|(_, cost)| u64::from(cost + f.leaf_cost_offset));
                    if metric < u64::from(f.leaf_cost_offset) || want.is_some_and(|w| metric != w) {
                        below = true;
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
            // Our accept is not the last word: every base chain at the forward hook runs and
            // one drop verdict ends the packet. Without this check `verify` reported
            // `posture ok` with transit 100 % dead (Docker, measured on pve1 2026-09-04).
            let blocked = unresolved_forward_drops(sys)?;
            if !blocked.is_empty() {
                let ifs: Vec<String> = view
                    .owned_forwarding()
                    .into_iter()
                    .filter(|(_, fwd)| *fwd)
                    .map(|(ifn, _)| ifn)
                    .collect();
                for b in &blocked {
                    c.bad(&format!(
                        "transit blocked by a foreign forward-hook chain: {b}"
                    ));
                }
                c.say(&format!("  {}", foreign_forward_remedy(&ifs)));
            }
            if let Some(admin) = view.admin_if() {
                for counter in ["admin-in", "admin-out"] {
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
            let present = conf_interfaces(sys)?;
            for (ifn, fwd) in view.owned_forwarding() {
                if !present.contains(&ifn) {
                    continue;
                }
                let v = sys.read(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"))?;
                let v = v.trim();
                if fwd && v != "1" {
                    c.bad(&format!(
                        "{ifn} forwarding=0 (class-table interface should forward)"
                    ));
                } else if !fwd && v != "0" {
                    c.bad(&format!(
                        "{ifn} forwarding=1 (cfab interface that must not transit)"
                    ));
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
                if !view.owns_if(&ifn) {
                    continue;
                }
                let path = format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding");
                if sys.read(&path)?.trim() != "0" {
                    c.bad(&format!("{path} = 1 with HOST_FORWARD=0"));
                }
            }
        }
    }
    Ok(())
}

/// ietf-ospf `nbr-state-type`, in its enum order. The rescue bar is 2-Way: on a broadcast LAN
/// two DROthers never go past it, so Full would be a bar a healthy rescue LAN cannot clear.
const NBR_STATES: [&str; 8] = [
    "down", "attempt", "init", "2-way", "exstart", "exchange", "loading", "full",
];

fn at_least_two_way(state: &str) -> bool {
    NBR_STATES
        .iter()
        .position(|s| *s == state)
        .is_some_and(|i| i >= 3)
}

/// The rescue segment: which wire each zone's bond is actually on, whether every peer that
/// carries the row is adjacent on it, and — the point of the whole segment — that a peer we
/// share no island with is reached over the bond, which is HEALTH, not degradation.
///
/// Runs after convergence, so the routes it reads have settled. Nothing here touches the
/// headline: rescue carries no BFD, so `<n> BFD up` counts segments only.
fn rescue(sys: &mut dyn Sys, view: &View, c: &mut Ctx) -> Result<()> {
    let f = view.fabric;
    let rows = view.rescue_rows();
    if rows.is_empty() {
        return Ok(());
    }
    let doc = engine_ctl::state(sys, f)?;
    let ours = segments_of(f, view.member);
    for r in &rows {
        let z = f.zone(&r.zone)?;
        let zone = &r.zone;

        // ---- the leg: bonding/{mii_status,active_slave} ------------------------------
        let mii = sys.read(&format!("/sys/class/net/{}/bonding/mii_status", r.ifname));
        let active = sys.read(&format!("/sys/class/net/{}/bonding/active_slave", r.ifname));
        let (Ok(mii), Ok(active)) = (mii, active) else {
            c.bad(&format!(
                "rescue {zone}: {} is not a bond (/sys/class/net/{}/bonding unreadable) — re-run cfab up",
                r.ifname, r.ifname
            ));
            continue;
        };
        if mii.trim() != "up" {
            c.warn(&format!("rescue {zone} no carrier"));
            c.rescue.push(format!("{zone}:rescue-leg"));
        } else {
            let active = active.trim();
            let Some(wire) = r
                .slaves
                .iter()
                .find(|s| s.ifname == active)
                .map(|s| s.wire.clone())
            else {
                c.bad(&format!(
                    "rescue {zone}: {} is up with no slave of ours active (active_slave={active:?})",
                    r.ifname
                ));
                continue;
            };
            if wire == r.home {
                c.say(&format!("  rescue {zone} via {wire}"));
            } else {
                // Off the home wire is only a fault while the home wire still has carrier:
                // that is a stuck reselect. A dark home is the bond doing its job. An
                // unreadable carrier is neither and is never assumed healthy — the file
                // returns EINVAL on a down interface, so this is a field state, not a
                // theoretical one.
                match sys.read(&format!("/sys/class/net/{}/carrier", r.home)) {
                    Ok(s) if s.trim() == "1" => {
                        c.warn(&format!(
                            "rescue {zone} via {wire} (home {} has carrier but is not active)",
                            r.home
                        ));
                        c.rescue.push(format!("{zone}:rescue-leg"));
                    }
                    Ok(_) => c.say(&format!("  rescue {zone} via {wire}")),
                    Err(_) => {
                        c.warn(&format!(
                            "rescue {zone} via {wire} (home {} carrier unreadable)",
                            r.home
                        ));
                        c.rescue.push(format!("{zone}:rescue-leg"));
                    }
                }
            }
        }

        // ---- adjacency: every peer carrying this zone's rescue row, at least 2-Way ----
        // An interface the engine does not carry indexes to Null here, and Null reads as an
        // empty neighbor list — every declared peer would be reported absent, which names
        // the wrong fault. The missing interface IS the fault; say that instead.
        let nbrs = doc["ospf"][zone]["interfaces"].get(r.ifname.as_str());
        let Some(nbrs) = nbrs.map(|i| &i["neighbors"]) else {
            c.bad(&format!(
                "rescue {zone}: {} is missing from the engine's ospf state (its neighbors \
                 cannot be read) — re-run cfab up",
                r.ifname
            ));
            c.rescue.push(format!("{zone}:rescue-nbr"));
            continue;
        };
        let peers: Vec<&crate::model::Member> = f
            .members
            .iter()
            .filter(|m| m.name != view.member.name)
            .filter(|m| {
                crate::derive::rescue_rows_of(f, m)
                    .iter()
                    .any(|p| p.zone == *zone)
            })
            .collect();
        let mut adjacent = 0usize;
        for m in &peers {
            let rid = format!("{}.0.{}", z.block(), m.node);
            let state = nbrs
                .as_array()
                .into_iter()
                .flatten()
                .find(|n| n["router_id"] == rid.as_str())
                .and_then(|n| n["state"].as_str())
                .map(|s| s.rsplit(':').next().unwrap_or(s))
                .unwrap_or("absent");
            if at_least_two_way(state) {
                adjacent += 1;
            } else {
                c.warn(&format!(
                    "rescue {zone} neighbor {} is {state} (want 2-Way or better)",
                    m.name
                ));
                c.rescue.push(format!("{zone}:rescue-nbr"));
            }
        }
        c.say(&format!(
            "  rescue {zone} neighbors: {adjacent}/{} 2-Way or better",
            peers.len()
        ));

        // ---- island-disjoint peers: reached over the bond, and that is health ---------
        for m in &f.members {
            if m.name == view.member.name {
                continue;
            }
            let theirs = segments_of(f, m);
            if ours
                .intersection(&theirs)
                .any(|s| s.starts_with(&format!("{zone}:")))
            {
                continue;
            }
            let target = format!("{}.0.{}", z.block(), m.node);
            let (dev, route_line) = route_dev(sys, &target)?;
            if dev == r.ifname {
                c.say(&format!(
                    "  {zone} id .0.{} ({}) via rescue {}",
                    m.node, m.name, r.ifname
                ));
            } else {
                // Reachable only when a segment is down: `check()` makes the same comparison
                // and refuses to converge on it, but skips it entirely while `down` is
                // non-empty. That is exactly when the rescue path matters most, so the
                // degraded verdict has to come from here.
                c.warn(&format!(
                    "{zone} id .0.{} via {dev}, not rescue {}: [{route_line}]",
                    m.node, r.ifname
                ));
                c.rescue.push(format!("{zone}:rescue-path"));
            }
        }
    }
    Ok(())
}

/// Return-path rules per zone; a gw zone's table must hold the engine's default, its leg must carry
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
        let doc = engine_ctl::state(sys, f)?;
        let nbr = doc["bgp"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|n| n["peer"] == gw.router.as_str());
        let state = nbr
            .and_then(|n| n["state"].as_str())
            .unwrap_or("absent")
            .to_string();
        if state == "Established" {
            let n = nbr.expect("Established comes from an entry");
            let prefixes = format!("{} accepted, {} sent prefixes", n["pfx_rcd"], n["pfx_snt"]);
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
    let doc = engine_ctl::state(sys, f)?;
    let up_addrs: BTreeSet<String> = doc["bfd"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| s["state"] == "up")
        .filter_map(|s| s["peer"].as_str().map(str::to_string))
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
            // No shared segment = island-disjoint from this peer in this zone: the rescue
            // bond is the expected path, and reaching the peer over it is health.
            let prim = candidates
                .first()
                .map(|(_, i)| i.clone())
                .or_else(|| {
                    view.rescue_rows()
                        .into_iter()
                        .find(|r| r.zone == z.name)
                        .map(|r| r.ifname)
                })
                .unwrap_or_default();
            let (dev, route_line) = route_dev(sys, &target)?;
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

/// `ip route get <target>` → (the `dev` it leaves by, the whole first line). The line is
/// carried back with the device because every caller quotes it in the failure it reports.
fn route_dev(sys: &mut dyn Sys, target: &str) -> Result<(String, String)> {
    let route = sys.run(&["ip", "route", "get", target])?.stdout;
    let route_line = route.lines().next().unwrap_or("").trim().to_string();
    let words: Vec<&str> = route_line.split_whitespace().collect();
    let dev = words
        .iter()
        .position(|w| *w == "dev")
        .and_then(|i| words.get(i + 1))
        .map(|s| s.to_string())
        .unwrap_or_default();
    Ok((dev, route_line))
}

/// The headline notes name each condition once: a zone with two down peers pushes its token
/// per peer, and this output is machine-read.
fn once_each(tokens: &[String]) -> Vec<String> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    tokens
        .iter()
        .filter(|t| seen.insert(t.as_str()))
        .cloned()
        .collect()
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

    /// The engine's state document as `engine::state::document` shapes it: every instance
    /// healthy with transit links at the leaf offset, one BFD session per (peer, state), and
    /// every peer that carries the zone's rescue row adjacent on the rescue bond.
    fn engine_value(view: &View, bfd: &[(String, &str)]) -> serde_json::Value {
        let f = view.fabric;
        let mut doc = engine_ctl::tests::healthy_doc(view);
        doc["bfd"] = bfd
            .iter()
            .map(|(peer, state)| {
                serde_json::json!({
                    "local": null, "peer": peer, "if": "cfab-x", "state": state,
                    "rx_us": 300000, "tx_us": 300000, "mult": 3
                })
            })
            .collect();
        for r in view.rescue_rows() {
            let z = f.zone(&r.zone).unwrap();
            let nbrs: Vec<serde_json::Value> = f
                .members
                .iter()
                .filter(|m| m.name != view.member.name)
                .filter(|m| {
                    crate::derive::rescue_rows_of(f, m)
                        .iter()
                        .any(|p| p.zone == r.zone)
                })
                .map(|m| {
                    serde_json::json!({
                        "router_id": format!("{}.0.{}", z.block(), m.node),
                        "addr": format!("{}.{}.{}", z.block(), r.seg, m.node),
                        "state": "full",
                    })
                })
                .collect();
            doc["ospf"][&r.zone]["interfaces"][&r.ifname]["neighbors"] =
                serde_json::Value::Array(nbrs);
        }
        doc
    }

    fn engine_doc(view: &View, bfd: &[(String, &str)]) -> String {
        engine_value(view, bfd).to_string()
    }

    /// The `bonding/` sysfs a live active-backup bond exposes, captured from the spike
    /// container (`cat /sys/class/net/cfab-st-rs/bonding/{mii_status,active_slave}` →
    /// `up` / `cfab-st-rs-st`), plus the L3 posture `up` sets on the bond itself.
    fn rescue_sysfs(mut sys: MockSys, view: &View, forwarding: &str) -> MockSys {
        for r in view.rescue_rows() {
            let home = r
                .slaves
                .iter()
                .find(|s| s.wire == r.home)
                .expect("the home wire is one of the slaves");
            sys = sys
                .file(
                    &format!("/sys/class/net/{}/bonding/mii_status", r.ifname),
                    "up\n",
                )
                .file(
                    &format!("/sys/class/net/{}/bonding/active_slave", r.ifname),
                    &format!("{}\n", home.ifname),
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", r.ifname),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                    forwarding,
                );
        }
        sys
    }

    /// A leaf's healthy environment: posture sysctls on every segment, the rescue bonds and
    /// the identity veths, the leak-guard and return-path rules, and the gw zone's learned
    /// default. Each test adds the engine state and the routes it wants to prove.
    fn leaf_env(view: &View) -> MockSys {
        let f = view.fabric;
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
        sys = rescue_sysfs(sys, view, "0\n");
        sys
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
                "default via 10.249.3.1 dev cfab-mg proto ospf metric 20\n")
    }

    /// Every expected BFD session, up.
    fn all_bfd_up(f: &Fabric) -> Vec<(String, &'static str)> {
        let mut bfd = Vec::new();
        for p in [1u8, 2u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    bfd.push((format!("{}.{seg}.{p}", z.block()), "up"));
                }
            }
        }
        bfd
    }

    /// Each peer identity reached over the zone's primary segment with a pinned src.
    fn primary_routes(mut sys: MockSys, view: &View) -> MockSys {
        for p in [1u8, 2u8] {
            for z in &view.fabric.zones {
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
        sys
    }

    #[test]
    fn counter_parse() {
        let chain = "    iifname @admin counter packets 0 bytes 0 drop comment \"admin-in\"\n\
                     counter packets 42 bytes 999 comment \"default-deny\"";
        assert_eq!(counter_packets(chain, "admin-in"), Some(0));
        assert_eq!(counter_packets(chain, "default-deny"), Some(42));
        assert_eq!(counter_packets(chain, "nope"), None);
    }

    /// A leaf whose whole environment is healthy reports OK with the right session count.
    #[test]
    fn leaf_verify_ok_end_to_end_mocked() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &all_bfd_up(&f)));
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 0, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("verify OK on pve3-tb (leaf): 18 BFD up"),
            "{}",
            report.output
        );
        // The rescue clause: each bond active on the wire carrying that zone's cheapest
        // segment, and every peer that carries the row adjacent on it.
        for (zone, wire) in [("storage", "eth9"), ("cluster", "eth1"), ("mgmt", "eth0")] {
            assert!(
                report
                    .output
                    .contains(&format!("  rescue {zone} via {wire}\n")),
                "{}",
                report.output
            );
            assert!(
                report
                    .output
                    .contains(&format!("  rescue {zone} neighbors: 2/2 2-Way or better\n")),
                "{}",
                report.output
            );
        }
    }

    /// Pull one segment (dark) → DEGRADED with the session named.
    #[test]
    fn leaf_verify_degraded_names_the_down_segment() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = leaf_env(&view);
        // BFD: all up EXCEPT storage seg 1 to node 1 (10.99.1.1), which the engine still
        // lists, down
        let mut bfd = Vec::new();
        for p in [1u8, 2u8] {
            for z in &f.zones {
                for seg in [1u8, 2, 3] {
                    let dark = p == 1 && z.name == "storage" && seg == 1;
                    bfd.push((
                        format!("{}.{seg}.{p}", z.block()),
                        if dark { "down" } else { "up" },
                    ));
                }
            }
        }
        sys = sys.socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
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

    /// The bond is active on a wire that is not the home while the home still has carrier —
    /// a stuck reselect. DEGRADED, and the line names both wires.
    #[test]
    fn rescue_leg_degraded_when_the_home_has_carrier_but_is_not_active() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &all_bfd_up(&f)))
            // storage homes on eth9 (cfab-st, cost 10); the bond sits on the mg slave
            .file(
                "/sys/class/net/cfab-st-rs/bonding/active_slave",
                "cfab-st-rs-mg\n",
            )
            .file("/sys/class/net/eth9/carrier", "1\n");
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 2, "output:\n{}", report.output);
        assert!(
            report.output.contains(
                "  warn: rescue storage via eth0 (home eth9 has carrier but is not active)\n"
            ),
            "{}",
            report.output
        );
        assert!(
            report
                .output
                .contains("; rescue degraded: storage:rescue-leg"),
            "{}",
            report.output
        );
    }

    /// The same reselect, but the home wire is dark: the bond did exactly its job, so the
    /// line is the plain OK spelling and the report stays OK.
    #[test]
    fn rescue_leg_on_a_backup_wire_is_ok_when_the_home_is_dark() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &all_bfd_up(&f)))
            .file(
                "/sys/class/net/cfab-st-rs/bonding/active_slave",
                "cfab-st-rs-mg\n",
            )
            .file("/sys/class/net/eth9/carrier", "0\n");
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 0, "output:\n{}", report.output);
        assert!(
            report.output.contains("  rescue storage via eth0\n"),
            "{}",
            report.output
        );
    }

    /// The same reselect, but the home wire's carrier cannot be read at all (the file
    /// returns EINVAL on a down interface). Unreadable is never healthy: its own spelling,
    /// and DEGRADED.
    #[test]
    fn rescue_leg_home_carrier_unreadable_is_degraded() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let sys = leaf_env(&view);
        // no /sys/class/net/eth9/carrier at all — the read fails
        let mut sys = primary_routes(sys, &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &all_bfd_up(&f)))
            .file(
                "/sys/class/net/cfab-st-rs/bonding/active_slave",
                "cfab-st-rs-mg\n",
            );
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 2, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  warn: rescue storage via eth0 (home eth9 carrier unreadable)\n"),
            "{}",
            report.output
        );
        assert!(
            report
                .output
                .contains("; rescue degraded: storage:rescue-leg"),
            "{}",
            report.output
        );
    }

    /// Two peers down in the SAME zone push the same token twice; the headline note names
    /// each condition once, because it is machine-read.
    #[test]
    fn a_zone_with_two_down_peers_names_its_token_once() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_value(&view, &all_bfd_up(&f));
        // both peers gone from the storage rescue LAN
        doc["ospf"]["storage"]["interfaces"]["cfab-st-rs"]["neighbors"] = serde_json::json!([]);
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view).socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 2, "output:\n{}", report.output);
        for m in ["pve1-tb", "pve2-tb"] {
            assert!(
                report.output.contains(&format!(
                    "  warn: rescue storage neighbor {m} is absent (want 2-Way or better)\n"
                )),
                "{}",
                report.output
            );
        }
        assert!(
            report
                .output
                .contains("; rescue degraded: storage:rescue-nbr\n"),
            "{}",
            report.output
        );
    }

    /// Every slave dark: one spelling, `no carrier`, and DEGRADED.
    #[test]
    fn rescue_leg_no_carrier_is_degraded() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &all_bfd_up(&f)))
            .file("/sys/class/net/cfab-cl-rs/bonding/mii_status", "down\n")
            .file("/sys/class/net/cfab-cl-rs/bonding/active_slave", "\n");
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 2, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  warn: rescue cluster no carrier\n"),
            "{}",
            report.output
        );
        assert!(
            report
                .output
                .contains("; rescue degraded: cluster:rescue-leg"),
            "{}",
            report.output
        );
    }

    /// "Which member is down": a peer that carries the zone's rescue row but is not adjacent
    /// on the bond is named, and the report is DEGRADED.
    #[test]
    fn rescue_neighbor_below_two_way_is_named() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_value(&view, &all_bfd_up(&f));
        // pve1-tb (10.99.0.1) drops out of the storage rescue LAN entirely; pve2-tb is stuck
        // in init on the mgmt one.
        doc["ospf"]["storage"]["interfaces"]["cfab-st-rs"]["neighbors"] = serde_json::json!([
            { "router_id": "10.99.0.2", "addr": "10.99.9.2", "state": "2-way" }
        ]);
        doc["ospf"]["mgmt"]["interfaces"]["cfab-mg-rs"]["neighbors"] = serde_json::json!([
            { "router_id": "10.249.0.1", "addr": "10.249.9.1", "state": "full" },
            { "router_id": "10.249.0.2", "addr": "10.249.9.2", "state": "ietf-ospf:init" }
        ]);
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view).socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 2, "output:\n{}", report.output);
        assert!(
            report.output.contains(
                "  warn: rescue storage neighbor pve1-tb is absent (want 2-Way or better)\n"
            ),
            "{}",
            report.output
        );
        assert!(
            report
                .output
                .contains("  warn: rescue mgmt neighbor pve2-tb is init (want 2-Way or better)\n"),
            "{}",
            report.output
        );
        // 2-way itself clears the bar, and cluster is untouched.
        assert!(
            report
                .output
                .contains("  rescue cluster neighbors: 2/2 2-Way or better\n"),
            "{}",
            report.output
        );
        assert!(
            report
                .output
                .contains("; rescue degraded: storage:rescue-nbr mgmt:rescue-nbr"),
            "{}",
            report.output
        );
    }

    /// Two members with no island in common: pve1-tb has only its st wire, pve2-tb only its
    /// cl wire, so they share no segment in any zone. The rescue bond is the only path
    /// between them — and that is HEALTH, not degradation.
    fn disjoint_fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace(
                    "pve1-tb 1 host eth9:5000 eth1:1000 eth0:1000",
                    "pve1-tb 1 host eth9:5000 - -",
                )
                .replace(
                    "pve2-tb 2 host eth9:5000 eth1:1000 eth0:1000",
                    "pve2-tb 2 host - eth1:1000 -",
                )
                .replace("USB_NICS=\"pve1-tb:eth9 pve2-tb:eth9\"", "USB_NICS=\"\"");
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    #[test]
    fn an_island_disjoint_peer_is_expected_over_the_rescue_bond() {
        let f = disjoint_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        // pve1-tb and pve2-tb share nothing; pve3-tb has every wire, so it still shares the
        // st segments with pve1-tb.
        assert!(
            segments_of(&f, f.member("pve1-tb").unwrap())
                .intersection(&segments_of(&f, f.member("pve2-tb").unwrap()))
                .next()
                .is_none()
        );
        let mut sys = MockSys::default();
        for (target, dev) in [
            // the island-disjoint peer: over the storage rescue bond
            ("10.99.0.2", "cfab-st-rs"),
            ("10.199.0.2", "cfab-cl-rs"),
            ("10.249.0.2", "cfab-mg-rs"),
            // the peer we do share segments with: over the cheapest shared segment
            ("10.99.0.3", "cfab-st"),
            ("10.199.0.3", "cfab-cl-bk"),
            ("10.249.0.3", "cfab-mg-b2"),
        ] {
            sys = sys.on_stdout(
                &["ip", "route", "get", target],
                &format!(
                    "{target} dev {dev} src {}.0.1 uid 0\n",
                    &target[..target.len() - 4]
                ),
            );
        }
        let mut bfd: Vec<(String, &str)> = Vec::new();
        for (z, seg) in [("storage", 1u8), ("cluster", 2), ("mgmt", 3)] {
            let block = f.zone(z).unwrap().block();
            bfd.push((format!("{block}.{seg}.3"), "up"));
        }
        let expected: Vec<(u8, String, u8, String)> = bfd
            .iter()
            .zip([("storage", 1u8), ("cluster", 2), ("mgmt", 3)])
            .map(|((addr, _), (z, seg))| (3u8, z.to_string(), seg, addr.clone()))
            .collect();
        let mut sys = sys.socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        let (rc, why, down) = check(&mut sys, &view, &expected).unwrap();
        assert_eq!(rc, 0, "why: {why}");
        assert!(down.is_empty(), "{down:?}");
    }

    #[test]
    fn an_island_disjoint_peer_off_the_rescue_bond_does_not_converge() {
        let f = disjoint_fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = MockSys::default();
        for (target, dev) in [
            // storage to the disjoint peer leaves over a class segment, not the bond
            ("10.99.0.2", "cfab-st"),
            ("10.199.0.2", "cfab-cl-rs"),
            ("10.249.0.2", "cfab-mg-rs"),
            ("10.99.0.3", "cfab-st"),
            ("10.199.0.3", "cfab-cl-bk"),
            ("10.249.0.3", "cfab-mg-b2"),
        ] {
            sys = sys.on_stdout(
                &["ip", "route", "get", target],
                &format!(
                    "{target} dev {dev} src {}.0.1 uid 0\n",
                    &target[..target.len() - 4]
                ),
            );
        }
        let mut sys = sys.socket("/run/cfab/engine.sock", &engine_doc(&view, &[]));
        let (rc, why, _) = check(&mut sys, &view, &[]).unwrap();
        assert_eq!(rc, 1, "why: {why}");
        assert!(
            why.contains("storage id .0.2 via cfab-st, not primary cfab-st-rs"),
            "{why}"
        );
    }

    /// pve1-tb and pve3-tb sit on the st and mg islands, pve2-tb only on cl: pve2-tb shares
    /// no segment with pve3-tb in any zone, while pve1-tb shares two per zone (so one of
    /// them can go dark without the zone losing its only session).
    fn half_disjoint_fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace(
                    "pve1-tb 1 host eth9:5000 eth1:1000 eth0:1000",
                    "pve1-tb 1 host eth9:5000 - eth0:1000",
                )
                .replace(
                    "pve2-tb 2 host eth9:5000 eth1:1000 eth0:1000",
                    "pve2-tb 2 host - eth1:1000 -",
                )
                .replace(
                    "pve3-tb 3 leaf eth9:10000 eth1:1000 eth0:1000",
                    "pve3-tb 3 leaf eth9:10000 - eth0:1000",
                )
                .replace("USB_NICS=\"pve1-tb:eth9 pve2-tb:eth9\"", "USB_NICS=\"\"");
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// The `<zone>:rescue-path` branch through the only path that reaches it: a down segment
    /// makes `check()` skip its primary comparison, so the rescue clause is the only thing
    /// left watching the island-disjoint peer — and it is exactly then that the rescue
    /// segment is load-bearing.
    #[test]
    fn an_island_disjoint_peer_off_the_bond_is_degraded_while_a_segment_is_down() {
        let f = half_disjoint_fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        assert!(
            segments_of(&f, view.member)
                .intersection(&segments_of(&f, f.member("pve2-tb").unwrap()))
                .next()
                .is_none(),
            "pve2-tb must be island-disjoint from pve3-tb in every zone"
        );
        let sys = leaf_env(&view);
        // pve1-tb shares two segments per zone; storage seg 1 is dark, the rest up.
        let bfd: Vec<(String, &str)> = [
            ("10.99.1.1", "down"),
            ("10.99.3.1", "up"),
            ("10.199.2.1", "up"),
            ("10.199.3.1", "up"),
            ("10.249.1.1", "up"),
            ("10.249.3.1", "up"),
        ]
        .iter()
        .map(|(a, s)| (a.to_string(), *s))
        .collect();
        let mut sys = sys.socket("/run/cfab/engine.sock", &engine_doc(&view, &bfd));
        for (target, dev) in [
            // the peer we share segments with
            ("10.99.0.1", "cfab-st"),
            ("10.199.0.1", "cfab-cl-bk"),
            ("10.249.0.1", "cfab-mg"),
            // the island-disjoint peer: cluster and mgmt over the bond, storage NOT
            ("10.99.0.2", "cfab-st-b2"),
            ("10.199.0.2", "cfab-cl-rs"),
            ("10.249.0.2", "cfab-mg-rs"),
        ] {
            sys = sys.on_stdout(
                &["ip", "route", "get", target],
                &format!(
                    "{target} dev {dev} src {}.0.3 uid 0\n",
                    &target[..target.len() - 4]
                ),
            );
        }
        let report = run(&mut sys, &view, 60).unwrap();
        assert_eq!(report.code, 2, "output:\n{}", report.output);
        assert!(
            report.output.contains(
                "  warn: storage id .0.2 via cfab-st-b2, not rescue cfab-st-rs: \
                 [10.99.0.2 dev cfab-st-b2 src 10.99.0.3 uid 0]\n"
            ),
            "{}",
            report.output
        );
        // the other direction, over the same live run
        assert!(
            report
                .output
                .contains("  cluster id .0.2 (pve2-tb) via rescue cfab-cl-rs\n"),
            "{}",
            report.output
        );
        assert!(
            report
                .output
                .contains("; rescue degraded: storage:rescue-path\n"),
            "{}",
            report.output
        );
    }

    /// 5.4: the bond carries L3 and must have the loose rp_filter every cfab interface has.
    #[test]
    fn rescue_bond_rp_filter_is_a_posture_check() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &all_bfd_up(&f)))
            .file("/proc/sys/net/ipv4/conf/cfab-mg-rs/rp_filter", "1\n");
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 1, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  FAIL: cfab-mg-rs rp_filter=1 (want 2 = loose, every role)\n"),
            "{}",
            report.output
        );
    }

    /// 5.4: a leaf never transits — on the bond either.
    #[test]
    fn rescue_bond_forwarding_is_a_leaf_posture_check() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view)
            .socket("/run/cfab/engine.sock", &engine_doc(&view, &all_bfd_up(&f)))
            .file("/proc/sys/net/ipv4/conf/cfab-st-rs/forwarding", "1\n");
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 1, "output:\n{}", report.output);
        assert!(
            report
                .output
                .contains("  FAIL: cfab-st-rs forwarding!=0 (a leaf never transits)\n"),
            "{}",
            report.output
        );
    }

    /// An interface the engine does not carry yields `Null` where its neighbors should be,
    /// and `Null` reads as an empty list — every declared peer would be reported absent,
    /// naming the wrong fault. Name the real one instead.
    #[test]
    fn a_rescue_interface_absent_from_the_engine_state_is_named() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_value(&view, &all_bfd_up(&f));
        doc["ospf"]["storage"]["interfaces"]
            .as_object_mut()
            .unwrap()
            .remove("cfab-st-rs");
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view).socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 1, "output:\n{}", report.output);
        assert!(
            report.output.contains(
                "  FAIL: rescue storage: cfab-st-rs is missing from the engine's ospf state \
                 (its neighbors cannot be read) — re-run cfab up\n"
            ),
            "{}",
            report.output
        );
        // and NOT the misleading per-peer verdict it used to print
        assert!(
            !report.output.contains("rescue storage neighbor"),
            "{}",
            report.output
        );
    }

    /// The never-a-transit check must hold the rescue bond to the EXACT offset too: the bond
    /// advertises from `10.<id>.9.<node>`, which no class row owns, so a rescue-blind check
    /// silently falls back to the weaker "at least the offset" arm and lets a wrong metric
    /// through. 5000 + 30000 = 35000 is the only acceptable value.
    #[test]
    fn a_leafs_rescue_transit_link_is_held_to_the_exact_offset() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = engine_value(&view, &all_bfd_up(&f));
        let rescue_addr = view.segment_addr(f.zone("storage").unwrap(), 9);
        let links = doc["ospf"]["storage"]["self_lsa_links"]
            .as_array_mut()
            .unwrap();
        let link = links
            .iter_mut()
            .find(|l| l["if"] == rescue_addr.as_str())
            .expect("the rescue bond advertises a transit link");
        // Above LEAF_COST_OFFSET, so the weak arm accepts it; not cost + offset, so the
        // exact arm must not.
        link["metric"] = serde_json::json!(31000);
        let sys = leaf_env(&view);
        let mut sys = primary_routes(sys, &view).socket("/run/cfab/engine.sock", &doc.to_string());
        let report = run(&mut sys, &view, 10).unwrap();
        assert_eq!(report.code, 1, "output:\n{}", report.output);
        assert!(
            report.output.contains(
                "  FAIL: ospf 99: a transit link in our router LSA is advertised below \
                 LEAF_COST_OFFSET=30000"
            ),
            "{}",
            report.output
        );
    }

    #[test]
    fn two_way_is_the_adjacency_bar() {
        for s in ["2-way", "exstart", "exchange", "loading", "full"] {
            assert!(at_least_two_way(s), "{s}");
        }
        for s in ["down", "attempt", "init", "absent", ""] {
            assert!(!at_least_two_way(s), "{s}");
        }
    }
}
