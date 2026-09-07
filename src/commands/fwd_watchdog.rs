//! `cfab fwd-watchdog` — the fail-closed forwarding check. Run every few seconds by the
//! transient systemd timer `cfab up` starts. If the forward policy is not loaded with a drop
//! default, switch forwarding OFF on every cfab interface and say so (recovery = re-run
//! `cfab up`). Forwarding flags on cfab's own interfaces that drifted from the declared value
//! are written back and logged: the flag is the belt, the (verified-present) policy is the
//! braces, and a foreign stack writing `ip_forward=1` propagates 1 onto every interface
//! including ours — that is drift to correct, not a breach. Interfaces cfab does not own are
//! never read or written (scoped posture; `View::owned_forwarding`). Per-interface forwarding
//! is what the kernel checks — so conf/<if>/forwarding is written, never ip_forward.
//!
//! It also reports foreign forward-hook chains whose policy is drop. Those are reported and
//! never corrected: every base chain at a hook runs and any one drop verdict ends the packet,
//! so cfab cannot out-accept them, and switching our own forwarding off would not restore a
//! single packet. Silence here was a real bug — with Docker running, transit was 100 % dead
//! while cfab's own counters recorded accepts and `cfab status` reported a healthy posture.

use crate::commands::common::{
    self, conf_interfaces, ensure_foreign_transit_accept, foreign_forward_remedy,
    unresolved_forward_drops,
};
use crate::commands::common::{link_exists, link_kind_is};
use crate::commands::{apply, engine_ctl};
use crate::derive::{Port, View};
use crate::driver_features;
use crate::emit::engine::TransitCost;
use crate::error::Result;
use crate::model::MemberKind;
use crate::prober::HeldPrimaries;
use crate::sys::{Sys, run_ignore};

pub struct WatchdogReport {
    /// None = healthy; Some(reason) = failed closed.
    pub failed: Option<String>,
    /// cfab interfaces whose forwarding flag was written back to the declared value.
    pub corrected: Vec<String>,
    /// Foreign forward-hook chains dropping what cfab accepts. Reported, never "corrected":
    /// cfab cannot override another table's verdict, and switching our own forwarding off
    /// would not restore a single packet.
    pub blocked: Vec<String>,
    /// A foreign-stack accept cfab installed on this tick (`None` = nothing needed doing).
    pub resolved: Option<String>,
    /// Objects cfab owns that had drifted and were put back: an rp_filter sysctl, an `ip rule`,
    /// a bond's membership. Restoring is always tried FIRST — a false positive then costs one
    /// idempotent write instead of an outage.
    pub restored: Vec<String>,
    /// Restores that failed, after which the narrowest thing that removes the hazard was
    /// brought down. The name says what went down and why.
    pub downed: Vec<String>,
    /// The engine would not take the `transit-cost` re-advertisement (it is down, or it
    /// refused the candidate). Loud, but never an exit code of its own: an engine that is not
    /// answering is `status`'s story, and the forwarding flags are already off.
    pub transit_cost_error: Option<String>,
    /// Restores that failed where there is nothing to actuate on — the drift stands, loudly,
    /// and `status` keeps reporting it. Never silent, never an outage.
    pub unrestored: Vec<String>,
    /// Legs of a PRESENT wire that had no netdev and were built back exactly as `apply` builds
    /// them: `rebuilt <zone>/<ifname> on <wire>`, one line per leg. The motivating case is a USB
    /// NIC that re-enumerates with a new ifindex — every sub-interface, bond port and ingress
    /// leg on that wire dies with the old netdev and nothing ever re-created them, so the member
    /// sat UP-DEGRADED until an operator reloaded cfab (measured on the testbed, 2026-09-06).
    pub rebuilt: Vec<String>,
}

/// `held` is what the ingress prober is holding each migrating gw bond's `primary` on. The
/// standalone `cfab fwd-watchdog` has no prober and passes an empty map, which restores the
/// declared home exactly as it always did.
pub fn run(sys: &mut dyn Sys, view: &View, held: &HeldPrimaries) -> Result<WatchdogReport> {
    // The forward policy is a transit fact: a leaf never transits and never loads the table, so
    // asking it for `policy drop` would fail it closed on a posture it is not supposed to have.
    // (`up` only schedules this timer on a forwarding host today; the guard makes the command
    // safe to run anywhere, which is what the rule restores below need.)
    let transits = view.kind() == MemberKind::Host && view.fabric.host_forward;
    let mut transit_cost_error = None;
    if transits {
        let chain = sys.run(&["nft", "list", "chain", "inet", "cfab-fwd", "forward"])?;
        if !chain.ok() || !chain.stdout.contains("policy drop;") {
            return fail_closed(
                sys,
                view,
                "table inet cfab-fwd / chain forward with policy drop is not loaded",
            );
        }
        // The policy is loaded, so this member may transit again: put the transit links back
        // at their declared cost. Re-asserted every tick, not remembered — the engine diffs
        // the candidate, so the cost already in force costs nothing, and no state file can
        // disagree with what is actually advertised.
        transit_cost_error = ask_transit_cost(sys, view, TransitCost::Declared);
    }
    let present = conf_interfaces(sys)?;
    let mut corrected = Vec::new();
    for (ifn, fwd) in view.owned_forwarding() {
        if !present.contains(&ifn) {
            continue;
        }
        let want = if fwd { "1" } else { "0" };
        let path = format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding");
        let v = sys
            .read(&path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if v != want {
            sys.write(&path, want)?;
            corrected.push(format!("{ifn} forwarding {v}->{want}"));
        }
    }
    if !corrected.is_empty() {
        run_ignore(
            sys,
            &[
                "logger",
                "-t",
                "cfab-fwd-watchdog",
                &format!(
                    "corrected forwarding on cfab interfaces: {} (a foreign stack wrote ip_forward?)",
                    corrected.join(", ")
                ),
            ],
        )?;
    }
    // ---- restore what cfab owns, and actuate only where a restore failed ----------------
    // Narrowest hazard first, and the one that can amputate LAST: a leg-wide sysctl, then one
    // bond's membership, then the member-wide rules. Running the rules first would down every
    // fabric leg — the bonds included — under a bond restore that had not been tried yet.
    //
    // The missing legs come FIRST, before any of them: a leg that has no netdev has no
    // rp_filter to restore, no bond membership to police and no return-path default to re-add,
    // so rebuilding it first lets the same tick finish the job instead of leaving three ticks
    // of half-configured leg behind it.
    let mut restored: Vec<String> = Vec::new();
    let mut downed: Vec<String> = Vec::new();
    let mut unrestored: Vec<String> = Vec::new();
    let mut rebuilt: Vec<String> = Vec::new();
    restore_missing_legs(sys, view, held, &mut rebuilt, &mut unrestored)?;
    restore_rp_filter(sys, view, &mut restored, &mut unrestored)?;
    restore_bond_membership(sys, view, &mut restored, &mut downed)?;
    restore_rules(sys, view, &mut restored, &mut downed)?;
    restore_gw_return_defaults(sys, view, &mut restored)?;
    for line in restored
        .iter()
        .chain(rebuilt.iter())
        .chain(downed.iter())
        .chain(unrestored.iter())
    {
        run_ignore(sys, &["logger", "-t", "cfab-fwd-watchdog", line])?;
    }

    if !transits {
        return Ok(WatchdogReport {
            failed: None,
            corrected,
            blocked: Vec::new(),
            resolved: None,
            restored,
            downed,
            unrestored,
            rebuilt,
            transit_cost_error,
        });
    }
    // Ask the foreign stack to pass cfab transit before judging it: Docker's policy stays DROP
    // by its own design, so the question is never "is there a drop" but "is our accept in".
    let mut resolved = None;
    if let Some(rule) = ensure_foreign_transit_accept(sys)? {
        run_ignore(
            sys,
            &[
                "logger",
                "-t",
                "cfab-fwd-watchdog",
                &format!("installed a foreign-stack accept for cfab transit: {rule}"),
            ],
        )?;
        resolved = Some(rule);
    }
    let blocked = unresolved_forward_drops(sys)?;
    if !blocked.is_empty() {
        let ifs: Vec<String> = view
            .owned_forwarding()
            .into_iter()
            .filter(|(_, fwd)| *fwd)
            .map(|(ifn, _)| ifn)
            .collect();
        run_ignore(
            sys,
            &[
                "logger",
                "-t",
                "cfab-fwd-watchdog",
                &format!(
                    "BLOCKED by a foreign ruleset: {} — {}",
                    blocked.join(", "),
                    foreign_forward_remedy(&ifs)
                ),
            ],
        )?;
    }
    Ok(WatchdogReport {
        failed: None,
        corrected,
        blocked,
        resolved,
        restored,
        downed,
        unrestored,
        rebuilt,
        transit_cost_error,
    })
}

/// The L3 netdevs cfab owns: class segments and the fallback bonds. Their ports are L2 only.
fn fabric_legs(view: &View) -> Vec<String> {
    view.class_rows()
        .into_iter()
        .map(|r| r.ifname)
        .chain(view.fallback_rows().into_iter().map(|r| r.ifname))
        .collect()
}

/// Row 4. cfab owns the value (loose, every role — strict rp_filter black-holed control for
/// ~5 s when all links returned at once), so drift is written back, never reported and left.
/// Radius is a leg and the fix is one idempotent write, so there is nothing here to actuate on.
/// A write that fails is recorded and the tick continues: one unwritable sysctl must not cost
/// the bond and rule restores that follow it.
fn restore_rp_filter(
    sys: &mut dyn Sys,
    view: &View,
    restored: &mut Vec<String>,
    unrestored: &mut Vec<String>,
) -> Result<()> {
    for ifname in fabric_legs(view) {
        let path = format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter");
        // An absent leg is not ours to create — `cfab up` does that.
        let Ok(v) = sys.read(&path) else { continue };
        let v = v.trim().to_string();
        if v != "2" {
            match sys.write(&path, "2") {
                Ok(()) => restored.push(format!("rp_filter {ifname} {v}->2 (want 2 = loose)")),
                Err(e) => unrestored.push(format!(
                    "rp_filter {ifname}={v}: could not write 2 ({e}) — re-run cfab up"
                )),
            }
        }
    }
    Ok(())
}

/// Rows 5 and 6: the leaf leak guard and the return path. Both are member-wide — with either
/// missing, fabric-block traffic can leave by a path cfab never sanctioned — and neither can be
/// narrowed to one leg. So: re-add first; only if the re-add fails do the fabric legs go down,
/// which removes the hazard by removing the fabric, and `status` then reads FAILED.
fn restore_rules(
    sys: &mut dyn Sys,
    view: &View,
    restored: &mut Vec<String>,
    downed: &mut Vec<String>,
) -> Result<()> {
    let mut rules = Vec::new();
    if view.kind() == MemberKind::Leaf {
        rules.extend(common::leak_guard_rules(view));
    }
    rules.extend(common::return_path_rules(view));
    let mut unrestorable: Vec<String> = Vec::new();
    for r in &rules {
        if common::fabric_rule_present(sys, r)? {
            continue;
        }
        let what = format!("pref {} {}", r.pref, r.needle);
        match common::ensure_fabric_rule(sys, r) {
            Ok(()) => restored.push(format!("re-added ip rule {what}")),
            Err(_) => unrestorable.push(what),
        }
    }
    if unrestorable.is_empty() {
        return Ok(());
    }
    for ifname in fabric_legs(view) {
        run_ignore(sys, &["ip", "link", "set", &ifname, "down"])?;
    }
    downed.push(format!(
        "fabric legs down: could not restore {} — re-run cfab up",
        unrestorable.join(", ")
    ));
    Ok(())
}

/// The gw-zone return-path default (`default via <router> ... table <id> proto 205`). The kernel
/// deletes this dev-scoped route when its ingress leg goes down and never re-adds it on link-up,
/// so a single gw-leg flap black-holes off-fabric ingress until the next reapply (measured on the
/// pve3 fixture, 2026-09-06). `up` installs it and this restores it — through the same
/// `GwReturnDefault` so the spellings cannot drift.
///
/// Best-effort, unlike the rules: a re-add that fails means the leg is down, which is already the
/// reported fault and self-resolves on link-up, so it is neither logged as a fault nor allowed to
/// down anything — a missing return path while the leg is down is not a hazard to actuate on. A
/// successful re-add IS recorded, so a flap recovery shows in the journal. No-op on a member with
/// no ingress leg (`gw_return_defaults` is empty).
fn restore_gw_return_defaults(
    sys: &mut dyn Sys,
    view: &View,
    restored: &mut Vec<String>,
) -> Result<()> {
    for d in common::gw_return_defaults(view) {
        if d.present(sys)? {
            continue;
        }
        if d.install(sys).is_ok() {
            restored.push(format!(
                "re-added return-path default table {} via {}",
                d.table, d.via
            ));
        }
    }
    Ok(())
}

/// Rebuild the legs of a PRESENT wire that have no netdev at all.
///
/// A wire's netdev can vanish and come back with a new ifindex — a USB NIC re-enumerated by an
/// unplug/replug or a driver reload, measured on the testbed 2026-09-06. Everything stacked on
/// it dies with the old netdev: the class-segment sub-interfaces, the fallback bond's port, the
/// ingress leg. Nothing re-created them, so the member sat `UP-DEGRADED 12/18` until an operator
/// ran `systemctl reload cfab`. The routing engine already rebinds to a re-created netdev
/// (holo fork `ifindex-rebind`), so a leg put back here is picked up without restarting the
/// engine or any other child — and this restore never touches one.
///
/// The invariant restored is "every leg apply would have built on a present wire exists". So:
///   - an ABSENT wire is skipped in silence — `apply` and `status` already say
///     `wire <dev> absent (no such netdev) …`, and its legs are not supposed to exist;
///   - a leg netdev that EXISTS is left alone, whatever state it is in: the other restores own
///     its sysctls, its membership and its route. Only total absence is this one's business;
///   - a leg netdev of the WRONG KIND is reported and never deleted. `apply` deletes a stray
///     vlan and refuses a stray bond; a three-second tick has no business deleting a live
///     netdev, so both conditions land in `unrestored` and `status` keeps saying so.
///
/// Cheap by construction: on the ordinary tick this is one `ip link show` per wire plus one per
/// leg, and not a single `ip link add` or sysctl write.
fn restore_missing_legs(
    sys: &mut dyn Sys,
    view: &View,
    held: &HeldPrimaries,
    rebuilt: &mut Vec<String>,
    unrestored: &mut Vec<String>,
) -> Result<()> {
    let f = view.fabric;
    for wire in view.wires() {
        if !link_exists(sys, &wire)? {
            continue; // an absent wire's legs are not supposed to exist
        }
        let rebuilt_before = rebuilt.len();
        for r in view.class_rows().iter().filter(|r| r.wire == wire) {
            if !leg_absent(sys, &r.ifname, &r.wire, r.vid, unrestored)? {
                continue;
            }
            apply::build_class_leg(sys, view, r)?;
            set_leg_forwarding(sys, view, &r.ifname)?;
            rebuilt.push(rebuilt_line(&r.zone, &r.ifname, &wire));
        }
        for r in &view.gw_rows() {
            if r.migrates() {
                let z = f.zone(&r.zone)?;
                let qos = apply::qos_map(f, z);
                rebuild_bond_ports(
                    sys,
                    view,
                    &wire,
                    &r.zone,
                    &r.ifname,
                    r.vid,
                    &r.ports,
                    &r.home,
                    held.port_for(&r.ifname),
                    &qos,
                    &gw_bond_leg_cidr(view, r)?,
                    rebuilt,
                    unrestored,
                )?;
            } else if r.home == wire {
                if !leg_absent(sys, &r.ifname, &r.home, r.vid, unrestored)? {
                    continue;
                }
                apply::build_gw_vlan_leg(sys, view, r)?;
                set_leg_forwarding(sys, view, &r.ifname)?;
                // The kernel drops the dev-scoped return-path default with its device;
                // `restore_gw_return_defaults` runs later in this same tick and re-adds it.
                rebuilt.push(rebuilt_line(&r.zone, &r.ifname, &wire));
            }
        }
        for r in &view.fallback_rows() {
            let z = f.zone(&r.zone)?;
            let qos = apply::qos_map(f, z);
            let cidr = format!("{}/24", view.segment_addr(z, r.seg));
            // A fallback bond's primary is the prober's too (F20): a wire that re-enumerates
            // is re-added last, and re-asserting the DECLARED home here would undo a move
            // the prober made for cause on the very next USB blip.
            rebuild_bond_ports(
                sys,
                view,
                &wire,
                &r.zone,
                &r.ifname,
                r.vid,
                &r.ports,
                &r.home,
                held.port_for(&r.ifname),
                &qos,
                &cidr,
                rebuilt,
                unrestored,
            )?;
        }
        if rebuilt.len() > rebuilt_before {
            returned_wire(sys, view, &wire, rebuilt, unrestored)?;
        }
    }
    Ok(())
}

/// A wire whose legs had all vanished and were just rebuilt is a wire whose NETDEV returned —
/// a USB adapter re-enumerated, a driver reloaded. Two things follow from it being a *new*
/// netdev, and neither belongs on the ordinary tick (this runs only on the tick that rebuilt
/// a leg, so the steady state stays one `ip link show` per wire and per leg):
///
///   - its `ethtool -K` features are back at the driver's defaults, so a declared
///     `driver_features` string is put in force again — `apply` would have set it, and this
///     restore exists exactly so a returned wire ends up where `apply` would have left it;
///   - it may not be the same ADAPTER. `apply` recorded the driver each wire had; a different
///     one back on the same name is reported (James 2026-09-07) and never silently accepted —
///     the settings this member is about to re-apply were chosen for a different NIC.
///
/// The driver record is deliberately NOT rewritten here: it says what `apply` found, which is
/// what `down`'s restore was computed against.
fn returned_wire(
    sys: &mut dyn Sys,
    view: &View,
    wire: &str,
    rebuilt: &mut Vec<String>,
    unrestored: &mut Vec<String>,
) -> Result<()> {
    let Some(w) = view.member.wire_named(wire) else {
        return Ok(());
    };
    let now = driver_features::driver_of(sys, wire).unwrap_or_default();
    if !now.is_empty()
        && let Some(was) = driver_features::recorded_driver(sys, &view.fabric.run_dir, wire)
        && was != now
    {
        unrestored.push(format!(
            "wire {wire} came back under driver '{now}', not the '{was}' apply recorded — this \
             is a different adapter, check it before trusting its settings"
        ));
    }
    if let Some(spec) = &w.driver_features {
        let mut warnings = Vec::new();
        let changes = driver_features::apply_to_wire(sys, wire, spec, &mut warnings)?;
        rebuilt.push(format!("re-applied driver_features on {wire}: {spec}"));
        unrestored.extend(warnings);
        // A change made HERE is as much cfab's doing as one `up` made, so it goes in the same
        // record — otherwise `down` would put back only what `up` touched and leave this
        // wire's features exactly as the watchdog set them. Merging keeps the prior `up`
        // recorded for a feature already there: that is the value the NIC had before cfab
        // first touched it, not the driver default a re-created netdev came up with.
        if !changes.is_empty()
            && let Err(e) = driver_features::merge_changes(sys, &view.fabric.run_dir, &changes)
        {
            unrestored.push(format!(
                "could not record the driver features re-applied on {wire} ({e}) — `down` will \
                 not put them back"
            ));
        }
    }
    Ok(())
}

fn rebuilt_line(zone: &str, ifname: &str, wire: &str) -> String {
    format!("rebuilt {zone}/{ifname} on {wire}")
}

/// The address a migrating ingress leg's bond carries — the same `leg_cidr` `apply` gives it.
fn gw_bond_leg_cidr(view: &View, r: &crate::derive::GwRow) -> Result<String> {
    let z = view.fabric.zone(&r.zone)?;
    let gw = z.gw.as_ref().expect("gw_rows lists gw zones");
    Ok(gw.leg_cidr(view.node()))
}

/// Whether a leg's netdev is genuinely missing (so it must be rebuilt). A netdev that exists
/// with the wrong kind is NOT missing: it is reported and left exactly where it is.
fn leg_absent(
    sys: &mut dyn Sys,
    ifname: &str,
    lower: &str,
    vid: u16,
    unrestored: &mut Vec<String>,
) -> Result<bool> {
    if !link_exists(sys, ifname)? {
        return Ok(true);
    }
    if !link_kind_is(sys, ifname, &apply::vlan_marker(vid))? {
        unrestored.push(apply::not_our_vlan(ifname, lower, vid));
    }
    Ok(false)
}

/// The declared forwarding flag for one rebuilt leg. `owned_forwarding` is the single place
/// that decides it (a leaf never transits; a host does only under `[forward] enabled`), so a
/// rebuilt leg cannot end up disagreeing with what `apply`'s `enable_forwarding` set. The leg
/// builders leave `forwarding=0` behind them, so this only ever writes on a transiting host.
fn set_leg_forwarding(sys: &mut dyn Sys, view: &View, ifname: &str) -> Result<()> {
    if view
        .owned_forwarding()
        .iter()
        .any(|(n, fwd)| n == ifname && *fwd)
    {
        common::proc_sysctl(sys, ifname, "forwarding", "1")?;
    }
    Ok(())
}

/// The port the ingress prober holds this bond's `primary` on, if it holds one this bond
/// actually has. A held name that is not a port of ours is ignored rather than written: the
/// prober and this function derive their port lists from the same declaration, so a mismatch
/// means one of them is running on a stale view, and writing a stranger into `primary` would
/// take the leg down.
fn want_primary<'a>(ports: &'a [Port], held: Option<&'a str>) -> Option<&'a str> {
    held.filter(|w| ports.iter().any(|s| s.ifname == *w))
}

/// The port carrying the leg's declared home wire — what owns `primary` when nothing else does.
fn home_port_ifname<'a>(ports: &'a [Port], home: &str) -> &'a str {
    ports
        .iter()
        .find(|s| s.wire == home)
        .map(|s| s.ifname.as_str())
        .unwrap_or_default()
}

/// The ports of one bond leg that live on `wire`. `held` is the port the ingress prober is
/// holding this bond's `primary` on, `None` for a leg nothing probes. The bond itself is rebuilt
/// whole when it is
/// the thing that is missing — that should not happen when only a wire re-enumerated, but the
/// invariant is "the declared leg set exists", not "the case we expected".
#[allow(clippy::too_many_arguments)]
fn rebuild_bond_ports(
    sys: &mut dyn Sys,
    view: &View,
    wire: &str,
    zone: &str,
    bond: &str,
    vid: u16,
    ports: &[Port],
    home: &str,
    held: Option<&str>,
    qos: &[String; 2],
    cidr: &str,
    rebuilt: &mut Vec<String>,
    unrestored: &mut Vec<String>,
) -> Result<()> {
    if !ports.iter().any(|s| s.wire == wire) {
        return Ok(());
    }
    let qos: Vec<&str> = qos.iter().map(String::as_str).collect();
    if !link_exists(sys, bond)? {
        // The whole leg is gone: rebuild it through the same builder `apply` uses, which puts
        // every port, the primary, the address and the sysctls back in one go.
        apply::mk_bond_leg(
            sys,
            &apply::BondLeg {
                ifname: bond,
                vid,
                home,
                ports,
                cidr,
            },
            &qos,
        )?;
        set_leg_forwarding(sys, view, bond)?;
        // `mk_bond_leg` set `primary` to the DECLARED home, which is right for a leg nothing
        // probes and wrong for one the ingress prober has moved: the whole bond is new, but the
        // prober's knowledge of which wire the router answers over is not.
        if let Some(w) = want_primary(ports, held) {
            apply::set_bond_primary(sys, bond, w)?;
        }
        rebuilt.push(rebuilt_line(zone, bond, wire));
        return Ok(());
    }
    if !link_kind_is(sys, bond, " bond ")? {
        unrestored.push(apply::not_a_bond(bond));
        return Ok(());
    }
    let want = want_primary(ports, held).unwrap_or(home_port_ifname(ports, home));
    for s in ports.iter().filter(|s| s.wire == wire) {
        if !leg_absent(sys, &s.ifname, &s.wire, vid, unrestored)? {
            continue;
        }
        apply::add_bond_port(sys, bond, s, vid, &qos)?;
        // `primary` names a port, so the kernel dropped it with the netdev: re-assert it when
        // the port we just put back is the one that must own it (`primary_reselect` is already
        // on the bond, and `ip link set … type bond` carries both in one command).
        if s.ifname == want {
            apply::set_bond_primary(sys, bond, &s.ifname)?;
        }
        rebuilt.push(rebuilt_line(zone, &s.ifname, wire));
    }
    Ok(())
}

/// Row 19. The hazard is the FOREIGN port, not the bond: something else added a netdev as a
/// port into a bond cfab created, and traffic cfab believes is on its own wire is on somebody
/// else's. So
/// release the intruder and keep ours running; the bond goes down only if the release fails.
/// `active_slave` is compared against the names cfab itself created — an unreadable `bonding/`
/// file is row 17 (a reason line), never this.
fn restore_bond_membership(
    sys: &mut dyn Sys,
    view: &View,
    restored: &mut Vec<String>,
    downed: &mut Vec<String>,
) -> Result<()> {
    for r in view.fallback_rows() {
        let Ok(active) = sys.read(&format!("/sys/class/net/{}/bonding/active_slave", r.ifname))
        else {
            continue;
        };
        let active = active.trim().to_string();
        if active.is_empty() || r.ports.iter().any(|s| s.ifname == active) {
            continue;
        }
        if sys.run(&["ip", "link", "set", &active, "nomaster"])?.ok() {
            restored.push(format!(
                "{} fallback: released foreign port {active}",
                r.zone
            ));
        } else {
            run_ignore(sys, &["ip", "link", "set", &r.ifname, "down"])?;
            downed.push(format!(
                "{} fallback down: foreign port {active} could not be released",
                r.zone
            ));
        }
    }
    Ok(())
}

/// Tell the engine what cost to advertise this member's transit links at (spec §12 (b)).
/// Returns the error text when the engine would not take it — loud, never fatal: the
/// forwarding flags are the actuator, this is only what the peers are told.
fn ask_transit_cost(sys: &mut dyn Sys, view: &View, at: TransitCost) -> Option<String> {
    let sock = engine_ctl::sock_path(view.fabric);
    let line = format!("transit-cost {}\n", at.word());
    match sys.unix_request(&sock, &line) {
        Ok(reply) if reply.contains("\"error\"") => {
            Some(format!("engine refused {}: {}", line.trim(), reply.trim()))
        }
        Ok(_) => None,
        Err(e) => Some(format!("engine would not take {}: {e}", line.trim())),
    }
}

fn fail_closed(sys: &mut dyn Sys, view: &View, reason: &str) -> Result<WatchdogReport> {
    let present = conf_interfaces(sys)?;
    for (ifn, _) in view.owned_forwarding() {
        if present.contains(&ifn) {
            sys.write(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "0")?;
        }
    }
    // Forwarding is off here, so every packet a peer still sends through this member is a
    // black hole until the peers stop choosing it as transit. Re-advertise at the leaf offset:
    // still reachable, never a path through. A leaf is already offset and is never asked.
    let transit_cost_error = if view.kind() == MemberKind::Host && view.fabric.host_forward {
        ask_transit_cost(sys, view, TransitCost::LeafOffset)
    } else {
        None
    };
    run_ignore(
        sys,
        &[
            "logger",
            "-t",
            "cfab-fwd-watchdog",
            &format!(
                "FAIL-CLOSED: {reason} — forwarding=0 on every cfab interface; re-run cfab up"
            ),
        ],
    )?;
    Ok(WatchdogReport {
        failed: Some(reason.to_string()),
        corrected: Vec::new(),
        blocked: Vec::new(),
        resolved: None,
        restored: Vec::new(),
        downed: Vec::new(),
        unrestored: Vec::new(),
        rebuilt: Vec::new(),
        transit_cost_error,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::decl::Declaration;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn view_fixture() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    /// `nft -j list chains` with only cfab's own tables. `extra` appends a foreign chain.
    fn chains_json(extra: &str) -> String {
        format!(
            r#"{{"nftables":[
              {{"chain":{{"family":"inet","table":"cfab-fwd","name":"forward",
                          "hook":"forward","prio":0,"policy":"drop"}}}}
              {extra}]}}"#
        )
    }

    const DOCKER_FORWARD: &str = r#",
      {"chain":{"family":"ip","table":"filter","name":"FORWARD",
                "hook":"forward","prio":0,"policy":"drop"}}"#;

    fn healthy_sys(view: &View) -> MockSys {
        let mut sys = MockSys::default()
            .socket(
                &engine_ctl::sock_path(view.fabric),
                "{\"transit_cost\":\"normal\"}",
            )
            .on_stdout(
                &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
                "chain forward {\n  type filter hook forward priority filter; policy drop;\n}",
            )
            .on_stdout(&["nft", "-j", "list", "chains"], &chains_json(""));
        for r in view.class_rows() {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                "1\n",
            );
        }
        for r in view.gw_rows() {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                "1\n",
            );
        }
        sys = sys
            .file("/proc/sys/net/ipv4/conf/eth0/forwarding", "0\n")
            .file("/proc/sys/net/ipv4/conf/lo/forwarding", "0\n")
            .file("/proc/sys/net/ipv4/conf/all/forwarding", "1\n");
        // Everything the NEW restores read, healthy: the loose rp_filter cfab owns on every L3
        // leg, every `ip rule` cfab installed, and each bond active on a port of ours.
        for ifname in fabric_legs(view) {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"),
                "2\n",
            );
        }
        // The bonds are transit-eligible like a segment (a fallback leg for one zone can carry
        // another zone's domain-disjoint traffic on a forwarding host).
        for r in view.fallback_rows() {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                "1\n",
            );
        }
        // A healthy gw member's per-zone table holds cfab's return-path default; the restore is
        // then a no-op. A flap test overrides this stub with an empty table.
        for d in common::gw_return_defaults(view) {
            sys = sys.on_stdout(
                &["ip", "route", "show", "table", &d.table, "default"],
                &format!("default via {} dev {} proto cfab-return\n", d.via, d.dev),
            );
        }
        legs_present(rules_present(sys, view), view)
    }

    /// Every declared leg of every declared wire present and of the kind cfab created it with —
    /// the shape a healthy member has, and the baseline the rebuild step must find nothing to do
    /// in. Wires answer `ip link show`; each class leg, gw leg and bond port answers `ip -d link
    /// show` with its vlan marker, each bond with " bond ".
    pub(crate) fn legs_present(mut sys: MockSys, view: &View) -> MockSys {
        let mut vlans: Vec<(String, u16)> = view
            .class_rows()
            .into_iter()
            .map(|r| (r.ifname, r.vid))
            .collect();
        for r in view.gw_rows() {
            if r.migrates() {
                sys = bond_kind(sys, &r.ifname);
                vlans.extend(r.ports.into_iter().map(|s| (s.ifname, r.vid)));
            } else {
                vlans.push((r.ifname, r.vid));
            }
        }
        for r in view.fallback_rows() {
            sys = bond_kind(sys, &r.ifname);
            vlans.extend(r.ports.into_iter().map(|s| (s.ifname, r.vid)));
        }
        for (ifname, vid) in vlans {
            sys = sys.on_stdout(
                &["ip", "-d", "link", "show", &ifname],
                &format!("9: {ifname}: <UP> {} \n", apply::vlan_marker(vid)),
            );
        }
        sys
    }

    fn bond_kind(sys: MockSys, ifname: &str) -> MockSys {
        sys.on_stdout(
            &["ip", "-d", "link", "show", ifname],
            &format!("9: {ifname}: <UP> bond \n"),
        )
    }

    /// `ip rule show pref <p>` answering with every rule cfab declared at that pref.
    fn rules_present(mut sys: MockSys, view: &View) -> MockSys {
        let mut by_pref: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for r in common::leak_guard_rules(view)
            .into_iter()
            .chain(common::return_path_rules(view))
        {
            by_pref
                .entry(r.pref.clone())
                .or_default()
                .push(format!("{}: from all {}\n", r.pref, r.needle));
        }
        for (pref, lines) in by_pref {
            sys = sys.on_stdout(&["ip", "rule", "show", "pref", &pref], &lines.concat());
        }
        for r in view.fallback_rows() {
            let home = r
                .ports
                .iter()
                .find(|s| s.wire == r.home)
                .expect("the home wire is one of the ports");
            sys = sys.file(
                &format!("/sys/class/net/{}/bonding/active_slave", r.ifname),
                &format!("{}\n", home.ifname),
            );
        }
        sys
    }

    #[test]
    fn healthy_posture_passes() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none());
        assert!(report.corrected.is_empty());
        assert!(!sys.ran("logger"));
    }

    #[test]
    fn missing_policy_fails_closed_on_cfab_interfaces_only() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view)
            .file("/proc/sys/net/ipv4/conf/docker0/forwarding", "1\n")
            .on_fail(
                &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
                1,
                "no such table",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(
            report
                .failed
                .as_deref()
                .unwrap_or("")
                .contains("policy drop"),
            "{:?}",
            report.failed
        );
        // cfab's interfaces written to 0; a foreign one and the `all` propagator untouched
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            Some("0")
        );
        // (the mock returns seeded content for an untouched path: "1\n" = never written)
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/all/forwarding"),
            Some("1\n")
        );
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/docker0/forwarding"),
            Some("1\n")
        );
        assert!(sys.ran("logger"));
    }

    #[test]
    fn foreign_forwarder_is_not_ours_to_police() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).file("/proc/sys/net/ipv4/conf/docker0/forwarding", "1\n");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert!(report.corrected.is_empty());
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/docker0/forwarding"),
            Some("1\n")
        );
        assert!(!sys.ran("logger"));
    }

    #[test]
    fn drift_on_own_interface_is_corrected_and_logged() {
        // a foreign `ip_forward=1` propagates 1 onto the admin NIC: write it back, say so, stay up
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).file("/proc/sys/net/ipv4/conf/eth0/forwarding", "1\n");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert_eq!(report.corrected, vec!["eth0 forwarding 1->0".to_string()]);
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/eth0/forwarding"),
            Some("0")
        );
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            Some("1\n")
        );
        assert!(sys.ran("logger"));
    }

    #[test]
    fn a_foreign_forward_drop_is_reported_loudly_and_does_not_fail_closed() {
        // Docker's `ip filter FORWARD` policy DROP kills transit that cfab accepts. Say so --
        // but do not switch our forwarding off: it would not restore a single packet, and
        // availability-first means we never make a foreign breakage worse.
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).on_stdout(
            &["nft", "-j", "list", "chains"],
            &chains_json(DOCKER_FORWARD),
        );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert_eq!(
            report.blocked,
            vec!["ip filter FORWARD (policy drop)".to_string()]
        );
        assert!(sys.ran("logger"));
        // forwarding on a class interface is left exactly as declared
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            Some("1\n")
        );
    }

    /// PROVING existing behavior, not new logic: `owned_forwarding()` (Task 2) already flags
    /// the fallback bond `transit`-eligible like a class segment (a fallback leg for one zone can
    /// carry another zone's domain-disjoint traffic on a forwarding host) — this test exercises
    /// that through the watchdog's own correction path rather than reading `owned_forwarding`
    /// directly, so a regression here fails where it would actually bite in production.
    #[test]
    fn a_fallback_bond_drifted_to_0_is_corrected_to_1_like_a_segment() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        assert!(
            !view.fallback_rows().is_empty(),
            "fixture must carry fallback rows"
        );
        let mut sys = healthy_sys(&view);
        for r in view.fallback_rows() {
            sys = sys.file(
                &format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname),
                "0\n",
            );
        }
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        for r in view.fallback_rows() {
            assert!(
                report
                    .corrected
                    .iter()
                    .any(|c| c.starts_with(&format!("{} forwarding 0->1", r.ifname))),
                "{}: not corrected to 1 like a segment: {:?}",
                r.ifname,
                report.corrected
            );
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname)),
                Some("1")
            );
        }
    }

    /// A fallback port is L2 only (`owned_forwarding` always pairs it with `false`): even if
    /// something turned its forwarding sysctl on, the watchdog writes it back to 0, same as
    /// the admin NIC — it is never flagged transit-eligible the way the bond is.
    #[test]
    fn a_fallback_port_drifted_to_1_is_corrected_to_0_never_flagged_transit() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let port_ifs: Vec<String> = view
            .fallback_rows()
            .into_iter()
            .flat_map(|r| r.ports)
            .map(|s| s.ifname)
            .collect();
        assert!(!port_ifs.is_empty(), "fixture must carry fallback ports");
        let mut sys = healthy_sys(&view);
        for ifn in &port_ifs {
            sys = sys.file(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding"), "1\n");
        }
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        for ifn in &port_ifs {
            assert!(
                report
                    .corrected
                    .iter()
                    .any(|c| c.starts_with(&format!("{ifn} forwarding 1->0"))),
                "{ifn}: port was not corrected back to 0: {:?}",
                report.corrected
            );
            assert_eq!(
                sys.writes_to(&format!("/proc/sys/net/ipv4/conf/{ifn}/forwarding")),
                Some("0")
            );
        }
    }

    /// A leaf environment for the leak guard (row 5) and the rebuild step: pve3-tb, every rule
    /// present and every declared leg present and of cfab's own kind.
    fn healthy_leaf_sys(view: &View) -> MockSys {
        let mut sys = MockSys::default();
        for ifname in fabric_legs(view) {
            sys = sys
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter"),
                    "2\n",
                )
                .file(
                    &format!("/proc/sys/net/ipv4/conf/{ifname}/forwarding"),
                    "0\n",
                );
        }
        legs_present(rules_present(sys, view), view)
    }

    /// Spec §12 (b). Failing closed turns forwarding off, which black-holes anything a peer
    /// still sends through this member — so the same tick tells the engine to re-advertise the
    /// transit links at the leaf offset. A healthy tick asks for the declared cost back: the
    /// request is re-asserted every tick rather than remembered, so no state file can disagree
    /// with what is actually advertised.
    #[test]
    fn failing_closed_re_advertises_at_the_leaf_offset_and_a_healthy_tick_puts_it_back() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let sock = engine_ctl::sock_path(view.fabric);

        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none());
        assert!(
            sys.ran(&format!("unix_request {sock} transit-cost normal")),
            "{:?}",
            sys.calls
        );
        assert_eq!(report.transit_cost_error, None);

        let mut sys = healthy_sys(&view)
            .socket(&sock, "{\"transit_cost\":\"leaf\"}")
            .on_stdout(
                &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
                "chain forward {\n  type filter hook forward priority filter; policy accept;\n}",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_some());
        assert!(
            sys.ran(&format!("unix_request {sock} transit-cost leaf")),
            "{:?}",
            sys.calls
        );
        assert!(
            !sys.ran(&format!("unix_request {sock} transit-cost normal")),
            "{:?}",
            sys.calls
        );
        assert_eq!(report.transit_cost_error, None);
    }

    /// An engine that is not answering must not turn a fail-closed tick into a panic or a
    /// silent success: the forwarding flags still go off, and the undelivered re-advertisement
    /// is named.
    #[test]
    fn an_engine_that_will_not_take_the_re_advertisement_is_loud_not_fatal() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).on_stdout(
            &["nft", "list", "chain", "inet", "cfab-fwd", "forward"],
            "chain forward {\n  type filter hook forward priority filter; policy accept;\n}",
        );
        sys.sockets.clear();
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_some());
        let e = report.transit_cost_error.expect("named");
        assert!(e.contains("transit-cost leaf"), "{e}");
        assert!(
            sys.ran("write /proc/sys/net/ipv4/conf/cfab-st/forwarding"),
            "{:?}",
            sys.calls
        );
    }

    /// A leaf is offset by what it is and never transits: it asks for nothing, in either
    /// direction, so a leaf with no engine socket is not a fail-closed leaf.
    #[test]
    fn a_leaf_never_asks_for_a_transit_cost() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf_sys(&view);
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(report.transit_cost_error, None);
        assert!(
            !sys.calls.iter().any(|c| c.contains("transit-cost")),
            "{:?}",
            sys.calls
        );
    }

    /// Row 4, restore. cfab owns the loose rp_filter, so drift is written back — and nothing is
    /// downed for a condition one idempotent write repairs.
    #[test]
    fn row4_rp_filter_drift_is_written_back_and_downs_nothing() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys =
            healthy_sys(&view).file("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter", "1\n");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(
            report.restored,
            vec!["rp_filter cfab-st-fb 1->2 (want 2 = loose)".to_string()]
        );
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert_eq!(
            sys.writes_to("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter"),
            Some("2")
        );
        assert!(!sys.ran("ip link set"), "{:?}", sys.calls);
    }

    /// Row 4, false-positive guard: a leg that is not there is not ours to create.
    #[test]
    fn row4_leaves_an_absent_leg_alone() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        sys.files
            .remove("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.restored.is_empty(), "{:?}", report.restored);
    }

    /// Row 4, unrestorable. A read-only `/proc` (a container, a hardened host) must not cost
    /// the restores that follow it: the drift is reported loudly and the tick carries on to the
    /// bond and the rules. Availability-first — one stuck sysctl is not a reason to stop
    /// repairing everything else.
    #[test]
    fn row4_an_unwritable_rp_filter_is_loud_and_does_not_abort_the_tick() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view)
            .file("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter", "1\n")
            .write_fail("/proc/sys/net/ipv4/conf/cfab-st-fb/rp_filter")
            .file(
                "/sys/class/net/cfab-cl-fb/bonding/active_slave",
                "someone-elses0\n",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(report.unrestored.len(), 1, "{:?}", report.unrestored);
        assert!(
            report.unrestored[0].starts_with("rp_filter cfab-st-fb=1: could not write 2"),
            "{:?}",
            report.unrestored
        );
        // The bond restore behind it still ran.
        assert_eq!(
            report.restored,
            vec!["cluster fallback: released foreign port someone-elses0".to_string()]
        );
        assert!(report.downed.is_empty(), "{:?}", report.downed);
    }

    /// Ordering: the member-wide amputation runs LAST. With the rules first, an unrestorable
    /// leak guard would down every fabric leg — the bonds included — under a bond restore that
    /// had not been tried yet, and the release would then be attempted on a dead bond.
    #[test]
    fn the_bond_release_is_tried_before_the_member_wide_amputation() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf_sys(&view)
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "someone-elses0\n",
            )
            .on_stdout(&["ip", "rule", "show", "pref", "1001"], "")
            .on_fail(
                &["ip", "rule", "add", "pref", "1001"],
                2,
                "RTNETLINK: EPERM",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(
            report
                .restored
                .contains(&"storage fallback: released foreign port someone-elses0".to_string()),
            "{:?}",
            report.restored
        );
        let release = sys
            .calls
            .iter()
            .position(|c| c == "ip link set someone-elses0 nomaster")
            .expect("the release was attempted");
        let amputation = sys
            .calls
            .iter()
            .position(|c| c == "ip link set cfab-st-fb down")
            .expect("the legs went down");
        assert!(release < amputation, "{:?}", sys.calls);
    }

    /// Row 5, restore. A leaf's leak guard is re-added, and the fabric stays up.
    #[test]
    fn row5_a_missing_leak_guard_is_re_added() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys =
            healthy_leaf_sys(&view).on_stdout(&["ip", "rule", "show", "pref", "1001"], "");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        for blk in ["10.99.0.0/16", "10.199.0.0/16", "10.249.0.0/16"] {
            assert!(
                sys.ran(&format!("ip rule add pref 1001 to {blk} unreachable")),
                "{:?}",
                sys.calls
            );
        }
        assert!(!sys.ran("ip link set"), "restored: nothing to amputate");
    }

    /// Row 5, actuate. The re-add itself fails, so the hazard is member-wide and unrestorable:
    /// every fabric leg goes down and `status` then reads FAILED. This is the arm that proves
    /// the actuator bites — without it "restore first" is just a comment.
    #[test]
    fn row5_an_unrestorable_leak_guard_downs_the_fabric_legs() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf_sys(&view)
            .on_stdout(&["ip", "rule", "show", "pref", "1001"], "")
            .on_fail(
                &["ip", "rule", "add", "pref", "1001"],
                2,
                "RTNETLINK: EPERM",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(report.downed.len(), 1, "{:?}", report.downed);
        assert!(
            report.downed[0].starts_with("fabric legs down: could not restore pref 1001"),
            "{:?}",
            report.downed
        );
        for ifname in fabric_legs(&view) {
            assert!(
                sys.ran(&format!("ip link set {ifname} down")),
                "{ifname} still up: {:?}",
                sys.calls
            );
        }
    }

    /// Row 6, restore then actuate, same pair on the return path.
    #[test]
    fn row6_a_missing_return_path_rule_is_re_added_then_actuated_if_it_cannot_be() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();

        let mut sys = healthy_sys(&view).on_stdout(&["ip", "rule", "show", "pref", "2002"], "");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert!(
            sys.ran("ip rule add pref 2002 from 10.99.0.0/16 unreachable"),
            "{:?}",
            sys.calls
        );
        assert!(!sys.ran("ip link set"));

        let mut sys = healthy_sys(&view)
            .on_stdout(&["ip", "rule", "show", "pref", "2002"], "")
            .on_fail(
                &["ip", "rule", "add", "pref", "2002"],
                2,
                "RTNETLINK: EPERM",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(report.downed.len(), 1, "{:?}", report.downed);
        for ifname in fabric_legs(&view) {
            assert!(sys.ran(&format!("ip link set {ifname} down")), "{ifname}");
        }
    }

    /// Finding C (2026-09-06): after a gw-leg flap the kernel has dropped cfab's return-path
    /// default from the zone's table; the tick must re-add it, and must NOT down anything (a
    /// missing return path is not a member-wide hazard like a missing rule). Its teeth: without
    /// `restore_gw_return_defaults` the `ip route replace` is never issued.
    #[test]
    fn a_flapped_gw_return_default_is_re_added() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let defaults = common::gw_return_defaults(&view);
        assert!(
            !defaults.is_empty(),
            "the fixture member must carry a gw zone for this test to prove anything"
        );
        let d = defaults[0].clone();
        // The leg flapped: the table now has no default (the kernel dropped the dev-scoped route).
        let mut sys = healthy_sys(&view)
            .on_stdout(&["ip", "route", "show", "table", &d.table, "default"], "");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(
            report.downed.is_empty(),
            "a missing return-path default must not down anything: {:?}",
            report.downed
        );
        assert!(
            sys.ran(&format!(
                "ip route replace default via {} dev {} table {} proto 205",
                d.via, d.dev, d.table
            )),
            "{:?}",
            sys.calls
        );
        assert!(
            report
                .restored
                .iter()
                .any(|s| s.contains(&format!("return-path default table {}", d.table))),
            "{:?}",
            report.restored
        );
    }

    /// Best-effort: when the leg is down the re-add fails, and that is neither a fault to report
    /// nor a reason to down a leg — the leg-down is the reported fault and self-resolves on
    /// link-up (the next tick then re-adds the default).
    #[test]
    fn a_gw_return_default_that_cannot_be_re_added_is_silent() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let d = common::gw_return_defaults(&view)[0].clone();
        let mut sys = healthy_sys(&view)
            .on_stdout(&["ip", "route", "show", "table", &d.table, "default"], "")
            .on_fail(
                &["ip", "route", "replace", "default", "via", &d.via],
                2,
                "RTNETLINK: Nexthop device is down",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert!(
            !report
                .restored
                .iter()
                .any(|s| s.contains("return-path default")),
            "a failed re-add must not claim it restored anything: {:?}",
            report.restored
        );
    }

    /// Row 19, restore. The hazard is the foreign port, so the intruder is released and ours
    /// keeps running — the bond is never downed for something an eviction fixes.
    #[test]
    fn row19_a_foreign_active_port_is_released_not_the_bond_downed() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view).file(
            "/sys/class/net/cfab-st-fb/bonding/active_slave",
            "someone-elses0\n",
        );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(
            report.restored,
            vec!["storage fallback: released foreign port someone-elses0".to_string()]
        );
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert!(
            sys.ran("ip link set someone-elses0 nomaster"),
            "{:?}",
            sys.calls
        );
        assert!(
            !sys.ran("ip link set cfab-st-fb down"),
            "the bond must survive the eviction: {:?}",
            sys.calls
        );
    }

    /// Row 19, actuate. The release fails, so the narrowest thing that removes the hazard is
    /// the bond itself — and only the bond.
    #[test]
    fn row19_an_unreleasable_foreign_port_downs_only_that_bond() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view)
            .file(
                "/sys/class/net/cfab-st-fb/bonding/active_slave",
                "someone-elses0\n",
            )
            .on_fail(
                &["ip", "link", "set", "someone-elses0", "nomaster"],
                2,
                "RTNETLINK: EPERM",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(
            report.downed,
            vec![
                "storage fallback down: foreign port someone-elses0 could not be released"
                    .to_string()
            ]
        );
        assert!(sys.ran("ip link set cfab-st-fb down"), "{:?}", sys.calls);
        for other in ["cfab-cl-fb", "cfab-mg-fb", "cfab-st"] {
            assert!(
                !sys.ran(&format!("ip link set {other} down")),
                "{other} was downed for another bond's hazard: {:?}",
                sys.calls
            );
        }
    }

    /// Row 19, false-positive guard: an `active_slave` that IS ours must write nothing at all,
    /// and an unreadable `bonding/` file is row 17 (a reason line in `status`), never this.
    #[test]
    fn row19_leaves_our_own_active_port_and_an_unreadable_file_alone() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.restored.is_empty(), "{:?}", report.restored);
        assert!(!sys.ran("nomaster"), "{:?}", sys.calls);

        let mut sys = healthy_sys(&view);
        for r in view.fallback_rows() {
            sys.files
                .remove(&format!("/sys/class/net/{}/bonding/active_slave", r.ifname));
        }
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.restored.is_empty(), "{:?}", report.restored);
        assert!(report.downed.is_empty(), "{:?}", report.downed);
        assert!(!sys.ran("nomaster"), "{:?}", sys.calls);
    }

    /// A leaf loads no forward policy and never transits, so asking it for `policy drop` would
    /// fail it closed on a posture it is not supposed to have. It must still get its restores.
    #[test]
    fn a_leaf_is_not_failed_closed_for_having_no_forward_policy() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = healthy_leaf_sys(&view);
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.failed.is_none(), "{:?}", report.failed);
        assert!(
            !sys.ran("nft list chain inet cfab-fwd"),
            "a leaf's posture is not a transit posture: {:?}",
            sys.calls
        );
    }

    /// The wire `eth9` present but every leg on it gone — a USB NIC that re-enumerated with a
    /// new ifindex, which takes every sub-interface and bond port stacked on it with it. The
    /// watchdog must put back exactly what `apply` built: three class legs (created with the
    /// egress-qos map, addressed, up, segment sysctls, then forwarding=1 because this host
    /// transits) and three fallback-bond ports (created DOWN and address-less, added,
    /// brought up, forwarding=0) — with `primary` re-asserted on the ONE bond whose home wire
    /// is eth9. Argv by argv, so it cannot drift from `apply`'s pinned sequence.
    #[test]
    fn a_re_enumerated_wires_legs_are_rebuilt_exactly_as_apply_built_them() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wire_legs_missing(healthy_sys(&view), &view, "eth9");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(
            calls_naming(&sys, &["cfab-st", "cfab-st-fb-a"]),
            [
                // `leg_absent` probes once, then mk_vlan twice (kind-check, then create)
                "ip link show cfab-st",
                "ip link show cfab-st",
                "ip link show cfab-st",
                "ip link add link eth9 name cfab-st type vlan id 100 egress-qos-map 0:0 6:6",
                "ip addr replace 10.99.1.1/24 dev cfab-st",
                "ip link set cfab-st up",
                "write /proc/sys/net/ipv4/conf/cfab-st/arp_ignore",
                "write /proc/sys/net/ipv4/conf/cfab-st/rp_filter",
                "write /proc/sys/net/ipv4/conf/cfab-st/send_redirects",
                "write /proc/sys/net/ipv4/conf/cfab-st/forwarding",
                // ...then forwarding=1, because `[forward] enabled`=1 on this member
                "write /proc/sys/net/ipv4/conf/cfab-st/forwarding",
                // the storage fallback bond's port on eth9, which is that bond's home wire
                "ip link show cfab-st-fb-a",
                "ip link show cfab-st-fb-a",
                "ip link show cfab-st-fb-a",
                "ip link add link eth9 name cfab-st-fb-a type vlan id 300 egress-qos-map 0:0 6:6",
                "ip link set cfab-st-fb-a master cfab-st-fb",
                "ip link set cfab-st-fb-a up",
                "write /proc/sys/net/ipv4/conf/cfab-st-fb-a/forwarding",
                "ip link set cfab-st-fb type bond primary cfab-st-fb-a primary_reselect always",
            ]
        );
        assert_eq!(
            report.rebuilt,
            [
                "rebuilt storage/cfab-st on eth9",
                "rebuilt cluster/cfab-cl-bk on eth9",
                "rebuilt mgmt/cfab-mg-b2 on eth9",
                // the migrating ingress leg's port on this wire, rebuilt like any other
                "rebuilt mgmt/cfab-gw249-a on eth9",
                "rebuilt storage/cfab-st-fb-a on eth9",
                "rebuilt cluster/cfab-cl-fb-a on eth9",
                "rebuilt mgmt/cfab-mg-fb-a on eth9",
            ]
        );
        assert!(report.unrestored.is_empty(), "{:?}", report.unrestored);
        // Only eth9's bond takes a new primary: cl and mg are homed on other wires and their
        // port there never went away.
        assert_eq!(
            calls_for(&sys, "primary"),
            ["ip link set cfab-st-fb type bond primary cfab-st-fb-a primary_reselect always"]
        );
    }

    /// F21: the prober moves the ingress bond off a wire the router cannot be reached over, and
    /// `primary` is what makes that move survive the next link event. So a rebuild triggered by
    /// an unrelated blip on ANOTHER wire must re-assert the port the PROBER holds — writing the
    /// declared home instead would hand ingress straight back to the dead wire.
    #[test]
    fn a_rebuild_re_asserts_the_primary_the_ingress_prober_holds() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        // mgmt's primary domain is c, so the ingress leg's declared home is the eth0 port.
        // The prober has moved the bond to eth9's port for cause.
        let mut held = HeldPrimaries::default();
        held.hold("cfab-gw249", "cfab-gw249-a");
        let mut sys = wire_legs_missing(healthy_sys(&view), &view, "eth9");
        let report = run(&mut sys, &view, &held).unwrap();
        assert!(
            report
                .rebuilt
                .contains(&"rebuilt mgmt/cfab-gw249-a on eth9".to_string()),
            "{:?}",
            report.rebuilt
        );
        assert!(
            calls_for(&sys, "primary").contains(
                &"ip link set cfab-gw249 type bond primary cfab-gw249-a primary_reselect always"
                    .to_string()
            ),
            "the rebuild must put primary back on the port the prober holds: {:?}",
            calls_for(&sys, "primary")
        );
        assert!(
            !calls_for(&sys, "primary")
                .iter()
                .any(|c| c.contains("cfab-gw249 type bond primary cfab-gw249-c")),
            "and never on the declared home while the prober holds another: {:?}",
            calls_for(&sys, "primary")
        );
    }

    /// F20, the same rule on a fallback bond: a USB wire that re-enumerates is re-added
    /// LAST, so the bond's backup order is join order and the prober will have moved it to
    /// the preferred wire. Re-asserting the DECLARED home on the rebuild would undo that move
    /// on every blip — which is how a 1G island came to carry a fallback segment while the 5G
    /// one sat idle (pve1/pve2, 2026-09-07).
    #[test]
    fn a_rebuild_re_asserts_the_primary_the_prober_holds_on_a_fallback_bond_too() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        // storage's fallback bond is homed on eth9 (island a). The prober has moved it to
        // eth1's port for cause, and eth1 is the wire that re-enumerates.
        let mut held = HeldPrimaries::default();
        held.hold("cfab-st-fb", "cfab-st-fb-b");
        let mut sys = wire_legs_missing(healthy_sys(&view), &view, "eth1");
        let report = run(&mut sys, &view, &held).unwrap();
        assert!(
            report
                .rebuilt
                .contains(&"rebuilt storage/cfab-st-fb-b on eth1".to_string()),
            "{:?}",
            report.rebuilt
        );
        assert!(
            calls_for(&sys, "primary").contains(
                &"ip link set cfab-st-fb type bond primary cfab-st-fb-b primary_reselect always"
                    .to_string()
            ),
            "the rebuild must put primary back on the port the prober holds: {:?}",
            calls_for(&sys, "primary")
        );
        assert!(
            !calls_for(&sys, "primary")
                .iter()
                .any(|c| c.contains("cfab-st-fb type bond primary cfab-st-fb-a")),
            "and never on the declared home while the prober holds another: {:?}",
            calls_for(&sys, "primary")
        );
    }

    /// The example with `driver_features` on every member's eth9.
    fn fixture_with_driver_features() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap()
                .replace(
                    "domain = \"a\", speed_mbps = 5000 },",
                    "domain = \"a\", speed_mbps = 5000, driver_features = \"sg off\" },",
                );
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    /// A returned netdev comes up at the driver's defaults, so the declared `driver_features`
    /// go back on with the legs — otherwise a re-enumerated USB NIC silently runs with the
    /// scatter-gather that was turned off for it, and only a reload would put it back.
    #[test]
    fn a_returned_wire_gets_its_declared_driver_features_back() {
        let f = fixture_with_driver_features();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wire_legs_missing(healthy_sys(&view), &view, "eth9")
            .on_stdout(&["ethtool", "-i", "eth9"], "driver: r8152\n")
            .on_stdout(
                &["ethtool", "-k", "eth9"],
                "Features for eth9:\nscatter-gather: on\n",
            )
            .file("/run/cfab/wire-drivers", "eth9 r8152\n");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(calls_for(&sys, "ethtool -K"), ["ethtool -K eth9 sg off"]);
        assert!(
            report
                .rebuilt
                .contains(&"re-applied driver_features on eth9: sg off".to_string()),
            "{:?}",
            report.rebuilt
        );
        assert!(
            report.unrestored.is_empty(),
            "the same driver is not a finding: {:?}",
            report.unrestored
        );
    }

    /// A change the watchdog made must reach the record, or the operator's NIC keeps cfab's
    /// settings after `cfab down`. Proved end to end through the very function `down` calls:
    /// the watchdog re-applies, then `driver_features::restore` — `down`'s own restore step —
    /// puts it back on the same `Sys`.
    #[test]
    fn a_driver_feature_the_watchdog_re_applied_is_restored_by_down() {
        let f = fixture_with_driver_features();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wire_legs_missing(healthy_sys(&view), &view, "eth9")
            .on_stdout(&["ethtool", "-i", "eth9"], "driver: r8152\n")
            .on_stdout(
                &["ethtool", "-k", "eth9"],
                "Features for eth9:\nscatter-gather: on\n",
            )
            .file("/run/cfab/wire-drivers", "eth9 r8152\n");
        run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(
            sys.writes_to("/run/cfab/wire-driver-features"),
            Some("eth9 sg on\n"),
            "the watchdog's change reached the record"
        );
        let calls_before = sys.calls.len();
        let notes = driver_features::restore(&mut sys, &view.fabric.run_dir);
        assert_eq!(
            sys.calls[calls_before..],
            ["ethtool -K eth9 sg on".to_string()]
        );
        assert_eq!(notes, ["note: driver features put back on eth9: sg on"]);
    }

    /// The prior `up` recorded survives a watchdog re-apply: `down` owes the operator the
    /// value the NIC had before cfab touched it, not the driver default the returned netdev
    /// came up with.
    #[test]
    fn a_re_apply_keeps_the_prior_up_recorded() {
        let f = fixture_with_driver_features();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wire_legs_missing(healthy_sys(&view), &view, "eth9")
            .on_stdout(&["ethtool", "-i", "eth9"], "driver: r8152\n")
            .on_stdout(
                &["ethtool", "-k", "eth9"],
                "Features for eth9:\nscatter-gather: on\n",
            )
            .file("/run/cfab/wire-drivers", "eth9 r8152\n")
            // `up` found sg OFF on this NIC and turned it on... then the wire re-enumerated
            // with the driver default (on) and the watchdog set it off again.
            .file("/run/cfab/wire-driver-features", "eth9 sg off\n");
        run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(
            sys.ran("write /run/cfab/wire-driver-features"),
            "the record was rewritten, not merely left alone: {:?}",
            sys.calls
        );
        assert_eq!(
            sys.writes_to("/run/cfab/wire-driver-features"),
            Some("eth9 sg off\n"),
            "the original prior stands"
        );
    }

    /// James 2026-09-07: a wire that comes back under a DIFFERENT driver is a different
    /// adapter wearing the same name. Loud (journal + the report `status` reads), never
    /// silently accepted — the features about to be re-applied were chosen for the old NIC.
    #[test]
    fn a_wire_that_returns_under_a_different_driver_is_reported() {
        let f = fixture_with_driver_features();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wire_legs_missing(healthy_sys(&view), &view, "eth9")
            .on_stdout(&["ethtool", "-i", "eth9"], "driver: cdc_ncm\n")
            .on_stdout(
                &["ethtool", "-k", "eth9"],
                "Features for eth9:\nscatter-gather: on\n",
            )
            .file("/run/cfab/wire-drivers", "eth9 r8152\n");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(
            report.unrestored,
            [
                "wire eth9 came back under driver 'cdc_ncm', not the 'r8152' apply recorded — \
                 this is a different adapter, check it before trusting its settings"
            ]
        );
        // Reported AND still put in the declared state: a warning is not a reason to leave the
        // NIC at defaults.
        assert_eq!(calls_for(&sys, "ethtool -K"), ["ethtool -K eth9 sg off"]);
        // The journal carries it, like every other watchdog finding.
        assert!(
            sys.ran("logger -t cfab-fwd-watchdog wire eth9 came back under driver"),
            "{:?}",
            sys.calls
        );
    }

    /// The ordinary tick asks ethtool nothing: the driver comparison and the feature re-apply
    /// happen only on the tick that rebuilt a leg, so the steady state stays as cheap as it was.
    #[test]
    fn a_tick_that_rebuilds_nothing_runs_no_ethtool() {
        let f = fixture_with_driver_features();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.rebuilt.is_empty(), "{:?}", report.rebuilt);
        assert!(!sys.ran("ethtool"), "{:?}", sys.calls);
    }

    /// A wire with no `driver_features` and no driver record (an older run dir) returns with
    /// no ethtool traffic beyond the one `-i` probe and no finding.
    #[test]
    fn a_returned_wire_with_nothing_declared_only_probes_the_driver() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = wire_legs_missing(healthy_sys(&view), &view, "eth9")
            .on_stdout(&["ethtool", "-i", "eth9"], "driver: igb\n");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(calls_for(&sys, "ethtool"), ["ethtool -i eth9"]);
        assert!(report.unrestored.is_empty(), "{:?}", report.unrestored);
    }

    /// A leaf rebuilds the same legs, and `forwarding` stays 0 on every one of them: a leaf
    /// never transits, so `owned_forwarding` says false and the leg builders' own zero is the
    /// last word. The one write per class leg is `class_sysctls`'s.
    #[test]
    fn a_leaf_rebuilds_its_legs_and_never_raises_forwarding() {
        let f = view_fixture();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut sys = wire_legs_missing(healthy_leaf_sys(&view), &view, "eth9");
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert_eq!(
            calls_naming(&sys, &["cfab-st"]),
            [
                "ip link show cfab-st",
                "ip link show cfab-st",
                "ip link show cfab-st",
                "ip link add link eth9 name cfab-st type vlan id 100 egress-qos-map 0:0 6:6",
                "ip addr replace 10.99.1.3/24 dev cfab-st",
                "ip link set cfab-st up",
                "write /proc/sys/net/ipv4/conf/cfab-st/arp_ignore",
                "write /proc/sys/net/ipv4/conf/cfab-st/rp_filter",
                "write /proc/sys/net/ipv4/conf/cfab-st/send_redirects",
                "write /proc/sys/net/ipv4/conf/cfab-st/forwarding",
            ]
        );
        assert_eq!(report.rebuilt.len(), 6, "{:?}", report.rebuilt);
        for r in view.class_rows() {
            let path = format!("/proc/sys/net/ipv4/conf/{}/forwarding", r.ifname);
            assert_eq!(
                sys.writes_to(&path).map(str::trim),
                Some("0"),
                "{} forwards on a leaf",
                r.ifname
            );
        }
    }

    /// The ordinary tick — the one that runs every few seconds on every member. Nothing is
    /// missing, so the rebuild step must create NO netdev and write NO leg sysctl at all: it
    /// is one `ip link show` per wire and per leg and nothing else.
    #[test]
    fn a_tick_with_nothing_missing_creates_nothing() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.rebuilt.is_empty(), "{:?}", report.rebuilt);
        assert!(report.unrestored.is_empty(), "{:?}", report.unrestored);
        for c in &sys.calls {
            assert!(!c.starts_with("ip link add"), "{c}");
            assert!(!c.starts_with("ip link set"), "{c}");
            assert!(!c.starts_with("ip addr"), "{c}");
            assert!(!c.starts_with("write /proc/sys"), "{c}");
        }
    }

    /// A netdev holding a leg's name but of another kind: the watchdog reports it in cfab's own
    /// wording and does not delete it. `apply` deletes a stray vlan and refuses a stray bond,
    /// but a three-second tick has no business destroying a live netdev — so the leg stays
    /// unbuilt, loudly, and `status` keeps saying so.
    #[test]
    fn a_leg_of_the_wrong_kind_is_reported_and_never_deleted() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view)
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-st"],
                "9: cfab-st: bridge \n",
            )
            .on_stdout(
                &["ip", "-d", "link", "show", "cfab-cl-fb"],
                "9: cfab-cl-fb: bridge \n",
            );
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.rebuilt.is_empty(), "{:?}", report.rebuilt);
        assert!(
            report
                .unrestored
                .contains(&apply::not_our_vlan("cfab-st", "eth9", 100)),
            "{:?}",
            report.unrestored
        );
        assert!(
            report.unrestored.contains(&apply::not_a_bond("cfab-cl-fb")),
            "{:?}",
            report.unrestored
        );
        for c in &sys.calls {
            assert!(!c.starts_with("ip link del"), "{c}");
            assert!(!c.starts_with("ip link add"), "{c}");
        }
    }

    /// Every declared leg of `wire` absent, the wire itself still present: the exact shape a
    /// re-enumerated NIC leaves behind. Legs on the other wires are untouched.
    fn wire_legs_missing(mut sys: MockSys, view: &View, wire: &str) -> MockSys {
        for ifname in legs_on(view, wire) {
            sys = sys.on_fail(&["ip", "link", "show", &ifname], 1, "Device does not exist");
        }
        sys
    }

    /// The leg netdevs `apply` builds on one wire: its class segments, its bond ports, and a
    /// non-migrating ingress leg homed there.
    fn legs_on(view: &View, wire: &str) -> Vec<String> {
        let mut out: Vec<String> = view
            .class_rows()
            .into_iter()
            .filter(|r| r.wire == wire)
            .map(|r| r.ifname)
            .collect();
        for r in view.gw_rows() {
            if r.migrates() {
                out.extend(
                    r.ports
                        .into_iter()
                        .filter(|s| s.wire == wire)
                        .map(|s| s.ifname),
                );
            } else if r.home == wire {
                out.push(r.ifname);
            }
        }
        for r in view.fallback_rows() {
            out.extend(
                r.ports
                    .into_iter()
                    .filter(|s| s.wire == wire)
                    .map(|s| s.ifname),
            );
        }
        out
    }

    fn calls_for(sys: &MockSys, needle: &str) -> Vec<String> {
        sys.calls
            .iter()
            .filter(|c| c.contains(needle))
            .cloned()
            .collect()
    }

    /// Calls naming exactly one of these devices (token equality: `cfab-st` never matches
    /// `cfab-st-fb-a`), and writes to their `/proc/sys/net/ipv4/conf/<dev>/…`. The journal lines
    /// are left out — the report's own `rebuilt` list is what pins those.
    fn calls_naming(sys: &MockSys, devs: &[&str]) -> Vec<String> {
        sys.calls
            .iter()
            .filter(|c| !c.starts_with("logger"))
            .filter(|c| {
                c.split(|ch: char| ch.is_whitespace() || ch == '/')
                    .any(|t| devs.contains(&t))
            })
            .cloned()
            .collect()
    }

    #[test]
    fn a_healthy_host_reports_nothing_blocked() {
        let f = view_fixture();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut sys = healthy_sys(&view);
        let report = run(&mut sys, &view, &HeldPrimaries::default()).unwrap();
        assert!(report.blocked.is_empty(), "{:?}", report.blocked);
    }
}
