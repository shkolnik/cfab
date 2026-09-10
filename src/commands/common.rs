//! Helpers shared by the imperative commands (up/down/status/daemons).

use crate::derive::View;
use crate::error::{Error, Result};
use crate::sys::{Sys, have_tool, run_ignore, run_ok, run_optional};

/// The kernel routing table holding cfab's additive host default (spec §6). One route lives
/// in it — the default through the mgmt gateway — and rule 2101 is the only thing that looks
/// it up. cfab always addresses it by this NUMBER; `HOST_DEFAULT_TABLE_NAME` is what the
/// packaged `rt_tables.d` fragment calls it, which is how `ip route show` and `ip rule show`
/// render it on a host that has the package installed and not on one that does not.
pub const HOST_DEFAULT_TABLE: &str = "250";

/// The name the packaged iproute2 fragment gives `HOST_DEFAULT_TABLE`.
pub const HOST_DEFAULT_TABLE_NAME: &str = "cfab-default";

/// One `ip rule` cfab owns: the pref it lives at, the substring that proves it is present, and
/// the `ip rule add` tail that creates it. One definition, two consumers — `up` installs them
/// and the watchdog restores them, and a rule whose two spellings drift is a rule the watchdog
/// re-adds forever or never notices at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricRule {
    pub pref: String,
    pub needle: String,
    pub add: Vec<String>,
}

impl FabricRule {
    fn new(pref: &str, needle: String, add: &[&str]) -> Self {
        FabricRule {
            pref: pref.to_string(),
            needle,
            add: add.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Pref-2000 siblings (spec §5 item 4): fabric-sourced traffic to a workload prefix leaves via
/// main on every member and leaf, before the 2001 per-zone table catches it. One per (allowed
/// zone, workload), fabric-wide: leaves need it too, to answer `ip route get <vm> from
/// <identity>`. Tail-only `.add`, the same convention every other rule in this file uses:
/// `return_path_rules` splices this function's own output (never re-formats the same needle
/// itself), and teardown passes `.add` straight to `drop_rules`, which prepends `ip rule del
/// pref <pref>` itself — one `FabricRule` shape, one place that decides which (zone, workload)
/// pairs get a sibling.
pub fn workload_return_rules(view: &View) -> Vec<FabricRule> {
    let mut out = Vec::new();
    for z in &view.fabric.zones {
        let blk = format!("{}.0.0/16", z.block());
        for w in view
            .fabric
            .workloads
            .iter()
            .filter(|w| w.allow.iter().any(|a| a == &z.name))
        {
            let prefix = w.prefix.to_string();
            out.push(FabricRule::new(
                "2000",
                format!("from {blk} to {prefix} lookup main"),
                &["from", &blk, "to", &prefix, "lookup", "main"],
            ));
        }
    }
    out
}

/// The leaf leak guard: a fabric block is looked up in main ONLY when locally originated;
/// anything arriving on another interface bound for a fabric block is refused. Leaf only.
pub fn leak_guard_rules(view: &View) -> Vec<FabricRule> {
    let mut out = Vec::new();
    for z in &view.fabric.zones {
        let blk = format!("{}.0.0/16", z.block());
        out.push(FabricRule::new(
            "1000",
            format!("to {blk} iif lo lookup main"),
            &["to", &blk, "iif", "lo", "lookup", "main"],
        ));
        out.push(FabricRule::new(
            "1001",
            format!("to {blk} unreachable"),
            &["to", &blk, "unreachable"],
        ));
    }
    out
}

/// Return path per zone: identity-sourced traffic never leaves untagged. Uniform on both kinds:
/// on a leaf (and for any zone without a gw) no table-<id> exists, so 2001 matches nothing and
/// 2002 answers a reply bound off-fabric with a local `unreachable`. That is the intended end of
/// the unsupported path "reach a leaf from outside at a fabric identity" (James 2026-09-06): the
/// outside reaches a leaf at the leaf's own addresses; only members use its identities.
pub fn return_path_rules(view: &View) -> Vec<FabricRule> {
    let mut out = Vec::new();
    // Fabric-wide, computed once: `workload_return_rules` is the one place that decides which
    // (zone, workload) pairs get a pref-2000 sibling, so this splices its own output rather
    // than re-formatting the same needle a second time.
    let siblings = workload_return_rules(view);
    for z in &view.fabric.zones {
        let blk = format!("{}.0.0/16", z.block());
        let id = z.id.to_string();
        out.push(FabricRule::new(
            "2000",
            format!("from {blk} to {blk} lookup main suppress_prefixlength 0"),
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
        ));
        // The sibling: fabric-sourced traffic bound for a workload this zone may reach leaves
        // via main too, before it can fall through to this zone's 2001/2002 pair below.
        out.extend(
            siblings
                .iter()
                .filter(|r| r.needle.starts_with(&format!("from {blk} to ")))
                .cloned(),
        );
        // The substring "lookup <id>" is unique within this pref's rules.
        out.push(FabricRule::new(
            "2001",
            format!("from {blk} lookup {id}"),
            &["from", &blk, "lookup", &id],
        ));
        out.push(FabricRule::new(
            "2002",
            format!("from {blk} unreachable"),
            &["from", &blk, "unreachable"],
        ));
    }
    out
}

/// cfab's own gw-zone return-path default: `default via <router> dev <leg> table <id> proto
/// 205`, one per gw zone this member carries. A reply sourced from a fabric identity is sent to
/// the zone's table by return-path rule 2001; this default is that table's only exit, so without
/// it the reply hits rule 2002 (`unreachable`) and an off-fabric ingress client is black-holed.
///
/// `up`/apply install it when the leg is built; the watchdog restores it after a gw-leg flap.
/// The kernel deletes a dev-scoped route when its device goes down and never re-adds it on
/// link-up, so a single leg flap otherwise black-holes ingress until the next reapply (measured
/// on the pve3 fixture, 2026-09-06). One definition, two consumers, so the installed and restored
/// spellings cannot drift (cf. `FabricRule`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GwReturnDefault {
    pub table: String,
    pub via: String,
    pub dev: String,
}

impl GwReturnDefault {
    fn argv(&self, verb: &str) -> Vec<String> {
        [
            "ip",
            "route",
            verb,
            "default",
            "via",
            &self.via,
            "dev",
            &self.dev,
            "table",
            &self.table,
            "proto",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(std::iter::once(crate::emit::engine::CFAB_PROTO.to_string()))
        .collect()
    }

    /// Whether the table already holds a default via our router.
    pub fn present(&self, sys: &mut dyn Sys) -> Result<bool> {
        Ok(sys
            .run(&["ip", "route", "show", "table", &self.table, "default"])?
            .stdout
            .contains(&format!("default via {}", self.via)))
    }

    /// Unconditional install (`up`/apply): `ip route replace` is idempotent by itself.
    pub fn install(&self, sys: &mut dyn Sys) -> Result<()> {
        let owned = self.argv("replace");
        let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
        run_ok(sys, &argv)?;
        Ok(())
    }
}

/// The gw-zone return-path defaults this member carries, one per gw zone. Empty on a member with
/// no ingress leg. Built from the same `gw_rows`/zone/gw data `up` installs from.
pub fn gw_return_defaults(view: &View) -> Vec<GwReturnDefault> {
    let f = view.fabric;
    view.gw_rows()
        .into_iter()
        .filter_map(|r| {
            let z = f.zone(&r.zone).ok()?;
            let gw = z.gw.as_ref()?;
            Some(GwReturnDefault {
                table: z.id.to_string(),
                via: gw.router.clone(),
                dev: r.ifname,
            })
        })
        .collect()
}

/// cfab's additive host default (spec §6): `default via <the gw zone's router> dev <the gw leg>
/// src <this member's own address on that leg> table 250 proto 206`.
///
/// Locally originated traffic with no more specific route in main reaches it through the rules
/// `host_default_rules` builds; everything else is untouched. That is what "additive" means
/// here: the ifupdown default in main is never modified or removed, and with cfab gone — table
/// 250 empty, the rules dropped — the kernel's own final `32766 from all lookup main` finds it
/// exactly as it did before cfab ran.
///
/// One definition, four consumers (`up` installs it, the reconcile installs and withdraws it,
/// `down` deletes it, `status` reads it), so the spellings cannot drift — the same reason
/// `GwReturnDefault` next door is a type and not four `format!` sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDefault {
    pub table: String,
    pub via: String,
    pub dev: String,
    pub src: String,
}

impl HostDefault {
    fn argv(&self, verb: &str) -> Vec<String> {
        [
            "ip",
            "route",
            verb,
            "default",
            "via",
            &self.via,
            "dev",
            &self.dev,
            "src",
            &self.src,
            "table",
            &self.table,
            "proto",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(std::iter::once(
            crate::emit::engine::CFAB_DEFAULT_PROTO.to_string(),
        ))
        .collect()
    }

    /// Whether table 250 already holds our default.
    pub fn present(&self, sys: &mut dyn Sys) -> Result<bool> {
        Ok(sys
            .run(&["ip", "route", "show", "table", &self.table, "default"])?
            .stdout
            .contains(&format!("default via {}", self.via)))
    }

    /// Install it. `ip route replace` is idempotent by itself.
    pub fn install(&self, sys: &mut dyn Sys) -> Result<()> {
        let owned = self.argv("replace");
        let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
        run_ok(sys, &argv)?;
        Ok(())
    }

    /// Delete it by its exact key — prefix, via, dev, src, table and proto, never a flush of
    /// table 250 — and say nothing when it is not there. Idempotent AND loud: a delete that
    /// runs and fails is an error, a delete of a route that is already gone is not.
    pub fn withdraw(&self, sys: &mut dyn Sys) -> Result<()> {
        if !self.present(sys)? {
            return Ok(());
        }
        let owned = self.argv("del");
        let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
        run_ok(sys, &argv)?;
        Ok(())
    }
}

/// This member's additive host default, or `None` on a member with no gw zone (every leaf, and
/// any host whose zones declare no `gw`) — which installs nothing at all, route or rules.
///
/// Table 250 holds exactly one route, so with more than one gw zone the FIRST in `[[zone]]`
/// order owns it; the same total order `gw_rows` already publishes.
pub fn host_default(view: &View) -> Option<HostDefault> {
    let r = view.gw_rows().into_iter().next()?;
    let z = view.fabric.zone(&r.zone).ok()?;
    let gw = z.gw.as_ref()?;
    let cidr = gw.leg_cidr(view.node());
    Some(HostDefault {
        table: HOST_DEFAULT_TABLE.to_string(),
        via: gw.router.clone(),
        dev: r.ifname,
        src: cidr.split('/').next()?.to_string(),
    })
}

/// One pref-2099 rule: an address of the floor device keeps its own locally originated traffic
/// on main. Replies of an admin-sourced session (ssh from off-subnet, the Proxmox UI) would
/// otherwise leave over the fabric gateway and read as asymmetric at a zone-based firewall.
fn floor_rule(addr: &str) -> FabricRule {
    FabricRule::new(
        "2099",
        format!("from {addr} iif lo lookup main"),
        &["from", addr, "iif", "lo", "lookup", "main"],
    )
}

/// The three rules the host default rides on (spec §6, ruling 4), in install order: 2099 per
/// floor address, then 2100, then 2101. Empty on a member with no gw zone.
///
/// 2100 and 2101 are the wg-quick pattern: `suppress_prefixlength 0` makes the main lookup skip
/// its own default (and only its default — every connected and more specific route still wins),
/// and 2101 then finds ours. `iif lo` scopes both to locally originated traffic, so a VM's
/// packet to an undeclared destination still meets the forward chain instead of taking the
/// host's fabric default, and a leaf's reply to a VM does too.
pub fn host_default_rules(view: &View, floor_addrs: &[String]) -> Vec<FabricRule> {
    if host_default(view).is_none() {
        return Vec::new();
    }
    let mut out: Vec<FabricRule> = floor_addrs.iter().map(|a| floor_rule(a)).collect();
    out.extend(lookup_rules());
    out
}

/// The two rules that reach table 250, in install order. They depend on nothing this host has
/// read, which is why the teardown can drop them without a declaration.
fn lookup_rules() -> [FabricRule; 2] {
    [
        FabricRule::new(
            "2100",
            "from all iif lo lookup main suppress_prefixlength 0".to_string(),
            &[
                "from",
                "all",
                "iif",
                "lo",
                "lookup",
                "main",
                "suppress_prefixlength",
                "0",
            ],
        ),
        // The needle stops before the table on purpose: `ip rule show` renders a table by its
        // rt_tables name where one exists, so this rule reads `lookup cfab-default` on a host
        // carrying the package's fragment and `lookup 250` on one without it. The selector
        // alone is unique within pref 2101, which cfab is the only writer of, and the `del`
        // argv is still the exact rule.
        FabricRule::new(
            "2101",
            "from all iif lo".to_string(),
            &["from", "all", "iif", "lo", "lookup", HOST_DEFAULT_TABLE],
        ),
    ]
}

/// The host's own default route — the floor cfab adds to and never removes (spec §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorDefault {
    pub via: String,
    /// The device it leaves by: on the homelab a host-owned bridge cfab never names, which is
    /// why this is read from the kernel rather than derived from the declaration.
    pub dev: String,
}

/// Route protocols that are cfab's own or its engine's, by name and by number. A default
/// carrying one of them is never the floor: 201..206 is the engine's range plus cfab's two own
/// ids, and 110 / `ospf` covers a host running someone else's OSPF at the conventional id.
fn is_fabric_proto(tok: &str) -> bool {
    const NAMES: &[&str] = &[
        "ospf",
        "cfab-ospf",
        "cfab-static",
        "cfab-bgp",
        "cfab-other",
        "cfab-return",
        "cfab-default",
    ];
    if NAMES.contains(&tok) {
        return true;
    }
    match tok.parse::<u16>() {
        Ok(110) => true,
        Ok(n) => (u16::from(crate::emit::engine::PROTO_BASE)
            ..=u16::from(crate::emit::engine::CFAB_DEFAULT_PROTO))
            .contains(&n),
        Err(_) => false,
    }
}

/// The floor default in `ip route show table main default`, or `None` when every default there
/// is one cfab or its engine installed (and when there is none at all).
///
/// ifupdown's `gateway` line writes `RTPROT_BOOT`, which iproute2 renders by printing no `proto`
/// word at all; a DHCP client writes `proto dhcp`. Both are floors. A `dead linkdown` floor is
/// still the floor — its device still carries the host's admin addresses, which is what pref
/// 2099 is about. With more than one floor default the first line wins.
fn parse_floor_default(stdout: &str) -> Option<FloorDefault> {
    for line in stdout.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        if w.first() != Some(&"default") {
            continue;
        }
        let after = |key: &str| {
            w.iter()
                .position(|t| *t == key)
                .and_then(|i| w.get(i + 1))
                .map(|s| (*s).to_string())
        };
        if after("proto").is_some_and(|p| is_fabric_proto(&p)) {
            continue;
        }
        let (Some(via), Some(dev)) = (after("via"), after("dev")) else {
            continue;
        };
        return Some(FloorDefault { via, dev });
    }
    None
}

pub fn floor_default(sys: &mut dyn Sys) -> Result<Option<FloorDefault>> {
    let out = sys.run(&["ip", "route", "show", "table", "main", "default"])?;
    if !out.ok() {
        return Err(Error::fatal(format!(
            "cannot read this host's own default route: `ip route show table main default` \
             exited {} ({}) — the additive host default (table {HOST_DEFAULT_TABLE}) is not \
             installed without it",
            out.status,
            out.stderr.trim()
        )));
    }
    Ok(parse_floor_default(&out.stdout))
}

/// Every IPv4 address the floor device carries, without its prefix length: one pref-2099 rule
/// each. Empty is a real answer (a device with no address); a read that did not run is not.
pub fn floor_addresses(sys: &mut dyn Sys, dev: &str) -> Result<Vec<String>> {
    let out = sys.run(&["ip", "-4", "-br", "addr", "show", "dev", dev])?;
    if !out.ok() {
        return Err(Error::fatal(format!(
            "cannot read the addresses of the floor device {dev}: `ip -4 -br addr show dev \
             {dev}` exited {} ({}) — this host's own default route names it",
            out.status,
            out.stderr.trim()
        )));
    }
    Ok(out
        .stdout
        .split_whitespace()
        .filter_map(|t| t.split_once('/'))
        .filter(|(a, len)| a.parse::<std::net::Ipv4Addr>().is_ok() && len.parse::<u8>().is_ok())
        .map(|(a, _)| a.to_string())
        .collect())
}

/// The addresses pref 2099 currently carries, read back from the kernel — what is there, never
/// what we last wrote. Only lines of cfab's own shape count: a rule parked at the same pref by
/// something else is neither refreshed nor deleted (prove ownership before destroy).
fn parse_installed_floor_addresses(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter_map(|(_, rest)| {
            let w: Vec<&str> = rest.split_whitespace().collect();
            match w.as_slice() {
                ["from", addr, "iif", "lo", "lookup", "main"] => Some((*addr).to_string()),
                _ => None,
            }
        })
        .collect()
}

pub fn installed_floor_addresses(sys: &mut dyn Sys) -> Result<Vec<String>> {
    Ok(parse_installed_floor_addresses(
        &sys.run(&["ip", "rule", "show", "pref", "2099"])?.stdout,
    ))
}

/// Bring pref 2099 level with the floor device's current addresses: add what is missing, drop
/// what the device no longer carries. Returns one line per change, in the order it was made,
/// for the caller's journal.
///
/// Level-triggered, like every other restore: an address added to the admin bridge between two
/// ticks gets its rule on the next one without anything having to notice it appeared.
pub fn sync_floor_rules(sys: &mut dyn Sys, wanted: &[String]) -> Result<Vec<String>> {
    let installed = installed_floor_addresses(sys)?;
    let mut out = Vec::new();
    for a in wanted.iter().filter(|a| !installed.contains(a)) {
        let r = floor_rule(a);
        ensure_fabric_rule(sys, &r)?;
        out.push(format!("added ip rule pref {} {}", r.pref, r.needle));
    }
    for a in installed.iter().filter(|a| !wanted.contains(a)) {
        let r = floor_rule(a);
        drop_fabric_rule(sys, &r)?;
        out.push(format!("dropped ip rule pref {} {}", r.pref, r.needle));
    }
    Ok(out)
}

/// Take the additive host default back out: the 250 route, then every rule that reaches it.
///
/// One function, two callers — `down`, and the unwind of a half-installed `up` — and both are
/// idempotent, so a member that never installed it tears down clean. Nothing here consults the
/// declaration: a member whose gw zone was removed since `up` still has these objects in the
/// kernel, and they are cfab's whether or not the current declaration would install them. The
/// route goes by its exact key (prefix + table + proto, the shape `down` already deletes the
/// per-zone return-path defaults by), and the 2099 rules from the kernel's own readback, one
/// exact rule at a time.
pub fn remove_host_default(sys: &mut dyn Sys) -> Result<()> {
    run_ignore(
        sys,
        &[
            "ip",
            "route",
            "del",
            "default",
            "table",
            HOST_DEFAULT_TABLE,
            "proto",
            &crate::emit::engine::CFAB_DEFAULT_PROTO.to_string(),
        ],
    )?;
    for a in installed_floor_addresses(sys)? {
        drop_fabric_rule(sys, &floor_rule(&a))?;
    }
    for r in lookup_rules() {
        drop_fabric_rule(sys, &r)?;
    }
    Ok(())
}

/// `drop_rules` for a `FabricRule`, the mirror of `ensure_fabric_rule`.
pub fn drop_fabric_rule(sys: &mut dyn Sys, r: &FabricRule) -> Result<()> {
    let del: Vec<&str> = r.add.iter().map(String::as_str).collect();
    drop_rules(sys, &r.pref, &r.needle, &del)
}

pub fn fabric_rule_present(sys: &mut dyn Sys, r: &FabricRule) -> Result<bool> {
    Ok(sys
        .run(&["ip", "rule", "show", "pref", &r.pref])?
        .stdout
        .contains(&r.needle))
}

pub fn ensure_fabric_rule(sys: &mut dyn Sys, r: &FabricRule) -> Result<()> {
    let add: Vec<&str> = r.add.iter().map(String::as_str).collect();
    ensure_rule(sys, &r.pref, &r.needle, &add)
}

pub fn link_exists(sys: &mut dyn Sys, dev: &str) -> Result<bool> {
    Ok(sys.run(&["ip", "link", "show", dev])?.ok())
}

/// `ip -d link show <dev>` contains the marker (e.g. " veth ", "vlan protocol 802.1Q id 100 ").
pub fn link_kind_is(sys: &mut dyn Sys, dev: &str, marker: &str) -> Result<bool> {
    let out = sys.run(&["ip", "-d", "link", "show", dev])?;
    Ok(out.ok() && out.stdout.contains(marker))
}

/// Idempotent `ip rule` presence: `ip rule show pref <pref>` must contain `needle`, else add.
pub fn ensure_rule(sys: &mut dyn Sys, pref: &str, needle: &str, add: &[&str]) -> Result<()> {
    let shown = sys.run(&["ip", "rule", "show", "pref", pref])?;
    if !shown.stdout.contains(needle) {
        let mut argv = vec!["ip", "rule", "add", "pref", pref];
        argv.extend_from_slice(add);
        run_ok(sys, &argv)?;
    }
    Ok(())
}

/// Delete every matching rule (teardown: loop while present, prove-ownership by pref+selector).
pub fn drop_rules(sys: &mut dyn Sys, pref: &str, needle: &str, del: &[&str]) -> Result<()> {
    loop {
        let shown = sys.run(&["ip", "rule", "show", "pref", pref])?;
        if !shown.stdout.contains(needle) {
            return Ok(());
        }
        let mut argv = vec!["ip", "rule", "del", "pref", pref];
        argv.extend_from_slice(del);
        run_ok(sys, &argv)?;
    }
}

/// Write a per-interface sysctl through /proc (sysctl(8) mangles interface names).
pub fn proc_sysctl(sys: &mut dyn Sys, ifname: &str, key: &str, value: &str) -> Result<()> {
    sys.write(&format!("/proc/sys/net/ipv4/conf/{ifname}/{key}"), value)
}

/// Interface names under /proc/sys/net/ipv4/conf (the kernel's per-interface view).
pub fn conf_interfaces(sys: &mut dyn Sys) -> Result<Vec<String>> {
    sys.list_dir("/proc/sys/net/ipv4/conf")
}

/// Is `cidr` one of the whitespace-separated tokens of an `ip -br addr show` line? A substring
/// check false-positives: `10.0.0.1/24` is a substring of `110.0.0.1/24`, and `ip -br addr`
/// packs every address for the device onto one line with no other separator, so token-exact is
/// the only correct match.
pub fn has_ip_addr(stdout: &str, cidr: &str) -> bool {
    stdout.split_whitespace().any(|tok| tok == cidr)
}

/// A base chain at the netfilter `forward` hook that cfab does not own and whose policy is
/// `drop`, or a reason we could not tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignForwardDrop {
    pub desc: String,
    /// Docker's `ip filter FORWARD`, the one foreign drop we can neutralize by asking its
    /// documented user hook. Anything else can only be reported.
    pub coverable: bool,
}

impl ForeignForwardDrop {
    fn other(desc: String) -> Self {
        Self {
            desc,
            coverable: false,
        }
    }
}

/// Foreign forward-hook chains that drop what cfab accepts, plus an iptables-legacy `FORWARD`
/// policy DROP (which nft cannot see).
///
/// Every base chain registered at a hook runs, and a drop verdict from any one of them ends the
/// packet — so cfab's `accept` in `inet cfab-fwd` cannot override a foreign drop. Transit dies
/// while cfab's own counters record the accept, which is why this has to be probed rather than
/// inferred from our own ruleset. Docker is the usual source: it sets `ip filter` FORWARD to
/// policy DROP whenever the daemon starts (measured on pve1, 2026-09-04).
///
/// Necessary, not sufficient: this sees a base-chain *policy* drop, not a drop issued by a
/// foreign *rule*.
pub fn foreign_forward_drops(sys: &mut dyn Sys) -> Result<Vec<ForeignForwardDrop>> {
    let mut found = Vec::new();
    let out = sys.run(&["nft", "-j", "list", "chains"])?;
    if !out.ok() {
        found.push(ForeignForwardDrop::other(format!(
            "could not enumerate forward-hook chains: `nft -j list chains` exited {} ({})",
            out.status,
            out.stderr.trim()
        )));
        return Ok(found);
    }
    match serde_json::from_str::<serde_json::Value>(&out.stdout) {
        Ok(doc) => {
            for obj in doc["nftables"].as_array().into_iter().flatten() {
                let c = &obj["chain"];
                if c["hook"].as_str() != Some("forward") || c["policy"].as_str() != Some("drop") {
                    continue;
                }
                let (family, table) = (
                    c["family"].as_str().unwrap_or("?"),
                    c["table"].as_str().unwrap_or("?"),
                );
                if OWNED_TABLES.contains(&(family, table)) {
                    continue;
                }
                let name = c["name"].as_str().unwrap_or("?");
                found.push(ForeignForwardDrop {
                    desc: format!("{family} {table} {name} (policy drop)"),
                    coverable: (family, table, name) == ("ip", "filter", "FORWARD"),
                });
            }
        }
        Err(e) => found.push(ForeignForwardDrop::other(format!(
            "could not parse `nft -j list chains` output: {e} (forward-hook chains unchecked)"
        ))),
    }
    // iptables-legacy keeps its own ruleset that nft cannot see. Only ask when the legacy
    // filter table is actually loaded — reading /proc has no side effect, whereas running
    // iptables-legacy would load the module on every watchdog tick.
    if sys
        .read("/proc/net/ip_tables_names")
        .map(|s| s.lines().any(|l| l.trim() == "filter"))
        .unwrap_or(false)
    {
        let legacy = run_optional(sys, &["iptables-legacy", "-S", "FORWARD"]).unwrap_or_default();
        if legacy.stdout.lines().any(|l| l.trim() == "-P FORWARD DROP") {
            found.push(ForeignForwardDrop::other(
                "ip filter FORWARD (policy drop, iptables-legacy)".to_string(),
            ));
        }
    }
    Ok(found)
}

/// The drops that are still breaking transit: everything we cannot cover, plus the coverable
/// ones when our accept is not actually installed. A covered Docker drop is not a fault — the
/// policy stays DROP by Docker's design and our `DOCKER-USER` accept passes cfab transit
/// through it, so reporting it would be a permanent false alarm.
pub fn unresolved_forward_drops(sys: &mut dyn Sys) -> Result<Vec<String>> {
    let drops = foreign_forward_drops(sys)?;
    if drops.is_empty() {
        return Ok(Vec::new());
    }
    let covered = foreign_transit_accept_present(sys)?;
    Ok(drops
        .into_iter()
        .filter(|d| !(d.coverable && covered))
        .map(|d| d.desc)
        .collect())
}

/// Tables cfab loads and is therefore allowed to see a forward-hook drop in.
const OWNED_TABLES: &[(&str, &str)] = &[("inet", "cfab-fwd"), ("inet", "cfab")];

/// The one-line remedy printed alongside every foreign-drop report.
pub fn foreign_forward_remedy(ifs: &[String]) -> String {
    let example = ifs.first().map(String::as_str).unwrap_or("<cfab-if>");
    format!(
        "transit through this host is dropped by a foreign ruleset, not by cfab. \
         Remedy: allow cfab transit in the foreign stack's user hook, e.g. \
         `iptables -I DOCKER-USER -i {example} -o {example} -j ACCEPT` per cfab interface pair"
    )
}

/// Marks the one rule cfab inserts into a foreign user hook, so teardown can prove ownership.
pub const FOREIGN_ACCEPT_TAG: &str = "cfab-transit";

/// Ask a foreign stack to stop dropping cfab transit, if it offers a hook for saying so.
///
/// Docker is the only common stack that does: `DOCKER-USER` is the chain it documents as never
/// rewritten, so one rule there survives daemon restarts and container churn. Returns the rule
/// description when it inserts one, `None` when there is no such hook (nothing to do) or the
/// rule is already present (idempotent).
///
/// This cannot widen cfab's policy. Every base chain at the forward hook still runs and cfab's
/// own chain still gets a verdict, so an accept here only removes the *foreign* drop -- packets
/// cfab denies are still denied by `inet cfab-fwd`. That is why one `cfab+` wildcard rule is
/// enough and safe: it needs no per-zone pairs and no update when interfaces come and go.
pub fn ensure_foreign_transit_accept(sys: &mut dyn Sys) -> Result<Option<String>> {
    let Some(shown) = run_optional(sys, &["iptables", "-S", "DOCKER-USER"]) else {
        return Ok(None); // no iptables on this host at all
    };
    if !shown.stdout.contains("-N DOCKER-USER") {
        return Ok(None); // no such hook: nothing offers us a way in
    }
    if shown.stdout.contains(FOREIGN_ACCEPT_TAG) {
        return Ok(None); // already ours
    }
    run_ok(sys, &foreign_accept_argv("-I"))?;
    Ok(Some("DOCKER-USER: -i cfab+ -o cfab+ -j ACCEPT".to_string()))
}

/// Whether cfab's accept is currently installed in the foreign user hook.
pub fn foreign_transit_accept_present(sys: &mut dyn Sys) -> Result<bool> {
    Ok(run_optional(sys, &["iptables", "-S", "DOCKER-USER"])
        .is_some_and(|o| o.stdout.contains(FOREIGN_ACCEPT_TAG)))
}

/// Remove every rule cfab inserted into a foreign user hook. Only rules carrying our tag are
/// touched, and only while one is still present -- never a broad flush of someone else's chain.
pub fn remove_foreign_transit_accept(sys: &mut dyn Sys) -> Result<usize> {
    let mut removed = 0;
    loop {
        let Some(shown) = run_optional(sys, &["iptables", "-S", "DOCKER-USER"]) else {
            return Ok(removed);
        };
        if !shown.stdout.contains(FOREIGN_ACCEPT_TAG) {
            return Ok(removed);
        }
        run_ok(sys, &foreign_accept_argv("-D"))?;
        removed += 1;
    }
}

fn foreign_accept_argv(op: &str) -> [&str; 13] {
    [
        "iptables",
        op,
        "DOCKER-USER",
        "-i",
        "cfab+",
        "-o",
        "cfab+",
        "-m",
        "comment",
        "--comment",
        FOREIGN_ACCEPT_TAG,
        "-j",
        "ACCEPT",
    ]
}

/// Remove the iptables-legacy mark state: the OUTPUT jump, then every `cfab-*` mangle chain the
/// live readback names — flushed first (a chain `cfab-out` still jumps to cannot be deleted),
/// then deleted. Exact names from the readback, never a pattern: the mangle table is shared with
/// Docker, the NAS's own rules and anything else the operator runs.
///
/// One helper, two callers: `down` on this backend, and `up` on the OTHER backend, where a leaf
/// that has gained nf_tables must not leave its old chains resident. `have_tool`-guarded, so a
/// member that no longer has the binaries still applies and still tears down.
pub fn remove_mark_ipt(sys: &mut dyn Sys) -> Result<()> {
    if !(have_tool(sys, "iptables-legacy")? && have_tool(sys, "iptables-legacy-save")?) {
        return Ok(());
    }
    let save = sys.run(&["iptables-legacy-save", "-t", "mangle"])?;
    let chains = crate::emit::ceiling_ipt::chains_in(&save.stdout);
    for chain in &chains {
        if chain == crate::emit::ceiling_ipt::OUT_CHAIN {
            run_ignore(
                sys,
                &[
                    "iptables-legacy",
                    "-t",
                    "mangle",
                    "-D",
                    "OUTPUT",
                    "-j",
                    chain,
                ],
            )?;
        }
        run_ignore(sys, &["iptables-legacy", "-t", "mangle", "-F", chain])?;
    }
    for chain in &chains {
        run_ignore(sys, &["iptables-legacy", "-t", "mangle", "-X", chain])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::Declaration;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn wl_fabric() -> Fabric {
        Fabric::from_decl(
            &Declaration::parse(&crate::decl::fixtures::with_workload(
                &crate::decl::fixtures::example(),
            ))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn workload_return_rules_are_one_pref_2000_sibling_per_allowed_zone_on_every_member_and_leaf() {
        let f = wl_fabric();
        for m in ["pve1-tb", "pve3-tb"] {
            let v = View::new(&f, m).unwrap();
            let r = workload_return_rules(&v);
            assert_eq!(
                r.len(),
                1,
                "{m}: one per allowed zone (storage), none for cluster or mgmt"
            );
            assert_eq!(r[0].pref, "2000");
            assert_eq!(
                r[0].needle,
                "from 10.99.0.0/16 to 192.168.20.0/24 lookup main"
            );
            assert_eq!(
                r[0].add,
                vec![
                    "from",
                    "10.99.0.0/16",
                    "to",
                    "192.168.20.0/24",
                    "lookup",
                    "main"
                ]
            );
        }
    }

    #[test]
    fn return_path_rules_place_the_sibling_after_the_allowed_zones_2000_and_before_its_2001() {
        let f = wl_fabric();
        let v = View::new(&f, "pve3-tb").unwrap();
        let rules = return_path_rules(&v);
        let prefs: Vec<&str> = rules.iter().map(|r| r.pref.as_str()).collect();
        // storage (allowed): 2000, sibling 2000, 2001, 2002; cluster and mgmt: 2000, 2001, 2002
        assert_eq!(
            prefs,
            [
                "2000", "2000", "2001", "2002", "2000", "2001", "2002", "2000", "2001", "2002"
            ]
        );
        assert_eq!(
            rules[1].needle,
            "from 10.99.0.0/16 to 192.168.20.0/24 lookup main"
        );
    }

    /// Shape of `nft -j list chains`, as captured on pve1-tb. `cfab-fwd`'s own forward chain is
    /// policy drop and must never be reported; Docker's `ip filter FORWARD` is the foreign one.
    fn chains_json(extra: &str) -> String {
        format!(
            r#"{{"nftables":[
              {{"metainfo":{{"version":"1.1.1"}}}},
              {{"chain":{{"family":"inet","table":"cfab-fwd","name":"forward",
                          "hook":"forward","prio":0,"policy":"drop"}}}},
              {{"chain":{{"family":"inet","table":"cfab","name":"out",
                          "hook":"output","prio":-150,"policy":"accept"}}}}
              {extra}]}}"#
        )
    }

    const DOCKER_FORWARD: &str = r#",
      {"chain":{"family":"ip","table":"filter","name":"FORWARD",
                "hook":"forward","prio":0,"policy":"drop"}}"#;

    fn sys_with(json: String) -> MockSys {
        MockSys::default().on_stdout(&["nft", "-j", "list", "chains"], &json)
    }

    fn descs(sys: &mut MockSys) -> Vec<String> {
        foreign_forward_drops(sys)
            .unwrap()
            .into_iter()
            .map(|d| d.desc)
            .collect()
    }

    #[test]
    fn our_own_forward_drop_is_not_foreign() {
        let mut sys = sys_with(chains_json(""));
        assert!(descs(&mut sys).is_empty());
    }

    #[test]
    fn dockers_forward_policy_drop_is_reported() {
        let mut sys = sys_with(chains_json(DOCKER_FORWARD));
        let found = foreign_forward_drops(&mut sys).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].desc, "ip filter FORWARD (policy drop)");
        assert!(found[0].coverable, "Docker's is the one we can neutralize");
    }

    #[test]
    fn a_foreign_forward_chain_that_accepts_is_fine() {
        let accepting = DOCKER_FORWARD.replace(r#""policy":"drop""#, r#""policy":"accept""#);
        let mut sys = sys_with(chains_json(&accepting));
        assert!(descs(&mut sys).is_empty());
    }

    #[test]
    fn a_foreign_drop_at_another_hook_does_not_touch_transit() {
        let input = DOCKER_FORWARD.replace(r#""hook":"forward""#, r#""hook":"input""#);
        let mut sys = sys_with(chains_json(&input));
        assert!(descs(&mut sys).is_empty());
    }

    #[test]
    fn an_unreadable_ruleset_is_reported_never_assumed_clean() {
        // fail loud: not being able to answer is not the same as a clean answer
        let mut sys = MockSys::default().on_fail(&["nft", "-j", "list", "chains"], 1, "boom");
        let found = descs(&mut sys);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("could not enumerate"), "{found:?}");

        let mut sys = sys_with("not json at all".to_string());
        let found = descs(&mut sys);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("could not parse"), "{found:?}");
    }

    #[test]
    fn iptables_legacy_forward_drop_is_seen_even_though_nft_cannot_see_it() {
        let mut sys = sys_with(chains_json(""))
            .file("/proc/net/ip_tables_names", "filter\n")
            .on_stdout(
                &["iptables-legacy", "-S", "FORWARD"],
                "-P FORWARD DROP\n-A FORWARD -j SOMETHING\n",
            );
        let found = descs(&mut sys);
        assert_eq!(
            found,
            vec!["ip filter FORWARD (policy drop, iptables-legacy)".to_string()]
        );
    }

    #[test]
    fn legacy_is_not_probed_when_its_table_is_not_loaded() {
        // reading /proc has no side effect; running iptables-legacy would load the module
        let mut sys = sys_with(chains_json(""));
        assert!(descs(&mut sys).is_empty());
        assert!(!sys.ran("iptables-legacy"));
    }

    /// The verbatim `nft -j list chains` output from pve1-tb with dockerd running, captured
    /// 2026-09-04 (nftables 1.1.3). Guards the parse against the real format -- the synthesized
    /// fixtures above are only as good as my reading of it, and this file is not.
    #[test]
    fn the_real_capture_from_a_docker_host_is_parsed() {
        let real = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/nft-chains-docker-pve1.json"
        ));
        let mut sys = sys_with(real.to_string());
        let found = foreign_forward_drops(&mut sys).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].desc, "ip filter FORWARD (policy drop)");
        assert!(found[0].coverable);
    }

    const DOCKER_USER_EMPTY: &str = "-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n";

    #[test]
    fn no_iptables_at_all_means_nothing_to_do() {
        // MockSys answers an unstubbed command with an empty success, which is exactly the
        // "chain not there" shape -- the real `absent binary` case returns Err and is mapped
        // to None by run_optional.
        let mut sys = MockSys::default();
        assert_eq!(ensure_foreign_transit_accept(&mut sys).unwrap(), None);
        assert!(!sys.ran("iptables -I"));
    }

    #[test]
    fn a_docker_user_hook_gets_exactly_one_tagged_rule() {
        let mut sys =
            MockSys::default().on_stdout(&["iptables", "-S", "DOCKER-USER"], DOCKER_USER_EMPTY);
        let added = ensure_foreign_transit_accept(&mut sys).unwrap();
        assert!(added.is_some(), "should have inserted");
        assert!(
            sys.ran("iptables -I DOCKER-USER -i cfab+ -o cfab+ -m comment --comment cfab-transit -j ACCEPT"),
            "{:?}",
            sys.calls
        );
    }

    #[test]
    fn inserting_twice_is_a_no_op() {
        let already = format!(
            "{DOCKER_USER_EMPTY}-A DOCKER-USER -i cfab+ -o cfab+ -m comment --comment {FOREIGN_ACCEPT_TAG} -j ACCEPT\n"
        );
        let mut sys = MockSys::default().on_stdout(&["iptables", "-S", "DOCKER-USER"], &already);
        assert_eq!(ensure_foreign_transit_accept(&mut sys).unwrap(), None);
        assert!(!sys.ran("iptables -I"), "{:?}", sys.calls);
    }

    #[test]
    fn teardown_removes_only_our_own_tagged_rule() {
        // someone else's rule in the same chain must survive; ours must go
        let foreign = "-A DOCKER-USER -i eth0 -o eth0 -j ACCEPT\n";
        let ours = format!(
            "-A DOCKER-USER -i cfab+ -o cfab+ -m comment --comment {FOREIGN_ACCEPT_TAG} -j ACCEPT\n"
        );
        let mut sys = MockSys::default().on_stdout(
            &["iptables", "-S", "DOCKER-USER"],
            &format!("{DOCKER_USER_EMPTY}{foreign}{ours}"),
        );
        // the mock replays the same listing forever, so stop after proving the first delete is
        // ours and correctly shaped
        let deleted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for _ in 0..2 {
                let _ = run_ok(&mut sys, &foreign_accept_argv("-D"));
            }
        }));
        assert!(deleted.is_ok());
        assert!(
            sys.ran("iptables -D DOCKER-USER -i cfab+ -o cfab+ -m comment --comment cfab-transit -j ACCEPT"),
            "{:?}",
            sys.calls
        );
        assert!(!sys.ran("-i eth0"), "never touches a foreign rule");
    }

    #[test]
    fn teardown_on_a_host_with_no_hook_removes_nothing() {
        let mut sys = MockSys::default();
        assert_eq!(remove_foreign_transit_accept(&mut sys).unwrap(), 0);
        assert!(!sys.ran("iptables -D"));
    }

    #[test]
    fn a_covered_docker_drop_is_not_reported_as_a_fault() {
        // Docker's policy stays DROP forever by its own design. Once our accept is in the user
        // hook, transit works -- reporting the policy would be a permanent false alarm.
        let ours = format!(
            "-N DOCKER-USER\n-A DOCKER-USER -i cfab+ -o cfab+ -m comment --comment {FOREIGN_ACCEPT_TAG} -j ACCEPT\n"
        );
        let mut sys = sys_with(chains_json(DOCKER_FORWARD))
            .on_stdout(&["iptables", "-S", "DOCKER-USER"], &ours);
        assert!(unresolved_forward_drops(&mut sys).unwrap().is_empty());
    }

    #[test]
    fn an_uncovered_docker_drop_is_reported() {
        let mut sys = sys_with(chains_json(DOCKER_FORWARD))
            .on_stdout(&["iptables", "-S", "DOCKER-USER"], DOCKER_USER_EMPTY);
        assert_eq!(
            unresolved_forward_drops(&mut sys).unwrap(),
            vec!["ip filter FORWARD (policy drop)".to_string()]
        );
    }

    #[test]
    fn a_foreign_drop_we_cannot_cover_is_reported_even_with_our_accept_in() {
        // some other stack's table: our DOCKER-USER rule says nothing about it
        let other = DOCKER_FORWARD
            .replace(r#""table":"filter""#, r#""table":"someone-else""#)
            .replace(r#""family":"ip""#, r#""family":"inet""#);
        let ours = format!(
            "-N DOCKER-USER\n-A DOCKER-USER -m comment --comment {FOREIGN_ACCEPT_TAG} -j ACCEPT\n"
        );
        let mut sys =
            sys_with(chains_json(&other)).on_stdout(&["iptables", "-S", "DOCKER-USER"], &ours);
        let found = unresolved_forward_drops(&mut sys).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("someone-else"), "{found:?}");
    }

    #[test]
    fn the_remedy_names_a_real_interface() {
        let r = foreign_forward_remedy(&["cfab-st".to_string()]);
        assert!(r.contains("-i cfab-st -o cfab-st"), "{r}");
        assert!(foreign_forward_remedy(&[]).contains("<cfab-if>"));
    }

    #[test]
    fn has_ip_addr_is_token_exact_not_substring() {
        assert!(has_ip_addr(
            "cfab-work-vms UP 192.168.20.2/24\n",
            "192.168.20.2/24"
        ));
        assert!(has_ip_addr(
            "cfab-work-vms UP 10.0.0.1/24 192.168.20.2/24\n",
            "192.168.20.2/24"
        ));
        // A substring collision must not false-positive: 10.0.0.1/24 is a substring of
        // 110.0.0.1/24, and the reverse.
        assert!(!has_ip_addr(
            "cfab-work-vms UP 110.0.0.1/24\n",
            "10.0.0.1/24"
        ));
        assert!(!has_ip_addr(
            "cfab-work-vms UP 10.0.0.1/24\n",
            "110.0.0.1/24"
        ));
    }
}

#[cfg(test)]
mod host_default_tests {
    use super::*;
    use crate::decl::Declaration;
    use crate::model::Fabric;
    use crate::sys::mock::MockSys;

    fn fabric() -> Fabric {
        Fabric::from_decl(&Declaration::parse(&crate::decl::fixtures::example()).unwrap()).unwrap()
    }

    /// The one gw zone in the example fabric is `mgmt`: router 192.168.249.254 on the migrating
    /// leg `cfab-gw249`, so pve1-tb (node 1) sources from 192.168.249.1.
    #[test]
    fn the_host_default_is_the_gw_zones_leg_sourced_from_this_members_own_address() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            host_default(&v),
            Some(HostDefault {
                table: "250".to_string(),
                via: "192.168.249.254".to_string(),
                dev: "cfab-gw249".to_string(),
                src: "192.168.249.1".to_string(),
            })
        );
    }

    /// A leaf carries no ingress leg at all, so it has no fabric gateway to prefer and installs
    /// nothing: no route, and no rules either.
    #[test]
    fn a_member_with_no_gw_zone_has_no_host_default_and_no_rules() {
        let f = fabric();
        let v = View::new(&f, "pve3-tb").unwrap();
        assert_eq!(host_default(&v), None);
        assert!(host_default_rules(&v, &["192.168.10.3".to_string()]).is_empty());
    }

    #[test]
    fn the_host_default_argv_names_the_table_and_proto_206_both_ways() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let d = host_default(&v).unwrap();
        for verb in ["replace", "del"] {
            assert_eq!(
                d.argv(verb),
                vec![
                    "ip",
                    "route",
                    verb,
                    "default",
                    "via",
                    "192.168.249.254",
                    "dev",
                    "cfab-gw249",
                    "src",
                    "192.168.249.1",
                    "table",
                    "250",
                    "proto",
                    "206"
                ]
            );
        }
    }

    #[test]
    fn the_rules_are_one_2099_per_floor_address_then_2100_then_2101() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let addrs = ["192.168.10.1".to_string(), "192.168.10.11".to_string()];
        let rules = host_default_rules(&v, &addrs);
        let prefs: Vec<&str> = rules.iter().map(|r| r.pref.as_str()).collect();
        assert_eq!(prefs, ["2099", "2099", "2100", "2101"]);
        assert_eq!(rules[0].needle, "from 192.168.10.1 iif lo lookup main");
        assert_eq!(
            rules[0].add,
            vec!["from", "192.168.10.1", "iif", "lo", "lookup", "main"]
        );
        assert_eq!(rules[1].needle, "from 192.168.10.11 iif lo lookup main");
        assert_eq!(
            rules[2].add,
            vec![
                "from",
                "all",
                "iif",
                "lo",
                "lookup",
                "main",
                "suppress_prefixlength",
                "0"
            ]
        );
        assert_eq!(
            rules[3].add,
            vec!["from", "all", "iif", "lo", "lookup", "250"]
        );
    }

    /// No floor default on the host means no 2099 rules — and the other two, and the 250
    /// default, still go in: §6 is additive, and nothing was removed to make room for it.
    #[test]
    fn no_floor_address_leaves_2100_and_2101_installed() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let prefs: Vec<String> = host_default_rules(&v, &[])
            .iter()
            .map(|r| r.pref.clone())
            .collect();
        assert_eq!(prefs, ["2100", "2101"]);
    }

    /// `ip rule show` renders a table by its rt_tables name where one exists, so pref 2101 reads
    /// `lookup cfab-default` on a host with the package's fragment installed and `lookup 250` on
    /// one without it. The presence test must find the rule either way.
    #[test]
    fn the_2101_rule_is_found_under_both_renderings_of_table_250() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let r = host_default_rules(&v, &[]).pop().unwrap();
        assert_eq!(r.pref, "2101");
        for shown in [
            "2101:\tfrom all iif lo lookup 250\n",
            "2101:\tfrom all iif lo lookup cfab-default\n",
        ] {
            let mut sys =
                MockSys::default().on_stdout(&["ip", "rule", "show", "pref", "2101"], shown);
            assert!(
                fabric_rule_present(&mut sys, &r).unwrap(),
                "not found in {shown:?}"
            );
        }
        let mut empty = MockSys::default().on_stdout(&["ip", "rule", "show", "pref", "2101"], "");
        assert!(!fabric_rule_present(&mut empty, &r).unwrap());
    }

    const MAIN_DEFAULTS: &str = "\
default via 192.168.10.1 dev primary onlink
default via 10.99.0.4 dev cfab-st proto cfab-ospf metric 20
default via 192.168.249.254 dev cfab-gw249 proto cfab-default
";

    #[test]
    fn the_floor_is_the_default_no_cfab_protocol_installed() {
        let mut sys = MockSys::default().on_stdout(
            &["ip", "route", "show", "table", "main", "default"],
            MAIN_DEFAULTS,
        );
        assert_eq!(
            floor_default(&mut sys).unwrap(),
            Some(FloorDefault {
                via: "192.168.10.1".to_string(),
                dev: "primary".to_string(),
            })
        );
    }

    /// Every default is one cfab or its engine installed: there is no floor, which is a real
    /// answer (no 2099 rules) and never "the fabric's own default is the floor".
    #[test]
    fn a_table_of_only_cfab_defaults_has_no_floor() {
        let only_ours = "\
default via 10.99.0.4 dev cfab-st proto cfab-ospf metric 20
default via 10.99.0.4 dev cfab-st proto 201 metric 20
default via 192.168.249.254 dev cfab-gw249 proto 205
default via 192.168.1.1 dev eth3 proto 110
";
        let mut sys = MockSys::default().on_stdout(
            &["ip", "route", "show", "table", "main", "default"],
            only_ours,
        );
        assert_eq!(floor_default(&mut sys).unwrap(), None);
    }

    /// A DHCP-written default is a floor exactly as ifupdown's protoless one is.
    #[test]
    fn a_dhcp_default_is_a_floor() {
        let mut sys = MockSys::default().on_stdout(
            &["ip", "route", "show", "table", "main", "default"],
            "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100\n",
        );
        assert_eq!(
            floor_default(&mut sys).unwrap().unwrap().dev,
            "eth0".to_string()
        );
    }

    /// Fail loud: a read of main's routes that did not run is not "this host has no floor".
    #[test]
    fn a_failed_read_of_mains_defaults_is_a_named_error() {
        let mut sys = MockSys::default().on_fail(
            &["ip", "route", "show", "table", "main", "default"],
            2,
            "Cannot open netlink socket",
        );
        let e = floor_default(&mut sys).unwrap_err().to_string();
        assert!(e.contains("ip route show table main default"), "{e}");
        assert!(e.contains("Cannot open netlink socket"), "{e}");
        assert_no_double_space(&e);
    }

    /// Fail loud: a read of the floor device's addresses that did not run is not "it carries
    /// none", because that answer would drop every pref-2099 pin.
    #[test]
    fn a_failed_read_of_the_floor_devices_addresses_is_a_named_error() {
        let mut sys = MockSys::default().on_fail(
            &["ip", "-4", "-br", "addr", "show", "dev", "primary"],
            1,
            "Device \"primary\" does not exist.",
        );
        let e = floor_addresses(&mut sys, "primary")
            .unwrap_err()
            .to_string();
        assert!(e.contains("ip -4 -br addr show dev primary"), "{e}");
        assert!(e.contains("does not exist"), "{e}");
        assert_no_double_space(&e);
    }

    /// A wrapped string literal that loses its `\` continuation keeps the source indentation as
    /// a run of literal spaces in the middle of the sentence — invisible in the source, glaring
    /// in the journal, and it breaks a grep for the phrase. Every message this file builds is
    /// asserted against it at the point it is built.
    fn assert_no_double_space(msg: &str) {
        assert!(
            !msg.contains("  "),
            "message carries a run of spaces (a lost `\\` continuation?): {msg:?}"
        );
    }

    #[test]
    fn floor_addresses_are_the_ipv4_addresses_that_device_carries() {
        let mut sys = MockSys::default().on_stdout(
            &["ip", "-4", "-br", "addr", "show", "dev", "primary"],
            "primary          UP             192.168.10.3/24 192.168.10.60/24\n",
        );
        assert_eq!(
            floor_addresses(&mut sys, "primary").unwrap(),
            vec!["192.168.10.3".to_string(), "192.168.10.60".to_string()]
        );
    }

    /// Only rules of cfab's own shape are read back as ours; a foreign rule parked at the same
    /// pref is neither refreshed nor deleted.
    #[test]
    fn only_our_own_shape_is_read_back_from_pref_2099() {
        let mut sys = MockSys::default().on_stdout(
            &["ip", "rule", "show", "pref", "2099"],
            "2099:\tfrom 192.168.10.3 iif lo lookup main\n\
             2099:\tfrom 172.16.0.1 lookup 42\n\
             2099:\tfrom 192.168.10.60 iif lo lookup main\n",
        );
        assert_eq!(
            installed_floor_addresses(&mut sys).unwrap(),
            vec!["192.168.10.3".to_string(), "192.168.10.60".to_string()]
        );
    }

    /// The refresh is level-triggered off the kernel's own readback: an address the floor device
    /// gained gets a rule, one it lost loses its rule, and an address that is in both sets is
    /// touched neither way.
    #[test]
    fn syncing_the_floor_rules_adds_the_missing_and_drops_the_stale() {
        let mut sys2 = MockSys::default().on_stdout(
            &["ip", "rule", "show", "pref", "2099"],
            "2099:\tfrom 192.168.10.3 iif lo lookup main\n\
             2099:\tfrom 192.168.10.99 iif lo lookup main\n",
        );
        let lines = sync_floor_rules(
            &mut sys2,
            &["192.168.10.3".to_string(), "192.168.10.60".to_string()],
        )
        .unwrap();
        let adds: Vec<&String> = sys2
            .calls
            .iter()
            .filter(|c| c.starts_with("ip rule add"))
            .collect();
        let dels: Vec<&String> = sys2
            .calls
            .iter()
            .filter(|c| c.starts_with("ip rule del"))
            .collect();
        assert_eq!(
            adds,
            vec!["ip rule add pref 2099 from 192.168.10.60 iif lo lookup main"]
        );
        assert_eq!(
            dels,
            vec!["ip rule del pref 2099 from 192.168.10.99 iif lo lookup main"]
        );
        assert_eq!(
            lines,
            vec![
                "added ip rule pref 2099 from 192.168.10.60 iif lo lookup main",
                "dropped ip rule pref 2099 from 192.168.10.99 iif lo lookup main",
            ]
        );
    }
}
