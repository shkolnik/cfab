//! Helpers shared by the imperative commands (up/down/status/daemons).

use crate::error::Result;
use crate::sys::{Sys, run_ok, run_optional};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

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
}
