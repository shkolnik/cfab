//! `cfab policy-teeth` — prove the generated forward policy does what the class table says, AND
//! prove the tests bite. Runs on any Linux with nft + netns; touches nothing outside throwaway
//! netnses named cfab-teeth-*.
//!
//! Fixture: a router netns whose veths carry the REAL class-table names so the very same ruleset
//! the generator emits for a host loads unchanged; one endpoint netns behind each interface. A
//! "pair" test pings from the endpoint behind <from> to the endpoint behind <to> and counts
//! REPLIES — the replies of an allowed pair are accepted by the policy's conntrack rule, so each
//! allowed pair is tested together with its return leg.
//!
//! Two foreign interfaces (not cfab's, forwarding on) stand in for another stack's bridges:
//! foreign<->foreign must pass, foreign<->zone and admin->foreign must drop (scoped posture).
//!
//! Teeth: (1) regress — re-generate from a MODEL with an extra allowed pair (storage>cluster)
//! through the real parser+generator: the negative test for that pair must go RED. (2) mutate —
//! strip the admin drop rules and splice the admin NIC into the storage set: the admin negative
//! test must go RED (proves it is those rules, not the default policy, protecting the admin NIC).
//! (3) mutate — strip the foreign-transit accept: foreign<->foreign must go RED (proves that
//! rule, not a hole in the default policy, is what lets another stack forward).

use std::fmt::Write as _;

use crate::config::RawConfig;
use crate::derive::View;
use crate::emit;
use crate::error::{Error, Result};
use crate::model::{Fabric, Role};
use crate::sys::{Sys, run_ignore, run_ok};

const ROUTER: &str = "cfab-teeth-r";
/// Stand-ins for another stack's interfaces on the same router (no `cfab-` name, not declared).
const FOREIGN: [&str; 2] = ["foreign0", "foreign1"];

pub struct TeethReport {
    pub ok: bool,
    pub output: String,
}

struct Fixture {
    /// interface name → (endpoint netns, 10.7.<i> net prefix)
    map: Vec<(String, String, String)>,
}

impl Fixture {
    fn endpoint(&self, ifname: &str) -> Result<(&str, &str)> {
        self.map
            .iter()
            .find(|(i, _, _)| i == ifname)
            .map(|(_, ns, net)| (ns.as_str(), net.as_str()))
            .ok_or_else(|| Error::fatal(format!("policy-teeth: no endpoint behind {ifname}")))
    }
}

pub fn run(sys: &mut dyn Sys, view: &View, conf_text: &str) -> Result<TeethReport> {
    let result = run_inner(sys, view, conf_text);
    cleanup(sys)?; // always reap our netnses, success or failure
    result
}

fn run_inner(sys: &mut dyn Sys, view: &View, conf_text: &str) -> Result<TeethReport> {
    let f = view.fabric;
    let mut out = String::new();
    let mut ifs: Vec<String> = view.class_rows().into_iter().map(|r| r.ifname).collect();
    // Rescue bonds are in the zone's forward-policy set (`zone_ifs`) like a segment, so the
    // fixture's router carries a veth stand-in for each — proves the generated ruleset does not
    // special-case them out. No endpoint netns test exercises a rescue ifname directly (no
    // production traffic addresses it in this fixture); the container proof on real hardware is
    // the only proof of actual rescue transit (Task 7.2(c)). Slaves are NOT added: they carry no
    // L3 and are not in any forward-policy set.
    ifs.extend(view.rescue_rows().into_iter().map(|r| r.ifname));
    if let Some(a) = view.admin_if() {
        ifs.push(a.to_string());
    }
    if f.vrrp_gw {
        ifs.push(f.vrrp_if.clone());
    }
    ifs.extend(FOREIGN.iter().map(|s| s.to_string()));

    cleanup(sys)?;
    run_ok(sys, &["ip", "netns", "add", ROUTER])?;
    let mut fx = Fixture { map: Vec::new() };
    for (i, ifn) in ifs.iter().enumerate() {
        let i = i + 1;
        let ep = format!("cfab-teeth-{i}");
        let net = format!("10.7.{i}");
        run_ok(sys, &["ip", "netns", "add", &ep])?;
        run_ok(
            sys,
            &[
                "ip", "-n", ROUTER, "link", "add", ifn, "type", "veth", "peer", "name", "ep0",
                "netns", &ep,
            ],
        )?;
        run_ok(
            sys,
            &[
                "ip",
                "-n",
                ROUTER,
                "addr",
                "add",
                &format!("{net}.1/24"),
                "dev",
                ifn,
            ],
        )?;
        run_ok(sys, &["ip", "-n", ROUTER, "link", "set", ifn, "up"])?;
        run_ok(
            sys,
            &[
                "ip",
                "-n",
                &ep,
                "addr",
                "add",
                &format!("{net}.2/24"),
                "dev",
                "ep0",
            ],
        )?;
        run_ok(sys, &["ip", "-n", &ep, "link", "set", "ep0", "up"])?;
        run_ok(sys, &["ip", "-n", &ep, "link", "set", "lo", "up"])?;
        run_ok(
            sys,
            &[
                "ip",
                "-n",
                &ep,
                "route",
                "add",
                "default",
                "via",
                &format!("{net}.1"),
            ],
        )?;
        fx.map.push((ifn.clone(), ep, net));
    }
    run_ok(sys, &["ip", "-n", ROUTER, "link", "set", "lo", "up"])?;
    run_ok(
        sys,
        &[
            "ip",
            "netns",
            "exec",
            ROUTER,
            "sysctl",
            "-qw",
            "net.ipv4.conf.all.send_redirects=0",
            "net.ipv4.conf.all.rp_filter=0",
        ],
    )?;
    for ifn in &ifs {
        // forwarding=1 even on the admin NIC here ON PURPOSE — the teeth test isolates the
        // POLICY; the sysctl belt is verified separately (verify / watchdog).
        run_ok(
            sys,
            &[
                "ip",
                "netns",
                "exec",
                ROUTER,
                "sysctl",
                "-qw",
                &format!("net.ipv4.conf.{ifn}.forwarding=1"),
                &format!("net.ipv4.conf.{ifn}.send_redirects=0"),
            ],
        )?;
    }

    let prod = emit::policy::generate(view)?;

    let _ = writeln!(out, "== 1. production policy");
    load(sys, &prod)?;
    let r1 = matrix(sys, view, &fx, &mut out)?;

    let _ = writeln!(
        out,
        "== 2. teeth: allow storage>cluster in the model -> the storage->cluster negative must go RED"
    );
    // regress the MODEL, not the output: an edited declaration through the real parser+generator
    let declared: Vec<String> = f
        .forward_allow
        .iter()
        .map(|(a, b)| format!("{a}>{b}"))
        .collect();
    let regressed_conf = replace_forward_allow(
        conf_text,
        &format!("{} storage>cluster", declared.join(" ")),
    );
    let regressed_fabric = Fabric::from_raw(&RawConfig::parse(&regressed_conf)?)?;
    let regressed_view = View::new(&regressed_fabric, &view.member.name)?;
    let regressed = emit::policy::generate(&regressed_view)?;
    if !regressed.contains("allow-storage-cluster") {
        return Err(Error::fatal(
            "fixture bug: regression did not reach the generator",
        ));
    }
    load(sys, &regressed)?;
    let got = reach(
        sys,
        &fx,
        first_if(view, "storage")?,
        first_if(view, "cluster")?,
    )?;
    let r2 = if got == 0 {
        let _ = writeln!(
            out,
            "  NO TEETH: negative test did not notice the added allow"
        );
        false
    } else {
        let _ = writeln!(
            out,
            "  RED  regressed: storage -> cluster = {got}/3 (want 0) — the wanted outcome"
        );
        true
    };

    let _ = writeln!(
        out,
        "== 3. teeth: strip the admin drop rules from the ruleset -> the admin negative must go RED"
    );
    let admin = view
        .admin_if()
        .ok_or_else(|| Error::fatal("policy-teeth: no admin NIC on this member (host only)"))?;
    let noadmin: String = prod
        .lines()
        .filter(|l| !l.contains("comment \"admin-"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    // Simulate the worst case: a hand-edit that adds the admin NIC to the storage zone set.
    let noadmin = noadmin.replace(
        "set storage { type ifname; elements = { ",
        &format!("set storage {{ type ifname; elements = {{ \"{admin}\", "),
    );
    load(sys, &noadmin)?;
    let got = reach(sys, &fx, admin, first_if(view, "storage")?)?;
    let r3 = if got == 0 {
        let _ = writeln!(
            out,
            "  NO TEETH: admin test did not notice the missing admin rules"
        );
        false
    } else {
        let _ = writeln!(
            out,
            "  RED  mutated: {admin} -> storage = {got}/3 (want 0) — the wanted outcome"
        );
        true
    };

    let _ = writeln!(
        out,
        "== 4. teeth: strip the foreign-transit accept -> foreign <-> foreign must go RED"
    );
    let noforeign: String = prod
        .lines()
        .filter(|l| !l.contains("comment \"foreign-transit\""))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    load(sys, &noforeign)?;
    let got = reach(sys, &fx, FOREIGN[0], FOREIGN[1])?;
    let r4 = if got == 3 {
        let _ = writeln!(
            out,
            "  NO TEETH: foreign pair still forwards without the foreign-transit rule"
        );
        false
    } else {
        let _ = writeln!(
            out,
            "  RED  mutated: {} -> {} = {got}/3 (want 3) — the wanted outcome",
            FOREIGN[0], FOREIGN[1]
        );
        true
    };

    let _ = writeln!(
        out,
        "== 5. production policy again (fixture sanity after mutations)"
    );
    load(sys, &prod)?;
    let r5 = matrix(sys, view, &fx, &mut out)?;

    let ok = r1 && r2 && r3 && r4 && r5;
    if ok {
        let _ = writeln!(
            out,
            "policy-teeth OK: policy matches the class table and the tests bite"
        );
    } else {
        let _ = writeln!(
            out,
            "policy-teeth FAILED (policy={} regress-teeth={} mutate-teeth={} foreign-teeth={} sanity={})",
            u8::from(!r1),
            u8::from(!r2),
            u8::from(!r3),
            u8::from(!r4),
            u8::from(!r5)
        );
    }
    Ok(TeethReport { ok, output: out })
}

fn cleanup(sys: &mut dyn Sys) -> Result<()> {
    let list = sys.run(&["ip", "netns", "list"])?.stdout;
    for ns in list.lines().filter_map(|l| l.split_whitespace().next()) {
        if ns.starts_with("cfab-teeth-") {
            run_ignore(sys, &["ip", "netns", "del", ns])?;
        }
    }
    Ok(())
}

fn load(sys: &mut dyn Sys, ruleset: &str) -> Result<()> {
    // nft -f /dev/stdin is not portable across netns exec; write to a temp file in /tmp of the
    // host mount ns (netns share the mount ns here).
    let path = "/tmp/cfab-teeth-policy.nft";
    sys.write(path, ruleset)?;
    run_ok(sys, &["ip", "netns", "exec", ROUTER, "nft", "-f", path])?;
    sys.remove(path)?;
    Ok(())
}

/// Pings 3 times from the endpoint behind `from` to the endpoint behind `to`; returns how many
/// replies came back (3 = the pair forwards, 0 = dropped).
fn reach(sys: &mut dyn Sys, fx: &Fixture, from: &str, to: &str) -> Result<u32> {
    let (from_ns, _) = fx.endpoint(from)?;
    let (_, to_net) = fx.endpoint(to)?;
    let dst = format!("{to_net}.2");
    let out = sys.run(&[
        "ip", "netns", "exec", from_ns, "ping", "-c", "3", "-i", "0.2", "-W", "0.3", &dst,
    ])?;
    Ok(out
        .stdout
        .lines()
        .find(|l| l.contains(" received"))
        .and_then(|l| {
            l.split(',')
                .find(|part| part.contains("received"))
                .and_then(|part| part.split_whitespace().next())
                .and_then(|n| n.parse().ok())
        })
        .unwrap_or(0))
}

fn first_if<'v>(view: &'v View, zone: &str) -> Result<&'v str> {
    // Only segment sub-ifs get endpoints (the gw leg exists in the set but has no netns).
    // Excludes Role::Rescue explicitly: a rescue row shares the zone name but has no endpoint
    // in this fixture (its ifname is never added to `ifs` — class_rows() drops it by
    // construction), so picking one up here would fail loudly via `Fixture::endpoint`, not
    // silently — but the guard makes the intended row (a real segment) explicit rather than
    // relying on rescue rows happening to sort last in the table.
    view.fabric
        .class_table
        .iter()
        .filter(|r| r.role != Role::Rescue)
        .find(|r| r.zone == zone)
        .map(|r| r.ifname.as_str())
        .ok_or_else(|| Error::fatal(format!("policy-teeth: zone {zone} has no interface")))
}

fn second_if<'v>(view: &'v View, zone: &str) -> Option<&'v str> {
    // Same exclusion as `first_if`: never let a rescue row (no fixture endpoint) satisfy the
    // "zone's second interface" lookup.
    view.fabric
        .class_table
        .iter()
        .filter(|r| r.zone == zone && r.role != Role::Rescue)
        .nth(1)
        .map(|r| r.ifname.as_str())
}

/// The pair matrix from the class table: allowed pairs pass, everything else drops, the
/// untagged admin NIC never forwards.
fn matrix(sys: &mut dyn Sys, view: &View, fx: &Fixture, out: &mut String) -> Result<bool> {
    let f = view.fabric;
    let mut ok = true;
    let mut expect = |sys: &mut dyn Sys,
                      label: &str,
                      from: &str,
                      to: &str,
                      want: u32,
                      out: &mut String|
     -> Result<()> {
        let got = reach(sys, fx, from, to)?;
        if got == want {
            let _ = writeln!(out, "  ok   {label}: {from} -> {to} = {got}/3");
        } else {
            let _ = writeln!(
                out,
                "  RED  {label}: {from} -> {to} = {got}/3 (want {want})"
            );
            ok = false;
        }
        Ok(())
    };
    let zones: Vec<String> = f.zones.iter().map(|z| z.name.clone()).collect();
    for z1 in &zones {
        for z2 in &zones {
            let want = if f.forward_allow.iter().any(|(a, b)| a == z1 && b == z2) {
                3
            } else {
                0
            };
            let to = if z1 == z2 {
                match second_if(view, z2) {
                    Some(t) => t,
                    None => {
                        let _ = writeln!(out, "  skip pair {z1}>{z2}: zone has one interface");
                        continue;
                    }
                }
            } else {
                first_if(view, z2)?
            };
            expect(sys, "pair", first_if(view, z1)?, to, want, out)?;
        }
    }
    if let Some(admin) = view.admin_if() {
        expect(sys, "admin-in", admin, first_if(view, "storage")?, 0, out)?;
        expect(sys, "admin-out", first_if(view, "storage")?, admin, 0, out)?;
    }
    if f.vrrp_gw {
        expect(
            sys,
            "vrrp-ingress",
            &f.vrrp_if.clone(),
            first_if(view, "storage")?,
            3,
            out,
        )?;
    }
    // scoped posture: another stack's interfaces forward among themselves, never into or out
    // of a zone, and the admin NIC stays fenced from them too
    let storage = first_if(view, "storage")?;
    expect(sys, "foreign-transit", FOREIGN[0], FOREIGN[1], 3, out)?;
    expect(sys, "foreign-in", FOREIGN[0], storage, 0, out)?;
    expect(sys, "foreign-out", storage, FOREIGN[0], 0, out)?;
    if let Some(admin) = view.admin_if() {
        expect(sys, "admin-to-foreign", admin, FOREIGN[0], 0, out)?;
    }
    Ok(ok)
}

/// Replace the FORWARD_ALLOW literal in the declaration text.
fn replace_forward_allow(conf: &str, new_value: &str) -> String {
    conf.lines()
        .map(|l| {
            if l.starts_with("FORWARD_ALLOW=") {
                format!("FORWARD_ALLOW=\"{new_value}\"")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_allow_replacement() {
        let conf = "A=1\nFORWARD_ALLOW=\"storage>storage\"\nB=2\n";
        let got = replace_forward_allow(conf, "storage>storage storage>cluster");
        assert!(got.contains("FORWARD_ALLOW=\"storage>storage storage>cluster\""));
        assert!(got.contains("A=1\n") && got.contains("B=2\n"));
    }

    #[test]
    fn ping_reply_parse() {
        // parsing lives in reach(); test the line format it expects
        let line = "3 packets transmitted, 3 received, 0% packet loss, time 403ms";
        let n: u32 = line
            .split(',')
            .find(|part| part.contains("received"))
            .and_then(|part| part.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        assert_eq!(n, 3);
    }
}
