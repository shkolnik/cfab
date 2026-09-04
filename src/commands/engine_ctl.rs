//! The embedded routing engine's lifecycle from the outside: start it (systemd where there
//! is one, `setsid` in a container), wait for its state socket to report ready, stop it and
//! sweep the kernel routes it owns, read its state, and check that the running engine took
//! the configuration `up` meant (spec §9 readback). Shared by up/down/verify.

use serde_json::Value;

use crate::derive::View;
use crate::emit::engine::PROTO_BASE;
use crate::engine::sock::is_engine_cmdline;
use crate::engine::{PID_NAME, SOCK_NAME};
use crate::error::{Error, Result};
use crate::model::{Fabric, MemberKind};
use crate::sys::{Sys, run_ignore, run_ok};

pub const UNIT: &str = "cfab-engine";
pub const LOG_NAME: &str = "engine.log";
/// Every kernel route-protocol id the engine may install under (spec §7 P2: base+0 ospf,
/// +1 static, +2 bgp, +3 spare); `down` sweeps exactly this range.
const PROTO_RANGE: std::ops::RangeInclusive<u8> = PROTO_BASE..=PROTO_BASE + 3;
const STOP_WAIT_MS: u64 = 10_000;
const START_WAIT_MS: u64 = 30_000;
const POLL_MS: u64 = 500;
/// How long `up` re-reads the state document before believing a configured interface really
/// is operationally down (see `settled_down_ifs`).
pub const SETTLE_MS: u64 = 3_000;
/// Route type words `ip route show` prints before the prefix (RTN_* other than unicast).
const ROUTE_TYPES: [&str; 10] = [
    "unreachable",
    "blackhole",
    "prohibit",
    "throw",
    "local",
    "broadcast",
    "anycast",
    "multicast",
    "nat",
    "unicast",
];

pub fn sock_path(f: &Fabric) -> String {
    format!("{}/{SOCK_NAME}", f.run_dir)
}

fn pid_path(f: &Fabric) -> String {
    format!("{}/{PID_NAME}", f.run_dir)
}

/// Where a detached (non-systemd) engine's stdout+stderr go.
pub fn log_path(f: &Fabric) -> String {
    format!("{}/{LOG_NAME}", f.run_dir)
}

/// Stop any running engine (systemd unit or pidfile), wait ≤10 s, SIGKILL after; then sweep
/// every kernel route carrying the engine's private protocol ids in every table (a crash
/// leaves them behind; the engine's own shutdown withdraws them). Idempotent. A pid is
/// signalled only after `/proc/<pid>/cmdline` proves it is a `cfab … engine` (the engine's
/// own test): a pidfile outlives a SIGKILLed/OOMed engine, and its pid gets recycled.
pub fn stop_and_sweep(sys: &mut dyn Sys, f: &Fabric) -> Result<()> {
    if sys.exists("/run/systemd/system") {
        run_ignore(sys, &["systemctl", "stop", &format!("{UNIT}.service")])?;
        run_ignore(
            sys,
            &["systemctl", "reset-failed", &format!("{UNIT}.service")],
        )?;
    }
    let pid_file = pid_path(f);
    if sys.exists(&pid_file) {
        let pid = sys.read(&pid_file)?.trim().to_string();
        if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
            // The status file, not the directory: readable and present for exactly the process lifetime.
            let proc_dir = format!("/proc/{pid}/status");
            let ours = sys.exists(&proc_dir)
                && sys
                    .read(&format!("/proc/{pid}/cmdline"))
                    .map(|c| is_engine_cmdline(c.as_bytes()))
                    .unwrap_or(false);
            if !ours && sys.exists(&proc_dir) {
                eprintln!(
                    "cfab: {pid_file} names pid {pid}, which is not a cfab engine — stale \
                     pidfile removed, process left alone"
                );
            }
            if ours {
                run_ignore(sys, &["kill", "-TERM", &pid])?;
                let mut waited = 0;
                while sys.exists(&proc_dir) && waited < STOP_WAIT_MS {
                    sys.sleep(std::time::Duration::from_millis(POLL_MS));
                    waited += POLL_MS;
                }
                if sys.exists(&proc_dir) {
                    eprintln!(
                        "cfab: engine pid {pid} did not exit within {}s — SIGKILL",
                        STOP_WAIT_MS / 1000
                    );
                    run_ignore(sys, &["kill", "-KILL", &pid])?;
                }
            }
        }
        sys.remove(&pid_file)?;
    }
    let n = sweep_routes(sys)?;
    if n > 0 {
        eprintln!(
            "cfab: swept {n} stale engine route(s) (proto {}..{})",
            PROTO_RANGE.start(),
            PROTO_RANGE.end()
        );
    }
    Ok(())
}

/// Delete every route in the private protocol range, keyed exactly as `ip` printed it
/// (type, prefix, table, proto, metric): the printed line itself is not `del` syntax —
/// multipath routes continue on indented `nexthop` lines and flags like `linkdown` are
/// output-only. A typed route (`unreachable`/`blackhole`/… prefix) keeps its type word in
/// front of the prefix, which is where `ip route del` wants it.
fn sweep_routes(sys: &mut dyn Sys) -> Result<usize> {
    let mut n = 0;
    for proto in PROTO_RANGE {
        let proto = proto.to_string();
        let shown = sys.run(&["ip", "-4", "route", "show", "table", "all", "proto", &proto])?;
        for line in shown.stdout.lines() {
            if line.is_empty() || line.starts_with(char::is_whitespace) {
                continue; // a multipath continuation line
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            let mut argv = vec!["ip", "route", "del"];
            let mut head = words.iter();
            match head.next() {
                Some(t) if ROUTE_TYPES.contains(t) => {
                    argv.push(t);
                    argv.extend(head.next());
                }
                Some(prefix) => argv.push(prefix),
                None => continue,
            }
            for key in ["table", "metric"] {
                let value = words
                    .iter()
                    .position(|w| *w == key)
                    .and_then(|i| words.get(i + 1));
                if let Some(v) = value {
                    argv.extend([key, v]);
                }
            }
            argv.extend(["proto", &proto]);
            run_ok(sys, &argv)?;
            n += 1;
        }
    }
    Ok(n)
}

/// Start the engine and wait until its state socket answers `"ready": true`. systemd hosts get
/// a transient unit (`Restart=on-failure`; stop waits ≤10 s before SIGKILL, matching
/// `stop_and_sweep`); a container leaf gets a detached process logging to `engine.log`.
pub fn start_and_wait(
    sys: &mut dyn Sys,
    f: &Fabric,
    exe: &str,
    config: &str,
    host: &str,
) -> Result<Value> {
    let systemd = sys.exists("/run/systemd/system");
    let tail = [exe, "--config", config, "--host", host, "engine"];
    let unit_arg = format!("--unit={UNIT}");
    if systemd {
        run_ignore(
            sys,
            &["systemctl", "reset-failed", &format!("{UNIT}.service")],
        )?;
        let mut argv = vec![
            "systemd-run",
            "--quiet",
            unit_arg.as_str(),
            "-p",
            "Restart=on-failure",
            "-p",
            "KillMode=mixed",
            "-p",
            "TimeoutStopSec=10",
        ];
        argv.extend(tail);
        run_ok(sys, &argv)?;
    } else {
        sys.spawn_detached(&tail, &log_path(f))?;
    }
    let sock = sock_path(f);
    let mut waited = 0;
    let last;
    loop {
        let why = match sys.unix_request(&sock, "state\n") {
            Ok(reply) => match parse_state(&reply) {
                Ok(doc) if doc["ready"] == true => return Ok(doc),
                Ok(_) => "engine answered but is not ready".to_string(),
                Err(e) => e.to_string(),
            },
            Err(e) => e.to_string(),
        };
        if waited >= START_WAIT_MS {
            last = why;
            break;
        }
        sys.sleep(std::time::Duration::from_millis(POLL_MS));
        waited += POLL_MS;
    }
    let logs = if systemd {
        format!("systemctl status {UNIT}; journalctl -u {UNIT}")
    } else {
        log_path(f)
    };
    Err(Error::fatal(format!(
        "engine did not become ready within {}s ({last}); see {logs}",
        START_WAIT_MS / 1000
    )))
}

/// One state read; fatal when the socket does not answer.
pub fn state(sys: &mut dyn Sys, f: &Fabric) -> Result<Value> {
    let sock = sock_path(f);
    let reply = sys
        .unix_request(&sock, "state\n")
        .map_err(|e| Error::fatal(format!("engine not running; run cfab up ({e})")))?;
    parse_state(&reply)
}

fn parse_state(reply: &str) -> Result<Value> {
    let doc: Value = serde_json::from_str(reply)
        .map_err(|e| Error::fatal(format!("engine state is not JSON: {e}")))?;
    if let Some(err) = doc["error"].as_str() {
        return Err(Error::fatal(format!("engine state request failed: {err}")));
    }
    Ok(doc)
}

/// The OSPF interfaces cfab configures per zone: segments, the identity, the ingress leg.
fn configured_ifs(view: &View, zone: &crate::model::Zone) -> Vec<String> {
    let mut ifs: Vec<String> = view
        .class_rows()
        .into_iter()
        .filter(|r| r.zone == zone.name)
        .map(|r| r.ifname)
        .collect();
    ifs.push(View::identity_if(zone));
    ifs.extend(
        view.gw_rows()
            .into_iter()
            .filter(|r| r.zone == zone.name)
            .map(|r| r.ifname),
    );
    ifs
}

/// Readback (spec §9): every zone's OSPF instance is present with the expected router-id and
/// every configured interface listed under it; a leaf's segment interfaces carry cost + offset
/// and so does every transit link its router LSA advertises (a segment still stub has no
/// link yet, so both are checked). `ready` alone is not proof the providers took the
/// configuration. Err names the first miss.
pub fn readback(view: &View, doc: &Value) -> Result<()> {
    let f = view.fabric;
    for z in &f.zones {
        let inst = &doc["ospf"][&z.name];
        if inst.is_null() {
            return Err(Error::fatal(format!(
                "engine readback: ospf instance '{}' missing",
                z.name
            )));
        }
        let want_rid = view.identity_addr(z);
        if inst["router_id"] != want_rid {
            return Err(Error::fatal(format!(
                "engine readback: ospf '{}' router-id is {} (want {want_rid})",
                z.name, inst["router_id"]
            )));
        }
        for ifn in configured_ifs(view, z) {
            let got = &inst["interfaces"][&ifn];
            if got.is_null() {
                return Err(Error::fatal(format!(
                    "engine readback: ospf '{}' does not list interface {ifn}",
                    z.name
                )));
            }
            // A listed interface always carries an ietf-ospf state; a document without one
            // is malformed (no wiring fault can produce it) and would read as healthy to the
            // operational check `up` runs on top of this one.
            if if_state(got).is_none() {
                return Err(Error::fatal(format!(
                    "engine readback: ospf '{}' interface {ifn} reports no state (got {}); the \
                     engine's state document is malformed — a cfab/holo defect, not a wiring \
                     fault",
                    z.name, got["state"]
                )));
            }
        }
        if view.kind() != MemberKind::Leaf {
            continue;
        }
        let rows: Vec<_> = view
            .class_rows()
            .into_iter()
            .filter(|r| r.zone == z.name)
            .collect();
        for r in &rows {
            let want = u64::from(r.ospf_cost + f.leaf_cost_offset);
            let got = inst["interfaces"][&r.ifname]["cost"].as_u64();
            if got != Some(want) {
                return Err(Error::fatal(format!(
                    "engine readback: ospf '{}' {} cost is {} (want {want} = cost + \
                     LEAF_COST_OFFSET)",
                    z.name, r.ifname, inst["interfaces"][&r.ifname]["cost"]
                )));
            }
        }
        let transit = inst["self_lsa_links"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|l| is_transit(&l["type"]));
        for link in transit {
            let addr = link["if"].as_str().unwrap_or("?");
            let Some(r) = rows.iter().find(|r| view.segment_addr(z, r.seg) == addr) else {
                return Err(Error::fatal(format!(
                    "engine readback: ospf '{}' advertises a transit link from {addr}, which \
                     is not one of this member's segment addresses",
                    z.name
                )));
            };
            let want = u64::from(r.ospf_cost + f.leaf_cost_offset);
            if link["metric"].as_u64() != Some(want) {
                return Err(Error::fatal(format!(
                    "engine readback: ospf '{}' transit link {} ({addr}) advertised at {} \
                     (want {want} = cost + LEAF_COST_OFFSET)",
                    z.name, r.ifname, link["metric"]
                )));
            }
        }
    }
    Ok(())
}

/// An interface's ietf-ospf state as a bare word (`down` `loopback` `waiting`
/// `point-to-point` `dr-other` `backup` `dr`), with any module prefix dropped.
fn if_state(i: &Value) -> Option<&str> {
    i["state"]
        .as_str()
        .map(|s| s.rsplit(':').next().unwrap_or(s))
}

/// The configured OSPF interfaces this document reports operationally `down`, as
/// `zone/ifname`. `waiting` is not down: a passive identity interface never leaves it
/// (gate-0 evidence §8.2).
fn down_ifs(view: &View, doc: &Value) -> Vec<String> {
    let mut down = Vec::new();
    for z in &view.fabric.zones {
        for ifn in configured_ifs(view, z) {
            if if_state(&doc["ospf"][&z.name]["interfaces"][&ifn]) == Some("down") {
                down.push(format!("{}/{ifn}", z.name));
            }
        }
    }
    down
}

/// The operational companion to `readback`, for `up`: the configured OSPF interfaces the
/// engine still reports `down` after a bounded settle, `zone/ifname`. Empty is healthy.
///
/// Two reasons for the settle rather than one read. holo-ospf creates every interface in
/// state `down` and leaves it only once its ibus subscription round trip to holo-interface
/// delivers the netlink view — that lands on another task, after the commit returns and the
/// state socket binds — so the first document a fresh engine answers can show a healthy
/// interface `down`. And a link that is merely slow to come up is worth those seconds.
///
/// Never fatal, by design: a wire with no carrier at `up` time is a genuine `down` (a VLAN
/// over a carrier-less lower wire is IFF_UP but not IFF_RUNNING, which is what holo reads),
/// and refusing the apply for it would leave the host with no fabric at all where it would
/// otherwise have come up on its surviving wires. `verify` grades the same condition
/// degraded. Whether a whole zone being down should instead refuse is James's call.
pub fn settled_down_ifs(sys: &mut dyn Sys, view: &View, doc: &Value) -> Result<Vec<String>> {
    let mut down = down_ifs(view, doc);
    let mut waited = 0;
    while !down.is_empty() && waited < SETTLE_MS {
        sys.sleep(std::time::Duration::from_millis(POLL_MS));
        waited += POLL_MS;
        down = down_ifs(view, &state(sys, view.fabric)?);
    }
    Ok(down)
}

/// A router-LSA link type as the state document carries it (holo's identity name, with or
/// without its module prefix, or the RFC 2328 numeric type 2).
pub fn is_transit(t: &Value) -> bool {
    match t {
        Value::String(s) => {
            let s = s.rsplit(':').next().unwrap_or(s);
            s == "transit-network-link" || s == "transit-network"
        }
        Value::Number(n) => n.as_u64() == Some(2),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::sys::mock::MockSys;
    use serde_json::json;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// A state document in the shape `engine::state::document` produces, for every zone of
    /// `view`, with each configured interface listed and (leaf) the transit links at
    /// cost + offset.
    pub fn healthy_doc(view: &View) -> Value {
        let f = view.fabric;
        let mut ospf = serde_json::Map::new();
        for z in &f.zones {
            let mut ifs = serde_json::Map::new();
            let mut links = Vec::new();
            for ifn in configured_ifs(view, z) {
                let row = view
                    .class_rows()
                    .into_iter()
                    .find(|r| r.ifname == ifn && r.zone == z.name);
                let cost = row.as_ref().map(|r| {
                    if view.kind() == MemberKind::Leaf {
                        r.ospf_cost + f.leaf_cost_offset
                    } else {
                        r.ospf_cost
                    }
                });
                ifs.insert(
                    ifn.clone(),
                    json!({ "state": "dr", "cost": cost, "passive": row.is_none(), "neighbors": [] }),
                );
                if let Some(r) = row {
                    links.push(json!({
                        "if": view.segment_addr(z, r.seg),
                        "link_id": view.segment_addr(z, r.seg),
                        "type": "transit-network-link",
                        "metric": cost,
                    }));
                }
            }
            ospf.insert(
                z.name.clone(),
                json!({
                    "router_id": view.identity_addr(z),
                    "interfaces": Value::Object(ifs),
                    "self_lsa_links": links,
                }),
            );
        }
        json!({ "ready": true, "ospf": Value::Object(ospf), "bfd": [], "bgp": [], "vrrp": [] })
    }

    #[test]
    fn readback_accepts_a_healthy_host_and_leaf() {
        let f = fabric();
        for m in ["pve1-tb", "pve3-tb"] {
            let view = View::new(&f, m).unwrap();
            readback(&view, &healthy_doc(&view)).unwrap();
        }
    }

    #[test]
    fn readback_names_the_missing_instance() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut doc = healthy_doc(&view);
        doc["ospf"].as_object_mut().unwrap().remove("mgmt");
        let e = readback(&view, &doc).unwrap_err().to_string();
        assert!(e.contains("ospf instance 'mgmt' missing"), "{e}");
    }

    #[test]
    fn readback_names_a_wrong_router_id_and_a_missing_interface() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut doc = healthy_doc(&view);
        doc["ospf"]["storage"]["router_id"] = json!("10.99.0.9");
        let e = readback(&view, &doc).unwrap_err().to_string();
        assert!(
            e.contains("ospf 'storage' router-id is \"10.99.0.9\" (want 10.99.0.1)"),
            "{e}"
        );
        let mut doc = healthy_doc(&view);
        doc["ospf"]["cluster"]["interfaces"]
            .as_object_mut()
            .unwrap()
            .remove("cfab-id199");
        let e = readback(&view, &doc).unwrap_err().to_string();
        assert!(
            e.contains("ospf 'cluster' does not list interface cfab-id199"),
            "{e}"
        );
    }

    /// A listed interface with no `state` is a malformed document, not a wiring fault: it
    /// must not slip past as healthy (the operational check reads an absent state as "not
    /// down").
    #[test]
    fn readback_rejects_an_interface_with_no_state() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        for broken in [json!(null), json!(3)] {
            let mut doc = healthy_doc(&view);
            doc["ospf"]["storage"]["interfaces"]["cfab-st"]["state"] = broken.clone();
            let e = readback(&view, &doc).unwrap_err().to_string();
            assert!(
                e.contains("ospf 'storage' interface cfab-st reports no state"),
                "{broken}: {e}"
            );
        }
        let mut doc = healthy_doc(&view);
        doc["ospf"]["storage"]["interfaces"]["cfab-st"]
            .as_object_mut()
            .unwrap()
            .remove("state");
        let e = readback(&view, &doc).unwrap_err().to_string();
        assert!(
            e.contains("ospf 'storage' interface cfab-st reports no state"),
            "{e}"
        );
    }

    /// Gate-0 evidence §8.4: an interface the engine reports `down` — a wire with no carrier
    /// at `up` time, or one `fabric.conf` names that the kernel does not have — is named, not
    /// silently accepted. Only after the settle, and only as a list for the caller to warn
    /// about: `settled_down_ifs` never errors.
    #[test]
    fn settled_down_ifs_names_an_interface_still_down_after_the_settle() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        for state in ["down", "ietf-ospf:down"] {
            let mut doc = healthy_doc(&view);
            doc["ospf"]["storage"]["interfaces"]["cfab-st"]["state"] = json!(state);
            let mut sys = MockSys::default().socket("/run/cfab/engine.sock", &doc.to_string());
            let got = settled_down_ifs(&mut sys, &view, &doc).unwrap();
            assert_eq!(got, ["storage/cfab-st"], "{state}");
            // Bounded: it re-read for SETTLE_MS and stopped, it did not spin.
            assert_eq!(sys.slept.len() as u64, SETTLE_MS / POLL_MS, "{state}");
        }
        // The identity interface is configured too, and is named the same way.
        let mut doc = healthy_doc(&view);
        doc["ospf"]["cluster"]["interfaces"]["cfab-id199"]["state"] = json!("down");
        let mut sys = MockSys::default().socket("/run/cfab/engine.sock", &doc.to_string());
        assert_eq!(
            settled_down_ifs(&mut sys, &view, &doc).unwrap(),
            ["cluster/cfab-id199"]
        );
    }

    /// The startup race: holo-ospf creates an interface in `down` and leaves it only when its
    /// ibus round trip to holo-interface lands, which can be after the state socket binds. A
    /// healthy host must not be named for a state it has already left, so the settle re-reads
    /// the document over the socket — the read `up` itself would make.
    #[test]
    fn settled_down_ifs_clears_when_the_interface_leaves_down_during_the_settle() {
        let f = fabric();
        let view = View::new(&f, "pve1-tb").unwrap();
        let mut down = healthy_doc(&view);
        down["ospf"]["storage"]["interfaces"]["cfab-st"]["state"] = json!("down");
        let mut sys = MockSys::default().socket_seq(
            "/run/cfab/engine.sock",
            &[down.to_string(), healthy_doc(&view).to_string()],
        );
        assert!(
            settled_down_ifs(&mut sys, &view, &down).unwrap().is_empty(),
            "an interface that came up during the settle must not be named"
        );
        // Still down on the first re-read, up on the second: two waits, not the full settle.
        assert_eq!(sys.slept.len(), 2);
    }

    /// Gate-0 evidence §8.2: a passive identity interface never leaves `waiting` (holo does
    /// not run the interface FSM on it). That is healthy, as is every other state a working
    /// link can be in — none of them is reported, and none of them costs a settle.
    #[test]
    fn settled_down_ifs_accepts_waiting_and_every_other_state() {
        let f = fabric();
        for m in ["pve1-tb", "pve3-tb"] {
            let view = View::new(&f, m).unwrap();
            let mut doc = healthy_doc(&view);
            for z in &f.zones {
                let ifs = doc["ospf"][&z.name]["interfaces"].as_object_mut().unwrap();
                ifs.get_mut(&View::identity_if(z)).unwrap()["state"] = json!("waiting");
            }
            let mut sys = MockSys::default().socket("/run/cfab/engine.sock", &doc.to_string());
            assert!(settled_down_ifs(&mut sys, &view, &doc).unwrap().is_empty());
            assert!(sys.slept.is_empty());
            for state in ["bdr", "dr-other", "point-to-point", "loopback", "dr"] {
                let mut doc = healthy_doc(&view);
                for z in &f.zones {
                    let ifs = doc["ospf"][&z.name]["interfaces"].as_object_mut().unwrap();
                    for (_, v) in ifs.iter_mut() {
                        v["state"] = json!(state);
                    }
                }
                let mut sys = MockSys::default().socket("/run/cfab/engine.sock", &doc.to_string());
                let got = settled_down_ifs(&mut sys, &view, &doc).unwrap();
                assert!(got.is_empty(), "{state}: {got:?}");
            }
        }
    }

    #[test]
    fn readback_leaf_transit_link_must_carry_the_offset() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = healthy_doc(&view);
        doc["ospf"]["storage"]["self_lsa_links"][0]["metric"] = json!(10);
        let e = readback(&view, &doc).unwrap_err().to_string();
        assert!(
            e.contains("transit link cfab-st (10.99.1.3) advertised at 10 (want 30010"),
            "{e}"
        );
        // A link from an address that is not ours cannot be checked: refuse, not ignore.
        let mut doc = healthy_doc(&view);
        doc["ospf"]["storage"]["self_lsa_links"][0]["if"] = json!("10.99.1.7");
        let e = readback(&view, &doc).unwrap_err().to_string();
        assert!(e.contains("transit link from 10.99.1.7"), "{e}");
    }

    #[test]
    fn readback_leaf_checks_the_configured_cost_with_and_without_an_lsa() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let mut doc = healthy_doc(&view);
        doc["ospf"]["storage"]["self_lsa_links"] = json!([]);
        readback(&view, &doc).unwrap();
        doc["ospf"]["storage"]["interfaces"]["cfab-st"]["cost"] = json!(10);
        let e = readback(&view, &doc).unwrap_err().to_string();
        assert!(
            e.contains("ospf 'storage' cfab-st cost is 10 (want 30010"),
            "{e}"
        );
        // Mixed state: one segment already transit (LSA link fine), the other still stub
        // with a wrong configured cost — the stub one must still be caught.
        let mut doc = healthy_doc(&view);
        let links = doc["ospf"]["storage"]["self_lsa_links"]
            .as_array_mut()
            .unwrap();
        links.truncate(1);
        doc["ospf"]["storage"]["interfaces"]["cfab-st-bk"]["cost"] = json!(10);
        let e = readback(&view, &doc).unwrap_err().to_string();
        assert!(
            e.contains("ospf 'storage' cfab-st-bk cost is 10 (want 30100"),
            "{e}"
        );
    }

    #[test]
    fn sweep_deletes_each_private_proto_route_by_its_key() {
        let f = fabric();
        let mut sys = MockSys::default().on_stdout(
            &["ip", "-4", "route", "show", "table", "all", "proto", "201"],
            "10.99.0.2 proto 201 metric 20 src 10.99.0.1\n\
             \tnexthop via 10.99.1.2 dev cfab-st weight 1\n\
             \tnexthop via 10.99.2.2 dev cfab-st-bk weight 1\n\
             10.249.0.2 via 10.249.1.2 dev cfab-mg table 249 proto 201 metric 20 linkdown\n",
        );
        stop_and_sweep(&mut sys, &f).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("ip route del"))
            .collect();
        assert_eq!(
            dels,
            [
                "ip route del 10.99.0.2 metric 20 proto 201",
                "ip route del 10.249.0.2 table 249 metric 20 proto 201"
            ]
        );
        // Every id of the range is swept, no systemd → no systemctl.
        for p in 201..=204 {
            assert!(sys.ran(&format!("route show table all proto {p}")));
        }
        assert!(!sys.ran("systemctl"));
    }

    const ENGINE_CMDLINE: &str =
        "/usr/bin/cfab\0--config\0/etc/cfab/fabric.conf\0--host\0pve3-tb\0engine\0";

    #[test]
    fn stop_terminates_a_pidfile_engine_and_kills_it_after_the_wait() {
        let f = fabric();
        let mut sys = MockSys::default()
            .file("/run/cfab/engine.pid", "4242\n")
            .file("/proc/4242/status", "")
            .file("/proc/4242/cmdline", ENGINE_CMDLINE);
        stop_and_sweep(&mut sys, &f).unwrap();
        assert!(sys.ran("kill -TERM 4242"));
        assert!(sys.ran("kill -KILL 4242"), "never exited → SIGKILL");
        assert_eq!(sys.slept.len(), 20, "10 s in 500 ms steps");
        assert!(sys.ran("rm /run/cfab/engine.pid"));
    }

    /// A recycled pid: the pidfile survived a SIGKILLed engine and now names some other
    /// program. Prove ownership before destroy — no signal, stale pidfile dropped.
    #[test]
    fn stop_leaves_a_recycled_pid_alone_and_drops_the_stale_pidfile() {
        let f = fabric();
        for cmdline in [
            "/usr/sbin/sshd\0-D\0",
            "/usr/bin/cfab\0verify\0",
            "/usr/bin/some-engine\0engine\0",
            "",
        ] {
            let mut sys = MockSys::default()
                .file("/run/cfab/engine.pid", "4242\n")
                .file("/proc/4242/status", "")
                .file("/proc/4242/cmdline", cmdline);
            stop_and_sweep(&mut sys, &f).unwrap();
            assert!(!sys.ran("kill"), "{cmdline:?}: {:?}", sys.calls);
            assert!(sys.slept.is_empty());
            assert!(sys.ran("rm /run/cfab/engine.pid"));
        }
        // Unreadable cmdline (process gone between the two reads): same answer.
        let mut sys = MockSys::default()
            .file("/run/cfab/engine.pid", "4242\n")
            .file("/proc/4242/status", "");
        stop_and_sweep(&mut sys, &f).unwrap();
        assert!(!sys.ran("kill"));
        assert!(sys.ran("rm /run/cfab/engine.pid"));
    }

    #[test]
    fn sweep_keeps_the_type_word_of_a_typed_route() {
        let f = fabric();
        let mut sys = MockSys::default().on_stdout(
            &["ip", "-4", "route", "show", "table", "all", "proto", "202"],
            "unreachable 10.99.0.0/16 table 99 proto 202 metric 20\n\
             blackhole 10.0.0.0/8 proto 202\n",
        );
        stop_and_sweep(&mut sys, &f).unwrap();
        let dels: Vec<&String> = sys
            .calls
            .iter()
            .filter(|c| c.starts_with("ip route del"))
            .collect();
        assert_eq!(
            dels,
            [
                "ip route del unreachable 10.99.0.0/16 table 99 metric 20 proto 202",
                "ip route del blackhole 10.0.0.0/8 proto 202"
            ]
        );
    }

    #[test]
    fn stop_uses_systemd_where_present() {
        let f = fabric();
        let mut sys = MockSys::default().file("/run/systemd/system", "");
        stop_and_sweep(&mut sys, &f).unwrap();
        assert!(sys.ran("systemctl stop cfab-engine.service"));
        assert!(!sys.ran("kill"));
    }

    #[test]
    fn start_returns_the_ready_document_or_names_the_logs() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let doc = healthy_doc(&view).to_string();
        let mut sys = MockSys::default().socket("/run/cfab/engine.sock", &doc);
        let got = start_and_wait(
            &mut sys,
            &f,
            "/usr/bin/cfab",
            "/etc/cfab/fabric.conf",
            "pve3-tb",
        )
        .unwrap();
        assert_eq!(got["ready"], true);
        assert!(sys.ran(
            "spawn_detached /usr/bin/cfab --config /etc/cfab/fabric.conf --host pve3-tb engine \
             >> /run/cfab/engine.log"
        ));
        let mut sys = MockSys::default();
        let e = start_and_wait(
            &mut sys,
            &f,
            "/usr/bin/cfab",
            "/etc/cfab/fabric.conf",
            "pve3-tb",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("see /run/cfab/engine.log"), "{e}");
        let mut sys = MockSys::default().file("/run/systemd/system", "");
        let e = start_and_wait(
            &mut sys,
            &f,
            "/usr/bin/cfab",
            "/etc/cfab/fabric.conf",
            "pve1-tb",
        )
        .unwrap_err()
        .to_string();
        assert!(sys.ran("systemd-run --quiet --unit=cfab-engine -p Restart=on-failure"));
        assert!(
            e.contains("see systemctl status cfab-engine; journalctl -u cfab-engine"),
            "{e}"
        );
        assert_eq!(sys.slept.len(), 60, "30 s in 500 ms steps");
    }

    #[test]
    fn state_fails_loud_without_an_engine() {
        let f = fabric();
        let mut sys = MockSys::default();
        let e = state(&mut sys, &f).unwrap_err().to_string();
        assert!(e.contains("engine not running; run cfab up"), "{e}");
        let mut sys = MockSys::default().socket("/run/cfab/engine.sock", "{\"error\":\"boom\"}\n");
        let e = state(&mut sys, &f).unwrap_err().to_string();
        assert!(e.contains("engine state request failed: boom"), "{e}");
    }
}
