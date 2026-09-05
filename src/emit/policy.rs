//! The nft forward policy (table inet cfab-fwd) derived from the class table. Default-deny for
//! everything that touches a cfab interface: only FORWARD_ALLOW pairs pass, the admin interface
//! never transits, every drop is counted. A packet that touches no cfab interface on either
//! side is another stack's business and is accepted here (nft forward hooks are cumulative, so
//! that stack's own policy still applies) — scoped posture. Pure text out.

use crate::derive::View;
use crate::error::Result;

pub fn generate(view: &View) -> Result<String> {
    let f = view.fabric;
    let mut out = String::new();
    out.push_str("table inet cfab-fwd\n");
    out.push_str("delete table inet cfab-fwd\n");
    out.push_str("table inet cfab-fwd {\n");
    match view.admin_if() {
        Some(a) => out.push_str(&format!(
            "  set admin {{ type ifname; elements = {{ \"{a}\" }} }}\n"
        )),
        None => out.push_str("  set admin { type ifname; }\n"),
    }
    for z in &f.zones {
        let mut ifs: Vec<String> = view
            .zone_ifs(&z.name)
            .into_iter()
            .map(|i| format!("\"{i}\""))
            .collect();
        if z.name == "storage" && f.vrrp_gw {
            ifs.push(format!("\"{}\"", f.vrrp_if));
        }
        if ifs.is_empty() {
            out.push_str(&format!("  set {} {{ type ifname; }}\n", z.name));
        } else {
            out.push_str(&format!(
                "  set {} {{ type ifname; elements = {{ {} }} }}\n",
                z.name,
                ifs.join(",")
            ));
        }
    }
    let owned: Vec<String> = view
        .owned_forwarding()
        .into_iter()
        .map(|(i, _)| format!("\"{i}\""))
        .collect();
    out.push_str(&format!(
        "  set cfab {{ type ifname; elements = {{ {} }} }}\n",
        owned.join(",")
    ));
    out.push_str(
        "  chain forward {\n\
         \x20   type filter hook forward priority filter; policy drop;\n\
         \x20   iifname @admin counter drop comment \"admin-in\"\n\
         \x20   oifname @admin counter drop comment \"admin-out\"\n\
         \x20   iifname != @cfab oifname != @cfab counter accept comment \"foreign-transit\"\n\
         \x20   ct state invalid counter comment \"ct-invalid-seen\"\n\
         \x20   ct state established,related accept comment \"return-of-allowed\"\n",
    );
    for (from, to) in &f.forward_allow {
        // Zone existence is already validated at parse; emit in declaration order.
        out.push_str(&format!(
            "    iifname @{from} oifname @{to} counter accept comment \"allow-{from}-{to}\"\n"
        ));
    }
    out.push_str("    counter comment \"default-deny\"\n  }\n}\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::model::Fabric;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// PROVING existing behavior, not new logic: `zone_ifs()` (Task 2) already returns the
    /// rescue bond after a zone's segments, and this generator just emits whatever `zone_ifs`
    /// gives it — no policy.rs code changed for this task. The bond belongs in the zone's set
    /// (so `FORWARD_ALLOW storage>storage` covers island-disjoint transit through it) and in
    /// the `cfab` owned set (`owned_forwarding()`, which the watchdog and scoped posture read).
    /// A slave is L2 only: it must NOT be in the zone set (it carries no zone traffic of its
    /// own — the bond does), but it IS in `owned_forwarding()` (Task 2, `false`/never-transit)
    /// and so correctly appears in the `cfab` owned set too — that set means "an interface cfab
    /// owns," not "an interface that transits," and a slave's own traffic (the bond's frames on
    /// the wire) must not fall into the blanket `iifname != @cfab` foreign-transit accept.
    #[test]
    fn zone_set_carries_the_rescue_bond_never_a_slave_owned_set_carries_both() {
        for member in ["pve1-tb", "pve3-tb"] {
            let f = fabric();
            let v = View::new(&f, member).unwrap();
            let out = generate(&v).unwrap();
            for row in v.rescue_rows() {
                let want = format!("\"{}\"", row.ifname);
                let set_line = out
                    .lines()
                    .find(|l| l.trim_start().starts_with(&format!("set {} {{", row.zone)))
                    .unwrap_or_else(|| panic!("{member}: missing set line for {}", row.zone));
                assert!(
                    set_line.contains(&want),
                    "{member}: zone set for {} missing the rescue bond: {set_line}",
                    row.zone
                );
                let cfab_line = out
                    .lines()
                    .find(|l| l.trim_start().starts_with("set cfab {"))
                    .unwrap();
                assert!(
                    cfab_line.contains(&want),
                    "{member}: cfab owned set missing the rescue bond: {cfab_line}"
                );
                for slave in &row.slaves {
                    let slave_tag = format!("\"{}\"", slave.ifname);
                    assert!(
                        !set_line.contains(&slave_tag),
                        "{member}: zone set for {} names a rescue slave {}: it carries no zone \
                         traffic of its own, the bond does",
                        row.zone,
                        slave.ifname
                    );
                    assert!(
                        cfab_line.contains(&slave_tag),
                        "{member}: cfab owned set missing the rescue slave {} \
                         (owned_forwarding lists it with transit=false)",
                        slave.ifname
                    );
                }
            }
        }
    }
}
