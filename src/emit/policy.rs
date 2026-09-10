//! The nft forward policy (table inet cfab-fwd) derived from the class table. Default-deny for
//! everything that touches a cfab interface: only `[forward] allow` pairs pass, the admin interface
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
    // Every wire of a host: the untagged path of each NIC is the admin plane, so each is
    // fenced out of transit. A leaf owns no L3 of ours on any wire, and its set is empty.
    let admin: Vec<String> = view
        .admin_ifs()
        .into_iter()
        .map(|a| format!("\"{a}\""))
        .collect();
    if admin.is_empty() {
        out.push_str("  set admin { type ifname; }\n");
    } else {
        out.push_str(&format!(
            "  set admin {{ type ifname; elements = {{ {} }} }}\n",
            admin.join(",")
        ));
    }
    for z in &f.zones {
        let ifs: Vec<String> = view
            .zone_ifs(&z.name)
            .into_iter()
            .map(|i| format!("\"{i}\""))
            .collect();
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
    // Spec §5.2, ruling 6: the VMs this member currently knows on each workload leg. Declared
    // empty and filled at runtime by `workload::hostroutes` — an empty set means "no VM is
    // local", which is the safe reading of "cfab is not running the reconcile".
    for row in view.workload_rows() {
        out.push_str(&format!(
            "  set {} {{ type ipv4_addr; }}\n",
            row.wl.local_set()
        ));
    }
    out.push_str(
        "  chain forward {\n\
         \x20   type filter hook forward priority filter; policy drop;\n\
         \x20   iifname @admin counter drop comment \"admin-in\"\n\
         \x20   oifname @admin counter drop comment \"admin-out\"\n\
         \x20   iifname != @cfab oifname != @cfab counter accept comment \"foreign-transit\"\n\
         \x20   ct state invalid counter comment \"ct-invalid-seen\"\n",
    );
    // Ruling 6 (drop and count), and the reason it sits HERE: a stray forward is a reply to a
    // VM that has left this host, so it is an ESTABLISHED packet and the `return-of-allowed`
    // accept below would take it first (r2 review N5). Above it, and above the per-zone
    // accepts, the drop is the only verdict a packet for an unknown VM can reach. The
    // aggregate /24 is what brings the packet to a host at all; this is what stops the host
    // that does not own the VM from putting it back on VLAN 3.
    for row in view.workload_rows() {
        for z in &row.wl.allow {
            out.push_str(&format!(
                "    iifname @{z} oifname \"{ifn}\" ip daddr != @{set} counter drop \
                 comment \"stray-{wl}\"\n",
                ifn = row.wl.leg_ifname(),
                set = row.wl.local_set(),
                wl = row.wl.name
            ));
        }
    }
    out.push_str("    ct state established,related accept comment \"return-of-allowed\"\n");
    for (from, to) in &f.forward_allow {
        // Zone existence is already validated at parse; emit in declaration order.
        out.push_str(&format!(
            "    iifname @{from} oifname @{to} counter accept comment \"allow-{from}-{to}\"\n"
        ));
    }
    // Spec §5 item 6: a symmetric, stateless accept pair per (workload, allowed zone).
    // Stateless is load-bearing (R4 measured `ct-invalid-seen` +3 when the storage→ifname
    // accept was deleted): the reverse leg is a plain accept, never `ct state`.
    for row in view.workload_rows() {
        for z in &row.wl.allow {
            out.push_str(&format!(
                "    iifname \"{ifn}\" oifname @{z} counter accept comment \"allow-{wl}-{z}\"\n",
                ifn = row.wl.leg_ifname(),
                wl = row.wl.name
            ));
            out.push_str(&format!(
                "    iifname @{z} oifname \"{ifn}\" counter accept comment \"allow-{z}-{wl}\"\n",
                ifn = row.wl.leg_ifname(),
                wl = row.wl.name
            ));
        }
    }
    out.push_str("    counter comment \"default-deny\"\n  }\n}\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::Declaration;
    use crate::model::Fabric;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.toml"))
                .unwrap();
        Fabric::from_decl(&Declaration::parse(&text).unwrap()).unwrap()
    }

    fn wl_fabric() -> Fabric {
        Fabric::from_decl(
            &Declaration::parse(&crate::decl::fixtures::with_workload(
                &crate::decl::fixtures::example(),
            ))
            .unwrap(),
        )
        .unwrap()
    }

    /// Spec §5 item 6: a workload gets a symmetric, stateless accept pair per allowed zone —
    /// stateless is load-bearing (R4 measured `ct-invalid-seen` +3 when the storage→ifname
    /// accept was deleted) — and its ifname lands in the `cfab` owned set so an undeclared pair
    /// hits default-deny rather than the blanket foreign-transit accept.
    #[test]
    fn a_workload_gets_symmetric_stateless_accepts_and_its_ifname_in_the_owned_set() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let t = generate(&v).unwrap();
        assert!(
            t.contains(
                "iifname \"cfab-work-vms\" oifname @storage counter accept comment \"allow-vms-storage\""
            ),
            "{t}"
        );
        assert!(
            t.contains(
                "iifname @storage oifname \"cfab-work-vms\" counter accept comment \"allow-storage-vms\""
            ),
            "{t}"
        );
        let cfab_set = t.split("set cfab {").nth(1).unwrap();
        assert!(
            cfab_set.contains("cfab-work-vms"),
            "owned set must carry the workload ifname so undeclared pairs hit default-deny, \
             not foreign-transit: {cfab_set}"
        );
        let pos = |s: &str| t.find(s).unwrap();
        assert!(
            pos("allow-vms-storage") > pos("return-of-allowed")
                && pos("allow-vms-storage") < pos("default-deny")
        );
    }

    /// The rule lines of the forward chain, trimmed, in order — the only honest way to assert
    /// a rule's POSITION, which is what decides whether it can match at all.
    fn chain_rules(text: &str) -> Vec<String> {
        text.lines()
            .skip_while(|l| !l.trim_start().starts_with("chain forward {"))
            .skip(1)
            .take_while(|l| l.trim() != "}")
            .map(|l| l.trim().to_string())
            .collect()
    }

    /// Ruling 6 (drop and count): a host forwards fabric traffic onto its leg only for the VMs
    /// it currently knows, and the rule sits between `ct state invalid` and the
    /// `return-of-allowed` accept. Position is the whole substance: a reply to a VM that left
    /// is an ESTABLISHED packet, so below that accept this rule would never match (r2 review
    /// N5), and below the per-zone accepts it would never match either.
    #[test]
    fn a_stray_forward_onto_a_workload_leg_is_dropped_between_ct_invalid_and_the_return_accept() {
        let f = wl_fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let t = generate(&v).unwrap();
        assert!(
            t.contains("  set cfab-work-vms-local { type ipv4_addr; }\n"),
            "the set the drop reads must be declared: {t}"
        );
        let rules = chain_rules(&t);
        let at = |needle: &str| {
            rules
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("no rule matching {needle}: {rules:#?}"))
        };
        assert_eq!(
            rules[at("stray-vms")],
            "iifname @storage oifname \"cfab-work-vms\" ip daddr != @cfab-work-vms-local \
             counter drop comment \"stray-vms\""
        );
        assert_eq!(at("stray-vms"), at("ct-invalid-seen") + 1);
        assert_eq!(at("return-of-allowed"), at("stray-vms") + 1);
        assert!(at("stray-vms") < at("allow-storage-vms"));
        // A member with no workload row declares no set and writes no drop.
        let leaf = generate(&View::new(&f, "pve3-tb").unwrap()).unwrap();
        assert!(!leaf.contains("-local"), "{leaf}");
        assert!(!leaf.contains("stray-"), "{leaf}");
    }

    /// One rule per allowed zone, in declaration order, all of them still above the accept —
    /// the packet arrives on whichever zone reaches this workload, and each has to be told.
    #[test]
    fn a_multi_zone_workload_gets_one_stray_drop_per_allowed_zone() {
        let f = Fabric::from_decl(
            &Declaration::parse(&crate::decl::fixtures::with_multi_zone_allow_workload(
                &crate::decl::fixtures::example(),
            ))
            .unwrap(),
        )
        .unwrap();
        let v = View::new(&f, "pve1-tb").unwrap();
        let rules = chain_rules(&generate(&v).unwrap());
        let strays: Vec<&String> = rules.iter().filter(|l| l.contains("stray-vms")).collect();
        assert_eq!(strays.len(), 2, "{rules:#?}");
        assert!(strays[0].starts_with("iifname @storage "), "{strays:?}");
        assert!(strays[1].starts_with("iifname @mgmt "), "{strays:?}");
        let accept = rules
            .iter()
            .position(|l| l.contains("return-of-allowed"))
            .unwrap();
        for s in &strays {
            assert!(rules.iter().position(|l| &l == s).unwrap() < accept);
        }
    }

    /// PROVING existing behavior, not new logic: `zone_ifs()` (Task 2) already returns the
    /// fallback bond after a zone's segments, and this generator just emits whatever `zone_ifs`
    /// gives it — no policy.rs code changed for this task. The bond belongs in the zone's set
    /// (so ``[forward] allow` storage>storage` covers domain-disjoint transit through it) and in
    /// the `cfab` owned set (`owned_forwarding()`, which the watchdog and scoped posture read).
    /// A port is L2 only: it must NOT be in the zone set (it carries no zone traffic of its
    /// own — the bond does), but it IS in `owned_forwarding()` (Task 2, `false`/never-transit)
    /// and so correctly appears in the `cfab` owned set too — that set means "an interface cfab
    /// owns," not "an interface that transits," and a port's own traffic (the bond's frames on
    /// the wire) must not fall into the blanket `iifname != @cfab` foreign-transit accept.
    #[test]
    fn zone_set_carries_the_fallback_bond_never_a_port_owned_set_carries_both() {
        for member in ["pve1-tb", "pve3-tb"] {
            let f = fabric();
            let v = View::new(&f, member).unwrap();
            let out = generate(&v).unwrap();
            for row in v.fallback_rows() {
                let want = format!("\"{}\"", row.ifname);
                let set_line = out
                    .lines()
                    .find(|l| l.trim_start().starts_with(&format!("set {} {{", row.zone)))
                    .unwrap_or_else(|| panic!("{member}: missing set line for {}", row.zone));
                assert!(
                    set_line.contains(&want),
                    "{member}: zone set for {} missing the fallback bond: {set_line}",
                    row.zone
                );
                let cfab_line = out
                    .lines()
                    .find(|l| l.trim_start().starts_with("set cfab {"))
                    .unwrap();
                assert!(
                    cfab_line.contains(&want),
                    "{member}: cfab owned set missing the fallback bond: {cfab_line}"
                );
                for port in &row.ports {
                    let port_tag = format!("\"{}\"", port.ifname);
                    assert!(
                        !set_line.contains(&port_tag),
                        "{member}: zone set for {} names a fallback port {}: it carries no zone \
                         traffic of its own, the bond does",
                        row.zone,
                        port.ifname
                    );
                    assert!(
                        cfab_line.contains(&port_tag),
                        "{member}: cfab owned set missing the fallback port {} \
                         (owned_forwarding lists it with transit=false)",
                        port.ifname
                    );
                }
            }
        }
    }

    /// Every wire of a HOST is the admin plane (its untagged path), so the admin set lists
    /// them all and the first two rules drop anything forwarded in or out of any of them. A
    /// leaf owns none of it: the set is present but empty, and an empty `@admin` matches
    /// nothing, so the drop rules are inert rather than absent.
    #[test]
    fn the_admin_set_is_every_wire_on_a_host_and_empty_on_a_leaf() {
        let f = fabric();
        let host = View::new(&f, "pve1-tb").unwrap();
        let line = |out: &str| {
            out.lines()
                .find(|l| l.trim_start().starts_with("set admin "))
                .unwrap()
                .to_string()
        };
        let out = generate(&host).unwrap();
        let set_line = line(&out);
        for wire in host.wires() {
            assert!(
                set_line.contains(&format!("\"{wire}\"")),
                "host admin set missing {wire}: {set_line}"
            );
        }
        assert_eq!(set_line.matches('"').count() / 2, host.wires().len());

        let leaf = View::new(&f, "pve3-tb").unwrap();
        let leaf_out = generate(&leaf).unwrap();
        assert_eq!(line(&leaf_out).trim(), "set admin { type ifname; }");
        for rule in ["iifname @admin counter drop", "oifname @admin counter drop"] {
            assert!(leaf_out.contains(rule), "leaf lost {rule}");
        }
    }
}
