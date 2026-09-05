//! Traffic-class marking (table inet cfab) derived from the class table. Two label planes
//! from one model: 802.1p PCP (skb-priority → sub-interface egress-qos-map) and IP DSCP (the
//! plane a DSCP-trusting switch queues on). Pure text out.

use crate::derive::View;
use crate::error::Result;

pub fn generate(view: &View) -> Result<String> {
    let f = view.fabric;
    let mut out = String::new();
    out.push_str("table inet cfab\n");
    out.push_str("delete table inet cfab\n");
    out.push_str("table inet cfab {\n");
    out.push_str("  chain out {\n");
    out.push_str("    type filter hook output priority mangle;\n");
    for z in &f.zones {
        let ifs_list = view.zone_ifs(&z.name);
        if ifs_list.is_empty() {
            continue;
        }
        let ifs = ifs_list
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        // PCP plane: lift OSPF/BFD to PCP_CTRL on zones mapped below it.
        if z.pcp != f.pcp_ctrl {
            out.push_str(&format!(
                "    oifname {{ {ifs} }} ip protocol ospf meta priority set 0:{} comment \"pcp-{}-ctrl\"\n",
                f.pcp_ctrl, z.name
            ));
            out.push_str(&format!(
                "    oifname {{ {ifs} }} udp dport 3784-3785 meta priority set 0:{} comment \"pcp-{}-bfd\"\n",
                f.pcp_ctrl, z.name
            ));
        }
        if !f.dscp_mark {
            continue;
        }
        // DSCP plane, order matters: clamp the WHOLE zone first, then lift its control
        // (last write wins per field) — makes bulk-in-the-control-queue unrepresentable.
        out.push_str(&format!(
            "    oifname {{ {ifs} }} ip dscp set {} comment \"dscp-{}-bulk\"\n",
            z.dscp, z.name
        ));
        if z.dscp != f.dscp_ctrl {
            out.push_str(&format!(
                "    oifname {{ {ifs} }} ip protocol ospf ip dscp set {} comment \"dscp-{}-ctrl\"\n",
                f.dscp_ctrl, z.name
            ));
            out.push_str(&format!(
                "    oifname {{ {ifs} }} udp dport 3784-3785 ip dscp set {} comment \"dscp-{}-bfd\"\n",
                f.dscp_ctrl, z.name
            ));
        }
    }
    out.push_str("  }\n}\n");
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
    /// rescue bond, and this generator's `oifname { ifs }` group is built straight from it — no
    /// mark.rs code changed for this task. This is what makes the shaping claim true: the bond
    /// gets the zone's DSCP/PCP output-hook rules, so a rescue frame is marked like any other
    /// frame in its zone. The on-wire PCP itself then comes from the ACTIVE SLAVE's
    /// egress-qos-map (set by `up`, not by this generator) mapping the PCP-plane skb-priority
    /// this rule sets — that half is INFERRED here, confirmed on hardware in a later task.
    #[test]
    fn the_oifname_group_carries_the_rescue_bond_never_a_slave() {
        for member in ["pve1-tb", "pve3-tb"] {
            let f = fabric();
            let v = View::new(&f, member).unwrap();
            let out = generate(&v).unwrap();
            for row in v.rescue_rows() {
                let want = format!("\"{}\"", row.ifname);
                assert!(
                    out.contains(&want),
                    "{member}: no marking rule mentions the rescue bond {}",
                    row.ifname
                );
                for slave in &row.slaves {
                    let slave_tag = format!("\"{}\"", slave.ifname);
                    assert!(
                        !out.contains(&slave_tag),
                        "{member}: marking rule names a rescue slave {}: it is L2 only, the \
                         PCP tag comes from its own egress-qos-map, not a mark rule",
                        slave.ifname
                    );
                }
            }
        }
    }
}
