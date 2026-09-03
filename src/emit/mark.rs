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
