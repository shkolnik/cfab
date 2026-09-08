//! Workload text: aggregate, DHCP option 121, bridge ARP guard.

// ---- aggregate and DHCP (lane B2) ----

// ---- bridge guard (lane B3) ----

use crate::workload::uplink::Uplink;

/// `table bridge cfab`: for every `(gateway address, uplink)` pair, a bridge-hook ARP guard that
/// drops any ARP claiming or requesting the gateway address coming FROM the uplink port(s) — a
/// VM (or anything upstream) cannot spoof or resolve the gateway across the uplink. `vlan type
/// arp`, not `ether type arp` (emulation trap, verified R3): under `vlan id <n>` the ethertype
/// match never fires because the frame has already been de-encapsulated to the tagged view by
/// the time this chain sees it. `priority filter` (-200) so the drop runs before pve-firewall's
/// `table bridge filter` chains; the table survives pve-firewall's restore, reconcile and flush
/// (VERIFIED, research R8 addendum). The `table … / delete table … / table … {` shape is the
/// idempotent apply idiom used by every other emitted table (see `mark.rs::generate`): the first
/// `table` statement makes `delete` a no-op on first apply instead of an error, and `delete`
/// clears whatever a previous generation left before this one is defined.
pub fn bridge_table(guards: &[(std::net::Ipv4Addr, Uplink)]) -> String {
    let mut out = String::new();
    out.push_str("table bridge cfab\n");
    out.push_str("delete table bridge cfab\n");
    out.push_str("table bridge cfab {\n");
    out.push_str("    chain pre {\n");
    out.push_str("        type filter hook prerouting priority filter; policy accept;\n");
    for (gw, up) in guards {
        for port in &up.ports {
            out.push_str(&format!(
                "        iifname \"{port}\" vlan id {} vlan type arp arp daddr ip {gw} counter drop comment \"gw-request-from-uplink\"\n",
                up.vid
            ));
            out.push_str(&format!(
                "        iifname \"{port}\" vlan id {} vlan type arp arp saddr ip {gw} counter drop comment \"gw-claim-from-uplink\"\n",
                up.vid
            ));
        }
    }
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod bridge_guard_tests {
    use super::*;

    #[test]
    fn the_bridge_table_drops_arp_for_gw_arriving_on_the_uplink_at_filter_priority() {
        let up = Uplink {
            bridge: "primary".into(),
            vid: 3,
            ports: vec!["eth0".into()],
        };
        assert_eq!(
            bridge_table(&[("192.168.20.254".parse().unwrap(), up)]),
            "\
table bridge cfab
delete table bridge cfab
table bridge cfab {
    chain pre {
        type filter hook prerouting priority filter; policy accept;
        iifname \"eth0\" vlan id 3 vlan type arp arp daddr ip 192.168.20.254 counter drop comment \"gw-request-from-uplink\"
        iifname \"eth0\" vlan id 3 vlan type arp arp saddr ip 192.168.20.254 counter drop comment \"gw-claim-from-uplink\"
    }
}
"
        );
    }

    #[test]
    fn two_uplink_ports_get_one_pair_of_rules_each() {
        let up = Uplink {
            bridge: "primary".into(),
            vid: 3,
            ports: vec!["eth0".into(), "eth1".into()],
        };
        let out = bridge_table(&[("192.168.20.254".parse().unwrap(), up)]);
        assert_eq!(out.matches("counter drop").count(), 4);
        assert_eq!(out.matches("iifname \"eth0\"").count(), 2);
        assert_eq!(out.matches("iifname \"eth1\"").count(), 2);
    }
}
