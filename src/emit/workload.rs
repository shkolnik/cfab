//! Workload text: aggregate, DHCP option 121, bridge ARP guard.

// ---- aggregate and DHCP (lane B2) ----

use std::net::Ipv4Addr;

/// Smallest set of prefixes covering every declared zone block `10.<id>.0.0/16` (spec §5 item
/// 9). Works on the second octet: a run of `2^k` aligned ids merges to a `/(16-k)`.
pub fn aggregate(zone_ids: &[u8]) -> Vec<String> {
    let mut ids: Vec<u16> = zone_ids.iter().map(|&i| u16::from(i)).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < ids.len() {
        let start = ids[i];
        let mut k = 0u8;
        // Grow while the next 2^(k+1) block is aligned and fully present.
        while k < 8 {
            let size = 1u16 << (k + 1);
            if !start.is_multiple_of(size) {
                break;
            }
            let need: Vec<u16> = (start..start + size).collect();
            if ids[i..].len() < need.len() || ids[i..i + need.len()] != need[..] {
                break;
            }
            k += 1;
        }
        out.push(format!("10.{start}.0.0/{}", 16 - k));
        i += 1usize << k;
    }
    out
}

const HEADER: &str = "# dhcpd.conf (ISC): RFC 3442 classless static routes for the workload VLAN. A client that receives\n";
/// The RFC 3442 classless-static-routes (option 121) dhcpd.conf snippet for one workload's
/// gateway: every aggregate prefix routed via `gw`, plus the default route via `router` (RULED,
/// spec §4 and §10 call 14: `router` is a declared key, refused outside `prefix`, printed only
/// here). A client that receives option 121 ignores option 3 entirely, so the default route
/// must be inside 121 or a client loses its existing default when it picks up this VLAN's lease.
pub fn dhcp_option_121(aggregate: &[String], gw: Ipv4Addr, router: Ipv4Addr) -> String {
    let g = gw.octets();
    let r = router
        .octets()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let routes = aggregate
        .iter()
        .map(|p| format!("{p} via {gw}"))
        .chain(std::iter::once(format!("0.0.0.0/0 via {router}")))
        .collect::<Vec<_>>()
        .join(", ");
    // Octets: <destination-length> <significant destination octets> <router>. Every aggregate
    // entry here is /8..=/16, so 1 or 2 significant octets (RFC 3442 §3).
    let items = aggregate
        .iter()
        .map(|p| {
            let (net, len) = p.split_once('/').expect("prefix with length");
            let len: u8 = len.parse().expect("length");
            let o: Vec<u8> = net.split('.').map(|x| x.parse().unwrap()).collect();
            let sig = usize::from(len.div_ceil(8));
            let mut e = vec![len];
            e.extend(&o[..sig]);
            e.extend(g);
            e.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{HEADER}# option 121 IGNORES option 3, so the default route (0.0.0.0/0 via {router}) is \
         INSIDE 121 (last entry).\n\
         # {routes}\n\
         option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n\
         option rfc3442-classless-static-routes {items}, 0, {r};\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_merges_aligned_neighboring_16s_and_leaves_the_rest() {
        assert_eq!(
            aggregate(&[99, 199, 249]),
            ["10.99.0.0/16", "10.199.0.0/16", "10.249.0.0/16"]
        );
        assert_eq!(aggregate(&[98, 99]), ["10.98.0.0/15"]);
        assert_eq!(aggregate(&[96, 97, 98, 99]), ["10.96.0.0/14"]);
        assert_eq!(aggregate(&[99, 100]), ["10.99.0.0/16", "10.100.0.0/16"]);
        assert_eq!(aggregate(&[199, 99, 99]), ["10.99.0.0/16", "10.199.0.0/16"]);
    }

    #[test]
    fn the_dhcp_snippet_carries_the_aggregate_via_gw_and_the_default_inside_option_121() {
        let s = dhcp_option_121(
            &["10.99.0.0/16".into(), "10.199.0.0/16".into()],
            "192.168.20.254".parse().unwrap(),
            "192.168.20.1".parse().unwrap(),
        );
        assert_eq!(
            s,
            "\
# dhcpd.conf (ISC): RFC 3442 classless static routes for the workload VLAN. A client that receives
# option 121 IGNORES option 3, so the default route (0.0.0.0/0 via 192.168.20.1) is INSIDE 121 (last entry).
# 10.99.0.0/16 via 192.168.20.254, 10.199.0.0/16 via 192.168.20.254, 0.0.0.0/0 via 192.168.20.1
option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;
option rfc3442-classless-static-routes 16, 10, 99, 192, 168, 20, 254, 16, 10, 199, 192, 168, 20, 254, 0, 192, 168, 20, 1;
"
        );
    }
}

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
