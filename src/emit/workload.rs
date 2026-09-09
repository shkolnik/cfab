//! Workload text: aggregate, DHCP option 121, bridge ARP guard.

// ---- aggregate and DHCP (lane B2) ----

use std::net::Ipv4Addr;

use crate::model::Ipv4Prefix;

/// Smallest set of prefixes covering every declared zone block `10.<id>.0.0/16` (spec §5 item
/// 9). Works on the second octet: a run of `2^k` aligned ids merges to a `/(16-k)`. Typed
/// (`Ipv4Prefix`, not a formatted string): `dhcp_option_121` reads `.net`/`.len` straight off
/// each entry, so a merge here can never desync from how the snippet decodes it.
pub fn aggregate(zone_ids: &[u8]) -> Vec<Ipv4Prefix> {
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
        // `start` is always < 256 (built from u8 zone ids), so it always fits the second octet.
        out.push(Ipv4Prefix {
            net: Ipv4Addr::new(10, start as u8, 0, 0),
            len: 16 - k,
        });
        i += 1usize << k;
    }
    out
}

const HEADER: &str =
    "# dhcpd.conf (ISC): RFC 3442 classless static routes for this workload's subnet. A client \
     that receives\n";
/// The one global option definition every workload's subnet block relies on; print it once,
/// above the blocks, never inside one.
pub const DHCP_OPTION_121_DEFINITION: &str =
    "# dhcpd.conf (ISC): option 121 is defined ONCE, globally; dhcpd refuses a definition inside a \
     subnet block.\n\
     option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n";
/// The RFC 3442 classless-static-routes (option 121) dhcpd.conf snippet for one workload's
/// gateway: every aggregate prefix routed via `gw`, plus the default route via `router` (RULED,
/// spec §4 and §10 call 14: `router` is a declared key, refused outside `prefix`, printed only
/// here). A client that receives option 121 ignores option 3 entirely, so the default route
/// must be inside 121 or a client loses its existing default when it picks up this VLAN's lease.
/// The value sits inside a `subnet <net> netmask <mask> { … }` block keyed on `prefix` (the
/// workload's own VLAN, not the aggregate): with more than one `[[workload]]` row, each row's
/// values differ, so without a subnet block to scope them, dhcpd would take only the last row's
/// `option` statement as a global default and silently drop the others. The option DEFINITION is
/// [`DHCP_OPTION_121_DEFINITION`], printed once and globally by the caller: isc-dhcpd 4.4.3
/// refuses a scoped one (`option definitions may not be scoped`, pve3-tb 2026-09-09).
pub fn dhcp_option_121(
    prefix: Ipv4Prefix,
    aggregate: &[Ipv4Prefix],
    gw: Ipv4Addr,
    router: Ipv4Addr,
) -> String {
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
            let o = p.net.octets();
            let sig = usize::from(p.len.div_ceil(8));
            let mut e = vec![p.len];
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
         subnet {} netmask {} {{\n\
         \toption rfc3442-classless-static-routes {items}, 0, {r};\n\
         }}\n",
        prefix.net,
        prefix.netmask(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg_strs(ids: &[u8]) -> Vec<String> {
        aggregate(ids).iter().map(Ipv4Prefix::to_string).collect()
    }

    #[test]
    fn aggregate_merges_aligned_neighboring_16s_and_leaves_the_rest() {
        assert_eq!(
            agg_strs(&[99, 199, 249]),
            ["10.99.0.0/16", "10.199.0.0/16", "10.249.0.0/16"]
        );
        assert_eq!(agg_strs(&[98, 99]), ["10.98.0.0/15"]);
        assert_eq!(agg_strs(&[96, 97, 98, 99]), ["10.96.0.0/14"]);
        assert_eq!(agg_strs(&[99, 100]), ["10.99.0.0/16", "10.100.0.0/16"]);
        assert_eq!(agg_strs(&[199, 99, 99]), ["10.99.0.0/16", "10.199.0.0/16"]);
    }

    #[test]
    fn the_dhcp_snippet_carries_the_aggregate_via_gw_and_the_default_inside_option_121() {
        let s = dhcp_option_121(
            Ipv4Prefix::parse("192.168.20.0/24").unwrap(),
            &[
                Ipv4Prefix::parse("10.99.0.0/16").unwrap(),
                Ipv4Prefix::parse("10.199.0.0/16").unwrap(),
            ],
            "192.168.20.254".parse().unwrap(),
            "192.168.20.1".parse().unwrap(),
        );
        assert_eq!(
            s,
            "\
# dhcpd.conf (ISC): RFC 3442 classless static routes for this workload's subnet. A client that receives
# option 121 IGNORES option 3, so the default route (0.0.0.0/0 via 192.168.20.1) is INSIDE 121 (last entry).
# 10.99.0.0/16 via 192.168.20.254, 10.199.0.0/16 via 192.168.20.254, 0.0.0.0/0 via 192.168.20.1
subnet 192.168.20.0 netmask 255.255.255.0 {
\toption rfc3442-classless-static-routes 16, 10, 99, 192, 168, 20, 254, 16, 10, 199, 192, 168, 20, 254, 0, 192, 168, 20, 1;
}
"
        );
    }

    /// Two rows never collide inside one dhcpd.conf: each gets its own `subnet … { … }`
    /// definition line, keyed on its own VLAN, not the shared aggregate.
    #[test]
    fn two_rows_get_two_distinct_subnet_definition_lines() {
        let agg = [Ipv4Prefix::parse("10.99.0.0/16").unwrap()];
        let a = dhcp_option_121(
            Ipv4Prefix::parse("192.168.20.0/24").unwrap(),
            &agg,
            "192.168.20.254".parse().unwrap(),
            "192.168.20.1".parse().unwrap(),
        );
        let b = dhcp_option_121(
            Ipv4Prefix::parse("192.168.30.0/24").unwrap(),
            &agg,
            "192.168.30.254".parse().unwrap(),
            "192.168.30.1".parse().unwrap(),
        );
        assert!(a.contains("subnet 192.168.20.0 netmask 255.255.255.0 {"), "{a}");
        assert!(b.contains("subnet 192.168.30.0 netmask 255.255.255.0 {"), "{b}");
        assert_ne!(a, b);
        // dhcpd: `option definitions may not be scoped` — the definition never appears in a block.
        assert!(!a.contains("code 121"), "{a}");
        assert!(DHCP_OPTION_121_DEFINITION.contains("code 121 = array of unsigned integer 8;"));
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
                "        iifname \"{port}\" vlan id {} vlan type arp arp saddr ip {gw} counter drop comment \"gw-claim-from-uplink\"\n",
                up.vid
            ));
            out.push_str(&format!(
                "        iifname \"{port}\" vlan id {} vlan type arp arp daddr ip {gw} counter drop comment \"gw-request-from-uplink\"\n",
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
        iifname \"eth0\" vlan id 3 vlan type arp arp saddr ip 192.168.20.254 counter drop comment \"gw-claim-from-uplink\"
        iifname \"eth0\" vlan id 3 vlan type arp arp daddr ip 192.168.20.254 counter drop comment \"gw-request-from-uplink\"
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
