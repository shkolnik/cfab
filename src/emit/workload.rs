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
