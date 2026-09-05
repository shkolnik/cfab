//! Traffic-class marking (table inet cfab) derived from the class table. Two label planes
//! from one model: 802.1p PCP (skb-priority → sub-interface egress-qos-map) and IP DSCP (the
//! plane a DSCP-trusting switch queues on), plus the fallback control-egress ceiling (below).
//! Pure text out.

use crate::derive::{View, class_rows_of};
use crate::error::Result;

/// Headroom over the derived legitimate cadence. Two doublings: one for a retransmission round
/// landing inside the same second as the flood it repeats, one for measurement margin.
const CEILING_HEADROOM: u64 = 4;

/// RFC 2328 RxmtInterval, seconds: the cadence at which an unacknowledged LSA is retransmitted,
/// unicast, once per neighbor. The one part of OSPF flooding that scales with the peer count on
/// a broadcast LAN (the flood itself is multicast, one packet per LSA however many peers hear
/// it).
const CEILING_RXMT_SECS: u64 = 5;

/// Measured worst legitimate egress on a fallback bond: 1 pkt/s steady, up to ~20 pkt/s for one
/// second during a convergence burst (three-member container fixture, 2026-09-05,
/// research repo, fallback-storm-ceiling study §3). A derived rate below this would
/// police a healthy fabric, so it is the floor — with the same headroom applied to it.
const CEILING_FLOOR_PPS: u64 = 20;

/// The control-egress ceiling for one fallback bond, with every term of its derivation kept so
/// the render and `cfab status` quote the same arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceiling {
    pub zone: String,
    pub ifname: String,
    /// Routers in this zone's OSPF area: members with at least one class row in the zone. Every
    /// one of them also carries the zone's fallback row (the row needs a home wire, which is a
    /// class row in the zone), so this is the fallback LAN's membership too.
    pub members: u64,
    /// Broadcast LANs in the zone = the zone's CLASS_TABLE rows, fallback row included: the
    /// network-LSA candidates.
    pub lans: u64,
    /// LSDB size for the zone: one router-LSA per member, one network-LSA per LAN.
    pub lsas: u64,
    /// Neighbors on the fallback LAN.
    pub peers: u64,
    /// Hellos + a whole-LSDB flood + one retransmission round, in one second.
    pub base_pps: u64,
    pub rate_pps: u64,
    pub burst_pkts: u64,
}

impl Ceiling {
    /// The `# ...` line that puts the derivation next to the rule.
    fn comment(&self) -> String {
        format!(
            "    # ceiling {}: {} members, {} LSAs ({} router + {} network), {} peers\n    \
             #   base = 1 hello + 2x{} flood + ceil({}x{}/{}) retx = {} pkt/s; \
             x{} headroom = {}; floor {} pkt/s (measured burst) x{} = {}\n",
            self.zone,
            self.members,
            self.lsas,
            self.members,
            self.lans,
            self.peers,
            self.lsas,
            self.lsas,
            self.peers,
            CEILING_RXMT_SECS,
            self.base_pps,
            CEILING_HEADROOM,
            self.base_pps * CEILING_HEADROOM,
            CEILING_FLOOR_PPS,
            CEILING_HEADROOM,
            CEILING_FLOOR_PPS * CEILING_HEADROOM,
        )
    }
}

/// The arithmetic, separated from the declaration so the three design-bound sizes can be tested
/// as numbers. `hello_s` is OSPF_HELLO in whole seconds.
fn ceiling_pps(members: u64, lans: u64, hello_s: u32) -> (u64, u64, u64, u64) {
    let peers = members.saturating_sub(1);
    let lsas = members + lans;
    // At most one hello per second: OSPF_HELLO is whole seconds and never below 1.
    let hello = 1u64.div_ceil(u64::from(hello_s).max(1));
    // A full convergence, compressed into a single second: every LSA flooded once (multicast)
    // and acknowledged once.
    let flood = 2 * lsas;
    // ...plus one unicast retransmission round to every neighbor, spread over RxmtInterval.
    let retx = (lsas * peers).div_ceil(CEILING_RXMT_SECS);
    let base = hello + flood + retx;
    let rate = (base * CEILING_HEADROOM).max(CEILING_FLOOR_PPS * CEILING_HEADROOM);
    (peers, lsas, base, rate)
}

/// This member's fallback control-egress ceilings, one per fallback bond it carries (table
/// order). Empty when the member carries no fallback row — then no rule is emitted at all.
pub fn ceilings(view: &View) -> Vec<Ceiling> {
    let f = view.fabric;
    view.fallback_rows()
        .into_iter()
        .map(|r| {
            let members = f
                .members
                .iter()
                .filter(|m| class_rows_of(f, m).iter().any(|c| c.zone == r.zone))
                .count() as u64;
            let lans = f.class_table.iter().filter(|s| s.zone == r.zone).count() as u64;
            let (peers, lsas, base_pps, rate_pps) = ceiling_pps(members, lans, f.ospf_hello);
            Ceiling {
                zone: r.zone,
                ifname: r.ifname,
                members,
                lans,
                lsas,
                peers,
                base_pps,
                rate_pps,
                burst_pkts: rate_pps * 2,
            }
        })
        .collect()
}

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
    // The fallback control-egress ceiling, last so a passed packet has already been marked and
    // a dropped one is dropped by the last word in the chain. Containment, not policing: a
    // fallback segment is one broadcast domain spanning every island, so a control-plane loop on
    // it reaches every switch port in the fabric. Over the derived rate the packets are dropped
    // and counted (`cfab status` reads the counter) — a member whose control plane has gone mad
    // stops shouting and at worst loses its own fallback adjacency, which is the cheaper half of
    // "degraded but up".
    //
    // OSPF only, and only on the bond: a fallback leg carries NO BFD by construction (`emit/
    // engine.rs` gives the bond no `bfd` key at all, and `segments_of()` keeps it out of BFD
    // pairing), so `ip protocol ospf` is the whole control class on this interface. Only the
    // control class is policed — when a zone is island-disjoint the bond carries that zone's
    // real traffic, which is exactly what the fallback exists for.
    for ce in ceilings(view) {
        out.push_str(&ce.comment());
        out.push_str(&format!(
            "    oifname {{ \"{}\" }} ip protocol ospf limit rate over {}/second burst {} packets counter drop comment \"ceiling-{}\"\n",
            ce.ifname, ce.rate_pps, ce.burst_pkts, ce.zone
        ));
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

    /// The same declaration grown to `n` members (node ids 1..=n, all hosts with all three
    /// wires), so the ceiling derivation is exercised across the project's scale bounds
    /// (< 50 members, most < 10) rather than only at the three-member testbed.
    fn fabric_with_members(n: u8) -> Fabric {
        let rows: String = (1..=n)
            .map(|i| format!("pve{i}-tb {i} host eth9:5000 eth1:1000 eth0:1000\n"))
            .collect();
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace(
                    "pve1-tb 1 host eth9:5000 eth1:1000 eth0:1000\n\
                     pve2-tb 2 host eth9:5000 eth1:1000 eth0:1000\n\
                     pve3-tb 3 leaf eth9:10000 eth1:1000 eth0:1000\n",
                    &rows,
                );
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// The threshold is a function of the declaration and of one measured number, at every size
    /// the project designs for. Storage has 4 CLASS_TABLE rows (3 segments + the fallback), so
    /// the LSDB is `members + 4` and the peer count on the fallback LAN is `members - 1`.
    ///
    /// The two margins this has to keep, as numbers (fixture measurements,
    /// research repo, fallback-storm-ceiling study §3 and §5):
    ///   * above the legitimate worst case — 1 pkt/s steady, ~20 pkt/s for one convergence
    ///     second: 80x steady and 4x the burst at 3 members, and only wider above that;
    ///   * below the pathology — the measured worst-case storm egressed 149 000 pkt/s per
    ///     member: 1 862x the 3-member ceiling, 677x the 10-member one, 60x the 49-member one.
    #[test]
    fn the_ceiling_derivation_at_3_10_and_49_members() {
        let want = [
            // members, LSAs, peers, base pkt/s, rate pkt/s
            (3u8, 7u64, 2u64, 18u64, 80u64),
            (10, 14, 9, 55, 220),
            (49, 53, 48, 616, 2464),
        ];
        for (n, lsas, peers, base, rate) in want {
            let f = fabric_with_members(n);
            let v = View::new(&f, "pve1-tb").unwrap();
            let c = ceilings(&v)
                .into_iter()
                .find(|c| c.zone == "storage")
                .unwrap();
            assert_eq!(
                (c.members, c.lans, c.lsas, c.peers, c.base_pps, c.rate_pps),
                (u64::from(n), 4, lsas, peers, base, rate),
                "{n} members"
            );
            assert_eq!(c.burst_pkts, rate * 2, "{n} members");
            // Above every legitimate rate ever measured on a fallback bond...
            assert!(
                c.rate_pps >= 20 * 4,
                "{n} members: below the measured floor"
            );
            // ...and far below the measured worst-case storm's own egress.
            assert!(
                149_000 / c.rate_pps >= 60,
                "{n} members: only {}x below the measured storm",
                149_000 / c.rate_pps
            );
        }
    }

    /// The rule is emitted with its arithmetic beside it, and it is OSPF on the bond and
    /// nothing else: never a slave (the bond is the L3 interface), never the zone's island
    /// segments (policing those would police the fabric it is protecting), never BFD (a
    /// fallback leg carries none — `emit/engine.rs` gives the bond no `bfd` key at all).
    #[test]
    fn the_ceiling_rule_is_ospf_on_the_bond_with_its_derivation_rendered() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let out = generate(&v).unwrap();
        let rules: Vec<&str> = out
            .lines()
            .filter(|l| l.contains("comment \"ceiling-"))
            .collect();
        assert_eq!(rules.len(), 3, "one per fallback bond: {out}");
        assert_eq!(
            rules[0].trim(),
            "oifname { \"cfab-st-fb\" } ip protocol ospf limit rate over 80/second \
             burst 160 packets counter drop comment \"ceiling-storage\""
        );
        assert!(out.contains(
            "    # ceiling storage: 3 members, 7 LSAs (3 router + 4 network), 2 peers\n    \
             #   base = 1 hello + 2x7 flood + ceil(7x2/5) retx = 18 pkt/s; x4 headroom = 72; \
             floor 20 pkt/s (measured burst) x4 = 80\n"
        ));
        for r in &rules {
            assert!(!r.contains("3784"), "the ceiling names a BFD port: {r}");
            assert!(!r.contains("-fb-"), "the ceiling names a slave: {r}");
            for seg in [
                "\"cfab-st\"",
                "\"cfab-st-bk\"",
                "\"cfab-cl\"",
                "\"cfab-mg\"",
            ] {
                assert!(!r.contains(seg), "the ceiling names an island segment: {r}");
            }
        }
        // Last in the chain: a passed packet is already marked, a dropped one is dropped by the
        // last word.
        let first_ceiling = out.find("ceiling-storage").unwrap();
        assert!(out.rfind("dscp-mgmt-bfd").unwrap() < first_ceiling);
    }

    /// No fallback row, no rule — and nothing else in the table moves. A member with no wire on
    /// a zone has no home wire for its fallback leg, so it carries none.
    #[test]
    fn a_member_with_no_fallback_row_gets_no_ceiling() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace("cfab-st-fb  any storage 9 300 fallback 5000\n", "")
                .replace("cfab-cl-fb  any cluster 9 301 fallback 5000\n", "")
                .replace("cfab-mg-fb  any mgmt    9 302 fallback 5000\n", "");
        let f = Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap();
        let v = View::new(&f, "pve1-tb").unwrap();
        assert!(v.fallback_rows().is_empty());
        assert!(ceilings(&v).is_empty());
        let out = generate(&v).unwrap();
        assert!(!out.contains("ceiling-"), "{out}");
        assert!(!out.contains("limit rate"), "{out}");
    }

    /// PROVING existing behavior, not new logic: `zone_ifs()` (Task 2) already returns the
    /// fallback bond, and this generator's `oifname { ifs }` group is built straight from it — no
    /// mark.rs code changed for this task. This is what makes the shaping claim true: the bond
    /// gets the zone's DSCP/PCP output-hook rules, so a fallback frame is marked like any other
    /// frame in its zone. The on-wire PCP itself then comes from the ACTIVE SLAVE's
    /// egress-qos-map (set by `up`, not by this generator) mapping the PCP-plane skb-priority
    /// this rule sets — that half is INFERRED here, confirmed on hardware in a later task.
    #[test]
    fn the_oifname_group_carries_the_fallback_bond_never_a_slave() {
        for member in ["pve1-tb", "pve3-tb"] {
            let f = fabric();
            let v = View::new(&f, member).unwrap();
            let out = generate(&v).unwrap();
            for row in v.fallback_rows() {
                let want = format!("\"{}\"", row.ifname);
                assert!(
                    out.contains(&want),
                    "{member}: no marking rule mentions the fallback bond {}",
                    row.ifname
                );
                for slave in &row.slaves {
                    let slave_tag = format!("\"{}\"", slave.ifname);
                    assert!(
                        !out.contains(&slave_tag),
                        "{member}: marking rule names a fallback slave {}: it is L2 only, the \
                         PCP tag comes from its own egress-qos-map, not a mark rule",
                        slave.ifname
                    );
                }
            }
        }
    }
}
