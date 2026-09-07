//! The two frames the ingress prober speaks, byte for byte.
//!
//! The question the prober asks is "does the router answer over THIS wire", and the only way to
//! ask it per wire on an active-backup bond is to bypass the bond entirely: build the Ethernet
//! frame ourselves and put it on one port's netdev. So the codec is here, pure, and the raw
//! socket is somebody else's problem (`super::io`).
//!
//! The probe is an RFC 5227 *probe*, not a plain ARP request: sender IP 0.0.0.0. That is
//! deliberate — a request carrying our leg address would poison the router's and the switches'
//! ARP/FDB tables for the leg address on whichever wire we last asked over, which is precisely
//! the damage that makes the kernel's own ARP monitor unusable here (measured, 2026-09-07). A
//! probe teaches nobody anything and is still answered: the UDM replied within 80 µs on the
//! rack.
//!
//! The source MAC is synthetic and per port for the same reason: three ports of one bond are
//! three ports into ONE broadcast domain, so a reply addressed to a MAC that two ports share
//! comes back on whichever port last used it. A per-port locally administered address makes
//! the reply's landing place unambiguous.

use std::net::Ipv4Addr;

/// Bytes of the probe frame: 14 Ethernet + 28 ARP. No padding — the kernel pads to the 60-byte
/// minimum on the way out.
pub const PROBE_LEN: usize = 42;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

/// The prober's source address on one port: `02:cf:ab:<node>:<zone id>:<port index>`.
///
/// `02` is the locally administered, individual bit pattern, so it can never collide with a
/// burned-in address; `cf:ab` is the project, there to make the address recognizable in a
/// capture or a switch FDB. The last three bytes make it unique per (member, zone, wire) across
/// the whole fabric, which is what keeps two members' probes on the same broadcast domain from
/// answering each other's replies. It is never the bond's MAC and never the wire's: those two
/// belong to the data path, and moving either is exactly the ARP-table damage this frame avoids.
pub fn synthetic_mac(node: u8, zone_id: u8, port_index: u8) -> [u8; 6] {
    [0x02, 0xcf, 0xab, node, zone_id, port_index]
}

/// One RFC 5227 ARP probe for `router`, broadcast, from `src`.
pub fn probe(src: [u8; 6], router: Ipv4Addr) -> [u8; PROBE_LEN] {
    let mut f = [0u8; PROBE_LEN];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&src);
    f[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    f[14..16].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    f[16..18].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&OP_REQUEST.to_be_bytes());
    f[22..28].copy_from_slice(&src);
    // sender IP stays 0.0.0.0 (f[28..32]) and target MAC stays all-zero (f[32..38]): that is
    // what makes this a probe rather than a request.
    f[38..42].copy_from_slice(&router.octets());
    f
}

/// The answering MAC, iff `frame` is a reply to OUR probe on this port: an ARP reply whose
/// sender IP is one of `targets` and whose target MAC is this port's synthetic address.
///
/// `targets` is a list because the two probers ask different questions with the same frame: the
/// ingress prober asks one router, and the fallback prober asks the zone's peers, any one of
/// which answering is evidence that the wire carries the segment (spec §3). One target is the
/// one-element case, not a second code path.
///
/// Everything else is dropped without comment, and two of those are ordinary rather than
/// exceptional: our own broadcast probe floods back in through the other islands of the same
/// VLAN (op 1), and the ETH_P_ALL tap sees every frame on the wire.
pub fn reply_from(frame: &[u8], src: [u8; 6], targets: &[Ipv4Addr]) -> Option<[u8; 6]> {
    // A VLAN header can still be present: the port netdev normally hands the frame up
    // stripped, but a tap on a wire carrying tags (or a driver without hardware stripping)
    // sees it. Skip at most one tag; a doubly tagged frame is not ours.
    let mut arp = 14;
    let mut ethertype = be16(frame.get(12..14)?);
    if ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
        arp = 18;
        ethertype = be16(frame.get(16..18)?);
    }
    if ethertype != ETHERTYPE_ARP {
        return None;
    }
    let a = frame.get(arp..arp + 28)?;
    if be16(&a[0..2]) != HTYPE_ETHERNET || be16(&a[2..4]) != PTYPE_IPV4 || a[4] != 6 || a[5] != 4 {
        return None;
    }
    if be16(&a[6..8]) != OP_REPLY {
        return None;
    }
    let sender_mac: [u8; 6] = a[8..14].try_into().ok()?;
    let sender_ip = Ipv4Addr::new(a[14], a[15], a[16], a[17]);
    let target_mac: [u8; 6] = a[18..24].try_into().ok()?;
    if !targets.contains(&sender_ip) || target_mac != src {
        return None;
    }
    Some(sender_mac)
}

/// AllSPFRouters — the only IPv4 destination an OSPF hello is sent to on a broadcast segment,
/// and the one the BPF filter (`super::bpf`) selects on.
const ALL_SPF_ROUTERS: [u8; 4] = [224, 0, 0, 5];
const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_OSPF: u8 = 89;

/// The Router ID of the member that sent `frame`, iff it is an OSPF packet to AllSPFRouters.
///
/// This is the whole of the passive channel's parsing. A hello on a port means a member that
/// carries this zone's fallback segment is alive on the far side of that wire — which is the
/// question the fallback prober asks — and the Router ID is the only field that says WHICH
/// member, so nothing else is read: not the neighbor list, not the area, not the checksum. A
/// packet whose type is not Hello is the same evidence (a member that is talking OSPF on this
/// segment is a member that is there), so the type is not read either.
///
/// Layout: RFC 791 (IHL × 4 = the IPv4 header length, so options shift what follows) and RFC
/// 2328 A.3.1 (version, type, length, then the Router ID at OSPF payload offset 4..8).
pub fn hello_router_id(frame: &[u8]) -> Option<u32> {
    // One VLAN tag is skipped for the same reason `reply_from` skips it: a tap on a netdev
    // without hardware tag stripping sees the tag. A doubly tagged frame is not ours.
    let mut ip = 14;
    let mut ethertype = be16(frame.get(12..14)?);
    if ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
        ip = 18;
        ethertype = be16(frame.get(16..18)?);
    }
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ihl = (frame.get(ip)? & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let hdr = frame.get(ip..ip + ihl)?;
    if hdr[9] != IPPROTO_OSPF || hdr[16..20] != ALL_SPF_ROUTERS {
        return None;
    }
    let rid = frame.get(ip + ihl + 4..ip + ihl + 8)?;
    Some(u32::from_be_bytes([rid[0], rid[1], rid[2], rid[3]]))
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rack's own addresses (worklog 2026-09-07 16:15): the UDM answering
    /// `192.168.249.254` to the prototype's synthetic `02:cf:ab:f2:10:00`.
    const UDM: [u8; 6] = [0x68, 0xd7, 0x9a, 0x66, 0x91, 0xa9];
    const OURS: [u8; 6] = [0x02, 0xcf, 0xab, 0xf2, 0x10, 0x00];
    const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 254);

    /// The reply the UDM sent, as captured: unicast to our synthetic MAC, sender IP the router,
    /// target IP 0.0.0.0 because it is answering a probe.
    fn rack_reply() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&OURS); // dst
        f.extend_from_slice(&UDM); // src
        f.extend_from_slice(&[0x08, 0x06]); // ARP
        f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
        f.extend_from_slice(&UDM); // sha
        f.extend_from_slice(&[192, 168, 249, 254]); // spa
        f.extend_from_slice(&OURS); // tha
        f.extend_from_slice(&[0, 0, 0, 0]); // tpa
        f
    }

    #[test]
    fn the_probe_is_the_42_golden_bytes_of_an_rfc_5227_probe() {
        #[rustfmt::skip]
        let want: [u8; PROBE_LEN] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x02, 0xcf, 0xab, 0xf2, 0x10, 0x00,
            0x08, 0x06,
            0x00, 0x01,
            0x08, 0x00,
            0x06, 0x04,
            0x00, 0x01,
            0x02, 0xcf, 0xab, 0xf2, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0xa8, 0xf9, 0xfe,
        ];
        assert_eq!(probe(OURS, ROUTER), want);
    }

    #[test]
    fn the_rack_reply_yields_the_routers_mac() {
        assert_eq!(reply_from(&rack_reply(), OURS, &[ROUTER]), Some(UDM));
    }

    /// Ethernet pads a 42-byte frame to the 60-byte minimum; the parse must not care.
    #[test]
    fn a_padded_reply_still_parses() {
        let mut f = rack_reply();
        f.resize(60, 0);
        assert_eq!(reply_from(&f, OURS, &[ROUTER]), Some(UDM));
    }

    /// Our own broadcast probe floods back in through the other islands of the same VLAN. It is
    /// op 1 and must never be counted as an answer.
    #[test]
    fn our_own_flooded_request_is_not_a_reply() {
        let mine = probe(OURS, ROUTER);
        assert_eq!(reply_from(&mine, OURS, &[ROUTER]), None);
    }

    #[test]
    fn a_reply_from_another_address_is_not_ours() {
        assert_eq!(
            reply_from(&rack_reply(), OURS, &[Ipv4Addr::new(192, 168, 249, 1)]),
            None
        );
    }

    /// The whole point of the per-port source MAC: a reply addressed to a different port is
    /// evidence about that port, never about this one.
    #[test]
    fn a_reply_to_another_ports_mac_is_not_ours() {
        let other = synthetic_mac(0xf2, 0x10, 1);
        assert_eq!(reply_from(&rack_reply(), other, &[ROUTER]), None);
    }

    #[test]
    fn a_non_arp_or_short_frame_is_dropped_quietly() {
        let mut ip = rack_reply();
        ip[12..14].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(reply_from(&ip, OURS, &[ROUTER]), None);
        assert_eq!(reply_from(&rack_reply()[..20], OURS, &[ROUTER]), None);
        assert_eq!(reply_from(&[], OURS, &[ROUTER]), None);
    }

    /// A tagged copy of the same reply parses identically: the tap is ETH_P_ALL, so a frame
    /// that reached us with its tag still on is the same evidence.
    #[test]
    fn a_vlan_tagged_reply_parses() {
        let r = rack_reply();
        let mut f = r[..12].to_vec();
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0xf9]);
        f.extend_from_slice(&r[12..]);
        assert_eq!(reply_from(&f, OURS, &[ROUTER]), Some(UDM));
    }

    /// The peers' own fallback addresses (`10.<zone>.<seg>.<node>`) are the escalation targets,
    /// and there is more than one of them: a reply from ANY of them is evidence about the wire.
    #[test]
    fn a_reply_from_any_target_counts() {
        let peers = [Ipv4Addr::new(10, 99, 9, 2), Ipv4Addr::new(10, 99, 9, 3)];
        let mut f = rack_reply();
        f[28..32].copy_from_slice(&[10, 99, 9, 3]);
        assert_eq!(reply_from(&f, OURS, &peers), Some(UDM));
        f[28..32].copy_from_slice(&[10, 99, 9, 4]);
        assert_eq!(reply_from(&f, OURS, &peers), None, "not one of ours");
        assert_eq!(reply_from(&rack_reply(), OURS, &[]), None, "nobody to hear");
    }

    /// A golden OSPFv2 hello: the peer's own router id is at payload offset 4..8, and that is
    /// the only field read.
    fn hello(router_id: [u8; 4], ihl: u8) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x05]); // AllSPFRouters
        f.extend_from_slice(&[0x02, 0xcf, 0xab, 0x00, 0x00, 0x01]);
        f.extend_from_slice(&[0x08, 0x00]); // IPv4
        let hlen = (ihl * 4) as usize;
        let mut ip = vec![0u8; hlen];
        ip[0] = 0x40 | ihl;
        ip[9] = 89; // OSPF
        ip[12..16].copy_from_slice(&[10, 99, 9, 2]); // src
        ip[16..20].copy_from_slice(&[224, 0, 0, 5]); // dst
        f.extend_from_slice(&ip);
        let mut ospf = vec![0u8; 24];
        ospf[0] = 2; // version
        ospf[1] = 1; // hello
        ospf[4..8].copy_from_slice(&router_id);
        f.extend_from_slice(&ospf);
        f
    }

    #[test]
    fn a_golden_hello_yields_its_router_id() {
        let rid = u32::from_be_bytes([10, 99, 0, 2]);
        assert_eq!(hello_router_id(&hello([10, 99, 0, 2], 5)), Some(rid));
        assert_eq!(
            hello_router_id(&hello([10, 99, 0, 2], 6)),
            Some(rid),
            "an IHL 6 header (one option word) shifts the OSPF header"
        );
    }

    /// A tagged copy is the same evidence, exactly as for an ARP reply.
    #[test]
    fn a_vlan_tagged_hello_parses() {
        let h = hello([10, 99, 0, 3], 5);
        let mut f = h[..12].to_vec();
        f.extend_from_slice(&[0x81, 0x00, 0x01, 0x2c]);
        f.extend_from_slice(&h[12..]);
        assert_eq!(
            hello_router_id(&f),
            Some(u32::from_be_bytes([10, 99, 0, 3]))
        );
    }

    /// Anything that is not OSPF to AllSPFRouters is not evidence, and neither is a frame that
    /// stops before the router id.
    #[test]
    fn a_non_ospf_or_short_frame_yields_no_router_id() {
        let mut wrong_proto = hello([10, 99, 0, 2], 5);
        wrong_proto[14 + 9] = 17;
        assert_eq!(hello_router_id(&wrong_proto), None);
        let mut wrong_dst = hello([10, 99, 0, 2], 5);
        wrong_dst[14 + 16..14 + 20].copy_from_slice(&[224, 0, 0, 6]);
        assert_eq!(hello_router_id(&wrong_dst), None);
        assert_eq!(
            hello_router_id(&rack_reply()),
            None,
            "an ARP reply is not a hello"
        );
        let h = hello([10, 99, 0, 2], 5);
        assert_eq!(hello_router_id(&h[..40]), None, "cut before the router id");
        assert_eq!(hello_router_id(&[]), None);
        let mut bad_ihl = hello([10, 99, 0, 2], 5);
        bad_ihl[14] = 0x43; // IHL 3: shorter than an IPv4 header can be
        assert_eq!(hello_router_id(&bad_ihl), None);
    }

    /// A type that is not Hello is still a live peer on that wire, and is read the same way.
    #[test]
    fn any_ospf_packet_type_is_evidence_of_the_peer() {
        let mut lsu = hello([10, 99, 0, 3], 5);
        lsu[14 + 20 + 1] = 4; // Link State Update
        assert_eq!(
            hello_router_id(&lsu),
            Some(u32::from_be_bytes([10, 99, 0, 3]))
        );
    }

    #[test]
    fn the_synthetic_mac_is_locally_administered_and_unique_per_port() {
        let m = synthetic_mac(2, 249, 1);
        assert_eq!(m, [0x02, 0xcf, 0xab, 0x02, 0xf9, 0x01]);
        assert_eq!(m[0] & 0x03, 0x02, "locally administered, individual");
        assert_ne!(m, synthetic_mac(2, 249, 0), "port index separates");
        assert_ne!(m, synthetic_mac(3, 249, 1), "node separates");
        assert_ne!(m, synthetic_mac(2, 248, 1), "zone separates");
    }
}
