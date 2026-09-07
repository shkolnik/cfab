//! The two frames the ingress prober speaks, byte for byte.
//!
//! The question the prober asks is "does the router answer over THIS wire", and the only way to
//! ask it per wire on an active-backup bond is to bypass the bond entirely: build the Ethernet
//! frame ourselves and put it on one slave's netdev. So the codec is here, pure, and the raw
//! socket is somebody else's problem (`super::io`).
//!
//! The probe is an RFC 5227 *probe*, not a plain ARP request: sender IP 0.0.0.0. That is
//! deliberate — a request carrying our leg address would poison the router's and the switches'
//! ARP/FDB tables for the leg address on whichever wire we last asked over, which is precisely
//! the damage that makes the kernel's own ARP monitor unusable here (measured, 2026-09-07). A
//! probe teaches nobody anything and is still answered: the UDM replied within 80 µs on the
//! rack.
//!
//! The source MAC is synthetic and per slave for the same reason: three slaves of one bond are
//! three ports into ONE broadcast domain, so a reply addressed to a MAC that two slaves share
//! comes back on whichever port last used it. A per-slave locally administered address makes
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

/// The prober's source address on one slave: `02:cf:ab:<node>:<zone id>:<slave index>`.
///
/// `02` is the locally administered, individual bit pattern, so it can never collide with a
/// burned-in address; `cf:ab` is the project, there to make the address recognizable in a
/// capture or a switch FDB. The last three bytes make it unique per (member, zone, wire) across
/// the whole fabric, which is what keeps two members' probes on the same broadcast domain from
/// answering each other's replies. It is never the bond's MAC and never the wire's: those two
/// belong to the data path, and moving either is exactly the ARP-table damage this frame avoids.
pub fn synthetic_mac(_node: u8, _zone_id: u8, _slave_index: u8) -> [u8; 6] {
    [0x02, 0xcf, 0xab, 0, 0, 0]
}

/// One RFC 5227 ARP probe for `router`, broadcast, from `src`.
pub fn probe(_src: [u8; 6], _router: Ipv4Addr) -> [u8; PROBE_LEN] {
    [0u8; PROBE_LEN]
}

/// The router's MAC, iff `frame` is a reply to OUR probe on this slave: an ARP reply whose
/// sender IP is `router` and whose target MAC is this slave's synthetic address.
///
/// Everything else is dropped without comment, and two of those are ordinary rather than
/// exceptional: our own broadcast probe floods back in through the other islands of the same
/// VLAN (op 1), and the ETH_P_ALL tap sees every frame on the wire.
pub fn reply_from(_frame: &[u8], _src: [u8; 6], _router: Ipv4Addr) -> Option<[u8; 6]> {
    None
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
        assert_eq!(reply_from(&rack_reply(), OURS, ROUTER), Some(UDM));
    }

    /// Ethernet pads a 42-byte frame to the 60-byte minimum; the parse must not care.
    #[test]
    fn a_padded_reply_still_parses() {
        let mut f = rack_reply();
        f.resize(60, 0);
        assert_eq!(reply_from(&f, OURS, ROUTER), Some(UDM));
    }

    /// Our own broadcast probe floods back in through the other islands of the same VLAN. It is
    /// op 1 and must never be counted as an answer.
    #[test]
    fn our_own_flooded_request_is_not_a_reply() {
        let mine = probe(OURS, ROUTER);
        assert_eq!(reply_from(&mine, OURS, ROUTER), None);
    }

    #[test]
    fn a_reply_from_another_address_is_not_ours() {
        assert_eq!(
            reply_from(&rack_reply(), OURS, Ipv4Addr::new(192, 168, 249, 1)),
            None
        );
    }

    /// The whole point of the per-slave source MAC: a reply addressed to a different slave is
    /// evidence about that slave, never about this one.
    #[test]
    fn a_reply_to_another_slaves_mac_is_not_ours() {
        let other = synthetic_mac(0xf2, 0x10, 1);
        assert_eq!(reply_from(&rack_reply(), other, ROUTER), None);
    }

    #[test]
    fn a_non_arp_or_short_frame_is_dropped_quietly() {
        let mut ip = rack_reply();
        ip[12..14].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(reply_from(&ip, OURS, ROUTER), None);
        assert_eq!(reply_from(&rack_reply()[..20], OURS, ROUTER), None);
        assert_eq!(reply_from(&[], OURS, ROUTER), None);
    }

    /// A tagged copy of the same reply parses identically: the tap is ETH_P_ALL, so a frame
    /// that reached us with its tag still on is the same evidence.
    #[test]
    fn a_vlan_tagged_reply_parses() {
        let r = rack_reply();
        let mut f = r[..12].to_vec();
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0xf9]);
        f.extend_from_slice(&r[12..]);
        assert_eq!(reply_from(&f, OURS, ROUTER), Some(UDM));
    }

    #[test]
    fn the_synthetic_mac_is_locally_administered_and_unique_per_slave() {
        let m = synthetic_mac(2, 249, 1);
        assert_eq!(m, [0x02, 0xcf, 0xab, 0x02, 0xf9, 0x01]);
        assert_eq!(m[0] & 0x03, 0x02, "locally administered, individual");
        assert_ne!(m, synthetic_mac(2, 249, 0), "slave index separates");
        assert_ne!(m, synthetic_mac(3, 249, 1), "node separates");
        assert_ne!(m, synthetic_mac(2, 248, 1), "zone separates");
    }
}
