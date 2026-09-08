//! Neighbour (FDB) event subscription: one non-blocking `NETLINK_ROUTE` socket in
//! `RTNLGRP_NEIGH`, decoded to the announcer's trigger events.
//!
//! `drain` returns every bridge FDB add seen since the last call and never blocks, so the
//! announcer can poll it from its own loop without a runtime — the same synchronous shape as
//! `crate::netlink`. `ENOBUFS` means the kernel dropped events because our receive queue filled:
//! the socket is reopened and the caller is told, so it can treat the gap as "something changed"
//! and burst once rather than miss a workload that started talking during the overflow.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::neighbour::{NeighbourAttribute, NeighbourMessage, NeighbourState};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{Socket, protocols::NETLINK_ROUTE};
use nix::errno::Errno;

/// `include/uapi/linux/rtnetlink.h`: `RTNLGRP_NEIGH` = 3. `NETLINK_ADD_MEMBERSHIP` takes the
/// group id itself, not the `1 << (id - 1)` bit that the legacy bind mask uses.
pub const RTNLGRP_NEIGH: u32 = 3;

/// `sizeof(struct nlmsghdr)`: the smallest length a well-formed message can claim.
const NETLINK_HEADER_LEN: usize = 16;

/// One bridge FDB add as the kernel announced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighEvent {
    /// The bridge port the MAC was seen on (`ndm_ifindex`), not the bridge.
    pub ifindex: u32,
    pub mac: [u8; 6],
    /// `NUD_PERMANENT`: the bridge's own address on the port or an entry added with
    /// `bridge fdb add ... permanent`. An admin `... static` entry is `NUD_NOARP`, so this flag
    /// does NOT mean "programmed by somebody" (measured on pve3-tb 2026-09-08: static = NOARP,
    /// permanent/own MAC = PERMANENT, learned = REACHABLE).
    pub permanent: bool,
}

/// The subscription. Held open across ticks; dropped and reopened on overflow.
pub struct NeighWatch {
    sock: Socket,
}

impl NeighWatch {
    pub fn open() -> io::Result<Self> {
        let mut sock = Socket::new(NETLINK_ROUTE)?;
        sock.bind_auto()?;
        sock.add_membership(RTNLGRP_NEIGH)?;
        sock.set_non_blocking(true)?;
        Ok(Self { sock })
    }

    /// Every bridge-family neighbour add pending on the socket. Never blocks: an empty queue is
    /// `Ok(vec![])`. On `ENOBUFS` the socket is replaced with a fresh one and the error is
    /// returned, which is the caller's signal to burst once and carry on.
    pub fn drain(&mut self) -> io::Result<Vec<NeighEvent>> {
        let mut out = Vec::new();
        loop {
            match self.sock.recv_from_full() {
                Ok((buf, _)) => out.extend(decode(&buf)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(out),
                Err(e) if e.raw_os_error() == Some(Errno::ENOBUFS as i32) => {
                    *self = Self::open()?;
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl AsRawFd for NeighWatch {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

/// Every `RTM_NEWNEIGH` with family `AF_BRIDGE` in one datagram — a multicast datagram may carry
/// several messages, and anything we do not understand is skipped, never an error.
pub fn decode(buf: &[u8]) -> Vec<NeighEvent> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        let Ok(msg) = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf[off..]) else {
            break;
        };
        // A header shorter than itself would not advance `off`; `new_checked` rejects one, but
        // the loop must not depend on that to terminate.
        let len = msg.header.length as usize;
        if len < NETLINK_HEADER_LEN {
            break;
        }
        if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(n)) = &msg.payload
            && let Some(ev) = bridge_event(n)
        {
            out.push(ev);
        }
        off += (len + 3) & !3; // NLMSG_ALIGN
    }
    out
}

// The match below is over the netlink crate's own `#[non_exhaustive]` enum, which no exhaustive
// match can cover: a `_` arm is the only legal spelling. cfab's own enums are still matched
// exhaustively.
#[allow(clippy::wildcard_enum_match_arm)]
fn bridge_event(n: &NeighbourMessage) -> Option<NeighEvent> {
    if n.header.family != AddressFamily::Bridge {
        return None;
    }
    let mac = n.attributes.iter().find_map(|a| match a {
        NeighbourAttribute::LinkLayerAddress(v) if v.len() == 6 => {
            Some([v[0], v[1], v[2], v[3], v[4], v[5]])
        }
        _ => None,
    })?;
    Some(NeighEvent {
        ifindex: n.header.ifindex,
        mac,
        permanent: n.header.state == NeighbourState::Permanent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::NetlinkHeader;
    use netlink_packet_route::neighbour::NeighbourHeader;

    fn newneigh(family: AddressFamily, ifindex: u32, state: NeighbourState) -> Vec<u8> {
        let mut n = NeighbourMessage::default();
        n.header = NeighbourHeader {
            family,
            ifindex,
            state,
            ..Default::default()
        };
        n.attributes.push(NeighbourAttribute::LinkLayerAddress(vec![
            2, 0xcf, 0xab, 0, 0, 1,
        ]));
        let mut msg = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::from(RouteNetlinkMessage::NewNeighbour(n)),
        );
        msg.finalize();
        let mut buf = vec![0; msg.buffer_len()];
        msg.serialize(&mut buf);
        buf
    }

    #[test]
    fn a_bridge_newneigh_decodes_to_ifindex_mac_and_permanence() {
        let ev = decode(&newneigh(
            AddressFamily::Bridge,
            17,
            NeighbourState::Reachable,
        ));
        assert_eq!(
            ev,
            vec![NeighEvent {
                ifindex: 17,
                mac: [2, 0xcf, 0xab, 0, 0, 1],
                permanent: false
            }]
        );
        assert!(
            decode(&newneigh(
                AddressFamily::Bridge,
                17,
                NeighbourState::Permanent
            ))[0]
                .permanent
        );
    }

    #[test]
    fn a_non_bridge_newneigh_is_ignored_and_two_in_one_datagram_both_decode() {
        assert!(
            decode(&newneigh(
                AddressFamily::Inet,
                17,
                NeighbourState::Reachable
            ))
            .is_empty()
        );
        let mut two = newneigh(AddressFamily::Bridge, 1, NeighbourState::Reachable);
        two.extend(newneigh(
            AddressFamily::Bridge,
            2,
            NeighbourState::Reachable,
        ));
        assert_eq!(
            decode(&two).iter().map(|e| e.ifindex).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    /// THE PROBE (ruling 12). Root, a bridge, and a MAC that starts talking on a non-uplink port.
    /// Run on the testbed, from /root/build/cfab as root:
    /// CFAB_PROBE_IFINDEX=<ifindex of cnfvm9-h> cargo test --release --lib -- --ignored a_learned_bridge_fdb_entry_emits_rtm_newneigh --nocapture
    #[test]
    #[ignore]
    fn a_learned_bridge_fdb_entry_emits_rtm_newneigh() {
        let want: u32 = std::env::var("CFAB_PROBE_IFINDEX")
            .expect("CFAB_PROBE_IFINDEX")
            .parse()
            .unwrap();
        let mut w = NeighWatch::open().expect("open RTNLGRP_NEIGH (root?)");
        eprintln!("probe: subscribed, waiting up to 30 s for a bridge FDB add on ifindex {want}");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            for ev in w.drain().unwrap_or_default() {
                eprintln!("probe: event {ev:?}");
                if ev.ifindex == want && !ev.permanent {
                    eprintln!("probe: RTM_NEWNEIGH FIRES for a learned entry");
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!(
            "probe: NO RTM_NEWNEIGH for a learned entry on ifindex {want} within 30 s — STOP and report"
        );
    }
}
