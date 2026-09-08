//! The prober's control loop over rtnetlink: read a bond port's facts, write the bond's active
//! port.
//!
//! The two operations here replace three sysfs paths the prober used to read and write as text
//! (`<port>/carrier`, `<port>/bonding_slave/mii_status`, `<bond>/bonding/active_slave`). The
//! gain is not speed — a GETLINK by name measured 20.8 us on pve3 against a real bond, against
//! 1.35 us for one sysfs read, which is 0.19 ms of a 500 ms tick at nine ports — it is that the
//! kernel answers in typed values and refuses in an
//! errno, so nothing between the kernel and `decide` is a string that could be spelled
//! differently by a future release. Configuration (`ip …` in apply/down) is untouched: this is
//! only the loop that runs on every live member twice a second.
//!
//! Everything is synchronous: one blocking `NETLINK_ROUTE` socket, one request, one reply. The
//! prober's tick has no runtime and gets none.

use std::io;
use std::os::fd::AsFd;
use std::time::Duration;

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::{
    InfoBond, InfoBondPort, InfoData, InfoKind, InfoPortData, LinkAttribute, LinkFlags, LinkInfo,
    LinkMessage, MiiStatus,
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::errno::Errno;
use nix::sys::socket::{setsockopt, sockopt::ReceiveTimeout};
use nix::sys::time::TimeVal;

use crate::error::{Error, Result};
use crate::prober::decide::BondLink;

/// How long one reply may take before the tick gives up on it. A netlink round trip is tens of
/// microseconds; anything near this is a socket that has stopped answering, and the sysfs read
/// this replaces could not hang at all. Well inside `PROBE_INTERVAL`, so a wedged socket costs
/// one late tick, not a stalled prober.
const RECV_TIMEOUT: Duration = Duration::from_millis(200);

/// One bond port as the kernel describes it, in one GETLINK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortState {
    /// The bonding driver's own per-port link state (`IFLA_BOND_SLAVE_MII_STATUS`). `None` when
    /// the netdev is not a bond port at all — the kernel sends no port data for it — which is
    /// the normal state of a plain sub-interface and is not news.
    pub link: Option<BondLink>,
    /// `IFF_LOWER_UP`: the cable is in and the driver has the link.
    pub carrier: bool,
    /// `IFLA_MASTER`: the bond this port belongs to, by ifindex. `None` when it is in none.
    pub master: Option<u32>,
}

/// Is this the kernel saying the netdev does not exist? `ENODEV` is the only error a caller
/// reads as a fact about the wire ("the port has gone away") rather than as a fault of ours.
pub fn is_no_device(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.raw_os_error() == Some(Errno::ENODEV as i32))
}

/// One blocking `NETLINK_ROUTE` socket, opened on first use and kept across ticks. Any error
/// that is not the kernel refusing a request drops the socket, so the next tick opens a fresh
/// one rather than inheriting a wedged fd.
#[derive(Default)]
pub struct BondNetlink {
    sock: Option<Socket>,
    seq: u32,
}

// The three matches below are over the netlink crate's own `#[non_exhaustive]` enums, which no
// exhaustive match can cover: a `_` arm is the only legal spelling, and each one says what the
// values it does not name mean. cfab's own enums are still matched exhaustively.
#[allow(clippy::wildcard_enum_match_arm)]
impl BondNetlink {
    pub fn new() -> BondNetlink {
        BondNetlink::default()
    }

    fn socket(&mut self) -> io::Result<&Socket> {
        if self.sock.is_none() {
            let mut s = Socket::new(NETLINK_ROUTE)?;
            s.bind_auto()?;
            s.connect(&SocketAddr::new(0, 0))?;
            setsockopt(
                &s.as_fd(),
                ReceiveTimeout,
                &TimeVal::new(0, RECV_TIMEOUT.as_micros() as i64),
            )?;
            self.sock = Some(s);
        }
        Ok(self.sock.as_ref().expect("just opened"))
    }

    /// Send one request and return the reply carrying OUR sequence number: `Some(link)` for a
    /// `NewLink`, `None` for a bare ACK, `Err` for the kernel's NACK (errno preserved).
    ///
    /// The sequence match is not bookkeeping. Any reply left in the receive queue by an earlier
    /// call — the ACK the kernel sends *in addition* to the answer when `NLM_F_ACK` is set on a
    /// GET, for one — is read by the next call as its own answer, silently and plausibly, so a
    /// tick acts on the previous tick's state (MEASURED 2026-09-08, which is why GETLINK below
    /// asks for no ACK).
    fn call(&mut self, m: RouteNetlinkMessage, flags: u16) -> io::Result<Option<LinkMessage>> {
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        let mut hdr = NetlinkHeader::default();
        hdr.flags = NLM_F_REQUEST | flags;
        hdr.sequence_number = seq;
        let mut req = NetlinkMessage::new(hdr, NetlinkPayload::from(m));
        req.finalize();
        let mut buf = vec![0u8; req.buffer_len()];
        req.serialize(&mut buf);
        let sock = self.socket()?;
        sock.send(&buf, 0)?;
        loop {
            // `recv_from_full` sizes the buffer from a MSG_PEEK|MSG_TRUNC probe, so an ifinfo
            // message larger than any fixed buffer arrives whole rather than truncated.
            let (resp, _) = sock.recv_from_full()?;
            let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp)
                .map_err(io::Error::other)?;
            if msg.header.sequence_number != seq {
                continue;
            }
            return match msg.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(l)) => Ok(Some(l)),
                NetlinkPayload::Error(e) => match e.code {
                    None => Ok(None),
                    Some(_) => Err(e.to_io()),
                },
                // The kernel answers a GETLINK with NewLink and everything else with Error;
                // any third shape is a reply we did not ask for.
                _ => Err(io::Error::other("unexpected netlink reply")),
            };
        }
    }

    /// `call`, plus the socket hygiene: a failure that is not the kernel's own refusal leaves
    /// the socket unusable as far as we can tell, so it is dropped and reopened next call.
    fn call_fresh(&mut self, m: RouteNetlinkMessage, flags: u16) -> Result<Option<LinkMessage>> {
        match self.call(m, flags) {
            Ok(r) => Ok(r),
            Err(e) => {
                if e.raw_os_error().is_none() {
                    self.sock = None;
                }
                Err(Error::Io(e))
            }
        }
    }

    fn get_link(&mut self, name: &str) -> Result<LinkMessage> {
        let mut lm = LinkMessage::default();
        lm.attributes.push(LinkAttribute::IfName(name.to_string()));
        // No NLM_F_ACK: on a successful GET the kernel would queue a second datagram.
        self.call_fresh(RouteNetlinkMessage::GetLink(lm), 0)?
            .ok_or_else(|| Error::Io(io::Error::other(format!("{name}: no link in reply"))))
    }

    /// One `RTM_GETLINK` by name: everything the prober's tick needs to know about a port.
    ///
    /// By NAME, not by ifindex: with `NETLINK_GET_STRICT_CHK` a by-ifindex GETLINK returned
    /// carrier and master but NO bond port data at all on every real port (rack, 2026-09-08),
    /// so the `mii_status` half of the answer would have been silently missing.
    pub fn port_state(&mut self, name: &str) -> Result<PortState> {
        let link = self.get_link(name)?;
        let mut st = PortState {
            carrier: link.header.flags.contains(LinkFlags::LowerUp),
            ..PortState::default()
        };
        for a in &link.attributes {
            match a {
                LinkAttribute::Controller(ix) => st.master = Some(*ix),
                LinkAttribute::LinkInfo(infos) => {
                    for i in infos {
                        if let LinkInfo::PortData(InfoPortData::BondPort(ports)) = i {
                            for p in ports {
                                if let InfoBondPort::MiiStatus(m) = p {
                                    st.link = Some(bond_link(*m));
                                }
                            }
                        }
                    }
                }
                // One GETLINK carries every attribute of the netdev; three of them are ours.
                _ => {}
            }
        }
        Ok(st)
    }

    fn ifindex(&mut self, name: &str) -> Result<u32> {
        Ok(self.get_link(name)?.header.index)
    }

    /// Make `port` the bond's active port (`IFLA_BOND_ACTIVE_SLAVE`, spelled `ActivePort` since
    /// the kernel's own rename).
    ///
    /// `EINVAL` is the kernel's refusal when the port is down or its link is not up — the same
    /// refusal the sysfs write gave, now as an errno rather than a sentence — so the errno is
    /// kept in the error text the prober logs.
    pub fn set_active_port(&mut self, bond: &str, port: &str) -> Result<()> {
        let port_ix = self.ifindex(port)?;
        let bond_ix = self.ifindex(bond)?;
        self.call_fresh(set_active_msg(bond_ix, port_ix), NLM_F_ACK)?;
        Ok(())
    }
}

/// The active-port write, as a message: `RTM_NEWLINK` on the bond by ifindex, carrying the bond
/// kind and its data.
///
/// It must be `NewLink`. `RTM_SETLINK` applies generic link attributes only and drops
/// `IFLA_INFO_DATA` on the floor — VERIFIED on the rack 2026-09-08, where a `SetLink` carrying
/// this same payload was ACKed with no error and no effect on a bond whose sysfs write and
/// `ip link set … type bond active_slave …` both refused with `EINVAL` and a kernel log line.
/// A prober built on `SetLink` would look healthy and never move a bond, so the message type is
/// asserted in a test of its own.
fn set_active_msg(bond_ifindex: u32, port_ifindex: u32) -> RouteNetlinkMessage {
    let mut lm = LinkMessage::default();
    lm.header.index = bond_ifindex;
    lm.attributes.push(LinkAttribute::LinkInfo(vec![
        // The kind must accompany the data or the kernel has no parser to hand it to.
        LinkInfo::Kind(InfoKind::Bond),
        LinkInfo::Data(InfoData::Bond(vec![InfoBond::ActivePort(port_ifindex)])),
    ]));
    RouteNetlinkMessage::NewLink(lm)
}

/// The bonding driver's ladder, as the kernel sends it. `Other` — and any value a future
/// release of the crate adds to its own non-exhaustive enum — is the loud unknown case: the
/// prober says the number and treats the port as not up, rather than guessing at a default.
#[allow(clippy::wildcard_enum_match_arm)]
fn bond_link(m: MiiStatus) -> BondLink {
    match m {
        MiiStatus::Up => BondLink::Up,
        MiiStatus::GoingBack => BondLink::GoingBack,
        MiiStatus::GoingDown => BondLink::GoingDown,
        MiiStatus::Down => BondLink::Down,
        // `Other`, and any rung a later crate release names: the raw number, said out loud.
        other => BondLink::Unknown(u8::from(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four states the driver has map to the domain type, and anything else carries its raw
    /// number through rather than becoming a silent default.
    #[test]
    fn mii_status_maps_to_the_domain_type_and_keeps_unknown_values() {
        assert_eq!(bond_link(MiiStatus::Up), BondLink::Up);
        assert_eq!(bond_link(MiiStatus::GoingBack), BondLink::GoingBack);
        assert_eq!(bond_link(MiiStatus::GoingDown), BondLink::GoingDown);
        assert_eq!(bond_link(MiiStatus::Down), BondLink::Down);
        assert_eq!(bond_link(MiiStatus::Other(9)), BondLink::Unknown(9));
    }

    /// `ENODEV` is a fact about the wire; every other errno is a fault to report.
    #[test]
    fn only_enodev_reads_as_the_netdev_being_gone() {
        let gone = Error::Io(io::Error::from_raw_os_error(Errno::ENODEV as i32));
        let refused = Error::Io(io::Error::from_raw_os_error(Errno::EINVAL as i32));
        assert!(is_no_device(&gone));
        assert!(!is_no_device(&refused));
        assert!(!is_no_device(&Error::fatal("no socket")));
    }

    /// The write is `RTM_NEWLINK` and names the bond by ifindex, carrying the bond kind next to
    /// the active port. `RTM_SETLINK` with the identical payload is ACKed and does nothing
    /// (rack, 2026-09-08), which every other assertion here would pass — so the message type is
    /// the assertion.
    #[test]
    fn the_active_port_write_is_a_newlink_carrying_the_bond_kind() {
        let RouteNetlinkMessage::NewLink(lm) = set_active_msg(7, 12) else {
            panic!("the active-port write must be RTM_NEWLINK: RTM_SETLINK is silently ignored");
        };
        assert_eq!(lm.header.index, 7);
        let [LinkAttribute::LinkInfo(infos)] = &lm.attributes[..] else {
            panic!("one LinkInfo attribute: {:?}", lm.attributes);
        };
        assert_eq!(infos[0], LinkInfo::Kind(InfoKind::Bond));
        assert_eq!(
            infos[1],
            LinkInfo::Data(InfoData::Bond(vec![InfoBond::ActivePort(12)]))
        );
    }

    /// A GETLINK on `lo` is unprivileged, so the whole round trip — open, sequence stamp, one
    /// reply, decode — is exercised for real wherever tests run. `lo` is in no bond, which is
    /// exactly the `link: None` case the prober must not treat as a fault.
    #[test]
    fn a_real_getlink_on_lo_answers_with_no_bond_port_data() {
        let mut nl = BondNetlink::new();
        let st = nl.port_state("lo").expect("GETLINK lo");
        assert_eq!(st.link, None);
        assert_eq!(st.master, None);
        // Two calls in a row over the same socket: the second must be the second answer, not
        // the first one left in the queue.
        assert_eq!(nl.port_state("lo").expect("GETLINK lo again"), st);
    }

    /// A netdev that does not exist is `ENODEV`, which is what the prober keys "gone" on.
    #[test]
    fn a_missing_netdev_is_enodev() {
        let mut nl = BondNetlink::new();
        let err = nl.port_state("cfab-nodev0").expect_err("no such netdev");
        assert!(is_no_device(&err), "{err}");
    }
}
