//! The raw-socket seam. One trait, one Linux implementation, one scripted implementation for
//! tests — so every decision above this line is testable without a NIC.

use crate::error::Result;

/// Layer-2 send and receive on ONE bond slave, bypassing the bond.
///
/// `recv` MUST NOT BLOCK. It runs on the supervisor's main loop, which also feeds the systemd
/// watchdog and answers `cfab.sock`: a blocking read on a wire nobody is talking on would stall
/// all three. It returns whatever has arrived since the previous call and nothing else, so a
/// tick on a silent wire costs one syscall that returns `EWOULDBLOCK`.
pub trait ProbeIo {
    /// Put one frame on `slave` exactly as given (no headers added).
    fn send(&mut self, slave: &str, frame: &[u8]) -> Result<()>;
    /// Drain every frame received on `slave` since the last call. Never blocks.
    fn recv(&mut self, slave: &str) -> Result<Vec<Vec<u8>>>;
}

/// Frames drained from one slave in a single tick. A probe draws exactly one reply, so anything
/// beyond a handful is other traffic the ETH_P_ALL tap happens to see; the cap bounds the tick
/// on a busy wire rather than reading until the queue is empty.
const MAX_DRAIN: usize = 64;

/// The largest frame we will read. Anything longer is not an ARP reply, and the tail is not
/// needed to know that.
const RECV_BUF: usize = 256;

/// The real tap: one `AF_PACKET`/`SOCK_RAW` socket per slave netdev, bound to that netdev.
///
/// The socket is bound with `ETH_P_ALL`, not `ETH_P_ARP`. This is the one fact the whole design
/// rests on and it is VERIFIED on the rack (2026-09-07): a socket bound to `ETH_P_ARP` sits
/// behind the bond's `rx_handler`, so it sees the backup slaves' replies but never the ACTIVE
/// slave's — which is exactly the slave whose reachability matters most. `ETH_P_ALL` taps ahead
/// of the handler and sees all three. The cost is that everything else on the wire arrives too,
/// so the filtering is ours (`super::frame::reply_from`).
///
/// Sockets are cached per slave and dropped on the first error. A USB NIC that re-enumerates
/// comes back with a fresh ifindex (finding F5), and a socket bound to the old one is deaf
/// forever — so an error is always treated as "re-bind next tick", never as a permanent state.
#[derive(Default)]
pub struct PacketIo {
    socks: std::collections::BTreeMap<String, std::os::fd::OwnedFd>,
}

impl PacketIo {
    pub fn new() -> PacketIo {
        PacketIo::default()
    }

    /// The socket for `slave`, opened and bound on first use.
    fn sock(&mut self, slave: &str) -> Result<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        if !self.socks.contains_key(slave) {
            let fd = Self::open(slave)?;
            self.socks.insert(slave.to_string(), fd);
        }
        Ok(self.socks[slave].as_fd())
    }

    fn open(slave: &str) -> Result<std::os::fd::OwnedFd> {
        use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, bind, socket};
        // `getifaddrs` is the one safe way to obtain a bound link-layer address for a netdev:
        // it hands back the kernel's own `sockaddr_ll` for the interface, ifindex filled in.
        // The address's `sll_protocol` is 0, and `packet_bind` reads that as "keep the protocol
        // the socket was created with", which is the ETH_P_ALL below.
        let addr = nix::ifaddrs::getifaddrs()
            .map_err(|e| crate::error::Error::fatal(format!("cannot list interfaces: {e}")))?
            .filter(|ia| ia.interface_name == slave)
            .find_map(|ia| ia.address.as_ref().and_then(|a| a.as_link_addr().copied()))
            .ok_or_else(|| {
                crate::error::Error::fatal(format!("{slave}: no link-layer address (no netdev?)"))
            })?;
        let fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            SockProtocol::EthAll,
        )
        .map_err(|e| crate::error::Error::fatal(format!("{slave}: cannot open AF_PACKET: {e}")))?;
        bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &addr)
            .map_err(|e| crate::error::Error::fatal(format!("{slave}: cannot bind socket: {e}")))?;
        Ok(fd)
    }
}

impl ProbeIo for PacketIo {
    fn send(&mut self, slave: &str, frame: &[u8]) -> Result<()> {
        use nix::sys::socket::{MsgFlags, send};
        let r = self
            .sock(slave)
            .and_then(|fd| {
                send(
                    std::os::fd::AsRawFd::as_raw_fd(&fd),
                    frame,
                    MsgFlags::empty(),
                )
                .map_err(|e| crate::error::Error::fatal(format!("{slave}: cannot send probe: {e}")))
            })
            .map(drop);
        if r.is_err() {
            self.socks.remove(slave);
        }
        r
    }

    fn recv(&mut self, slave: &str) -> Result<Vec<Vec<u8>>> {
        use nix::sys::socket::{MsgFlags, recv};
        let Some(fd) = self.socks.get(slave) else {
            // Nothing has been sent on this slave yet, so nothing can have answered. Opening a
            // socket here would only add a syscall to a tick that cannot learn anything.
            return Ok(Vec::new());
        };
        let raw = std::os::fd::AsRawFd::as_raw_fd(fd);
        let mut out = Vec::new();
        let mut buf = [0u8; RECV_BUF];
        while out.len() < MAX_DRAIN {
            // `MSG_DONTWAIT` on top of `SOCK_NONBLOCK`: the flag is what the contract promises,
            // and it holds even if the socket's own flag is ever lost.
            match recv(raw, &mut buf, MsgFlags::MSG_DONTWAIT) {
                Ok(0) => break,
                Ok(n) => out.push(buf[..n.min(RECV_BUF)].to_vec()),
                Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => break,
                Err(e) => {
                    self.socks.remove(slave);
                    return Err(crate::error::Error::fatal(format!(
                        "{slave}: cannot read probe replies: {e}"
                    )));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
pub mod mock {
    //! A scripted `ProbeIo`: the router answers on the slaves listed in `answering`, and only
    //! ever to a probe that was actually sent on that slave — so a test injects a fault by
    //! removing a name, exactly as pulling an uplink does.

    use std::collections::{BTreeMap, BTreeSet};
    use std::net::Ipv4Addr;

    use super::{ProbeIo, Result};

    pub struct ScriptedIo {
        /// The router's address; every synthesized reply comes from it.
        router: Ipv4Addr,
        /// The router's MAC in the replies.
        mac: [u8; 6],
        /// Slaves the router answers on. Mutate between ticks to inject or clear a fault.
        pub answering: BTreeSet<String>,
        /// Slaves whose `send` fails, as an absent netdev's would.
        pub send_fails: BTreeSet<String>,
        /// Frames handed back on the next `recv` regardless of any probe: other traffic the
        /// ETH_P_ALL tap sees, which must never be counted as an answer.
        pub noise: Vec<Vec<u8>>,
        /// Every frame sent, in order.
        pub sent: Vec<(String, Vec<u8>)>,
        /// Probes sent and not yet drained, per slave.
        outstanding: BTreeMap<String, Vec<u8>>,
        pub recv_calls: usize,
    }

    impl ScriptedIo {
        /// A router at `router` answering on every slave named.
        pub fn answering_on(router: &str, slaves: &[&str]) -> ScriptedIo {
            ScriptedIo {
                router: router.parse().expect("a test router address"),
                mac: [0x68, 0xd7, 0x9a, 0x66, 0x91, 0xa9],
                answering: slaves.iter().map(|s| s.to_string()).collect(),
                send_fails: BTreeSet::new(),
                noise: Vec::new(),
                sent: Vec::new(),
                outstanding: BTreeMap::new(),
                recv_calls: 0,
            }
        }

        /// Stop answering on `slave` — the dead-uplink fault.
        pub fn dark(&mut self, slave: &str) {
            self.answering.remove(slave);
        }

        /// Answer on `slave` again.
        pub fn lit(&mut self, slave: &str) {
            self.answering.insert(slave.to_string());
        }

        /// Frames sent on `slave`, in order.
        pub fn sent_on(&self, slave: &str) -> Vec<&[u8]> {
            self.sent
                .iter()
                .filter(|(s, _)| s == slave)
                .map(|(_, f)| f.as_slice())
                .collect()
        }

        /// The reply the router would send to `probe`: unicast back to the probe's source MAC.
        fn reply_to(&self, probe: &[u8]) -> Vec<u8> {
            let src: [u8; 6] = probe[6..12].try_into().expect("a probe has a source MAC");
            let mut f = Vec::new();
            f.extend_from_slice(&src);
            f.extend_from_slice(&self.mac);
            f.extend_from_slice(&[0x08, 0x06]);
            f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
            f.extend_from_slice(&self.mac);
            f.extend_from_slice(&self.router.octets());
            f.extend_from_slice(&src);
            f.extend_from_slice(&[0, 0, 0, 0]);
            f
        }
    }

    impl ProbeIo for ScriptedIo {
        fn send(&mut self, slave: &str, frame: &[u8]) -> Result<()> {
            if self.send_fails.contains(slave) {
                return Err(crate::error::Error::fatal(format!(
                    "{slave}: no such device"
                )));
            }
            self.sent.push((slave.to_string(), frame.to_vec()));
            self.outstanding.insert(slave.to_string(), frame.to_vec());
            Ok(())
        }

        fn recv(&mut self, slave: &str) -> Result<Vec<Vec<u8>>> {
            self.recv_calls += 1;
            let mut out = self.noise.clone();
            if let Some(probe) = self.outstanding.remove(slave)
                && self.answering.contains(slave)
            {
                out.push(self.reply_to(&probe));
            }
            Ok(out)
        }
    }
}
