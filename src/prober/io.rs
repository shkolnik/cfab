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
    /// Open the tap on `slave` if it is not open already, and say so if it cannot be.
    ///
    /// The fallback prober's steady state SENDS NOTHING, so `send` can no longer be what brings
    /// a tap up. It is also the capability probe the leaf needs: a container without the
    /// privileges for `AF_PACKET` or `SO_ATTACH_FILTER` must refuse the leg naming the reason
    /// rather than report every wire quiet forever (spec §11).
    fn listen(&mut self, slave: &str) -> Result<()>;
    /// Put one frame on `slave` exactly as given (no headers added).
    fn send(&mut self, slave: &str, frame: &[u8]) -> Result<()>;
    /// Drain every frame received on `slave` since the last call. Never blocks.
    fn recv(&mut self, slave: &str) -> Result<Vec<Vec<u8>>>;
}

/// Frames drained from one slave in a single tick. With the kernel-side filter attached
/// (`super::bpf`) the queue holds only frames that can be evidence — a handful of hellos and at
/// most one reply — so the cap bounds a pathological tick without being able to hide one.
/// Unfiltered, as the 0.4.6 tap was, it was a starvation hole on any wire with real traffic.
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
        // BEFORE the bind: between an open ETH_P_ALL socket and its filter there is a window in
        // which every frame on the wire is queued, and on a busy VLAN that window is exactly the
        // backlog the drain cap then cannot see past.
        super::bpf::attach(std::os::fd::AsRawFd::as_raw_fd(&fd)).map_err(|e| {
            crate::error::Error::fatal(format!("{slave}: cannot attach the packet filter: {e}"))
        })?;
        bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &addr)
            .map_err(|e| crate::error::Error::fatal(format!("{slave}: cannot bind socket: {e}")))?;
        Ok(fd)
    }
}

impl ProbeIo for PacketIo {
    fn listen(&mut self, slave: &str) -> Result<()> {
        let r = self.sock(slave).map(drop);
        if r.is_err() {
            self.socks.remove(slave);
        }
        r
    }

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
        use nix::sys::socket::{LinkAddr, recvfrom};
        let Some(fd) = self.socks.get(slave) else {
            // No tap here yet. `listen` is what opens one; a tick that has not asked for it
            // cannot have received anything, and opening one here would hide the failure.
            return Ok(Vec::new());
        };
        let raw = std::os::fd::AsRawFd::as_raw_fd(fd);
        let mut out = Vec::new();
        let mut buf = [0u8; RECV_BUF];
        while out.len() < MAX_DRAIN {
            // `recvfrom`, not `recv`, for one field: `sll_pkttype`. An ETH_P_ALL tap sees this
            // host's own TRANSMITTED frames too, and counting our own OSPF hello as evidence
            // that a peer is alive over this wire would make every active slave look healthy
            // forever. `PACKET_OUTGOING` is dropped here, at the seam, so nothing above can
            // forget to. (Our hello REFLECTED back through the backbone onto a backup slave is
            // a received frame and is kept — that is the lone member's self-check, spec §4.)
            // `nix`'s `recvfrom` takes no flags, so the non-blocking contract rests on the
            // socket's own `SOCK_NONBLOCK` (set at `open`, never cleared) and on `EAGAIN`
            // ending the drain below.
            match recvfrom::<LinkAddr>(raw, &mut buf) {
                Ok((0, _)) => break,
                Ok((_, Some(from))) if from.pkttype() == libc::PACKET_OUTGOING => continue,
                Ok((n, _)) => out.push(buf[..n.min(RECV_BUF)].to_vec()),
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
        /// Slaves whose tap cannot be opened at all — the unprivileged container (spec §11).
        pub deaf: BTreeSet<String>,
        /// Slaves `listen` has been called for, so a test can assert the tap was asked for.
        pub listening: BTreeSet<String>,
        /// Frames handed back on the next `recv` of one named slave, then cleared: the passive
        /// channel's evidence, injected per wire.
        pub heard: BTreeMap<String, Vec<Vec<u8>>>,
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
                deaf: BTreeSet::new(),
                listening: BTreeSet::new(),
                heard: BTreeMap::new(),
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
        fn listen(&mut self, slave: &str) -> Result<()> {
            if self.deaf.contains(slave) {
                return Err(crate::error::Error::fatal(format!(
                    "{slave}: cannot open AF_PACKET: Operation not permitted (os error 1)"
                )));
            }
            self.listening.insert(slave.to_string());
            Ok(())
        }

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
            out.extend(self.heard.remove(slave).unwrap_or_default());
            if let Some(probe) = self.outstanding.remove(slave)
                && self.answering.contains(slave)
            {
                out.push(self.reply_to(&probe));
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The starvation hole the 0.4.6 tap had and this one does not. `MAX_DRAIN` bounds a tick on
    /// a busy wire, and on an idle rack that bound is never reached — but a storage VLAN carries
    /// far more than 64 frames per 500 ms, and an unfiltered `ETH_P_ALL` tap would spend the
    /// whole budget on them and never see the one hello that is evidence. With the kernel-side
    /// filter the queue contains only frames that can be evidence, so the cap cannot hide one.
    #[test]
    fn the_filter_keeps_a_busy_wire_from_starving_the_drain() {
        let mut wire: Vec<Vec<u8>> = Vec::new();
        for i in 0..500u32 {
            // Ordinary VLAN traffic: an IPv4 unicast that is not OSPF.
            let mut f = vec![0u8; 64];
            f[12..14].copy_from_slice(&[0x08, 0x00]);
            f[14] = 0x45;
            f[14 + 9] = 6; // TCP
            f[30..34].copy_from_slice(&i.to_be_bytes());
            wire.push(f);
        }
        let hello = {
            let mut f = vec![0u8; 14 + 20 + 24];
            f[12..14].copy_from_slice(&[0x08, 0x00]);
            f[14] = 0x45;
            f[14 + 9] = 89;
            f[14 + 16..14 + 20].copy_from_slice(&[224, 0, 0, 5]);
            f
        };
        let reply = {
            let mut f = vec![0u8; 42];
            f[12..14].copy_from_slice(&[0x08, 0x06]);
            f
        };
        // The evidence arrives late, behind everything else, which is the whole difficulty.
        wire.push(hello.clone());
        wire.push(reply.clone());

        let queued: Vec<&Vec<u8>> = wire
            .iter()
            .filter(|f| super::super::bpf::interp::run(&super::super::bpf::FILTER, f) != 0)
            .take(MAX_DRAIN)
            .collect();
        assert!(queued.contains(&&hello), "the hello must survive the cap");
        assert!(queued.contains(&&reply), "the reply must survive the cap");
        assert!(
            queued.len() <= MAX_DRAIN,
            "the cap still bounds the tick: {}",
            queued.len()
        );
    }
}
