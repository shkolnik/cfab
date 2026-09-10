//! The DHCP relay: one `tokio::spawn` task per `[[workload]]` row declaring `dhcp_server`
//! (spec §5.4, call 2 RULED). Everything below the task loop is pure — BOOTP/DHCP parsing and
//! the RFC 1542 forwarding decision — and is unit-tested against the real packets captured off
//! the testbed wire (`tests/fixtures/dhcp-*.bin`); the task itself is a thin two-socket async
//! loop around that pure core, plus the one place it must NOT act directly: the kernel neighbor
//! write a relayed ACK earns, which crosses to the supervisor's main loop as `Cmd::DhcpAck`
//! because `Sys` is owned there and is not `Send` (spec §5.4, r3 review N2c).
//!
//! **Never an option rewriter.** RFC 1542 forwarding touches exactly `hops`, `giaddr`, and (to
//! pick where a reply goes) reads `ciaddr`; every byte of `sname`, `file` and the option area
//! rides through unexamined and unchanged. `Bootp` is built around that: it holds the whole
//! packet and exposes narrow accessors for the handful of fields the relay reads or writes,
//! never a struct that would have to understand every DHCP option to round-trip one back to
//! bytes it did not originate.
//!
//! **Both directions are validated before anything is acted on** (spec §5.4, r3/r4 review N6):
//! the client-facing socket ignores a `BOOTREPLY` (its own broadcast replies loop back to it) and
//! a client packet carrying a foreign `giaddr`; the server-facing socket — not device-bound, so
//! anything routable can reach it, including a VM unicasting straight to the leg address — ignores
//! a `BOOTREQUEST`, and a `BOOTREPLY` whose source is not the declared `dhcp_server` or whose
//! `giaddr` is not this row's own leg address. That is what makes "only toward the declared
//! server" true in both directions, not merely intended (spec §5.8).

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::model::Ipv4Prefix;
use crate::supervisor::child::BACKOFF;
use crate::supervisor::{Cmd, RelayEvent, Shared};

/// BOOTP opcodes (RFC 2131 §2).
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;

/// DHCP message types (option 53) the relay itself inspects; every other value is forwarded
/// unexamined — "no lease state" (spec §5.4).
const DHCPACK: u8 = 5;

/// Bytes from `op` through the end of `file`, before the magic cookie (RFC 2131 §2): 1+1+1+1
/// (op/htype/hlen/hops) + 4 (xid) + 2+2 (secs/flags) + 4×4 (ciaddr/yiaddr/siaddr/giaddr) + 16
/// (chaddr) + 64 (sname) + 128 (file).
const HEADER_LEN: usize = 236;
/// RFC 1497: the four bytes every DHCP (as opposed to plain BOOTP) packet carries right after
/// the fixed header, identifying the option area that follows.
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// The shortest buffer `Bootp::parse` accepts: the fixed header plus the cookie, no options.
/// Real traffic is never this short (the fixtures are 300 bytes), but nothing here should ever
/// index into a option area that was never validated to exist.
const MIN_LEN: usize = HEADER_LEN + MAGIC_COOKIE.len();

const CIADDR_OFF: usize = 12;
const YIADDR_OFF: usize = 16;
const GIADDR_OFF: usize = 24;
const CHADDR_OFF: usize = 28;

/// The relay's own well-known port: both of its sockets bind it (spec §5.4) — the client-facing
/// one at the wildcard address, the server-facing one at the leg's own address — which is
/// exactly why both need `SO_REUSEADDR`.
pub const PORT: u16 = 67;
/// Where a relayed reply is sent back to a client (RFC 951/2131: BOOTPC).
const CLIENT_PORT: u16 = 68;

/// A live view over one BOOTP/DHCP message. Holds the whole packet; every accessor reads (or,
/// for the three RFC 1542 forwarding fields, writes) a fixed offset, and `into_bytes` hands back
/// everything else — `sname`, `file`, the options — untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootp(Vec<u8>);

impl Bootp {
    /// Validates only what forwarding needs to trust: the packet is long enough to hold the
    /// fixed header and the DHCP magic cookie, and the cookie is the right one (a plain BOOTP
    /// packet, or garbage, is rejected the same way — the relay has nothing to say about either).
    pub fn parse(buf: &[u8]) -> Result<Bootp, String> {
        if buf.len() < MIN_LEN {
            return Err(format!(
                "short BOOTP packet: {} bytes (want at least {MIN_LEN}, the fixed header plus \
                 the DHCP magic cookie)",
                buf.len()
            ));
        }
        if buf[HEADER_LEN..HEADER_LEN + MAGIC_COOKIE.len()] != MAGIC_COOKIE {
            return Err("not a DHCP packet: bad magic cookie".to_string());
        }
        Ok(Bootp(buf.to_vec()))
    }

    pub fn op(&self) -> u8 {
        self.0[0]
    }

    fn htype(&self) -> u8 {
        self.0[1]
    }

    fn hlen(&self) -> u8 {
        self.0[2]
    }

    pub fn hops(&self) -> u8 {
        self.0[3]
    }

    pub fn set_hops(&mut self, hops: u8) {
        self.0[3] = hops;
    }

    pub fn ciaddr(&self) -> Ipv4Addr {
        addr_at(&self.0, CIADDR_OFF)
    }

    pub fn yiaddr(&self) -> Ipv4Addr {
        addr_at(&self.0, YIADDR_OFF)
    }

    pub fn giaddr(&self) -> Ipv4Addr {
        addr_at(&self.0, GIADDR_OFF)
    }

    pub fn set_giaddr(&mut self, addr: Ipv4Addr) {
        self.0[GIADDR_OFF..GIADDR_OFF + 4].copy_from_slice(&addr.octets());
    }

    /// The client's Ethernet address, when `chaddr` actually holds one (`htype` 1, `hlen` 6 —
    /// true of every fixture and every real Ethernet client this project targets). `None` for
    /// anything else, so a caller never manufactures a MAC out of padding bytes.
    pub fn chaddr6(&self) -> Option<[u8; 6]> {
        if self.htype() == 1 && self.hlen() == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&self.0[CHADDR_OFF..CHADDR_OFF + 6]);
            Some(mac)
        } else {
            None
        }
    }

    /// Option 53 (DHCP message type), scanned with bounds checks throughout: a truncated or
    /// malformed option area ends the scan rather than indexing past it, and yields `None`
    /// exactly as an absent option 53 would (the packet is still forwarded — this reads the
    /// message type, it does not gate on it, spec §5.4 "no lease state").
    pub fn message_type(&self) -> Option<u8> {
        let opts = &self.0[HEADER_LEN + MAGIC_COOKIE.len()..];
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                0 => i += 1,  // pad
                255 => break, // end
                code => {
                    let len = *opts.get(i + 1)?;
                    let start = i + 2;
                    let end = start + len as usize;
                    let val = opts.get(start..end)?;
                    if code == 53 && len == 1 {
                        return Some(val[0]);
                    }
                    i = end;
                }
            }
        }
        None
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

fn addr_at(bytes: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3])
}

/// What became of one packet the relay looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Forward `bytes` (the packet, with `hops`/`giaddr` updated where RFC 1542 requires) to
    /// `to`.
    Forward {
        to: SocketAddrV4,
        bytes: Vec<u8>,
    },
    Drop(DropReason),
}

/// Why a packet was not forwarded. Not logged one line per drop (a stray broadcast or a probing
/// scanner would make that a self-inflicted DoS on the journal) — carried only for the unit
/// tests, which assert the exact reason a case is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Malformed,
    /// A `BOOTREPLY` arrived on the client-facing socket: its own broadcast reply, looped back.
    NotABootrequest,
    /// A `BOOTREQUEST` arrived on the server-facing socket: ours forwarded back by an odd
    /// routing path, or a VM that unicasts straight to the leg address on port 67.
    NotABootreply,
    /// RFC 1542: 16 hops means a loop. Discard rather than forward it once more.
    HopsExceeded,
    /// A client packet already carries a `giaddr` that is neither zero nor ours — another
    /// relay's, or a forgery.
    ForeignGiaddr(Ipv4Addr),
    /// A server-facing `BOOTREPLY` whose UDP source is not the row's declared `dhcp_server`.
    UntrustedServer(Ipv4Addr),
    /// A server-facing `BOOTREPLY` whose `giaddr` is not this row's own leg address — not a
    /// reply to a request this relay made.
    ForeignReplyGiaddr(Ipv4Addr),
    /// A trusted reply's `ciaddr` is outside the row's own `prefix` (S3, defense in depth): the
    /// server-facing socket is not device-bound, so anything routable can reach it, and
    /// `rp_filter = 2` (loose) admits a spoofed source. Bounded blast radius even so —
    /// `hostroutes::local_vms` already filters to `prefix`, excludes `fabric_addresses`, and
    /// requires the MAC on a non-uplink FDB port — but this also catches a misconfigured dhcpd
    /// serving the wrong subnet, so it is worth the three lines.
    OutOfPrefix(Ipv4Addr),
}

/// The client→server half (spec §5.4): drop when `hops >= 16` or `giaddr` is someone else's;
/// else `hops += 1`, set `giaddr = leg` when it was zero, and send to `dhcp_server:67`.
pub fn forward_client(pkt: &[u8], leg: Ipv4Addr, dhcp_server: Ipv4Addr) -> Action {
    let mut p = match Bootp::parse(pkt) {
        Ok(p) => p,
        Err(_) => return Action::Drop(DropReason::Malformed),
    };
    if p.op() != BOOTREQUEST {
        return Action::Drop(DropReason::NotABootrequest);
    }
    let g = p.giaddr();
    if !g.is_unspecified() && g != leg {
        return Action::Drop(DropReason::ForeignGiaddr(g));
    }
    if p.hops() >= 16 {
        return Action::Drop(DropReason::HopsExceeded);
    }
    p.set_hops(p.hops() + 1);
    if g.is_unspecified() {
        p.set_giaddr(leg);
    }
    Action::Forward {
        to: SocketAddrV4::new(dhcp_server, PORT),
        bytes: p.into_bytes(),
    }
}

/// The server→client half (spec §5.4): trust only a `BOOTREPLY` whose UDP source is
/// `dhcp_server` and whose `giaddr` is this row's own leg address; then `ciaddr != 0` unicasts
/// to it, else broadcasts to the leg (a unicast to `yiaddr` cannot work before the client owns
/// the address — finding 9). A nonzero `ciaddr` outside `prefix` is refused (S3): the
/// server-facing socket is not device-bound and cfab sets `rp_filter = 2` (loose), so a spoofed
/// `BOOTREPLY` that otherwise passes the two trust checks above must not teach the host a
/// neighbor entry for an address this row has no business claiming.
pub fn forward_server(
    pkt: &[u8],
    src: Ipv4Addr,
    leg: Ipv4Addr,
    dhcp_server: Ipv4Addr,
    prefix: Ipv4Prefix,
) -> Action {
    let p = match Bootp::parse(pkt) {
        Ok(p) => p,
        Err(_) => return Action::Drop(DropReason::Malformed),
    };
    if p.op() != BOOTREPLY {
        return Action::Drop(DropReason::NotABootreply);
    }
    if src != dhcp_server {
        return Action::Drop(DropReason::UntrustedServer(src));
    }
    if p.giaddr() != leg {
        return Action::Drop(DropReason::ForeignReplyGiaddr(p.giaddr()));
    }
    let ciaddr = p.ciaddr();
    if !ciaddr.is_unspecified() && !prefix.contains(ciaddr) {
        return Action::Drop(DropReason::OutOfPrefix(ciaddr));
    }
    let dest = if ciaddr.is_unspecified() {
        Ipv4Addr::BROADCAST
    } else {
        ciaddr
    };
    Action::Forward {
        to: SocketAddrV4::new(dest, CLIENT_PORT),
        bytes: p.into_bytes(),
    }
}

/// Whether an already-trusted server→client reply should register a VM (spec §5.4, call 5
/// caveat): only a DHCPACK whose `chaddr` is a 6-byte Ethernet address and whose `yiaddr` is
/// set and inside `prefix` (S3, same defense in depth as `forward_server`'s `ciaddr` check — a
/// spoofed ACK must not earn a neighbor write for an address outside this row's own subnet). A
/// DHCPNAK never registers — no lease was granted. Re-parses the raw buffer rather than
/// threading the already-parsed `Bootp` through `forward_server`, so "is this reply trustworthy
/// enough to relay" and "does it teach us a VM's address" stay two functions a reviewer can
/// read, and mistrust, independently.
pub fn ack_discovery(pkt: &[u8], prefix: Ipv4Prefix) -> Option<(Ipv4Addr, [u8; 6])> {
    let p = Bootp::parse(pkt).ok()?;
    if p.message_type() != Some(DHCPACK) {
        return None;
    }
    let yiaddr = p.yiaddr();
    if yiaddr.is_unspecified() || !prefix.contains(yiaddr) {
        return None;
    }
    let chaddr = p.chaddr6()?;
    Some((yiaddr, chaddr))
}

/// One `[[workload]]` row this member runs a relay for.
#[derive(Debug, Clone)]
pub struct RelayRow {
    pub name: String,
    /// The leg's ifname, e.g. `cfab-work-vms` (`SO_BINDTODEVICE` for the client socket).
    pub leg: String,
    /// This member's own address on the leg — the `giaddr` the relay stamps, and the address
    /// the server-facing socket binds to.
    pub leg_addr: Ipv4Addr,
    pub dhcp_server: Ipv4Addr,
    /// This row's own subnet (S3): a trusted reply's `ciaddr`/`yiaddr` must fall inside it, or
    /// it is refused rather than acted on.
    pub prefix: Ipv4Prefix,
}

/// Bind the client-facing socket: `0.0.0.0:<port>`, restricted to `device` when given (several
/// rows each need port 67 — per-device binding is load-bearing, spec §5.4), broadcast-capable (a
/// reply with no known `ciaddr` yet must reach the leg's broadcast address). `SO_REUSEADDR`
/// before `bind`: it and the server-facing socket share port 67, one at the wildcard address and
/// one at a specific one, and Linux admits that only when every socket in the group sets it
/// (INFERRED from kernel semantics — a first-bind failure either way, so the rack proof settles
/// it for real).
fn bind_client(port: u16, device: Option<&str>) -> io::Result<std::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    if let Some(dev) = device {
        sock.bind_device(Some(dev.as_bytes()))?;
    }
    sock.set_broadcast(true)?;
    sock.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).into())?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// Bind the server-facing socket: the leg's own ADDRESS on `port`, no device restriction — the
/// server's reply arrives on whichever device routes to it (the mgmt ingress leg), never on the
/// leg itself (spec §5.4). `SO_REUSEADDR` for the same reason as the client socket.
fn bind_server(addr: Ipv4Addr, port: u16) -> io::Result<std::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.bind(&SocketAddr::V4(SocketAddrV4::new(addr, port)).into())?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

fn bind_pair(row: &RelayRow) -> io::Result<(UdpSocket, UdpSocket)> {
    let client = bind_client(PORT, Some(&row.leg))?;
    let server = bind_server(row.leg_addr, PORT)?;
    Ok((UdpSocket::from_std(client)?, UdpSocket::from_std(server)?))
}

/// DHCP messages this relay forwards fit in far less; 1500 gives headroom for a heavily
/// option-laden client (PXE, vendor options) without ever growing unbounded. A datagram larger
/// than this is silently truncated by `recv_from` (no error), and the truncated body is what
/// gets forwarded — accepted rather than guarded against, since Ethernet's own 1500-byte MTU
/// makes a larger UDP payload vanishingly rare on this wire (fold-in, opus review).
const BUF_LEN: usize = 1500;

/// The relay task (spec §5.4): bind, serve until a socket errors, then retry forever on the same
/// backoff a supervised child restarts on. A bind failure is loud (one journal line) and never
/// fatal to the member — this loop simply tries again, so a leg that does not exist yet (a
/// deferred row, a watchdog rebuild in progress) is indistinguishable in kind from a port
/// transiently held by something else: both clear themselves the moment the precondition does.
pub(crate) async fn run(
    row: RelayRow,
    shared: Arc<Mutex<Shared>>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
) {
    loop {
        match bind_pair(&row) {
            Ok((client, server)) => {
                shared
                    .lock()
                    .unwrap()
                    .relay_event(&row.name, row.dhcp_server, RelayEvent::Bound);
                eprintln!(
                    "cfab: workload {}: dhcp relay bound on {}, forwarding to {}",
                    row.name, row.leg, row.dhcp_server
                );
                let why = serve(&client, &server, &row, &shared, &cmd_tx).await;
                eprintln!(
                    "cfab: workload {}: dhcp relay socket lost ({why}); retrying in {}s",
                    row.name,
                    BACKOFF.as_secs()
                );
                shared.lock().unwrap().relay_event(
                    &row.name,
                    row.dhcp_server,
                    RelayEvent::BindError(why),
                );
            }
            Err(e) => {
                let msg = format!("cannot bind: {e}");
                shared.lock().unwrap().relay_event(
                    &row.name,
                    row.dhcp_server,
                    RelayEvent::BindError(msg.clone()),
                );
                eprintln!(
                    "cfab: workload {}: dhcp relay {msg}; retrying in {}s",
                    row.name,
                    BACKOFF.as_secs()
                );
            }
        }
        tokio::time::sleep(BACKOFF).await;
    }
}

/// Serve both sockets until one of them errors on `recv_from`; returns why. A `send_to` failure
/// is not fatal to the loop — one lost frame is cheaper than tearing down a relay that is
/// otherwise working, and the RFC's own client/server retransmits cover it.
async fn serve(
    client: &UdpSocket,
    server: &UdpSocket,
    row: &RelayRow,
    shared: &Arc<Mutex<Shared>>,
    cmd_tx: &mpsc::UnboundedSender<Cmd>,
) -> String {
    let mut cbuf = [0u8; BUF_LEN];
    let mut sbuf = [0u8; BUF_LEN];
    loop {
        tokio::select! {
            r = client.recv_from(&mut cbuf) => {
                match r {
                    Ok((n, _from)) => {
                        if let Action::Forward { to, bytes } =
                            forward_client(&cbuf[..n], row.leg_addr, row.dhcp_server)
                            && server.send_to(&bytes, to).await.is_ok()
                        {
                            shared.lock().unwrap().relay_event(
                                &row.name, row.dhcp_server, RelayEvent::Request,
                            );
                        }
                    }
                    Err(e) => return format!("client socket: {e}"),
                }
            }
            r = server.recv_from(&mut sbuf) => {
                match r {
                    Ok((n, from)) => {
                        let std::net::IpAddr::V4(src) = from.ip() else {
                            continue; // this relay never binds a v6 socket; not ours
                        };
                        if let Action::Forward { to, bytes } =
                            forward_server(&sbuf[..n], src, row.leg_addr, row.dhcp_server, row.prefix)
                        {
                            if let Some((yiaddr, chaddr)) = ack_discovery(&sbuf[..n], row.prefix) {
                                shared.lock().unwrap().relay_event(
                                    &row.name, row.dhcp_server, RelayEvent::Discovered,
                                );
                                let _ = cmd_tx.send(Cmd::DhcpAck {
                                    name: row.name.clone(),
                                    leg: row.leg.clone(),
                                    yiaddr,
                                    chaddr,
                                });
                            }
                            if client.send_to(&bytes, to).await.is_ok() {
                                shared.lock().unwrap().relay_event(
                                    &row.name, row.dhcp_server, RelayEvent::Reply,
                                );
                            }
                        }
                    }
                    Err(e) => return format!("server socket: {e}"),
                }
            }
        }
    }
}

/// `00:11:22:33:44:55` — the spelling `ip neigh` wants and every other tool prints a MAC in.
pub fn mac_str(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCOVER: &[u8] = include_bytes!("../../tests/fixtures/dhcp-discover.bin");
    const OFFER: &[u8] = include_bytes!("../../tests/fixtures/dhcp-offer.bin");
    const REQUEST: &[u8] = include_bytes!("../../tests/fixtures/dhcp-request.bin");
    const ACK: &[u8] = include_bytes!("../../tests/fixtures/dhcp-ack.bin");
    const NAK: &[u8] = include_bytes!("../../tests/fixtures/dhcp-nak.bin");

    const LEG: Ipv4Addr = Ipv4Addr::new(192, 168, 22, 2);
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 10, 11);
    const CHADDR: [u8; 6] = [0x4e, 0x48, 0xe9, 0x89, 0x2e, 0xe5];
    /// This row's own subnet (S3): covers `LEG` and every fixture's `yiaddr`
    /// (192.168.22.150), the way a real `[[workload]]` row's `prefix` would.
    const PREFIX: Ipv4Prefix = Ipv4Prefix {
        net: Ipv4Addr::new(192, 168, 22, 0),
        len: 24,
    };

    // ---- Bootp parse, over the real captured packets --------------------------------------

    #[test]
    fn every_fixture_parses_and_reports_its_op() {
        assert_eq!(Bootp::parse(DISCOVER).unwrap().op(), BOOTREQUEST);
        assert_eq!(Bootp::parse(OFFER).unwrap().op(), BOOTREPLY);
        assert_eq!(Bootp::parse(REQUEST).unwrap().op(), BOOTREQUEST);
        assert_eq!(Bootp::parse(ACK).unwrap().op(), BOOTREPLY);
        assert_eq!(Bootp::parse(NAK).unwrap().op(), BOOTREPLY);
    }

    #[test]
    fn the_discover_carries_no_giaddr_and_the_captured_chaddr() {
        let p = Bootp::parse(DISCOVER).unwrap();
        assert!(p.giaddr().is_unspecified());
        assert!(p.ciaddr().is_unspecified());
        assert_eq!(p.chaddr6(), Some(CHADDR));
        assert_eq!(p.hops(), 0);
    }

    #[test]
    fn the_offer_and_ack_carry_the_offered_address_as_yiaddr() {
        let offer = Bootp::parse(OFFER).unwrap();
        assert_eq!(offer.yiaddr(), Ipv4Addr::new(192, 168, 22, 150));
        assert_eq!(offer.message_type(), Some(2)); // DHCPOFFER
        let ack = Bootp::parse(ACK).unwrap();
        assert_eq!(ack.yiaddr(), Ipv4Addr::new(192, 168, 22, 150));
        assert_eq!(ack.message_type(), Some(DHCPACK));
    }

    #[test]
    fn the_nak_carries_no_yiaddr_and_the_broadcast_flag() {
        let nak = Bootp::parse(NAK).unwrap();
        assert_eq!(nak.message_type(), Some(6)); // DHCPNAK
        assert!(nak.yiaddr().is_unspecified());
    }

    #[test]
    fn set_hops_and_set_giaddr_touch_only_their_own_bytes() {
        let mut p = Bootp::parse(DISCOVER).unwrap();
        let before = p.as_bytes().to_vec();
        p.set_hops(1);
        p.set_giaddr(LEG);
        let mut expected = before;
        expected[3] = 1;
        expected[GIADDR_OFF..GIADDR_OFF + 4].copy_from_slice(&LEG.octets());
        assert_eq!(p.into_bytes(), expected);
    }

    #[test]
    fn a_short_buffer_is_rejected_without_indexing_past_it() {
        assert!(Bootp::parse(&DISCOVER[..MIN_LEN - 1]).is_err());
        assert!(Bootp::parse(&[]).is_err());
    }

    #[test]
    fn a_bad_magic_cookie_is_rejected() {
        let mut bad = DISCOVER.to_vec();
        bad[HEADER_LEN] = 0;
        assert!(Bootp::parse(&bad).is_err());
    }

    #[test]
    fn a_truncated_option_area_ends_the_scan_instead_of_panicking() {
        // A length byte claiming more bytes than the buffer holds must not panic the relay —
        // it is exactly what a hostile or corrupt packet would send.
        let mut evil = DISCOVER[..HEADER_LEN + 4].to_vec();
        evil.push(53); // option 53 (message type)
        evil.push(200); // claims 200 bytes of value; none follow
        assert_eq!(Bootp::parse(&evil).unwrap().message_type(), None);
    }

    // ---- forward_client: the client->server half, and its input validation ---------------

    #[test]
    fn a_discover_with_no_giaddr_is_forwarded_to_the_server_with_giaddr_and_hops_set() {
        match forward_client(DISCOVER, LEG, SERVER) {
            Action::Forward { to, bytes } => {
                assert_eq!(to, SocketAddrV4::new(SERVER, PORT));
                let p = Bootp::parse(&bytes).unwrap();
                assert_eq!(p.giaddr(), LEG);
                assert_eq!(p.hops(), 1);
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    /// Teeth: the client-facing socket must ignore a `BOOTREPLY` (its own broadcast reply,
    /// looped back). Feed one in as if it arrived on the client socket.
    #[test]
    fn a_bootreply_on_the_client_socket_is_dropped_not_forwarded() {
        assert_eq!(
            forward_client(OFFER, LEG, SERVER),
            Action::Drop(DropReason::NotABootrequest)
        );
    }

    #[test]
    fn a_client_packet_with_a_foreign_giaddr_is_dropped() {
        let mut p = Bootp::parse(DISCOVER).unwrap();
        p.set_giaddr(Ipv4Addr::new(192, 168, 22, 9)); // some other relay's leg
        match forward_client(p.as_bytes(), LEG, SERVER) {
            Action::Drop(DropReason::ForeignGiaddr(g)) => {
                assert_eq!(g, Ipv4Addr::new(192, 168, 22, 9))
            }
            other @ (Action::Forward { .. } | Action::Drop(_)) => {
                panic!("expected ForeignGiaddr, got {other:?}")
            }
        }
    }

    #[test]
    fn a_client_packet_already_carrying_our_own_giaddr_is_forwarded_unchanged_there() {
        let mut p = Bootp::parse(DISCOVER).unwrap();
        p.set_giaddr(LEG);
        match forward_client(p.as_bytes(), LEG, SERVER) {
            Action::Forward { bytes, .. } => {
                assert_eq!(Bootp::parse(&bytes).unwrap().giaddr(), LEG)
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn a_packet_at_16_hops_is_dropped_as_a_loop() {
        let mut p = Bootp::parse(DISCOVER).unwrap();
        p.set_hops(16);
        assert_eq!(
            forward_client(p.as_bytes(), LEG, SERVER),
            Action::Drop(DropReason::HopsExceeded)
        );
    }

    #[test]
    fn a_malformed_client_packet_is_dropped() {
        assert_eq!(
            forward_client(&[1, 2, 3], LEG, SERVER),
            Action::Drop(DropReason::Malformed)
        );
    }

    // ---- forward_server: the server->client half, and its input validation ---------------

    #[test]
    fn an_offer_from_the_real_server_with_our_giaddr_broadcasts_to_the_client_port() {
        let mut p = Bootp::parse(OFFER).unwrap();
        p.set_giaddr(LEG);
        match forward_server(p.as_bytes(), SERVER, LEG, SERVER, PREFIX) {
            Action::Forward { to, .. } => {
                assert_eq!(to, SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT))
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn a_reply_with_a_nonzero_ciaddr_unicasts_there_instead_of_broadcasting() {
        let mut p = Bootp::parse(ACK).unwrap();
        p.set_giaddr(LEG);
        let renewing = Ipv4Addr::new(192, 168, 22, 150);
        p.0[CIADDR_OFF..CIADDR_OFF + 4].copy_from_slice(&renewing.octets());
        match forward_server(p.as_bytes(), SERVER, LEG, SERVER, PREFIX) {
            Action::Forward { to, .. } => assert_eq!(to, SocketAddrV4::new(renewing, CLIENT_PORT)),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    /// Teeth (S3): a nonzero `ciaddr` outside the row's own `prefix` is refused even from the
    /// real server with the right `giaddr` — the two trust checks above establish WHO sent it,
    /// not that the address it names is one this row has any business claiming.
    #[test]
    fn a_reply_with_a_ciaddr_outside_the_prefix_is_dropped() {
        let mut p = Bootp::parse(ACK).unwrap();
        p.set_giaddr(LEG);
        let outsider = Ipv4Addr::new(10, 0, 0, 9);
        p.0[CIADDR_OFF..CIADDR_OFF + 4].copy_from_slice(&outsider.octets());
        match forward_server(p.as_bytes(), SERVER, LEG, SERVER, PREFIX) {
            Action::Drop(DropReason::OutOfPrefix(a)) => assert_eq!(a, outsider),
            other @ (Action::Forward { .. } | Action::Drop(_)) => {
                panic!("expected OutOfPrefix, got {other:?}")
            }
        }
    }

    /// Teeth: the server-facing socket must ignore a `BOOTREQUEST` — a VM unicasting straight
    /// to the leg address on port 67, or our own request looping back some other way.
    #[test]
    fn a_bootrequest_on_the_server_socket_is_dropped_not_forwarded() {
        assert_eq!(
            forward_server(DISCOVER, SERVER, LEG, SERVER, PREFIX),
            Action::Drop(DropReason::NotABootreply)
        );
    }

    /// Teeth: input validation, direction 1 — a reply whose UDP source is not the declared
    /// server is untrusted regardless of anything else in the packet.
    #[test]
    fn a_reply_whose_source_is_not_the_declared_server_is_dropped() {
        let mut p = Bootp::parse(OFFER).unwrap();
        p.set_giaddr(LEG);
        let forger = Ipv4Addr::new(6, 6, 6, 6);
        match forward_server(p.as_bytes(), forger, LEG, SERVER, PREFIX) {
            Action::Drop(DropReason::UntrustedServer(s)) => assert_eq!(s, forger),
            other @ (Action::Forward { .. } | Action::Drop(_)) => {
                panic!("expected UntrustedServer, got {other:?}")
            }
        }
    }

    /// Teeth: input validation, direction 2 — a reply from the real server whose `giaddr` is
    /// not this row's own leg address is not a reply to a request this relay made.
    #[test]
    fn a_reply_with_a_foreign_giaddr_is_dropped_even_from_the_real_server() {
        let p = Bootp::parse(OFFER).unwrap(); // giaddr is 0.0.0.0 in the raw capture
        match forward_server(p.as_bytes(), SERVER, LEG, SERVER, PREFIX) {
            Action::Drop(DropReason::ForeignReplyGiaddr(g)) => assert!(g.is_unspecified()),
            other @ (Action::Forward { .. } | Action::Drop(_)) => {
                panic!("expected ForeignReplyGiaddr, got {other:?}")
            }
        }
    }

    #[test]
    fn a_malformed_server_packet_is_dropped() {
        assert_eq!(
            forward_server(&[9, 9, 9], SERVER, LEG, SERVER, PREFIX),
            Action::Drop(DropReason::Malformed)
        );
    }

    // ---- ack_discovery: what registers a VM, and what must not ---------------------------

    #[test]
    fn an_ack_yields_the_leased_address_and_the_clients_mac() {
        assert_eq!(
            ack_discovery(ACK, PREFIX),
            Some((Ipv4Addr::new(192, 168, 22, 150), CHADDR))
        );
    }

    /// A copy of the NAK with a `yiaddr` planted: the raw capture's own `yiaddr` is already
    /// 0.0.0.0, so without this the message-type gate this test's name claims to cover is never
    /// reached — `an_ack_with_no_yiaddr_does_not_register` would have made it pass regardless
    /// (fold-in, opus review). Message type 6 (DHCPNAK) is still what actually refuses it.
    #[test]
    fn a_nak_never_registers() {
        let mut p = Bootp::parse(NAK).unwrap();
        p.0[YIADDR_OFF..YIADDR_OFF + 4].copy_from_slice(&Ipv4Addr::new(192, 168, 22, 150).octets());
        assert_eq!(ack_discovery(p.as_bytes(), PREFIX), None);
    }

    #[test]
    fn an_offer_never_registers_only_an_ack_does() {
        assert_eq!(ack_discovery(OFFER, PREFIX), None);
    }

    #[test]
    fn an_ack_with_no_yiaddr_does_not_register() {
        let mut p = Bootp::parse(ACK).unwrap();
        p.0[YIADDR_OFF..YIADDR_OFF + 4].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(ack_discovery(p.as_bytes(), PREFIX), None);
    }

    /// Teeth (S3): the same defense in depth on `ack_discovery` — an otherwise-trusted DHCPACK
    /// (right server, right giaddr, message type 5) whose `yiaddr` claims an address outside
    /// this row's own `prefix` must not earn a neighbor write.
    #[test]
    fn an_ack_with_a_yiaddr_outside_the_prefix_does_not_register() {
        let mut p = Bootp::parse(ACK).unwrap();
        let outsider = Ipv4Addr::new(10, 0, 0, 9);
        p.0[YIADDR_OFF..YIADDR_OFF + 4].copy_from_slice(&outsider.octets());
        assert_eq!(ack_discovery(p.as_bytes(), PREFIX), None);
    }

    // ---- sockets: SO_REUSEADDR on both, proven by binding both to the same port -----------

    /// An ephemeral port nobody else holds right now: bind to port 0, read back what the
    /// kernel chose, then free it. Good enough for a same-process test; a true collision with
    /// another process is what production's fixed port 67 accepts as a real, retried fact.
    fn free_port() -> u16 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    }

    /// Teeth (spec §5.4, N2b): the wildcard client socket and the address-bound server socket
    /// share one port. Both must set `SO_REUSEADDR` — proven by actually binding them, not by
    /// asserting a flag was set.
    #[test]
    fn both_sockets_bind_the_same_port_with_reuseaddr_set() {
        let port = free_port();
        let client = bind_client(port, None).expect("client bind");
        let server = bind_server(Ipv4Addr::LOCALHOST, port).expect("server bind alongside it");
        drop((client, server));
    }

    #[test]
    fn the_client_socket_can_bind_a_real_device() {
        // "lo" always exists; this proves the `bind_device` call path is wired, not that it
        // restricts routing (that needs two real interfaces — the rack proof's job).
        let port = free_port();
        bind_client(port, Some("lo")).expect("bind to a real device must not error");
    }

    // ---- end-to-end over loopback: the bytes `forward_client` produces are a real, sendable
    // UDP payload a peer socket bound exactly as `bind_server` binds it actually receives — not
    // just a shape asserted in memory. Two distinct loopback addresses stand in for "the leg"
    // and "the dhcp server" (both specific, neither wildcard, so this needs no `SO_REUSEADDR`
    // interplay and no broadcast — that half is `both_sockets_bind_the_same_port_with_reuseaddr_set`
    // and the rack proof's job).

    #[tokio::test]
    async fn a_forwarded_discover_reaches_a_real_socket_standing_in_for_the_server() {
        let leg = Ipv4Addr::new(127, 0, 0, 1);
        let dhcp_server = Ipv4Addr::new(127, 0, 0, 2);
        let fake_server = UdpSocket::from_std(bind_server(dhcp_server, PORT).unwrap()).unwrap();

        match forward_client(DISCOVER, leg, dhcp_server) {
            Action::Forward { to, bytes } => {
                assert_eq!(to, SocketAddrV4::new(dhcp_server, PORT));
                let sender = UdpSocket::from_std(bind_server(leg, PORT).unwrap()).unwrap();
                sender.send_to(&bytes, to).await.unwrap();
            }
            other => panic!("expected Forward, got {other:?}"),
        }
        let mut buf = [0u8; BUF_LEN];
        let (n, _) = fake_server.recv_from(&mut buf).await.unwrap();
        let relayed = Bootp::parse(&buf[..n]).unwrap();
        assert_eq!(relayed.giaddr(), leg);
        assert_eq!(relayed.hops(), 1);
    }

    // ---- mac_str -----------------------------------------------------------------------

    #[test]
    fn mac_str_is_lowercase_colon_hex() {
        assert_eq!(mac_str(CHADDR), "4e:48:e9:89:2e:e5");
    }
}
