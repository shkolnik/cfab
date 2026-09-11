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
//! `giaddr` is not this row's own leg address. **That source check is routing hygiene, not a
//! security boundary** (gate C fix round 3, S-B — corrected from an earlier, overclaiming
//! version of this paragraph): cfab writes `rp_filter = 2` (loose) on every interface for every
//! role (`src/commands/fwd_watchdog.rs`'s `restore_rp_filter`), so a VM on this row's own VLAN
//! can source-spoof `dhcp_server`'s address and reach this socket — "only toward the declared
//! server" is INTENDED, not kernel-enforced, exactly as `DropReason::OutOfPrefix`'s own doc
//! comment below already conceded. What actually bounds the damage: the `prefix` check refuses a
//! reply outside this row's own subnet, and a trusted ACK's neighbor write is deduplicated per
//! `(yiaddr, chaddr)` so a forged flood cannot drive more than one `ip neigh replace` fork per
//! distinct claim (S-B).

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::model::Ipv4Prefix;
use crate::supervisor::child::BACKOFF;
use crate::supervisor::metrics::BIND_RETRY;
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
    /// A trusted reply's `ciaddr` OR `yiaddr` is outside the row's own `prefix` (S3, defense in
    /// depth): the server-facing socket is not device-bound, so anything routable can reach it,
    /// and `rp_filter = 2` (loose) admits a spoofed source. Bounded blast radius even so —
    /// `hostroutes::local_vms` already filters to `prefix`, excludes `fabric_addresses`, and
    /// requires the MAC on a non-uplink FDB port — but this also catches a misconfigured dhcpd
    /// serving the wrong subnet, so it is worth the lines. `yiaddr` matters as much as `ciaddr`
    /// (gate C fix round 2, should-fix 5): a SELECTING-state OFFER/ACK carries `ciaddr = 0` and
    /// the offered lease only in `yiaddr`, so checking `ciaddr` alone let a wrong-subnet dhcpd's
    /// reply THROUGH to the VM even though `ack_discovery` already refused to register it —
    /// forwarded but never routable, a silent failure rather than a refused one.
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
/// the address — finding 9). A nonzero `ciaddr` OR `yiaddr` outside `prefix` is refused (S3, gate
/// C fix round 2 should-fix 5): the server-facing socket is not device-bound and cfab sets
/// `rp_filter = 2` (loose), so a spoofed `BOOTREPLY` — or, the case this actually guards against
/// in practice, a dhcpd misconfigured for the wrong subnet — that otherwise passes the two trust
/// checks above must not teach the host a neighbor entry for an address this row has no business
/// claiming, NOR reach the VM at all: forwarding an address the host will never route to is a
/// silent failure, not a refused one. `yiaddr` is checked whether or not `ciaddr` was (a
/// SELECTING-state OFFER/ACK carries `ciaddr = 0` and the offered lease only in `yiaddr`).
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
    let yiaddr = p.yiaddr();
    if !yiaddr.is_unspecified() && !prefix.contains(yiaddr) {
        return Action::Drop(DropReason::OutOfPrefix(yiaddr));
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

/// How many times `bind_pair_with_baseline` will redo the bind when the leg's identity moved
/// during it (S-A belt-and-braces), before giving up and returning an error (B3, gate C fix
/// round 3 review: the earlier code trusted the last attempt's baseline whether or not it
/// matched, which on a flapping leg reaches the exact permanent deafness this function exists
/// to prevent). Bounds a pathological flapping leg to a handful of syscalls rather than looping
/// forever; three is already generous for a race whose window is a handful of instructions.
const BASELINE_BIND_ATTEMPTS: u32 = 3;

/// Bind the pair and capture the leg's ifindex baseline at the same instant (S-A, gate C fix
/// round 3): the previous code read the baseline only after a mutex lock and a blocking
/// `eprintln!` ran, which is the exact permanent-deafness failure mode B1 fixed one layer up —
/// a leg deleted and rebuilt inside that window gives `baseline` the NEW ifindex while the
/// just-bound `SO_BINDTODEVICE` client socket is glued to the OLD one, so `serve`'s presence
/// watch compares equal forever and nothing can ever wake it (no packet can arrive on a socket
/// bound to a device that no longer carries that name). Reading `reader(&row.leg)` as the very
/// next statement after `bind_pair` returns shrinks that window to noise.
///
/// Belt-and-braces for the residual race inside `bind_pair` itself (the leg changing identity
/// while `bind_client`'s own `SO_BINDTODEVICE` call is in flight, before we ever get to read
/// anything): also read once before binding. If the pre-bind and post-bind reads disagree, the
/// leg moved sometime during the bind and we cannot tell whether `bind_client` resolved the name
/// to the old device or the new one — so the sockets we just opened are untrustworthy and are
/// dropped, and the bind is redone against whatever is current now, up to
/// `BASELINE_BIND_ATTEMPTS` times. Exhausting every attempt returns an error (B3) rather than
/// trusting whichever baseline the last attempt happened to read; `run_with_reader`'s `Err` arm
/// throttles a journal line and retries via `wait_for_leg` the same as any other bind failure.
fn bind_pair_with_baseline(
    row: &RelayRow,
    reader: &IfindexReader,
) -> io::Result<(UdpSocket, UdpSocket, Option<u32>)> {
    bind_pair_with_baseline_via(row, reader, bind_pair)
}

/// The actual retry/baseline logic behind `bind_pair_with_baseline`, generic over how the pair
/// gets bound so the racing-reader behavior is unit-testable without `CAP_NET_RAW` (real
/// `bind_pair` needs it for `SO_BINDTODEVICE`, and binds a privileged port besides).
fn bind_pair_with_baseline_via<F>(
    row: &RelayRow,
    reader: &IfindexReader,
    mut bind: F,
) -> io::Result<(UdpSocket, UdpSocket, Option<u32>)>
where
    F: FnMut(&RelayRow) -> io::Result<(UdpSocket, UdpSocket)>,
{
    let mut pre = reader(&row.leg);
    for _ in 0..BASELINE_BIND_ATTEMPTS {
        let (client, server) = bind(row)?;
        let post = reader(&row.leg);
        if pre == post {
            return Ok((client, server, post));
        }
        drop(client);
        drop(server);
        pre = post;
    }
    Err(io::Error::other(format!(
        "leg {} kept changing identity across {BASELINE_BIND_ATTEMPTS} bind attempts",
        row.leg
    )))
}

/// DHCP messages this relay forwards fit in far less; 1500 gives headroom for a heavily
/// option-laden client (PXE, vendor options) without ever growing unbounded. A datagram larger
/// than this is silently truncated by `recv_from` (no error), and the truncated body is what
/// gets forwarded — accepted rather than guarded against, since Ethernet's own 1500-byte MTU
/// makes a larger UDP payload vanishingly rare on this wire (fold-in, opus review).
const BUF_LEN: usize = 1500;

/// Whether a repeating condition's journal line should print (S1; gate C fix round 2 renamed
/// this from `should_log_bind_failure` — should-fix 2 — once it grew a second caller below that
/// is not a bind failure): only when the text differs from the previous streak's. A deferred
/// row, or a leg the watchdog has not built yet, hits the same bind failure on every retry until
/// its precondition clears; an unreachable `dhcp_server` drops the same way on every
/// retransmitted request. Either would restate the same line forever without this (relay.rs's
/// own doc comment on `DropReason` names the hazard). Both callers' `msg` comes from a bounded,
/// non-attacker-controlled set (an `io::Error`'s errno text); the third case that once lived here
/// — `OutOfPrefix`'s refusal, whose message embeds an attacker-chosen address — moved to a plain
/// once-per-streak flag instead (S-C, gate C fix round 3): keying a throttle on a string an
/// attacker can vary defeats the throttle.
fn should_log_once(previous: Option<&str>, msg: &str) -> bool {
    previous != Some(msg)
}

/// Whether an out-of-prefix drop's journal line should print this time, and updates `logged` for
/// next time (S-C, gate C fix round 3). Deliberately NOT built on `should_log_once`: that
/// function's key is whatever string the caller passes it, and the old bug here was passing the
/// drop's full message — which embeds the attacker-controlled claimed address — as that key, so
/// two forgeries claiming different addresses compared unequal and both printed. This function's
/// signature cannot repeat that mistake: it never receives the address, or any packet content at
/// all, only the streak's own state — there is exactly one reason a row's own prefix can be
/// violated (the prefix does not change mid-`serve()`), so the state degenerates to "printed
/// yet."
fn should_log_out_of_prefix_drop(logged: &mut bool) -> bool {
    if *logged {
        false
    } else {
        *logged = true;
        true
    }
}

/// How `serve`'s presence watch (B1) and the bind-failure wait (should-fix 8, folded in for
/// free) read a device's current ifindex: real relay tasks read `/sys/class/net/<dev>/ifindex`;
/// tests inject a closure so the leg-rebuild race is reproducible without CAP_NET_ADMIN. Boxed
/// behind `Arc<dyn Fn>` rather than a type parameter: `run` is `tokio::spawn`ed
/// (`supervisor/mod.rs`), so whatever reads the ifindex must be `Send + Sync + 'static`
/// regardless, and a trait object keeps `run`/`serve`'s signatures from growing a generic that
/// only tests exercise.
pub(crate) type IfindexReader = Arc<dyn Fn(&str) -> Option<u32> + Send + Sync>;

/// `None` when `dev` does not exist — never an error, since "the leg is not there yet" is the
/// everyday case this exists to detect (a deferred row, a watchdog rebuild in flight).
fn sysfs_ifindex(dev: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn default_ifindex_reader() -> IfindexReader {
    Arc::new(sysfs_ifindex)
}

/// How often `serve`'s presence watch re-reads the leg's ifindex (B1): a plain `stat`-class
/// read, cheap enough that "2-5 s" costs nothing measurable, and short enough that a leg rebuild
/// is caught well inside one DHCP client retransmit interval.
const IFINDEX_POLL: Duration = Duration::from_secs(3);

/// How many consecutive `None` reads with no baseline ever established (S-D) `serve` will accept
/// before treating "the leg's ifindex has never once been readable" as the rebuild signal it
/// really is. Narrow (needs a sysfs read to fail repeatedly right after `bind_device` just
/// succeeded on the same device), but the outcome if left unhandled is the same permanent
/// deafness as S-A: `(None, None)` forever never differs from itself, so the watch never fires
/// and nothing else can. Five polls at `IFINDEX_POLL`'s 3 s cadence (15 s) is well inside any
/// DHCP client's retry patience and short next to `BACKOFF`'s own retry cost of getting this
/// wrong forever.
const UNKNOWN_BASELINE_LIMIT: u32 = 5;

/// What `serve`'s presence watch needs to notice the leg it is bound to has been deleted and
/// rebuilt under it (B1, VERIFIED on real hardware — pve2: after `fwd_watchdog` deletes and
/// recreates a leg, the OLD ifindex's device-bound client socket goes deaf, but a fresh
/// `if_nametoindex`-equivalent read of the same NAME returns the NEW ifindex at once). A plain
/// struct rather than three loose parameters to `serve`, so a caller cannot swap the baseline
/// and the poll interval by accident.
struct LegWatch {
    /// The leg's ifindex read right after `bind_pair` succeeded. `None` only if that very first
    /// read raced the device's own creation (bind succeeded, sysfs had not caught up yet) — rare
    /// enough, and self-limiting enough (the next poll almost certainly reads `Some`), that it
    /// is treated as "unknown baseline" rather than an error: the watch simply arms itself off
    /// whatever the first poll observes instead of firing a false rebuild on tick one.
    baseline: Option<u32>,
    reader: IfindexReader,
    poll: Duration,
}

/// How often the bind-failure wait polls for the leg's appearance instead of sleeping the whole
/// `BIND_RETRY` blind (should-fix 8, folded in for free by B1's ifindex reader): a deferred row,
/// or a leg the watchdog has not built yet, normally clears in 2-3 s at boot, not `BIND_RETRY`'s
/// full 60 s. `BACKOFF`'s own cadence, reused rather than inventing a second constant for the
/// same "check again soon" idea.
const LEG_POLL: Duration = BACKOFF;

/// Sleep up to `retry`, but wake as soon as `leg` exists (should-fix 8): a `bind_pair` failure is
/// usually exactly this — the leg is not there yet — so re-attempting the instant it appears
/// turns a bind failure at boot into a 2-3 s gap instead of up to 60 s of DHCP blackout. A leg
/// that genuinely never appears still only re-tries the bind every `LEG_POLL`, cheap enough
/// (one sysfs read) that the shorter cadence costs nothing over the plain sleep it replaces.
async fn wait_for_leg(leg: &str, reader: &IfindexReader, poll: Duration, retry: Duration) {
    let deadline = tokio::time::Instant::now() + retry;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline || reader(leg).is_some() {
            return;
        }
        tokio::time::sleep(poll.min(deadline - now)).await;
    }
}

/// The relay task (spec §5.4): bind, serve until a socket errors, then retry. A task death (a
/// live relay whose socket later failed) retries on the same `BACKOFF` a supervised child
/// restarts on; a bind failure (the leg does not exist yet, or the address is not local) is a
/// standing condition rather than a transient hiccup, so it retries every `BIND_RETRY` instead
/// (woken early the moment the leg appears — should-fix 8) and is loud only when the reason
/// changes (S1). Neither is ever fatal to the member — a leg that does not exist yet (a deferred
/// row, a watchdog rebuild in progress) is indistinguishable in kind from a port transiently held
/// by something else: both clear themselves the moment the precondition does.
pub(crate) async fn run(
    row: RelayRow,
    shared: Arc<Mutex<Shared>>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
) {
    run_with_reader(row, shared, cmd_tx, default_ifindex_reader()).await
}

async fn run_with_reader(
    row: RelayRow,
    shared: Arc<Mutex<Shared>>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    reader: IfindexReader,
) {
    loop {
        // S1: which cadence retries this pass, and whether the journal line prints, depend on
        // which branch below runs. A task death (the `Ok` arm: bind succeeded, `serve` later
        // ended it) keeps the spec's own 2 s `BACKOFF` and always logs once, exactly as before.
        // A bind failure (the `Err` arm) is the one a deferred row, or a leg the watchdog has
        // not built yet, hits every pass until its precondition clears — that follows
        // `metrics::BIND_RETRY`'s 60 s cadence instead (woken early by `wait_for_leg`), and logs
        // only when the standing error actually changes.
        let bound = match bind_pair_with_baseline(&row, &reader) {
            Ok((client, server, baseline)) => {
                shared
                    .lock()
                    .unwrap()
                    .relay_event(&row.name, row.dhcp_server, RelayEvent::Bound);
                eprintln!(
                    "cfab: workload {}: dhcp relay bound on {}, forwarding to {}",
                    row.name, row.leg, row.dhcp_server
                );
                // B1/S-A: `baseline` was already captured, atomically with the bind, by
                // `bind_pair_with_baseline` above — before this lock and this `eprintln!`, not
                // after (S-A: that gap is exactly the window a leg rebuild could hide in). A
                // `None` baseline is the rare race noted on `LegWatch`, not a reason to skip the
                // watch — `serve` treats it as "adopt whatever the first poll sees" rather than a
                // false trigger (S-D narrows how long it will wait for that to happen).
                let watch = LegWatch {
                    baseline,
                    reader: reader.clone(),
                    poll: IFINDEX_POLL,
                };
                let why = serve(&client, &server, &row, &shared, &cmd_tx, &watch).await;
                eprintln!(
                    "cfab: workload {}: dhcp relay socket lost ({why}); retrying in {}s",
                    row.name,
                    BACKOFF.as_secs()
                );
                shared.lock().unwrap().relay_event(
                    &row.name,
                    row.dhcp_server,
                    RelayEvent::SocketError(why),
                );
                true
            }
            Err(e) => {
                let msg = format!("cannot bind: {e}");
                let previous = shared.lock().unwrap().relay_last_error(&row.name);
                let is_new = should_log_once(previous.as_deref(), &msg);
                shared.lock().unwrap().relay_event(
                    &row.name,
                    row.dhcp_server,
                    RelayEvent::BindError(msg.clone()),
                );
                if is_new {
                    eprintln!(
                        "cfab: workload {}: dhcp relay {msg}; retrying every {}s while it stands",
                        row.name,
                        BIND_RETRY.as_secs()
                    );
                }
                false
            }
        };
        if bound {
            tokio::time::sleep(BACKOFF).await;
        } else {
            wait_for_leg(&row.leg, &reader, LEG_POLL, BIND_RETRY).await;
        }
    }
}

/// Serve both sockets until something goes wrong; returns why. A `recv_from` error on either
/// socket, or `watch` catching the leg's ifindex change, end this loop and are recorded the same
/// way (`RelayEvent::SocketError` / `last_error`, so `status`/metrics show whichever failed
/// last). Neither `send_to` ends the loop (gate C fix round 2, should-fix 1, for the
/// server-facing send; gate C fix round 3, S-E, for the client-facing one): both are counted as
/// `RelayEvent::Dropped` and throttled instead.
///
/// `watch` is the load-bearing fix, not either socket's send failing (B1, VERIFIED on real
/// hardware — pve2, an isolated dummy device deleted and recreated under the same name): the
/// forwarding watchdog really does delete and rebuild a leg under a running supervisor
/// (`src/commands/fwd_watchdog.rs` "The whole leg is gone: rebuild it"), and the device-bound
/// CLIENT socket goes deaf on `recv_from` when that happens — it never errors, it just stops
/// delivering. `client.send_to` WOULD fail with `ENODEV`, but reaching it requires a fresh
/// request from a VM to arrive first via that same deaf `client.recv_from`, which cannot happen
/// post-rebuild — so that send is unreachable as a detection signal in exactly the scenario B1
/// exists for (S-E: which is also why treating a client-facing send error as fatal lost its
/// reason once `watch` existed — a NON-`ENODEV` client-facing error, EPERM from an nft output
/// drop or ENETUNREACH among them, IS reachable, and costs a full teardown and a 2 s outage for
/// no better reason than the server-facing case already rejected). `watch` polls the leg's
/// ifindex by NAME instead (a fresh read is unaffected by which old ifindex a socket is bound
/// to) and ends the loop the moment it moves, closing the deaf window without depending on any
/// packet ever arriving.
async fn serve(
    client: &UdpSocket,
    server: &UdpSocket,
    row: &RelayRow,
    shared: &Arc<Mutex<Shared>>,
    cmd_tx: &mpsc::UnboundedSender<Cmd>,
    watch: &LegWatch,
) -> String {
    let mut cbuf = [0u8; BUF_LEN];
    let mut sbuf = [0u8; BUF_LEN];
    let mut baseline = watch.baseline;
    // S-D: consecutive `(None, None)` polls, i.e. the ifindex has never once become readable
    // since this `serve()` call started. Reset the moment a real reading lands (an unknown
    // baseline that resolves is exactly the race the doc above names, not a fault).
    let mut unknown_polls: u32 = 0;
    let mut poll = tokio::time::interval_at(
        tokio::time::Instant::now() + watch.poll,
        watch.poll.max(Duration::from_millis(1)),
    );
    // Throttled per streak (S1's own pattern), local to this one serve() call: a rebind starts
    // both streaks fresh, which is correct — the previous socket's drop history says nothing
    // about the new one's.
    let mut last_send_drop: Option<String> = None;
    let mut last_client_send_drop: Option<String> = None;
    let mut prefix_drop_logged = false;
    // S-B: the last `(yiaddr, chaddr)` a trusted ACK earned a neighbor write for. The
    // server-facing source check is routing hygiene, not a security boundary (module doc, S-B —
    // `rp_filter = 2` is loose everywhere), so a VM on this row's own VLAN can forge a BOOTREPLY
    // and drive `Cmd::DhcpAck` on the supervisor's MAIN loop, which services it with a
    // synchronous `ip neigh replace` subprocess fork per packet. Skipping the write (and the
    // `Discovered` count) when the claim is unchanged bounds an attacker to one fork per distinct
    // claim, not one per packet — and costs nothing on the honest path, since `ip neigh replace`
    // of an identical binding is a no-op the kernel would otherwise perform over and over anyway.
    let mut last_ack: Option<(Ipv4Addr, [u8; 6])> = None;
    loop {
        tokio::select! {
            _ = poll.tick() => {
                let now = (watch.reader)(&row.leg);
                match (baseline, now) {
                    // The ordinary bind-time race resolving: adopt the first real reading rather
                    // than compare against "unknown" (`LegWatch::baseline`'s own doc).
                    (None, Some(n)) => {
                        baseline = Some(n);
                        unknown_polls = 0;
                    }
                    // S-D: still unknown. Unlike `(None, Some)` above, this never self-resolves
                    // by definition — `baseline` stays `None` and every future tick lands here
                    // again, so without a cap this watch would never fire no matter how long the
                    // leg's ifindex stays unreadable. `(Some(b), None)` (the leg vanishing after
                    // a baseline was established) is NOT this case — it already falls through to
                    // the rebuild arm below, which is correct: a device that HAD an ifindex and
                    // now has none is real information, not a race.
                    (None, None) => {
                        unknown_polls += 1;
                        if unknown_polls >= UNKNOWN_BASELINE_LIMIT {
                            let msg = format!(
                                "leg {} ifindex unreadable after {unknown_polls} polls with no \
                                 baseline ever established; treating as a rebuild",
                                row.leg
                            );
                            shared.lock().unwrap().relay_event(
                                &row.name, row.dhcp_server, RelayEvent::SocketError(msg.clone()),
                            );
                            return msg;
                        }
                    }
                    (Some(b), Some(n)) if b == n => {}
                    _ => {
                        let msg = format!(
                            "leg {} rebuilt (ifindex {baseline:?} -> {now:?})", row.leg
                        );
                        shared.lock().unwrap().relay_event(
                            &row.name, row.dhcp_server, RelayEvent::SocketError(msg.clone()),
                        );
                        return msg;
                    }
                }
            }
            r = client.recv_from(&mut cbuf) => {
                match r {
                    Ok((n, _from)) => {
                        if let Action::Forward { to, bytes } =
                            forward_client(&cbuf[..n], row.leg_addr, row.dhcp_server)
                        {
                            match server.send_to(&bytes, to).await {
                                Ok(_) => {
                                    shared.lock().unwrap().relay_event(
                                        &row.name, row.dhcp_server, RelayEvent::Request,
                                    );
                                }
                                Err(e) => {
                                    // Should-fix 1: the server socket is NOT device-bound, so
                                    // this is a routing fact (dhcp_server unreachable), never a
                                    // device-vanish signal — counted, and the loop keeps
                                    // serving, exactly like `hostroutes`'s own stray-forward
                                    // drop ("counted, NOT dropped" as a task-ending event).
                                    // Ending the loop here (the previous round's fix) tore down
                                    // BOTH sockets on every retransmit of an unreachable-server
                                    // DISCOVER — a self-inflicted DoS on top of the outage.
                                    let msg = format!("server-facing send: {e}");
                                    if should_log_once(last_send_drop.as_deref(), &msg) {
                                        eprintln!(
                                            "cfab: workload {}: dhcp request dropped ({msg})",
                                            row.name
                                        );
                                    }
                                    last_send_drop = Some(msg);
                                    shared.lock().unwrap().relay_event(
                                        &row.name, row.dhcp_server, RelayEvent::Dropped,
                                    );
                                }
                            }
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
                        match forward_server(&sbuf[..n], src, row.leg_addr, row.dhcp_server, row.prefix) {
                            Action::Forward { to, bytes } => {
                                if let Some((yiaddr, chaddr)) = ack_discovery(&sbuf[..n], row.prefix) {
                                    // S-B: skip both the write and the count when this is the
                                    // same claim as last time (see `last_ack`'s own doc above).
                                    if last_ack != Some((yiaddr, chaddr)) {
                                        last_ack = Some((yiaddr, chaddr));
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
                                }
                                match client.send_to(&bytes, to).await {
                                    Ok(_) => {
                                        shared.lock().unwrap().relay_event(
                                            &row.name, row.dhcp_server, RelayEvent::Reply,
                                        );
                                    }
                                    Err(e) => {
                                        // S-E: this used to end the loop (tear down both
                                        // sockets) on every client-facing send error. Round 2's
                                        // own rationale for `serve` (see its doc comment above)
                                        // is that `watch` — not a send error — is the load-bearing
                                        // detector of a dead client socket, because the ENODEV a
                                        // rebuild produces here is reachable only via a
                                        // recv_from the rebuild itself has already silenced. Once
                                        // that is true, a NON-`ENODEV` client-facing send error
                                        // (EPERM from an nft output drop, EMSGSIZE, ENETUNREACH
                                        // to a client address that stopped being local) is just a
                                        // routing/policy fact, exactly like the server-facing
                                        // send error above — so it gets the same treatment:
                                        // counted, throttled, and the loop keeps serving instead
                                        // of paying a full rebind and a 2 s outage per packet.
                                        let msg = format!("client-facing send: {e}");
                                        if should_log_once(last_client_send_drop.as_deref(), &msg) {
                                            eprintln!(
                                                "cfab: workload {}: dhcp reply dropped ({msg})",
                                                row.name
                                            );
                                        }
                                        last_client_send_drop = Some(msg);
                                        shared.lock().unwrap().relay_event(
                                            &row.name, row.dhcp_server, RelayEvent::Dropped,
                                        );
                                    }
                                }
                            }
                            // Should-fix 5: a wrong-subnet dhcpd (S3's own doc comment names the
                            // case) must not just fail silently to register — the reply is
                            // refused outright, counted, and throttled the same way a send
                            // drop is. Every other `Drop` reason stays silent by design
                            // (`DropReason`'s own doc: a stray broadcast or a probing scanner
                            // must not become a self-inflicted journal DoS).
                            //
                            // S-C: `should_log_out_of_prefix_drop` decides whether to print,
                            // fed only `prefix_drop_logged` — never `msg`, which embeds `addr`.
                            // The old bug used `msg` (attacker-controlled: a forged reply
                            // chooses `addr`) as the throttle key, so alternating the claimed
                            // address on every packet made every packet compare unequal to the
                            // last and defeated the throttle — one journal line per forged
                            // packet, the exact DoS class should-fix 1 fixed for the send-drop
                            // path last round. The reason here never changes (this row's prefix
                            // is fixed), so once logged it stays quiet until the next rebind
                            // starts a fresh streak.
                            Action::Drop(DropReason::OutOfPrefix(addr)) => {
                                let msg = format!(
                                    "dhcp reply from {} claims {addr}, outside {}'s prefix; refused",
                                    row.dhcp_server, row.name
                                );
                                if should_log_out_of_prefix_drop(&mut prefix_drop_logged) {
                                    eprintln!("cfab: workload {}: {msg}", row.name);
                                }
                                shared.lock().unwrap().relay_event(
                                    &row.name, row.dhcp_server, RelayEvent::Dropped,
                                );
                            }
                            Action::Drop(_) => {}
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

    /// A `LegWatch` that never fires: the reader always answers `None` and the poll interval is
    /// long enough to never tick inside a test's timeout. For tests exercising a path other than
    /// the presence watch itself.
    fn no_watch() -> LegWatch {
        LegWatch {
            baseline: None,
            reader: Arc::new(|_dev: &str| None),
            poll: Duration::from_secs(3600),
        }
    }

    // ---- bind_pair_with_baseline: the belt-and-braces retry (S-A) -------------------------

    /// A stand-in bind: never touches a privileged port or `SO_BINDTODEVICE` (both need
    /// capabilities this sandbox does not have), just two throwaway loopback sockets, so the
    /// retry/baseline logic in `bind_pair_with_baseline_via` is testable on its own.
    fn fake_bind(_row: &RelayRow) -> io::Result<(UdpSocket, UdpSocket)> {
        let a = std::net::UdpSocket::bind("127.0.0.1:0")?;
        a.set_nonblocking(true)?;
        let b = std::net::UdpSocket::bind("127.0.0.1:0")?;
        b.set_nonblocking(true)?;
        Ok((UdpSocket::from_std(a)?, UdpSocket::from_std(b)?))
    }

    /// S-A's belt-and-braces case: the leg's ifindex moves between the pre-bind read and the
    /// read taken immediately after the (fake) bind returns — exactly the residual race inside
    /// `bind_pair` itself that reading the baseline sooner (the main part of S-A) cannot close.
    /// The fix must not trust a bind that raced a rebuild: it has to drop those sockets and
    /// redo the bind against whatever is current, then re-check. Proven directly: `fake_bind` is
    /// called twice (not once), and the ifindex `bind_pair_with_baseline_via` finally reports
    /// matches the reader's SECOND-attempt reality (11), never the stale first one (10) a
    /// same-name-different-device rebuild would have glued the first pair of sockets to.
    #[tokio::test]
    async fn a_baseline_race_during_bind_itself_is_detected_and_the_bind_is_redone() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let bind_calls = std::sync::atomic::AtomicU32::new(0);
        let reader: IfindexReader = Arc::new(move |_dev: &str| {
            // Sequence of reads: pre-bind (attempt 1) = 10; post-bind (attempt 1) = 11, i.e.
            // the leg was rebuilt while `fake_bind` ran, same as a real `fwd_watchdog` rebuild
            // racing `bind_client`'s `SO_BINDTODEVICE` call; post-bind (attempt 2) = 11 again,
            // i.e. the leg is stable by the second attempt.
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(if n == 0 { 10 } else { 11 })
        });
        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "test-leg".to_string(),
            leg_addr: Ipv4Addr::new(127, 88, 0, 27),
            dhcp_server: Ipv4Addr::new(127, 88, 0, 28),
            prefix: PREFIX,
        };

        let (_client, _server, baseline) = bind_pair_with_baseline_via(&row, &reader, |r| {
            bind_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fake_bind(r)
        })
        .expect("fake_bind never fails");

        assert_eq!(
            bind_calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a pre/post mismatch must redo the bind, not trust the first (possibly stale) pair"
        );
        assert_eq!(
            baseline,
            Some(11),
            "the reported baseline must be the SECOND attempt's reality, not the first \
             attempt's stale reading a real socket could have been glued to"
        );
    }

    /// The ordinary case: no race, the first bind's pre/post reads agree. Must not retry —
    /// proof this fix does not cost every bind an extra syscall for a race that (by far) usually
    /// does not happen.
    #[tokio::test]
    async fn a_baseline_with_no_race_binds_exactly_once() {
        let reader: IfindexReader = Arc::new(|_dev: &str| Some(42));
        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "test-leg".to_string(),
            leg_addr: Ipv4Addr::new(127, 88, 0, 29),
            dhcp_server: Ipv4Addr::new(127, 88, 0, 30),
            prefix: PREFIX,
        };
        let bind_calls = std::sync::atomic::AtomicU32::new(0);

        let (_client, _server, baseline) = bind_pair_with_baseline_via(&row, &reader, |r| {
            bind_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fake_bind(r)
        })
        .expect("fake_bind never fails");

        assert_eq!(bind_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(baseline, Some(42));
    }

    /// T14 (B3, gate C fix round 3 review) — a leg that never stops moving exhausts every
    /// `BASELINE_BIND_ATTEMPTS` retry and the function returns an `Err`, not the last attempt's
    /// baseline trusted on faith. The reader disagrees with itself on every single read, so no
    /// attempt's pre/post pair can ever match. `run_with_reader`'s existing `Err` arm is what
    /// turns this into a throttled retry via `wait_for_leg` rather than a permanently wrong
    /// baseline glued to a socket the caller never rebinds.
    #[tokio::test]
    async fn bind_exhaustion_returns_an_error_not_a_guessed_baseline() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let reader: IfindexReader = Arc::new(move |_dev: &str| {
            // Every read disagrees with the one before it, so pre != post on every attempt.
            Some(calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
        });
        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "test-leg".to_string(),
            leg_addr: Ipv4Addr::new(127, 88, 0, 31),
            dhcp_server: Ipv4Addr::new(127, 88, 0, 32),
            prefix: PREFIX,
        };
        let bind_calls = std::sync::atomic::AtomicU32::new(0);

        let result = bind_pair_with_baseline_via(&row, &reader, |r| {
            bind_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fake_bind(r)
        });

        assert!(
            result.is_err(),
            "exhausting every retry on a leg that never settles must be an error, not a \
             trusted-on-faith Ok(..) carrying whichever baseline the last attempt happened to see"
        );
        assert_eq!(
            bind_calls.load(std::sync::atomic::Ordering::SeqCst),
            BASELINE_BIND_ATTEMPTS,
            "must have actually spent every retry, not given up early"
        );
    }

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

    /// Teeth (S3, gate C fix round 2 should-fix 5): the SELECTING-state shape — `ciaddr = 0`
    /// (the raw OFFER capture's own value), the offered lease only in `yiaddr` — is exactly the
    /// gap `ciaddr`-only checking left open: a wrong-subnet dhcpd's OFFER passed the ciaddr
    /// check (0.0.0.0 is unspecified, never out of prefix) and was forwarded to the VM even
    /// though `ack_discovery` already refused to register the same address. The fix must
    /// refuse the forward itself, not merely the registration.
    #[test]
    fn a_reply_with_a_yiaddr_outside_the_prefix_is_dropped_even_with_no_ciaddr() {
        let mut p = Bootp::parse(OFFER).unwrap();
        p.set_giaddr(LEG);
        assert!(p.ciaddr().is_unspecified(), "the raw capture's own ciaddr");
        let outsider = Ipv4Addr::new(10, 0, 0, 9);
        p.0[YIADDR_OFF..YIADDR_OFF + 4].copy_from_slice(&outsider.octets());
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

    // ---- serve: a client-facing send failure is counted and the loop keeps serving (S-E) --

    /// S-E, gate C fix round 3: a client-facing send error used to end the loop unconditionally
    /// (tearing down both sockets) — an asymmetry with the server-facing send error just above,
    /// which fix round 2 already made counted-not-fatal. Round 2's own rationale for that
    /// applies here too: `watch`, not a send error, is the load-bearing detector of a dead
    /// client socket (see `serve`'s own doc comment), so a client-facing send error that is NOT
    /// the unreachable `ENODEV` path is just a routing/policy fact and must not cost a rebind.
    /// Reproduced root-free the same way the old test for this path did: `bind_client` always
    /// sets `SO_BROADCAST`; a client-facing socket built by hand WITHOUT it fails a broadcast
    /// send with `EACCES` (a kernel-enforced socket-option check, not a privilege one). A
    /// crafted DHCPOFFER with no `ciaddr` yet makes `forward_server` broadcast the reply, driving
    /// exactly that `client.send_to` call.
    #[tokio::test]
    async fn a_client_facing_send_failure_is_counted_and_the_loop_keeps_serving() {
        let leg = Ipv4Addr::new(127, 88, 0, 3);
        let dhcp_server = Ipv4Addr::new(127, 88, 0, 4);

        let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        raw.set_reuse_address(true).unwrap();
        raw.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).into())
            .unwrap();
        raw.set_nonblocking(true).unwrap();
        let client = UdpSocket::from_std(raw.into()).unwrap();

        let server = UdpSocket::from_std(bind_server(leg, 0).unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Craft a DHCPOFFER forward_server will accept and broadcast: real dhcp_server as
        // source, this row's own leg as giaddr, ciaddr left unspecified (as captured).
        let mut offer = OFFER.to_vec();
        {
            let mut p = Bootp::parse(&offer).unwrap();
            p.set_giaddr(leg);
            offer = p.into_bytes();
        }

        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "lo".to_string(),
            leg_addr: leg,
            dhcp_server,
            prefix: PREFIX,
        };
        let shared = Arc::new(Mutex::new(Shared::new(1)));
        let shared_task = shared.clone();
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();

        let handle = tokio::spawn(async move {
            serve(&client, &server, &row, &shared_task, &cmd_tx, &no_watch()).await
        });

        let sender = UdpSocket::from_std(bind_server(dhcp_server, 0).unwrap()).unwrap();
        sender.send_to(&offer, server_addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            shared.lock().unwrap().relay_drops("test-row"),
            1,
            "a client-facing send failure must be counted"
        );
        assert!(
            shared
                .lock()
                .unwrap()
                .relay_last_error("test-row")
                .is_none(),
            "a counted drop is not a socket death and must not touch last_error"
        );
        assert!(
            !handle.is_finished(),
            "the loop must still be serving after a client-facing send failure"
        );
        handle.abort();
    }

    // ---- serve: the presence watch ends the loop on a leg rebuild (B1) --------------------

    /// B1's actual fix, proven directly: `watch` ends `serve` the moment the leg's ifindex
    /// changes, with NO packet ever arriving — closing exactly the window the module doc names
    /// (the device-bound client socket goes deaf on `recv_from`, so nothing downstream of a
    /// packet can ever fire again). The reader is a fake — no CAP_NET_ADMIN in this sandbox to
    /// actually delete and recreate a device — but `serve` cannot tell it apart from a real one:
    /// the injection point named on `IfindexReader`'s own doc comment IS the mechanism.
    #[tokio::test]
    async fn a_leg_rebuild_ends_serve_via_the_presence_watch_with_no_packet_at_all() {
        let leg_addr = Ipv4Addr::new(127, 88, 0, 21);
        let dhcp_server = Ipv4Addr::new(127, 88, 0, 22);
        // Neither socket ever receives anything: proof the watch fires on its own.
        let client = UdpSocket::from_std(bind_server(Ipv4Addr::LOCALHOST, 0).unwrap()).unwrap();
        let server = UdpSocket::from_std(bind_server(Ipv4Addr::LOCALHOST, 0).unwrap()).unwrap();

        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let calls2 = calls.clone();
        let reader: IfindexReader = Arc::new(move |_dev: &str| {
            // The first two polls still see the baseline ifindex (5); from the third on, the
            // leg has been rebuilt under a new one (6) — "same name, different device", exactly
            // what a real `fwd_watchdog` delete-and-recreate produces.
            let n = calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(if n < 2 { 5 } else { 6 })
        });
        let watch = LegWatch {
            baseline: Some(5),
            reader,
            poll: Duration::from_millis(5),
        };

        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "test-leg".to_string(),
            leg_addr,
            dhcp_server,
            prefix: PREFIX,
        };
        let shared = Arc::new(Mutex::new(Shared::new(1)));
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            serve(&client, &server, &row, &shared, &cmd_tx, &watch),
        )
        .await
        .expect(
            "serve must return once the presence watch catches the rebuild, not hang forever \
             waiting on a packet a dead client socket can never deliver",
        );

        assert!(
            result.contains("rebuilt"),
            "expected a rebuild message: {result}"
        );
        assert!(result.contains("test-leg"), "{result}");
        let recorded = shared.lock().unwrap().relay_last_error(&row.name);
        assert_eq!(
            recorded.as_deref(),
            Some(result.as_str()),
            "a leg rebuild is a socket death: it belongs in last_error, same as any other"
        );
    }

    /// The baseline race `LegWatch::baseline`'s doc names: the very first poll answers `None`
    /// (the bind-time read raced the device showing up in sysfs). It must be adopted as the new
    /// baseline, not treated as an instant "the leg is gone" false rebuild.
    #[tokio::test]
    async fn an_unknown_baseline_is_adopted_not_treated_as_a_rebuild() {
        let client = UdpSocket::from_std(bind_server(Ipv4Addr::LOCALHOST, 0).unwrap()).unwrap();
        let server = UdpSocket::from_std(bind_server(Ipv4Addr::LOCALHOST, 0).unwrap()).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let calls2 = calls.clone();
        let reader: IfindexReader = Arc::new(move |_dev: &str| {
            let n = calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Poll 0: still unknown (the race). Poll 1 on: settles on 7 and stays there — must
            // NOT be read as a rebuild relative to the adopted baseline.
            if n == 0 { None } else { Some(7) }
        });
        let watch = LegWatch {
            baseline: None,
            reader,
            poll: Duration::from_millis(5),
        };
        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "test-leg".to_string(),
            leg_addr: Ipv4Addr::new(127, 88, 0, 23),
            dhcp_server: Ipv4Addr::new(127, 88, 0, 24),
            prefix: PREFIX,
        };
        let shared = Arc::new(Mutex::new(Shared::new(1)));
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();

        // 30 ms is 6 polls at 5 ms each; if the unknown-baseline race were mishandled, `serve`
        // would have returned long before this deadline.
        let result = tokio::time::timeout(
            Duration::from_millis(30),
            serve(&client, &server, &row, &shared, &cmd_tx, &watch),
        )
        .await;
        assert!(
            result.is_err(),
            "serve must still be running: an adopted baseline is not a rebuild, got: {result:?}"
        );
    }

    /// S-D, gate C fix round 3: an unknown baseline that NEVER resolves — the reader keeps
    /// returning `None` forever — must not leave `serve` deaf for good. The `(None, _) =>
    /// baseline = now` arm the previous test exercises treats every `None` reading the same way
    /// whether or not it ever settles, so `(None, None)` compared against itself never differs
    /// and the watch would otherwise never fire, no matter how long this runs — the same
    /// permanent-deafness outcome S-A closes for the bind-time race. `UNKNOWN_BASELINE_LIMIT`
    /// consecutive unresolved polls must end the loop instead.
    #[tokio::test]
    async fn an_unknown_baseline_that_never_resolves_ends_serve_eventually() {
        let client = UdpSocket::from_std(bind_server(Ipv4Addr::LOCALHOST, 0).unwrap()).unwrap();
        let server = UdpSocket::from_std(bind_server(Ipv4Addr::LOCALHOST, 0).unwrap()).unwrap();
        // Never resolves, ever — the pathological case `(None, Some)` above does NOT cover.
        let reader: IfindexReader = Arc::new(|_dev: &str| None);
        let watch = LegWatch {
            baseline: None,
            reader,
            poll: Duration::from_millis(2),
        };
        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "test-leg".to_string(),
            leg_addr: Ipv4Addr::new(127, 88, 0, 25),
            dhcp_server: Ipv4Addr::new(127, 88, 0, 26),
            prefix: PREFIX,
        };
        let shared = Arc::new(Mutex::new(Shared::new(1)));
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            serve(&client, &server, &row, &shared, &cmd_tx, &watch),
        )
        .await
        .expect(
            "serve must eventually give up on a baseline that can never resolve, not hang \
             forever with a permanently deaf socket",
        );

        assert!(
            result.contains("unreadable") && result.contains("test-leg"),
            "expected the never-resolves message, got: {result}"
        );
        let recorded = shared.lock().unwrap().relay_last_error(&row.name);
        assert_eq!(
            recorded.as_deref(),
            Some(result.as_str()),
            "this is a socket-death fact and belongs in last_error, same as any other"
        );
    }

    // ---- serve: a server-facing send failure is counted, not fatal (should-fix 1) ---------

    /// Should-fix 1: the previous round ended BOTH sockets on a server-facing send failure —
    /// the server socket is not device-bound, so this is a routing fact (dhcp_server
    /// unreachable), never a device-vanish signal. It must be counted and the loop must keep
    /// serving, not cost the relay a rebind (and a self-inflicted DoS on the journal) on every
    /// retransmitted DISCOVER.
    #[tokio::test]
    async fn a_server_facing_send_failure_is_counted_and_the_loop_keeps_serving() {
        let leg = Ipv4Addr::new(127, 88, 0, 31);
        // A test-only trick, never a real configuration: `bind_server` never sets
        // `SO_BROADCAST` (only `bind_client` does), so sending to the broadcast address from
        // the server socket fails with `EACCES` — a kernel-refused send, deterministic and
        // root-free, standing in for the `ENETUNREACH` an unreachable real dhcp_server gives.
        let dhcp_server = Ipv4Addr::BROADCAST;

        let client = UdpSocket::from_std(bind_client(0, None).unwrap()).unwrap();
        let client_port = client.local_addr().unwrap().port();
        let server = UdpSocket::from_std(bind_server(leg, 0).unwrap()).unwrap();

        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "lo".to_string(),
            leg_addr: leg,
            dhcp_server,
            prefix: PREFIX,
        };
        let shared = Arc::new(Mutex::new(Shared::new(1)));
        let shared_task = shared.clone();
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();

        let handle = tokio::spawn(async move {
            serve(&client, &server, &row, &shared_task, &cmd_tx, &no_watch()).await
        });

        // The client socket is already bound, so the kernel buffers this regardless of whether
        // `serve` has started polling yet: a real BOOTREQUEST (unmodified giaddr, so
        // `forward_client` accepts and forwards it) delivered straight to the relay's own
        // client-facing port.
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(DISCOVER, (Ipv4Addr::LOCALHOST, client_port))
            .unwrap();

        // Give the task a moment to process the one packet, then prove both halves: it counted
        // the drop, AND it is still alive to serve the next one — the two facts should-fix 1
        // exists to establish together.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            shared.lock().unwrap().relay_drops("test-row"),
            1,
            "a server-facing send failure must be counted"
        );
        assert!(
            shared
                .lock()
                .unwrap()
                .relay_last_error("test-row")
                .is_none(),
            "a counted drop is not a socket death and must not touch last_error (should-fix 2)"
        );
        assert!(
            !handle.is_finished(),
            "the loop must still be serving after a server-facing send failure"
        );
        handle.abort();
    }

    // ---- serve: an out-of-prefix reply is refused and counted, not fatal (should-fix 5) ----

    /// Should-fix 5: a reply whose `yiaddr`/`ciaddr` falls outside the row's own prefix (a
    /// misconfigured, wrong-subnet dhcpd) must be refused rather than forwarded to the VM, and
    /// must not end the task either — it is a configuration fact about the SERVER, not this
    /// relay's own socket health.
    #[tokio::test]
    async fn an_out_of_prefix_reply_is_refused_counted_and_the_loop_keeps_serving() {
        let leg = Ipv4Addr::new(127, 88, 0, 41);
        let dhcp_server = Ipv4Addr::new(127, 88, 0, 42);

        let client = UdpSocket::from_std(bind_client(0, None).unwrap()).unwrap();
        let server = UdpSocket::from_std(bind_server(leg, 0).unwrap()).unwrap();
        let server_port = server.local_addr().unwrap().port();

        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "lo".to_string(),
            leg_addr: leg,
            dhcp_server,
            prefix: PREFIX,
        };
        let shared = Arc::new(Mutex::new(Shared::new(1)));
        let shared_task = shared.clone();
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();

        let handle = tokio::spawn(async move {
            serve(&client, &server, &row, &shared_task, &cmd_tx, &no_watch()).await
        });

        // A DHCPOFFER from the real, trusted server, with the right giaddr, but a yiaddr this
        // row's prefix does not own — the wrong-subnet-dhcpd shape should-fix 5 exists for.
        let mut p = Bootp::parse(OFFER).unwrap();
        p.set_giaddr(leg);
        let outsider = Ipv4Addr::new(10, 0, 0, 9);
        p.0[YIADDR_OFF..YIADDR_OFF + 4].copy_from_slice(&outsider.octets());
        let sender = std::net::UdpSocket::bind((dhcp_server, 0)).unwrap();
        sender.send_to(p.as_bytes(), (leg, server_port)).unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            shared.lock().unwrap().relay_drops("test-row"),
            1,
            "an out-of-prefix reply must be counted"
        );
        assert!(
            shared
                .lock()
                .unwrap()
                .relay_last_error("test-row")
                .is_none(),
            "a refused reply is not a socket death and must not touch last_error"
        );
        assert!(
            !handle.is_finished(),
            "the loop must still be serving after refusing an out-of-prefix reply"
        );
        handle.abort();
    }

    // ---- serve: the out-of-prefix journal line is throttled by reason, not address (S-C) --

    /// S-C, gate C fix round 3: the old throttle key was the drop's full message, which embeds
    /// the attacker-controlled claimed address, so two forgeries claiming different addresses
    /// compared unequal and both printed — one journal line per forged packet, defeating the
    /// throttle exactly the way an alternating attacker would. Proven at the level the rest of
    /// this file proves `should_log_once`-style throttles at (a pure decision function, not by
    /// capturing the process's real stderr — which the standard test harness's own output
    /// capture intercepts before it reaches a real fd, making that approach unreliable under
    /// plain `cargo test`): `should_log_out_of_prefix_drop`'s signature cannot even see an
    /// address, so calling it twice in a row (standing in for two packets claiming different
    /// addresses — the function cannot tell the difference, which is exactly the point) must
    /// print only the first time.
    #[test]
    fn an_out_of_prefix_drop_throttle_ignores_the_claimed_address() {
        let mut logged = false;
        assert!(
            should_log_out_of_prefix_drop(&mut logged),
            "the first refusal in a streak must print"
        );
        assert!(
            !should_log_out_of_prefix_drop(&mut logged),
            "a second refusal in the same streak must not print again, no matter what address \
             it claims — this function never receives the address at all"
        );
    }

    // ---- serve: a repeated identical ACK claim is deduplicated (S-B) ----------------------

    /// S-B, gate C fix round 3: the server-facing socket's only source check (`src ==
    /// dhcp_server`) is routing hygiene, not a security boundary — `rp_filter = 2` is loose on
    /// every role, so a VM on this row's own VLAN can forge that source. Each forged DHCPACK
    /// used to drive one `Cmd::DhcpAck` (and one `ip neigh replace` subprocess fork on the
    /// supervisor's MAIN loop) per packet, unbounded. An identical repeat of the same
    /// `(yiaddr, chaddr)` claim must register (and fork) at most once; a genuinely new claim
    /// must still get through.
    #[tokio::test]
    async fn a_repeated_identical_ack_is_deduplicated_but_a_new_claim_still_registers() {
        let leg = Ipv4Addr::new(127, 88, 0, 51);
        let dhcp_server = Ipv4Addr::new(127, 88, 0, 52);

        let client = UdpSocket::from_std(bind_client(0, None).unwrap()).unwrap();
        let server = UdpSocket::from_std(bind_server(leg, 0).unwrap()).unwrap();
        let server_port = server.local_addr().unwrap().port();

        let row = RelayRow {
            name: "test-row".to_string(),
            leg: "lo".to_string(),
            leg_addr: leg,
            dhcp_server,
            prefix: PREFIX,
        };
        let shared = Arc::new(Mutex::new(Shared::new(1)));
        let shared_task = shared.clone();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

        let handle = tokio::spawn(async move {
            serve(&client, &server, &row, &shared_task, &cmd_tx, &no_watch()).await
        });

        let mut p = Bootp::parse(ACK).unwrap();
        p.set_giaddr(leg);
        let ack_bytes = p.as_bytes().to_vec();

        let mut different_claim = Bootp::parse(&ack_bytes).unwrap();
        different_claim.0[CHADDR_OFF..CHADDR_OFF + 6]
            .copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x99]);
        let different_bytes = different_claim.into_bytes();

        let sender = std::net::UdpSocket::bind((dhcp_server, 0)).unwrap();
        // Same claim, twice: must register (and forward to the client) only the first time.
        sender.send_to(&ack_bytes, (leg, server_port)).unwrap();
        sender.send_to(&ack_bytes, (leg, server_port)).unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            shared.lock().unwrap().relay_discovered("test-row"),
            1,
            "an identical repeat ACK must not re-register"
        );

        // A different chaddr claiming the same address is a NEW claim: must still register.
        sender
            .send_to(&different_bytes, (leg, server_port))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            shared.lock().unwrap().relay_discovered("test-row"),
            2,
            "a genuinely different claim must still register"
        );

        let mut acks_received = 0;
        while cmd_rx.try_recv().is_ok() {
            acks_received += 1;
        }
        assert_eq!(
            acks_received, 2,
            "exactly one Cmd::DhcpAck per distinct claim, not one per packet"
        );

        assert!(!handle.is_finished(), "the loop must still be serving");
        handle.abort();
    }

    // ---- wait_for_leg: the bind-failure wait wakes early (should-fix 8, folded in free) ----

    /// Should-fix 8, closed as a side effect of B1's reader: a bind failure whose cause is "the
    /// leg is not there yet" must not sit out the full `BIND_RETRY` — it wakes the moment the
    /// reader reports the leg present, not after any fixed sleep.
    #[tokio::test]
    async fn wait_for_leg_wakes_as_soon_as_the_leg_appears() {
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let calls2 = calls.clone();
        // Absent for the first three polls, present from the fourth — well inside a 60 s
        // `BIND_RETRY` this test never actually waits out.
        let reader: IfindexReader = Arc::new(move |_dev: &str| {
            let n = calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < 3 { None } else { Some(1) }
        });
        let start = tokio::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_leg("test-leg", &reader, Duration::from_millis(5), BIND_RETRY),
        )
        .await
        .expect("wait_for_leg must return once the leg appears, not sit out the full BIND_RETRY");
        assert!(
            start.elapsed() < BIND_RETRY,
            "must wake well before the full retry window elapses"
        );
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 4);
    }

    /// A leg that never appears still only waits the bounded `retry`, never longer — the poll
    /// is a WAKE-UP mechanism, not a way to wait past the caller's own deadline.
    #[tokio::test]
    async fn wait_for_leg_gives_up_at_the_deadline_when_the_leg_never_appears() {
        let reader: IfindexReader = Arc::new(|_dev: &str| None);
        let start = tokio::time::Instant::now();
        let bound = Duration::from_millis(30);
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_leg("test-leg", &reader, Duration::from_millis(5), bound),
        )
        .await
        .expect("wait_for_leg must still return at the deadline");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= bound && elapsed < bound * 3,
            "expected roughly {bound:?}, got {elapsed:?}"
        );
    }

    // ---- should_log_once: a repeating condition's line prints once per streak (S1) ---------

    #[test]
    fn a_bind_failure_line_prints_once_per_streak_not_once_per_retry() {
        assert!(
            should_log_once(None, "cannot bind: address not available"),
            "the first failure in a streak must print"
        );
        assert!(
            !should_log_once(
                Some("cannot bind: address not available"),
                "cannot bind: address not available"
            ),
            "the same standing error must not print again"
        );
        assert!(
            should_log_once(
                Some("cannot bind: address not available"),
                "cannot bind: address in use"
            ),
            "a different reason is a new streak and must print"
        );
    }

    // ---- mac_str -----------------------------------------------------------------------

    #[test]
    fn mac_str_is_lowercase_colon_hex() {
        assert_eq!(mac_str(CHADDR), "4e:48:e9:89:2e:e5");
    }
}
