//! The classic-BPF program every prober tap wears.
//!
//! The taps are `ETH_P_ALL` sockets (`super::io`) because that is the only way to see the ACTIVE
//! slave's frames — a socket bound to one protocol sits behind the bond's `rx_handler` and never
//! does. The cost is that every frame on a busy VLAN is copied to userspace, and the drain cap
//! (`MAX_DRAIN`) then makes that a starvation risk: a storage VLAN's own traffic can fill the
//! per-tick budget and hide the one hello or the one ARP reply that is evidence.
//!
//! So the kernel is told what evidence looks like before it wakes us: OSPF to AllSPFRouters, or
//! ARP. Four loads and three compares, attached before the socket is bound so no unfiltered
//! frame can be queued in between.
//!
//! The program is a `const`, and the tests below run it through an interpreter of the same
//! classic-BPF subset — so the instruction sequence itself is proven against the golden frames,
//! not merely the behavior of a socket nobody can open in a unit test.

/// One classic-BPF instruction (`struct sock_filter`, linux/filter.h).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

// linux/bpf_common.h, the classic subset this program uses.
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;

const ETHERTYPE_ARP: u32 = 0x0806;
const ETHERTYPE_IPV4: u32 = 0x0800;
const IPPROTO_OSPF: u32 = 89;
/// 224.0.0.5 as a big-endian word, which is how a `BPF_LD|BPF_W|BPF_ABS` load reads it.
const ALL_SPF_ROUTERS: u32 = 0xe000_0005;

/// Accept the whole frame. Any number at least as large as the frames we read (`RECV_BUF`) will
/// do; this is the conventional one.
const ACCEPT: u32 = 0x0004_0000;

/// The filter, in the order it decides:
///
/// ```text
/// ldh  [12]                    ; ethertype
/// jeq  #0x0806 -> accept       ; ARP: the escalation's replies
/// jeq  #0x0800 else drop       ; otherwise it must be IPv4
/// ldb  [23]                    ; ip.proto
/// jeq  #89     else drop       ; OSPF
/// ld   [30]                    ; ip.dst
/// jeq  #224.0.0.5 -> accept else drop
/// ```
///
/// The offsets assume no VLAN tag, and that is what the socket sees: it is bound to the VLAN
/// SUB-interface, which delivers frames untagged (VERIFIED on pve1 2026-09-07 — `tcpdump -i
/// cfab-st-fb-b proto 89` matches without a `vlan` qualifier, while the same filter on the
/// physical wire needs one). The codec above still tolerates a tag; the filter does not have to
/// pay for a branch that the bind makes unreachable.
pub const FILTER: [Insn; 9] = [
    insn(LD_H_ABS, 0, 0, 12),
    insn(JEQ_K, 5, 0, ETHERTYPE_ARP),
    insn(JEQ_K, 0, 5, ETHERTYPE_IPV4),
    insn(LD_B_ABS, 0, 0, 23),
    insn(JEQ_K, 0, 3, IPPROTO_OSPF),
    insn(LD_W_ABS, 0, 0, 30),
    insn(JEQ_K, 0, 1, ALL_SPF_ROUTERS),
    insn(RET_K, 0, 0, ACCEPT),
    insn(RET_K, 0, 0, 0),
];

/// The same program in the shape `socket2` takes. Built from `FILTER` word for word, and the
/// test below holds the two together — the readable one is what the interpreter proves, and this
/// one is what the kernel gets.
const PROGRAM: [socket2::SockFilter; FILTER.len()] = {
    let mut p = [const { socket2::SockFilter::new(0, 0, 0, 0) }; FILTER.len()];
    let mut i = 0;
    while i < FILTER.len() {
        let Insn { code, jt, jf, k } = FILTER[i];
        p[i] = socket2::SockFilter::new(code, jt, jf, k);
        i += 1;
    }
    p
};

/// Attach `FILTER` to a raw socket. Called before `bind`, so the socket is never open and
/// unfiltered at the same time.
///
/// The fd goes in and comes back out through `socket2`'s own safe `OwnedFd` conversions, so the
/// socket is never owned twice and the tree keeps `#![forbid(unsafe_code)]`.
#[cfg(target_os = "linux")]
pub fn attach(fd: std::os::fd::OwnedFd) -> std::io::Result<std::os::fd::OwnedFd> {
    let sock = socket2::Socket::from(fd);
    sock.attach_filter(&PROGRAM)?;
    Ok(std::os::fd::OwnedFd::from(sock))
}

#[cfg(test)]
pub mod interp {
    //! The classic-BPF subset `FILTER` uses, interpreted — so the program is tested as a
    //! program. An out-of-bounds load returns 0 (the frame is dropped), which is what the
    //! kernel's own interpreter does with a short packet.

    use super::*;

    pub fn run(prog: &[Insn], frame: &[u8]) -> u32 {
        let mut pc = 0usize;
        let mut a: u32 = 0;
        // A malformed program would loop forever in here; the instruction budget is the same
        // bound the kernel's verifier gives one.
        for _ in 0..4096 {
            let Some(i) = prog.get(pc) else { return 0 };
            pc += 1;
            let k = i.k as usize;
            match i.code {
                LD_B_ABS => match frame.get(k) {
                    Some(b) => a = *b as u32,
                    None => return 0,
                },
                LD_H_ABS => match frame.get(k..k + 2) {
                    Some(b) => a = u16::from_be_bytes([b[0], b[1]]) as u32,
                    None => return 0,
                },
                LD_W_ABS => match frame.get(k..k + 4) {
                    Some(b) => a = u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                    None => return 0,
                },
                JEQ_K => {
                    let off = if a == i.k { i.jt } else { i.jf };
                    pc += off as usize;
                }
                RET_K => return i.k,
                other => panic!("the filter uses an opcode the interpreter does not: {other:#x}"),
            }
        }
        panic!("the filter did not return within the instruction budget")
    }
}

#[cfg(test)]
mod tests {
    use super::interp::run;
    use super::*;

    /// An OSPF hello to AllSPFRouters, `ihl` words of IPv4 header.
    fn hello(ihl: u8) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x05]);
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        let hlen = (ihl * 4) as usize;
        let mut ip = vec![0u8; hlen];
        ip[0] = 0x40 | ihl;
        ip[9] = 89;
        ip[16..20].copy_from_slice(&[224, 0, 0, 5]);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&[0u8; 24]);
        f
    }

    fn arp_reply() -> Vec<u8> {
        let mut f = vec![0u8; 42];
        f[12..14].copy_from_slice(&[0x08, 0x06]);
        f[20..22].copy_from_slice(&[0x00, 0x02]);
        f
    }

    /// The kernel gets the program the interpreter proves, instruction for instruction. Only
    /// the length can be checked from outside — `socket2::SockFilter`'s field is private — but
    /// the construction above is a word-for-word copy, so the length is what a dropped or
    /// duplicated instruction would change.
    #[test]
    fn the_program_handed_to_the_kernel_is_the_one_the_tests_run() {
        assert_eq!(PROGRAM.len(), FILTER.len());
    }

    #[test]
    fn the_filter_accepts_a_hello_and_an_arp_reply() {
        assert_eq!(run(&FILTER, &hello(5)), ACCEPT);
        assert_eq!(
            run(&FILTER, &hello(6)),
            ACCEPT,
            "the proto and dst offsets do not move with IHL"
        );
        assert_eq!(run(&FILTER, &arp_reply()), ACCEPT);
    }

    #[test]
    fn the_filter_drops_everything_that_cannot_be_evidence() {
        let mut tcp = hello(5);
        tcp[14 + 9] = 6;
        assert_eq!(run(&FILTER, &tcp), 0, "IP that is not OSPF");

        let mut unicast_ospf = hello(5);
        unicast_ospf[14 + 16..14 + 20].copy_from_slice(&[10, 99, 9, 2]);
        assert_eq!(run(&FILTER, &unicast_ospf), 0, "OSPF not to AllSPFRouters");

        let mut ipv6 = hello(5);
        ipv6[12..14].copy_from_slice(&[0x86, 0xdd]);
        assert_eq!(run(&FILTER, &ipv6), 0, "not IPv4");

        assert_eq!(run(&FILTER, &hello(5)[..20]), 0, "short: no ip.dst to read");
        assert_eq!(run(&FILTER, &[]), 0, "short: no ethertype to read");
    }
}
