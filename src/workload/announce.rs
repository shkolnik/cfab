//! Gateway announcer (spec §5.1 item 8, ruling 12): a gratuitous ARP request for `gw` every
//! PERIOD on a fixed schedule, plus a burst of BURST_LEN at BURST_GAP when a MAC is learned on a
//! VM port. The state machine is pure — the supervisor owns the clock, the socket and the
//! neighbor watch — and the one line of I/O goes through `AnnounceIo`, so every schedule test
//! runs without a kernel.
//!
//! R5 measured worst-case convergence 4.06 s at a 5 s period and 0.21 s at a 1 s period, with the
//! announce itself landing within 93 ms; R2 measured ~15 ms per neighbor update per frame.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::error::Result;

pub const PERIOD: Duration = Duration::from_secs(5);
pub const BURST_LEN: usize = 3;
pub const BURST_GAP: Duration = Duration::from_secs(1);
/// One burst per interface per PERIOD: at most BURST_LEN + 1 frames per PERIOD under MAC churn.
pub const BURST_MIN_GAP: Duration = PERIOD;

/// The send seam. The announcer never reads: it puts one frame on one interface and that is the
/// whole of its I/O. In production this is the prober's `AF_PACKET` socket (`PacketIo`, which
/// opens and binds the netdev on first use); in tests it is a recorder.
pub trait AnnounceIo {
    /// Put `frame` on `ifname` exactly as given — the sub-interface adds the VLAN tag.
    fn send(&mut self, ifname: &str, frame: &[u8]) -> Result<()>;
}

impl AnnounceIo for crate::prober::io::PacketIo {
    fn send(&mut self, ifname: &str, frame: &[u8]) -> Result<()> {
        crate::prober::io::ProbeIo::send(self, ifname, frame)
    }
}

/// The per-workload announce schedule.
///
/// Two independent deadlines: the beacon, which advances by whole PERIODs so that a late caller
/// never shifts it (R5 measured `send; sleep P` drifting to 5.011 s per round), and the burst,
/// which is armed by an ownership change and rate-limited to one per BURST_MIN_GAP.
#[derive(Debug)]
pub struct Announcer {
    pub ifname: String,
    pub gw: Ipv4Addr,
    beacon_due: Instant,
    burst_left: usize,
    burst_due: Option<Instant>,
    last_burst: Option<Instant>,
    announces: u64,
    bursts: u64,
}

impl Announcer {
    pub fn new(ifname: &str, gw: Ipv4Addr, now: Instant) -> Self {
        Self {
            ifname: ifname.into(),
            gw,
            beacon_due: now,
            burst_left: 0,
            burst_due: None,
            last_burst: None,
            announces: 0,
            bursts: 0,
        }
    }

    /// A MAC was learned on a non-uplink port: burst, unless a burst started less than
    /// BURST_MIN_GAP ago (or is still running).
    ///
    /// The caller also calls this once when `NeighWatch::drain` returns `ENOBUFS`: the kernel
    /// dropped events, so something may have changed and one burst is the safe reading of a gap.
    pub fn on_event(&mut self, now: Instant) {
        if self.burst_left > 0 {
            return;
        }
        if let Some(t) = self.last_burst
            && now < t + BURST_MIN_GAP
        {
            return;
        }
        self.burst_left = BURST_LEN;
        self.burst_due = Some(now);
        self.last_burst = Some(now);
        self.bursts += 1;
    }

    /// When the caller must next wake for this workload.
    pub fn next_due(&self) -> Instant {
        match self.burst_due {
            Some(b) => b.min(self.beacon_due),
            None => self.beacon_due,
        }
    }

    /// Advance the schedule. Returns whether a frame is due now.
    ///
    /// A beacon and a burst frame falling in the same call send ONE frame and count one: the
    /// point of the announce is that the neighbor caches see it, and they need one copy.
    pub fn fire(&mut self, now: Instant) -> bool {
        let mut send = false;
        if let Some(b) = self.burst_due
            && now >= b
        {
            self.burst_left -= 1;
            self.burst_due = if self.burst_left > 0 {
                Some(b + BURST_GAP)
            } else {
                None
            };
            send = true;
        }
        if now >= self.beacon_due {
            // deadline-based: advance by whole periods so a late caller does not shift the
            // schedule, and a caller that overslept several periods does not owe a backlog.
            while self.beacon_due <= now {
                self.beacon_due += PERIOD;
            }
            send = true;
        }
        if send {
            self.announces += 1
        }
        send
    }

    /// `fire`, and the frame if one is due. Returns whether a frame was due.
    ///
    /// The schedule advances before the send, so a dead socket cannot turn the beacon into a
    /// spin: the error is the caller's to journal, once per distinct text.
    pub fn announce_due(
        &mut self,
        io: &mut dyn AnnounceIo,
        src_mac: [u8; 6],
        now: Instant,
    ) -> Result<bool> {
        if !self.fire(now) {
            return Ok(false);
        }
        io.send(&self.ifname, &gratuitous(src_mac, self.gw))?;
        Ok(true)
    }

    /// `(announces, bursts)`. `announces` counts frames the schedule produced, whether or not the
    /// socket took them; a send failure is journaled by the caller, not hidden here.
    pub fn counters(&self) -> (u64, u64) {
        (self.announces, self.bursts)
    }
}

/// Gratuitous ARP *request*: sender IP == target IP == gw, broadcast destination, our MAC as
/// sender, target MAC zero. No reply is ever sent to it and none is expected.
///
/// R2: every Linux neighbor cache in the VLAN updates an EXISTING entry from this in ~15 ms at
/// the default `arp_accept=0`, and the 1 s `locktime` does not apply to gratuitous frames (a
/// plain unicast reply is subject to it, which is why the request shape won).
///
/// 42 bytes: 14-byte Ethernet header plus the 28-byte ARP body, with NO VLAN tag — the frame
/// goes out the sub-interface, which tags it.
pub fn gratuitous(src_mac: [u8; 6], gw: Ipv4Addr) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    // htype Ethernet, ptype IPv4, hlen 6, plen 4, op request
    f[14..22].copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
    f[22..28].copy_from_slice(&src_mac);
    f[28..32].copy_from_slice(&gw.octets());
    // target MAC stays zero: nobody is being asked
    f[38..42].copy_from_slice(&gw.octets());
    f
}

#[cfg(test)]
pub mod mock {
    //! A recording `AnnounceIo`: every frame handed to it, in order, with the interface it was
    //! addressed to — and an optional failure, as an absent netdev's send would give.

    use super::{AnnounceIo, Result};

    #[derive(Default)]
    pub struct RecordingIo {
        /// `(ifname, frame)` per successful send.
        pub sent: Vec<(String, Vec<u8>)>,
        /// When set, every send fails with this text and records nothing.
        pub fail: Option<String>,
    }

    impl AnnounceIo for RecordingIo {
        fn send(&mut self, ifname: &str, frame: &[u8]) -> Result<()> {
            if let Some(msg) = &self.fail {
                return Err(crate::error::Error::fatal(msg.clone()));
            }
            self.sent.push((ifname.to_string(), frame.to_vec()));
            Ok(())
        }
    }

    /// The same recorder behind a handle, so a test can hand one copy to the code under test
    /// (the supervisor's `Hooks` take an owned `Box<dyn AnnounceIo>`) and keep another to read
    /// what reached the wire.
    #[derive(Clone, Default)]
    pub struct SharedIo(pub std::sync::Arc<std::sync::Mutex<RecordingIo>>);

    impl SharedIo {
        /// The frames recorded so far, `(ifname, frame)` in order.
        pub fn sent(&self) -> Vec<(String, Vec<u8>)> {
            self.0.lock().unwrap().sent.clone()
        }
    }

    impl AnnounceIo for SharedIo {
        fn send(&mut self, ifname: &str, frame: &[u8]) -> Result<()> {
            self.0.lock().unwrap().send(ifname, frame)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn t0() -> Instant {
        Instant::now()
    }
    const S: Duration = Duration::from_secs(1);

    #[test]
    fn the_beacon_fires_on_a_fixed_5s_schedule_regardless_of_when_fire_is_called() {
        let a0 = t0();
        let mut a = Announcer::new("primary.3", "192.168.20.254".parse().unwrap(), a0);
        assert_eq!(a.next_due(), a0, "first beacon is immediate");
        assert!(a.fire(a0));
        assert_eq!(a.next_due(), a0 + PERIOD);
        assert!(!a.fire(a0 + 3 * S), "not due");
        assert!(
            a.fire(a0 + PERIOD + Duration::from_millis(700)),
            "late caller still fires"
        );
        assert_eq!(
            a.next_due(),
            a0 + 2 * PERIOD,
            "deadline-based: the schedule does not drift with the caller"
        );
    }

    #[test]
    fn an_event_starts_a_burst_of_three_one_second_apart_and_the_beacon_keeps_its_schedule() {
        let a0 = t0();
        let mut a = Announcer::new("primary.3", "192.168.20.254".parse().unwrap(), a0);
        a.fire(a0);
        let e = a0 + 2 * S;
        a.on_event(e);
        assert_eq!(a.next_due(), e);
        assert!(a.fire(e));
        assert_eq!(a.next_due(), e + BURST_GAP);
        assert!(a.fire(e + BURST_GAP));
        assert_eq!(a.next_due(), e + 2 * BURST_GAP);
        assert!(a.fire(e + 2 * BURST_GAP));
        assert_eq!(a.next_due(), a0 + PERIOD, "burst done; beacon is next");
        assert_eq!(a.counters(), (4, 1), "(announces, bursts)");
    }

    #[test]
    fn events_within_one_period_of_a_burst_start_do_not_start_another() {
        let a0 = t0();
        let mut a = Announcer::new("primary.3", "192.168.20.254".parse().unwrap(), a0);
        a.fire(a0);
        a.on_event(a0 + S);
        for _ in 0..3 {
            let d = a.next_due();
            a.fire(d);
        }
        a.on_event(a0 + S + Duration::from_millis(500)); // storm
        a.on_event(a0 + 4 * S);
        assert_eq!(a.counters().1, 1, "rate-limited to one burst per PERIOD");
        a.on_event(a0 + S + PERIOD);
        assert_eq!(a.counters().1, 2, "a period later a new burst is allowed");
    }

    #[test]
    fn the_gratuitous_request_has_sender_equal_target_and_broadcast_destination() {
        let f = gratuitous(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            "192.168.20.254".parse().unwrap(),
        );
        assert_eq!(&f[0..6], &[0xff; 6]); // dst broadcast
        assert_eq!(&f[6..12], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&f[12..14], &[0x08, 0x06]); // ethertype ARP
        assert_eq!(&f[20..22], &[0x00, 0x01]); // op request
        assert_eq!(&f[22..28], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // sender MAC
        assert_eq!(&f[28..32], &[192, 168, 20, 254]); // sender IP
        assert_eq!(&f[32..38], &[0; 6]); // target MAC zero
        assert_eq!(&f[38..42], &[192, 168, 20, 254]); // target IP == sender IP
    }

    /// The whole frame, byte for byte: 14-byte Ethernet header + 28-byte ARP, no VLAN tag (the
    /// sub-interface tags on the way out). This is the frame a peer's uplink `arp saddr` rule
    /// must match, so it is asserted verbatim, not field by field.
    #[test]
    fn the_frame_is_42_bytes_verbatim_with_no_vlan_tag() {
        let f = gratuitous(
            [0x02, 0xcf, 0xab, 0x00, 0x00, 0x01],
            "192.168.20.254".parse().unwrap(),
        );
        assert_eq!(
            f,
            [
                // Ethernet: dst, src, ethertype ARP
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
                0x02, 0xcf, 0xab, 0x00, 0x00, 0x01, //
                0x08, 0x06, //
                // ARP: htype Ethernet, ptype IPv4, hlen 6, plen 4, op request
                0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, //
                // sender MAC / sender IP
                0x02, 0xcf, 0xab, 0x00, 0x00, 0x01, //
                192, 168, 20, 254, //
                // target MAC (zero: nobody is being asked) / target IP == sender IP
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
                192, 168, 20, 254,
            ]
        );
    }

    #[test]
    fn announce_due_puts_exactly_the_due_frames_on_the_named_interface() {
        let a0 = t0();
        let mut io = mock::RecordingIo::default();
        let mut a = Announcer::new("primary.3", "192.168.20.254".parse().unwrap(), a0);
        let mac = [0x02, 0xcf, 0xab, 0x00, 0x00, 0x01];

        assert!(a.announce_due(&mut io, mac, a0).unwrap());
        assert!(!a.announce_due(&mut io, mac, a0 + S).unwrap(), "not due");
        a.on_event(a0 + S);
        for _ in 0..3 {
            let d = a.next_due();
            a.announce_due(&mut io, mac, d).unwrap();
        }
        assert_eq!(io.sent.len(), 4, "one beacon plus a burst of three");
        assert!(io.sent.iter().all(|(port, f)| port == "primary.3"
            && f[..] == gratuitous(mac, "192.168.20.254".parse().unwrap())[..]));
    }

    /// A caller that overslept several periods owes ONE frame, not a backlog, and the beacon
    /// lands back on the original grid — the schedule is a grid the caller samples, not a debt.
    #[test]
    fn a_caller_late_by_several_periods_sends_once_and_lands_on_the_original_grid() {
        let a0 = t0();
        let mut io = mock::RecordingIo::default();
        let mut a = Announcer::new("primary.3", "192.168.20.254".parse().unwrap(), a0);
        let mac = [0x02, 0xcf, 0xab, 0x00, 0x00, 0x01];
        assert!(a.announce_due(&mut io, mac, a0).unwrap());
        assert_eq!(a.next_due(), a0 + PERIOD);

        // Missed the a0 + PERIOD and a0 + 2 * PERIOD deadlines outright.
        let late = a0 + 2 * PERIOD + PERIOD / 2;
        assert!(a.announce_due(&mut io, mac, late).unwrap());
        assert_eq!(io.sent.len(), 2, "one frame owed, never a backlog of two");
        assert_eq!(
            a.next_due(),
            a0 + 3 * PERIOD,
            "back on the original grid, not `late + PERIOD`"
        );
        assert_eq!(a.counters(), (2, 0));
    }

    /// The one case the natural schedules do not produce on their own: a burst frame due at the
    /// same instant as a beacon. The neighbor caches need one copy, so one frame goes out and one
    /// is counted — and BOTH deadlines still advance.
    #[test]
    fn a_burst_frame_landing_on_a_beacon_deadline_sends_one_frame_and_counts_one() {
        let a0 = t0();
        let mut io = mock::RecordingIo::default();
        let mut a = Announcer::new("primary.3", "192.168.20.254".parse().unwrap(), a0);
        let mac = [0x02, 0xcf, 0xab, 0x00, 0x00, 0x01];
        a.announce_due(&mut io, mac, a0).unwrap(); // beacon grid: a0, a0 + 5 s, a0 + 10 s
        a.on_event(a0 + 3 * S); // burst frames: a0 + 3 s, a0 + 4 s, a0 + 5 s
        a.announce_due(&mut io, mac, a0 + 3 * S).unwrap();
        a.announce_due(&mut io, mac, a0 + 4 * S).unwrap();
        assert_eq!(io.sent.len(), 3);

        let coincide = a0 + 5 * S;
        assert_eq!(coincide, a0 + PERIOD, "the third burst frame IS a beacon deadline");
        assert!(a.announce_due(&mut io, mac, coincide).unwrap());
        assert_eq!(io.sent.len(), 4, "one frame, not two");
        assert_eq!(a.counters(), (4, 1), "one announce counted, not two");
        assert_eq!(
            a.next_due(),
            a0 + 2 * PERIOD,
            "burst done and the beacon advanced: neither deadline is stuck"
        );
    }

    #[test]
    fn a_send_failure_is_returned_to_the_caller_and_the_schedule_still_advances() {
        let a0 = t0();
        let mut io = mock::RecordingIo {
            fail: Some("primary.3: cannot send probe: ENODEV".into()),
            ..Default::default()
        };
        let mut a = Announcer::new("primary.3", "192.168.20.254".parse().unwrap(), a0);
        let e = a.announce_due(&mut io, [0; 6], a0).unwrap_err();
        assert!(e.to_string().contains("cannot send probe"));
        assert_eq!(
            a.next_due(),
            a0 + PERIOD,
            "a dead socket must not turn the beacon into a spin"
        );
    }
}
