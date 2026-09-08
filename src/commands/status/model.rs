//! The structured result of one `cfab status` gather.
//!
//! `status` reads the fabric's state once and renders it; this module holds what was read, so
//! that more than one renderer can consume the same gather. Nothing here reads or writes: every
//! field is a fact a renderer turns into its own words.

/// The member's verdict. `UP` (0) every expected adjacency available · `UP-DEGRADED` (1) up,
/// some down · `FAILED` (2) no adjacency available while up is desired · `DOWN` (3) up is not
/// desired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Up,
    /// Up, but some expected adjacency is down. One hyphenated token so it has one spelling and
    /// the word UP stays visible on a degraded member.
    UpDegraded,
    Failed,
    Down,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            State::Up => "UP",
            State::UpDegraded => "UP-DEGRADED",
            State::Failed => "FAILED",
            State::Down => "DOWN",
        }
    }

    /// Nagios-style: 0 ok, 1 warning, 2 critical, 3 unknown/not-desired.
    pub fn code(self) -> u8 {
        match self {
            State::Up => 0,
            State::UpDegraded => 1,
            State::Failed => 2,
            State::Down => 3,
        }
    }
}

/// The three fields of the headline, each `n/N`. All three are on the links axis; they are
/// separate because a lost BFD session shows sub-second and a lost fallback neighbor only after
/// the OSPF dead interval.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Headline {
    /// Peers with at least one adjacency up, of peers expected.
    pub peers_up: usize,
    pub peers: usize,
    /// BFD sessions up, of sessions expected (one per peer, zone and segment).
    pub links_up: usize,
    pub links: usize,
    /// Fallback OSPF neighbors at least 2-Way, of neighbors expected.
    pub fallbacks_up: usize,
    pub fallbacks: usize,
}

impl Headline {
    /// The verdict these counts carry on an applied fabric.
    pub fn state(&self) -> State {
        if self.links_up == 0 && self.fallbacks_up == 0 {
            State::Failed
        } else if self.links_up == self.links && self.fallbacks_up == self.fallbacks {
            State::Up
        } else {
            State::UpDegraded
        }
    }

    /// `<peers> | <links> | <fallbacks>`, the parenthesized half of the headline.
    pub fn fields(&self) -> String {
        format!(
            "{}/{} | {}/{} | {}/{}",
            self.peers_up, self.peers, self.links_up, self.links, self.fallbacks_up, self.fallbacks
        )
    }
}

/// What one condition means for `--wait`, and the only thing the classification decides
/// (F22, VERIFIED on the rack 2026-09-07: the headline goes UP seconds before the engine has
/// installed the routes, and a wait that ends on the headline alone lets a deployment gate pass
/// over a fabric that cannot carry anything yet).
///
/// Every emitter states its class at the call site — there is no default and no matching on the
/// text of a line, so a new condition cannot join either set by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The fabric itself clears this one: an adjacency that is still forming, a route or an
    /// address the engine has not installed yet, a child the supervisor is restarting, a
    /// sysctl/rule/leg `up` and the watchdog own. Its presence means "not settled", so it holds
    /// `--wait` open until the deadline.
    Settling,
    /// Waiting changes nothing: the condition is a design-health note a settled fabric reports,
    /// a counter, a drift against generated state, a foreign daemon, or a hardware fact.
    /// Holding the wait on one would cost every `status --wait` its whole deadline, every time.
    Standing,
}

/// One condition. Not a verdict: a posture condition either actuates (the links go down and the
/// state follows) or lands here, where it never moves the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub class: Class,
    /// The condition in words. Still prose this round: only the conditions that have a row of
    /// their own (adjacencies, legs) are structured so far.
    pub text: String,
}

/// One expected adjacency to a peer: a BFD session on a declared segment, or an OSPF neighbor
/// on the zone's fallback bond. The declaration is the denominator, so a row exists whether or
/// not the adjacency is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjacency {
    pub zone: String,
    /// The segment number, or `None` for the zone's fallback bond.
    pub seg: Option<u8>,
    /// The peer's node number, its last address octet in every zone.
    pub peer_node: u8,
    pub peer_name: String,
    /// The peer's segment address this BFD session is keyed by; `None` on a fallback bond,
    /// where the adjacency is keyed by the peer's router id instead.
    pub peer_addr: Option<String>,
    /// BFD `up`, or an OSPF neighbor at least 2-Way on the fallback bond.
    pub up: bool,
}

impl Adjacency {
    /// `<zone>:<segment>:.<node>` — how status names one adjacency, `fallback` in the segment
    /// position for the bond.
    pub fn label(&self) -> String {
        match self.seg {
            Some(s) => format!("{}:{s}:.{}", self.zone, self.peer_node),
            None => format!("{}:fallback:.{}", self.zone, self.peer_node),
        }
    }
}

/// Which family of migrating leg a row describes. The two legs cfab builds — a zone's universal
/// fallback segment and an ingress leg on gw scope `any` — are the same netdev shape built by
/// the same builder, so they are one row type; only the words a renderer picks differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegKind {
    Fallback,
    Ingress,
}

/// What the supervisor's prober says about the far end's liveness under one leg. Carrier cannot
/// answer this — an island whose uplink is dead keeps carrier and keeps switching locally
/// (finding F21) — so where the bond SITS and whether anything can be reached over the wire it
/// sits on are two different facts, and `status` needs both to name a cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// No rows: no supervisor answering, a supervisor from before the prober, or a leg nothing
    /// probes.
    Unknown,
    /// The far end is live over the home wire.
    Home,
    /// The home wire is silent and being asked, but nothing is confirmed yet.
    HomeSuspect,
    /// The home wire is confirmed dead, but another wire is live.
    HomeDark,
    /// No wire reaches the far end.
    AllDark,
    /// No wire of this leg has heard anything at all (spec §5 rule 2).
    Quiet,
}

/// One declared port of a leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegPort {
    pub ifname: String,
    /// The physical wire the port is tagged on.
    pub wire: String,
    /// The wire is gone from the kernel, so this port cannot exist right now.
    pub absent: bool,
}

/// `/sys/class/net/<home>/carrier`, read only when the leg is active off its home wire — the
/// one branch in which the file decides anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeCarrier {
    NotRead,
    /// The file returns EINVAL on a down interface, so this is a field state, never healthy.
    Unreadable,
    Value(String),
}

/// What `bonding/` said about a leg that is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bonding {
    /// `bonding/mii_status`, trimmed.
    pub mii_status: String,
    /// `bonding/active_slave`, trimmed; empty when the bond has no active port.
    pub active_slave: String,
    pub home_carrier: HomeCarrier,
    /// `bonding/slaves`, split on whitespace; `Err` carries the read error.
    pub slaves: std::result::Result<Vec<String>, String>,
}

/// One active-backup leg as it was read. Reads only — a leg that has migrated or lost a port is
/// the watchdog's business to actuate on; here it is a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondLeg {
    pub kind: LegKind,
    pub zone: String,
    pub ifname: String,
    /// The wire this leg belongs on: the zone's cheapest wire this member has.
    pub home: String,
    /// The gw router this leg reaches; `Some` only on an ingress leg.
    pub router: Option<String>,
    pub reach: Reach,
    pub ports: Vec<LegPort>,
    /// `None` when nothing under `bonding/` could be read — the netdev is not a bond.
    pub bonding: Option<Bonding>,
}

impl BondLeg {
    /// The wire the leg is carrying on, when a port of ours is active.
    pub fn active_wire(&self) -> Option<&str> {
        let b = self.bonding.as_ref()?;
        self.ports
            .iter()
            .find(|p| p.ifname == b.active_slave)
            .map(|p| p.wire.as_str())
    }

    /// Is the leg on the wire it belongs on?
    pub fn on_home(&self) -> bool {
        self.active_wire() == Some(self.home.as_str())
    }
}
