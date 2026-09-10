//! The structured result of one `cfab status` gather.
//!
//! `status` reads the fabric's state once and renders it; this module holds what was read, so
//! that more than one renderer can consume the same gather. Nothing here reads or writes: every
//! field is a fact a renderer turns into its own words.

use std::net::Ipv4Addr;

use crate::derive::HostZonePref;
use crate::model::MemberKind;
use crate::supervisor::report::Components;

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

/// One gw zone's ingress, as it was read: the table the return path uses, the leg the outside
/// arrives on, and the BGP session that teaches the router this zone's identities. A row exists
/// for every gw zone on a host, whether or not this member carries the leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingress {
    pub zone: String,
    /// The gw router's address.
    pub router: String,
    /// The routing table the zone's return path uses (the zone id).
    pub table: String,
    /// The table holds at least one `default` line.
    pub default_present: bool,
    /// A `default` line in the table is inactive (`linkdown`/`dead`). Read only on a leg that
    /// does not migrate: a migrating leg owns its own carrier diagnosis.
    pub default_linkdown: bool,
    /// The leg's netdev; `None` when this member carries no ingress leg for the zone.
    pub ifname: Option<String>,
    /// The address the leg must carry.
    pub cidr: String,
    /// The leg carries `cidr`; `None` when there is no leg to read.
    pub cidr_present: Option<bool>,
    /// The leg as a bond; `Some` only on gw scope `any`, where the leg migrates between wires.
    pub bond: Option<BondLeg>,
    /// The BGP session's state, `absent` when the router is not in the engine's list; `None`
    /// when the engine's socket is silent or there is no leg.
    pub bgp_state: Option<String>,
    /// Prefixes this member has sent the router; `None` alongside `bgp_state`.
    pub bgp_pfx_snt: Option<u64>,
}

impl Ingress {
    /// What the prober says about reaching the router under this leg; `None` on a leg that does
    /// not migrate, which nothing probes.
    pub fn reach(&self) -> Option<Reach> {
        self.bond.as_ref().map(|b| b.reach)
    }

    /// The wire the leg is carrying on, when it migrates and a port of ours is active.
    pub fn active_wire(&self) -> Option<&str> {
        self.bond.as_ref().and_then(|b| b.active_wire())
    }

    /// The wire the leg belongs on, when it migrates.
    pub fn home_wire(&self) -> Option<&str> {
        self.bond.as_ref().map(|b| b.home.as_str())
    }
}

/// A row's classification (metrics addendum 2026-09-09). Precedence when several conditions
/// apply at once: `Deferred` > `Broken` > `AnnouncerNotStarted` > `Up` — a deferred row is
/// classified before any of the checks below run (`apply` never gave it a gw address), and a
/// return-path-broken row (`c.broken_workloads`, which pushes no condition of its own) is
/// `Broken`, never `Up`, even though it adds nothing to `up`'s reasons by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadState {
    Up,
    Deferred,
    AnnouncerNotStarted,
    Broken,
}

impl WorkloadState {
    /// `WorkloadStatus.up` is always exactly this — the one place that maps a state to the
    /// boolean, so every production site that constructs a row sets `up: state.is_up()` instead
    /// of hand-writing the pair (review M3: a hand-written pair is only conventionally, not
    /// structurally, tied to `state`).
    pub fn is_up(self) -> bool {
        self == WorkloadState::Up
    }
}

/// The bridge guard's two counters (spec addendum, `counter_packets_for`), summed over the row's
/// uplink ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardDrops {
    pub claim: u64,
    pub request: u64,
}

/// One `[[workload]]` row on this member, as `status` read it (spec §5.1 item 10). A row exists
/// only on a member that carries the leg (`view.workload_rows()`) — a member the workload merely
/// reaches (an allowed zone with no address on the leg) has none, and is checked by the
/// return-path/route-get conditions alone (`return_path_and_ingress`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadStatus {
    pub name: String,
    /// The declared bridge this row's leg is a vlan of, e.g. `primary`.
    pub uplink: String,
    /// The declared vlan id on that bridge.
    pub vid: u16,
    /// The leg cfab derives and creates, e.g. `cfab-work-vms`.
    pub leg: String,
    /// This member's declared address on `leg`, e.g. `192.168.20.2/24`.
    pub address: String,
    /// The anycast gateway with the prefix's mask, e.g. `192.168.20.254/24`.
    pub gw: String,
    /// The interface, its addresses, the ARP guard and the return path are all in place.
    /// Always `state == WorkloadState::Up`.
    pub up: bool,
    /// This row's classification; `up == (state == Up)`.
    pub state: WorkloadState,
    /// Zones this workload is advertised into (the declared `allow` list).
    pub zones: Vec<String>,
    /// The bridge's uplink port(s), from `uplink::identify_declared`; empty when unidentified.
    pub uplink_ports: Vec<String>,
    /// What wakes the announcer (`neigh events` / `fdb poll (...)`), from the supervisor's
    /// `components` document; `None` when no supervisor is answering or the announcer has not
    /// started.
    pub trigger: Option<String>,
    /// The leg's `proxy_arp` sysctl (spec 5.2): `Some(true)` while the host answers ARP for the
    /// remote VMs it routes, `Some(false)` when it does not, `None` when the file could not be
    /// read (the leg may not exist yet). Every host's leg needs it on — with it on one host
    /// only, VM-to-VM across hosts is broken in one direction (G0, rack).
    pub proxy_arp: Option<bool>,
    /// Count of neighbor entries in `prefix` recently resolved to something other than a
    /// declared member or `gw` (a VM, presumptively). `None` when the row is not up,
    /// or the `ip -j neigh show dev` read failed — observability, never a health condition.
    pub vms_seen: Option<u32>,
    /// The bridge guard's claim/request drop counters, summed over the row's uplink ports;
    /// `None` when the guard table is absent, or the row's uplink ports are unknown (an
    /// `uplink::identify` failure leaves nothing to sum over).
    pub guard_drops: Option<GuardDrops>,
    /// `(rx_bytes, tx_bytes)` from `/sys/class/net/<ifname>/statistics/`; `None` on a read
    /// failure.
    pub bytes: Option<(u64, u64)>,
    /// The forward chain's `stray-<name>` drop counter, summed over the row's one rule per
    /// allowed zone (spec §5.2, ruling 6): fabric packets this member refused to put on its
    /// leg for a VM it does not know. `None` when the chain carries no such rule at all —
    /// an absent rule and a rule that has dropped nothing are different facts. The counter
    /// resets whenever `apply` re-renders `inet cfab-fwd`.
    pub stray_forwards: Option<u64>,
    /// This row's DHCP relay (spec §5.4/§6): `None` when the row declares no `dhcp_server` —
    /// "absent = no relay" — never a health condition of the row itself. `Some` with zero
    /// counters and no error is the normal shape before any packet has crossed it or before a
    /// supervisor has answered at all.
    pub relay: Option<RelayStatus>,
}

/// One `[[workload]]` row's DHCP relay, as `status` reads it from the supervisor's `components`
/// document (spec §5.4/§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatus {
    /// The declared `dhcp_server`.
    pub server: Ipv4Addr,
    pub requests: u64,
    pub replies: u64,
    /// The relay's last bind or socket error, for as long as it stands; `None` while healthy or
    /// before the task has reported anything (no supervisor answering, or the task's first tick
    /// has not run yet) — never a health condition of the row (spec §3.1, availability first).
    pub last_error: Option<String>,
}

/// Which default route this member's own traffic takes right now (spec §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultPath {
    /// cfab's additive default in table 250, through the fabric gateway.
    Fabric { via: String, dev: String },
    /// The host's own default in main — the floor cfab adds to and never removes.
    Floor { via: String, dev: String },
    /// Neither table holds one: this member has no default route at all.
    None,
}

/// Why this member's own traffic is not taking the fabric gateway. Typed, not prose, so the
/// metric can tell "this host has no gw zone at all" from "its router went dark" without
/// matching on the text of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultReason {
    /// The ingress prober says no wire of the gw leg reaches the router.
    RouterUnreachable,
    /// This member declares no `gw` zone, so cfab never had a default to add (every leaf).
    NoGwZone,
    /// Table 250 is empty and nothing says the router is dark: cfab is down, `down` ran, or the
    /// install failed.
    Withdrawn,
}

impl DefaultReason {
    /// The one spelling of each, in status prose.
    pub fn word(self) -> &'static str {
        match self {
            DefaultReason::RouterUnreachable => "router unreachable",
            DefaultReason::NoGwZone => "no gw zone",
            DefaultReason::Withdrawn => "withdrawn",
        }
    }
}

/// The host default as `status` read it: which path locally originated traffic takes, and why
/// it is not the fabric one when it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDefault {
    pub path: DefaultPath,
    /// `None` while the fabric default is in force.
    pub reason: Option<DefaultReason>,
}

impl HostDefault {
    /// The line `status` prints after `default: `.
    pub fn render(&self) -> String {
        let head = match &self.path {
            DefaultPath::Fabric { via, dev } => format!("via fabric gw {via} ({dev})"),
            DefaultPath::Floor { via, dev } => format!("via floor {via} ({dev})"),
            DefaultPath::None => "none".to_string(),
        };
        match self.reason {
            Some(r) => format!("{head}, {}", r.word()),
            None => head,
        }
    }
}

/// Which member this gather describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub name: String,
    pub kind: MemberKind,
    /// The cfab that produced this gather.
    pub version: String,
}

impl MemberInfo {
    /// `host` or `leaf`, the word status prints.
    pub fn kind_word(&self) -> &'static str {
        match self.kind {
            MemberKind::Host => "host",
            MemberKind::Leaf => "leaf",
        }
    }
}

/// One instant read of what this member's fabric is doing, structured. Every renderer consumes
/// this and nothing else; the gather that fills it is the only code that touches the system.
#[derive(Debug, Clone)]
pub struct StatusModel {
    pub member: MemberInfo,
    pub state: State,
    /// The headline counts; `None` when no fabric is applied, which is also what makes the
    /// components line unprintable — there is no supervisor to ask.
    pub headline: Option<Headline>,
    /// Every expected adjacency to a peer, up or down.
    pub adjacencies: Vec<Adjacency>,
    /// One row per zone carrying a fallback bond.
    pub fallbacks: Vec<BondLeg>,
    /// One row per gw zone on a host.
    pub ingress: Vec<Ingress>,
    /// One row per `[[workload]]` this member carries (empty on a member that carries none —
    /// including every leaf, spec §5.1).
    pub workloads: Vec<WorkloadStatus>,
    /// Every reason line the report prints, in the order the gather found them, each with what
    /// it means for `--wait`. This is the prose: the lines a row earns are rendered from that
    /// row and pushed here at the point the gather made it, so the rows below and this list are
    /// the same facts — one structured, one in words — and neither is derived from the other at
    /// render time.
    pub conditions: Vec<Condition>,
    /// The supervisor's `components` document; `None` when nothing answered on its socket.
    pub components: Option<Components>,
    /// This member's wire order per zone, with where the order came from.
    pub prefs: Vec<HostZonePref>,
    /// The run dir, which every "no supervisor answering" line names.
    pub run_dir: String,
    /// Which default route this member's own traffic takes (spec §6). `None` on a leaf and on
    /// a member with no fabric applied — neither has one of cfab's to describe.
    pub host_default: Option<HostDefault>,
}
