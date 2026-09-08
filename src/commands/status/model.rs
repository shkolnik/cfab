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
