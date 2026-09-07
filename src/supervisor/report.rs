//! The `components` document (spec §9) and the one line `cfab status` prints from it.
//!
//! Every duration in here is elapsed seconds from a monotonic clock, never a wall-clock
//! timestamp: a clock step must not make a component look restarted.

use serde::{Deserialize, Serialize};

use super::child::{ExitCause, State};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Components {
    pub supervisor: SupervisorInfo,
    pub components: Vec<Component>,
    pub watchdog: WatchdogInfo,
    /// One row per ingress leg this member carries, from the router prober. Empty on a leaf
    /// (which carries none) and `#[serde(default)]` so a supervisor from before the prober
    /// existed still answers a newer `cfab status`.
    #[serde(default)]
    pub ingress: Vec<IngressLeg>,
}

/// What the ingress prober knows about one zone's leg: where the bond sits, and whether the
/// router answers over each wire under it. Carrier is not the question — an island whose uplink
/// is dead keeps carrier and keeps switching locally (finding F21) — so reachability is reported
/// per wire and named by island, which is the thing an operator can go look at.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngressLeg {
    pub zone: String,
    /// The leg netdev: a bond on gw scope `any`, a plain sub-interface on a single domain.
    pub bond: String,
    /// The slave the prober is holding the bond on; `null` for a leg that cannot migrate.
    pub active: Option<String>,
    pub slaves: Vec<IngressSlave>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngressSlave {
    pub wire: String,
    /// The switch domain this wire lands in — which switch to go look at.
    pub island: String,
    pub reachable: bool,
    /// Milliseconds since the router last answered over this wire; `null` = never, this run.
    pub last_reply_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupervisorInfo {
    pub pid: u32,
    pub uptime_s: u64,
    pub applying: bool,
    pub applies: u64,
    pub last_apply_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub state: State,
    pub pid: Option<u32>,
    pub uptime_s: Option<u64>,
    pub restarts: u64,
    pub last_exit: Option<ExitCause>,
    /// Why this member does not run it, e.g. "not clustered". Only a `stopped` row carries
    /// one, and a row is never omitted: an absent row reads as a bug, a `stopped` row reads
    /// as a fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchdogInfo {
    pub last_tick_s_ago: Option<u64>,
    pub result: String,
    pub detail: Option<String>,
}

/// `1h02m` / `2m03s` / `4s` — two units at most, so the line stays scannable.
fn duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

fn component(c: &Component) -> String {
    let mut out = format!("{} {}", c.name, c.state.as_str());
    if let Some(u) = c.uptime_s {
        out.push_str(&format!(" {}", duration(u)));
    }
    let detail = match &c.why {
        Some(w) => w.clone(),
        None => {
            let mut parts = vec![format!("{} restarts", c.restarts)];
            if let Some(e) = &c.last_exit {
                parts.push(format!("last exit {} {}s ago", e.cause, e.s_ago));
            }
            parts.join(", ")
        }
    };
    out.push_str(&format!(" ({detail})"));
    out
}

fn watchdog(w: &WatchdogInfo) -> String {
    let mut out = match w.last_tick_s_ago {
        Some(n) => format!("watchdog {} {n}s ago", w.result),
        None => format!("watchdog {} (no tick yet)", w.result),
    };
    if let Some(d) = &w.detail {
        out.push_str(&format!(" ({d})"));
    }
    out
}

/// The single always-printed `status` line, unindented and without its newline: every
/// component named, a stopped one included, then the forwarding watchdog.
pub fn render_line(c: &Components) -> String {
    let mut parts: Vec<String> = c.components.iter().map(component).collect();
    parts.push(watchdog(&c.watchdog));
    // A refused reload leaves every component healthy — the running fabric is exactly the one
    // that was up — so the only place an operator can learn that their edit did NOT take is
    // here. It rides the always-printed line rather than a reason row for that reason.
    if let Some(e) = &c.supervisor.last_apply_error {
        parts.push(format!("last apply: {e}"));
    }
    format!("components: {}", parts.join(" | "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document a supervisor with one running engine, one crash-looping shape-daemon and
    /// a conf-sync this member does not run would publish (spec §9).
    const FIXTURE: &str = r#"{
      "supervisor": {"pid": 1234, "uptime_s": 3721, "applying": false, "applies": 3, "last_apply_error": null},
      "components": [
        {"name": "engine",       "state": "running",    "pid": 1240, "uptime_s": 3720, "restarts": 0, "last_exit": null},
        {"name": "shape-daemon", "state": "restarting", "pid": null, "uptime_s": null, "restarts": 3,
         "last_exit": {"cause": "signal SIGKILL", "s_ago": 1}},
        {"name": "conf-sync",    "state": "stopped",    "pid": null, "uptime_s": null, "restarts": 0, "last_exit": null,
         "why": "not clustered"}
      ],
      "watchdog": {"last_tick_s_ago": 2, "result": "ok", "detail": null}
    }"#;

    #[test]
    fn the_components_line_names_every_component_including_a_stopped_one() {
        let c: Components = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(
            render_line(&c),
            "components: engine running 1h02m (0 restarts) | shape-daemon restarting (3 restarts, \
             last exit signal SIGKILL 1s ago) | conf-sync stopped (not clustered) | watchdog ok 2s ago"
        );
    }

    /// A refused reload leaves every component healthy, so the components line is the only
    /// place `cfab status` can say the operator's edit did not take.
    #[test]
    fn a_refused_reload_is_named_on_the_components_line() {
        let mut c: Components = serde_json::from_str(FIXTURE).unwrap();
        c.supervisor.last_apply_error = Some(
            "reload refused, keeping the running fabric: /etc/cfab/fabric.toml: unknown key"
                .to_string(),
        );
        let line = render_line(&c);
        assert!(
            line.ends_with(
                "| last apply: reload refused, keeping the running fabric: \
                 /etc/cfab/fabric.toml: unknown key"
            ),
            "{line}"
        );
    }

    /// `cfab status` deserializes what the supervisor serializes: the document must survive
    /// the round trip unchanged, `why` included.
    #[test]
    fn the_document_round_trips_through_serde() {
        let c: Components = serde_json::from_str(FIXTURE).unwrap();
        let text = serde_json::to_string(&c).unwrap();
        let back: Components = serde_json::from_str(&text).unwrap();
        assert_eq!(render_line(&back), render_line(&c));
        assert!(text.contains("\"why\":\"not clustered\""));
        assert_eq!(
            text.matches("\"why\"").count(),
            1,
            "why is only on the row that has one"
        );
    }
}
