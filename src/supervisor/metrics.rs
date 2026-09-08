//! The member's telemetry: one instant of fabric state rendered as OpenMetrics text.
//!
//! `render` is pure. A fresh `Registry` and one `Collector` are built per call, so no metric
//! object outlives the snapshot it describes and a family can disappear when the fact behind it
//! does — which is what a state that is `None` means.

// Nothing outside the tests renders yet: the supervisor's serve loop is the only caller and it
// does not exist in this commit.
#![allow(dead_code)]

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::gauge::ConstGauge;
use prometheus_client::registry::Registry;

use crate::commands::status::model::StatusModel;
use crate::prober::ProbeRows;
use crate::supervisor::report::Components;

/// The port the endpoint listens on. Rule: a large, memorable port with the lowest collision
/// chance on a member; no registered Prometheus port exists to defer to.
pub(crate) const PORT: u16 = 23232;

/// One gather, everything a render needs and nothing it must read for itself.
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    pub model: StatusModel,
    pub components: Components,
    pub probed: ProbeRows,
    /// Wall-clock seconds at which this snapshot was gathered.
    pub collected_at_unix: f64,
    /// How long the gather took.
    pub collect_seconds: f64,
    /// Gathers that failed since the supervisor started.
    pub collect_failures: u64,
}

#[derive(Debug)]
struct FabricCollector {
    snap: Snapshot,
}

impl Collector for FabricCollector {
    fn encode(&self, mut enc: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let g = ConstGauge::new(1i64);
        let mut fam = enc.encode_descriptor(
            "cfab_build_info",
            "The cfab version this member runs.",
            None,
            MetricType::Gauge,
        )?;
        let labels = [("version", self.snap.model.member.version.as_str())];
        let e = fam.encode_family(&labels)?;
        g.encode(e)?;
        Ok(())
    }
}

/// The member's state as OpenMetrics text, ready to serve.
pub(crate) fn render(s: &Snapshot) -> String {
    let mut reg = Registry::default();
    reg.register_collector(Box::new(FabricCollector { snap: s.clone() }));
    let mut out = String::new();
    prometheus_client::encoding::text::encode(&mut out, &reg)
        .expect("fmt::Write on a String cannot fail");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::status::model::{Headline, MemberInfo, State};
    use crate::model::MemberKind;
    use crate::supervisor::child::State as ChildState;
    use crate::supervisor::report::{Component, SupervisorInfo, WatchdogInfo};

    fn component(
        name: &str,
        state: ChildState,
        uptime_s: Option<u64>,
        why: Option<&str>,
    ) -> Component {
        Component {
            name: name.to_string(),
            state,
            pid: Some(1234),
            uptime_s,
            restarts: 0,
            last_exit: None,
            why: why.map(str::to_string),
        }
    }

    pub(super) fn fixture_up() -> Snapshot {
        let components = Components {
            supervisor: SupervisorInfo {
                pid: 1000,
                uptime_s: 3600,
                applying: false,
                applies: 1,
                last_apply_error: None,
            },
            components: vec![
                component("engine", ChildState::Running, Some(60), None),
                component("shape-daemon", ChildState::Running, Some(60), None),
                component(
                    "conf-sync",
                    ChildState::Stopped,
                    None,
                    Some("not clustered"),
                ),
            ],
            watchdog: WatchdogInfo {
                last_tick_s_ago: Some(1),
                result: "ok".to_string(),
                detail: None,
            },
            ingress: Vec::new(),
            fallback: Vec::new(),
        };
        let model = StatusModel {
            member: MemberInfo {
                name: "pve1-tb".to_string(),
                kind: MemberKind::Host,
                version: "0.4.8".to_string(),
            },
            state: State::Up,
            headline: Some(Headline {
                peers_up: 2,
                peers: 2,
                links_up: 18,
                links: 18,
                fallbacks_up: 6,
                fallbacks: 6,
            }),
            adjacencies: Vec::new(),
            fallbacks: Vec::new(),
            ingress: Vec::new(),
            conditions: Vec::new(),
            components: Some(components.clone()),
            prefs: Vec::new(),
            run_dir: "/run/cfab".to_string(),
        };
        Snapshot {
            model,
            components,
            probed: ProbeRows::default(),
            collected_at_unix: 1_700_000_000.0,
            collect_seconds: 0.048,
            collect_failures: 0,
        }
    }

    #[test]
    fn build_info_is_emitted_and_parses() {
        let text = render(&fixture_up());
        assert!(
            text.contains("cfab_build_info{version=\"0.4.8\"} 1"),
            "{text}"
        );
        let scrape =
            prometheus_parse::Scrape::parse(text.lines().map(|l| Ok(l.to_string()))).unwrap();
        let s = scrape
            .samples
            .iter()
            .find(|s| s.metric == "cfab_build_info")
            .expect("family");
        assert_eq!(s.labels.get("version"), Some("0.4.8"));
    }

    #[test]
    fn output_ends_with_the_openmetrics_terminator() {
        assert!(render(&fixture_up()).ends_with("# EOF\n"));
    }
}
