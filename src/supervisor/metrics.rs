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

/// The largest request line the endpoint reads. Rule (spec §3.1): a scrape's request line is a
/// method, a short path and a version; anything larger is not a scraper and is dropped unread.
const MAX_REQUEST: usize = 1024;

/// What the endpoint answers a connection with. `head` means the request was `HEAD`: the same
/// headers, no body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Response {
    Metrics { head: bool },
    Landing { head: bool },
    NotFound,
    Close,
}

/// The page served at `/`: one link, so a browser pointed at the port finds the metrics.
const LANDING_BODY: &str = "<html><body><a href=\"/metrics\">/metrics</a></body></html>\n";

const NOT_FOUND_BODY: &str = "not found\n";

/// Classify one request by its request line alone. Headers are not read: the endpoint speaks
/// exactly enough HTTP for a scraper, and everything it does not recognize gets the connection
/// closed rather than an error page.
pub(crate) fn respond(request: &[u8]) -> Response {
    let capped = &request[..request.len().min(MAX_REQUEST)];
    let Some(end) = capped.iter().position(|&b| b == b'\n') else {
        return Response::Close;
    };
    let line = &capped[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Ok(line) = std::str::from_utf8(line) else {
        return Response::Close;
    };
    let mut tok = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (tok.next(), tok.next(), tok.next(), tok.next())
    else {
        return Response::Close;
    };
    if !version.starts_with("HTTP/1.") {
        return Response::Close;
    }
    let head = match method {
        "GET" => false,
        "HEAD" => true,
        _ => return Response::NotFound,
    };
    match target {
        "/metrics" => Response::Metrics { head },
        "/" => Response::Landing { head },
        _ => Response::NotFound,
    }
}

/// The full HTTP/1.1 bytes for a classified request. `body` is the metrics text; the landing and
/// not-found bodies are fixed. `Close` writes nothing.
pub(crate) fn write_response(r: &Response, body: &str) -> Vec<u8> {
    let (status, content_type, body, head) = match r {
        Response::Metrics { head } => (
            "200 OK",
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
            body,
            *head,
        ),
        Response::Landing { head } => ("200 OK", "text/html; charset=utf-8", LANDING_BODY, *head),
        Response::NotFound => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            NOT_FOUND_BODY,
            false,
        ),
        Response::Close => return Vec::new(),
    };
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if !head {
        out.push_str(body);
    }
    out.into_bytes()
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

#[cfg(test)]
mod request_tests {
    use super::*;

    #[test]
    fn get_metrics_10_and_11() {
        assert!(matches!(
            respond(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"),
            Response::Metrics { head: false }
        ));
        assert!(matches!(
            respond(b"GET /metrics HTTP/1.0\r\n\r\n"),
            Response::Metrics { head: false }
        ));
        assert!(matches!(
            respond(b"HEAD /metrics HTTP/1.1\r\n\r\n"),
            Response::Metrics { head: true }
        ));
    }

    #[test]
    fn landing_and_404() {
        assert!(matches!(
            respond(b"GET / HTTP/1.1\r\n\r\n"),
            Response::Landing { head: false }
        ));
        assert!(matches!(
            respond(b"HEAD / HTTP/1.1\r\n\r\n"),
            Response::Landing { head: true }
        ));
        // Query strings are not interpreted: the target is not the path.
        assert!(matches!(
            respond(b"GET /metrics?x=1 HTTP/1.1\r\n\r\n"),
            Response::NotFound
        ));
        assert!(matches!(
            respond(b"GET /other HTTP/1.1\r\n\r\n"),
            Response::NotFound
        ));
        assert!(matches!(
            respond(b"POST /metrics HTTP/1.1\r\n\r\n"),
            Response::NotFound
        ));
    }

    #[test]
    fn garbage_and_oversize_close() {
        assert!(matches!(respond(b"\x16\x03\x01\x00"), Response::Close)); // a TLS hello
        assert!(matches!(respond(b"GET /metrics"), Response::Close)); // no terminator yet
        assert!(matches!(respond(&vec![b'A'; 2048]), Response::Close));
        // A request line longer than the cap, terminator included, is still refused.
        let mut long = vec![b'A'; MAX_REQUEST + 8];
        long.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(respond(&long), Response::Close));
        // Bare LF is a terminator too.
        assert!(matches!(
            respond(b"GET /metrics HTTP/1.1\n\n"),
            Response::Metrics { head: false }
        ));
        // Not UTF-8.
        assert!(matches!(
            respond(b"GET /\xff\xfe HTTP/1.1\r\n\r\n"),
            Response::Close
        ));
        // Wrong protocol on a three-token line.
        assert!(matches!(
            respond(b"GET /metrics HTTP/2.0\r\n\r\n"),
            Response::Close
        ));
        // Wrong token count.
        assert!(matches!(respond(b"GET /metrics\r\n\r\n"), Response::Close));
    }

    #[test]
    fn response_bytes() {
        let b = write_response(&Response::Metrics { head: false }, "x 1\n");
        let s = String::from_utf8(b).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains(
            "Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\n"
        ));
        assert!(s.contains("Content-Length: 4\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("\r\n\r\nx 1\n"));

        // HEAD sends the headers the GET would have sent, and no body.
        let h =
            String::from_utf8(write_response(&Response::Metrics { head: true }, "x 1\n")).unwrap();
        assert!(h.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(h.contains("Content-Length: 4\r\n"));
        assert!(h.ends_with("\r\n\r\n"));

        let l = String::from_utf8(write_response(&Response::Landing { head: false }, "")).unwrap();
        assert!(l.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(l.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(l.contains(&format!("Content-Length: {}\r\n", LANDING_BODY.len())));
        assert!(l.ends_with(LANDING_BODY));
        let lh = String::from_utf8(write_response(&Response::Landing { head: true }, "")).unwrap();
        assert!(lh.contains(&format!("Content-Length: {}\r\n", LANDING_BODY.len())));
        assert!(lh.ends_with("\r\n\r\n"));

        assert!(
            String::from_utf8(write_response(&Response::NotFound, ""))
                .unwrap()
                .starts_with("HTTP/1.1 404 Not Found\r\n")
        );
        assert!(write_response(&Response::Close, "").is_empty());
    }
}
