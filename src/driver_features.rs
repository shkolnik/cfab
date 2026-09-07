//! A wire's `driver_features`: the declared `ethtool -K` words, and the records `up` keeps so
//! `down` and the forwarding watchdog can act on what it actually did.
//!
//! The string is handed to `ethtool -K <nic>` VERBATIM. cfab knows no adapter and no driver:
//! WHICH features a NIC needs turned off is the operator's declaration, never a table in the
//! binary. What cfab owns is three things the operator cannot get from ethtool alone:
//!
//!   1. the string is validated at declaration load (`cfab check`), not at bringup on the host
//!      whose network is about to change;
//!   2. the value each named feature had BEFORE `up` changed it is recorded, so `down` puts
//!      the NIC back the way it was found — only the features that were really changed;
//!   3. the driver each wire had at apply is recorded, so a wire that re-enumerates as a
//!      DIFFERENT adapter is reported instead of silently inheriting the old one's settings.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::sys::{Sys, run_ok};

/// One feature `up` changed on one wire, and the value it had before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub wire: String,
    pub feature: String,
    /// The value `ethtool -k` reported before the change — what `down` puts back.
    pub prior: String,
}

/// Validate one declared `driver_features` string and return its `(feature, on|off)` pairs.
///
/// Permissive about WHICH feature (ethtool's set grows with the kernel, and a name cfab has
/// never heard of is the operator's business), strict about SHAPE: an odd word count or a
/// value that is not `on`/`off` is a typo that would otherwise be discovered by `ethtool`
/// on the host, mid-bringup.
pub fn parse(spec: &str) -> Result<Vec<(&str, &str)>> {
    let words: Vec<&str> = spec.split_whitespace().collect();
    if words.is_empty() {
        return Err(Error::config(
            "driver_features is empty — omit the key instead of declaring nothing",
        ));
    }
    if !words.len().is_multiple_of(2) {
        return Err(Error::config(format!(
            "driver_features \"{spec}\": {} words — the string is <feature> on|off pairs",
            words.len()
        )));
    }
    let mut pairs = Vec::new();
    for pair in words.chunks(2) {
        let (feature, value) = (pair[0], pair[1]);
        if !is_feature_name(feature) {
            return Err(Error::config(format!(
                "driver_features \"{spec}\": '{feature}' is not an ethtool feature name \
                 (lowercase letters, digits and dashes)"
            )));
        }
        if value != "on" && value != "off" {
            return Err(Error::config(format!(
                "driver_features \"{spec}\": '{value}' is not on or off (feature {feature})"
            )));
        }
        pairs.push((feature, value));
    }
    Ok(pairs)
}

/// `^[a-z][a-z0-9-]*$` — ethtool's own naming, without pulling in a regex engine.
fn is_feature_name(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// ethtool's short names for the features `-K` takes, mapped to the long names `-k` reports.
/// This is the TOOL's vocabulary (ethtool(8), "off_flags"), not knowledge of any adapter:
/// without it the prior value of `sg` could not be read back, because `-k` calls it
/// `scatter-gather`. A name that is not in the table is used as reported.
const SHORT_NAMES: [(&str, &str); 12] = [
    ("rx", "rx-checksumming"),
    ("tx", "tx-checksumming"),
    ("sg", "scatter-gather"),
    ("tso", "tcp-segmentation-offload"),
    ("ufo", "udp-fragmentation-offload"),
    ("gso", "generic-segmentation-offload"),
    ("gro", "generic-receive-offload"),
    ("lro", "large-receive-offload"),
    ("rxvlan", "rx-vlan-offload"),
    ("txvlan", "tx-vlan-offload"),
    ("ntuple", "ntuple-filters"),
    ("rxhash", "receive-hashing"),
];

/// The name `ethtool -k` reports for a feature `ethtool -K` is asked for.
pub fn reported_name(feature: &str) -> &str {
    SHORT_NAMES
        .iter()
        .find(|(short, _)| *short == feature)
        .map_or(feature, |(_, long)| *long)
}

/// `ethtool -k <dev>` parsed: reported name -> (value, is it fixed by the driver).
///
/// Sub-features are indented under their parent and carry their own names, so a flat map keyed
/// by the trimmed name is exactly right; the first line for a name wins, which is the parent.
pub fn parse_report(stdout: &str) -> BTreeMap<String, (String, bool)> {
    let mut out: BTreeMap<String, (String, bool)> = BTreeMap::new();
    for line in stdout.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let rest = rest.trim();
        let Some(value) = rest.split_whitespace().next() else {
            continue; // "Features for eth0:" — a header, not a feature
        };
        if value != "on" && value != "off" {
            continue;
        }
        out.entry(name.to_string())
            .or_insert_with(|| (value.to_string(), rest.contains("[fixed]")));
    }
    out
}

/// The driver `ethtool -i <dev>` reports.
pub fn driver_of(sys: &mut dyn Sys, dev: &str) -> Result<String> {
    let out = run_ok(sys, &["ethtool", "-i", dev])?;
    Ok(out
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("driver:"))
        .map(str::trim)
        .unwrap_or("")
        .to_string())
}

/// Put one wire's declared features in force, and say what that actually changed.
///
/// Reads the whole `ethtool -k` report ONCE, before touching anything: setting `sg off` also
/// clears the features that depend on it, so a prior value read after the first change would
/// record the consequence instead of the state cfab found.
///
/// A feature already at the wanted value is not set and not recorded — `down` restores what
/// `up` changed, and nothing else. A feature the driver reports `[fixed]`, or does not report
/// at all, is skipped with a warning: cfab cannot restore a value it cannot read, and a
/// bringup must not die on an offload knob.
pub fn apply_to_wire(
    sys: &mut dyn Sys,
    dev: &str,
    spec: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<Change>> {
    let pairs = parse(spec)?;
    let report = parse_report(&run_ok(sys, &["ethtool", "-k", dev])?.stdout);
    let mut changes = Vec::new();
    let mut words: Vec<String> = Vec::new();
    for (feature, want) in pairs {
        let reported = reported_name(feature);
        let Some((current, fixed)) = report.get(reported) else {
            warnings.push(format!(
                "WARNING: {dev}: driver_features '{feature}' is not reported by `ethtool -k` — \
                 skipped"
            ));
            continue;
        };
        if *fixed {
            warnings.push(format!(
                "WARNING: {dev}: driver_features '{feature}' is fixed by the driver at \
                 {current} — left alone"
            ));
            continue;
        }
        if current == want {
            continue;
        }
        changes.push(Change {
            wire: dev.to_string(),
            feature: feature.to_string(),
            prior: current.clone(),
        });
        words.push(feature.to_string());
        words.push(want.to_string());
    }
    if !words.is_empty() {
        let mut argv = vec!["ethtool", "-K", dev];
        argv.extend(words.iter().map(String::as_str));
        run_ok(sys, &argv)?;
    }
    Ok(changes)
}

/// `<run_dir>/wire-drivers`: the driver each present wire had when `up` ran.
pub fn drivers_path(run_dir: &str) -> String {
    format!("{}/wire-drivers", run_dir.trim_end_matches('/'))
}

/// `<run_dir>/wire-driver-features`: every feature `up` changed, and the value it changed from.
pub fn changed_path(run_dir: &str) -> String {
    format!("{}/wire-driver-features", run_dir.trim_end_matches('/'))
}

pub fn render_drivers(rows: &[(String, String)]) -> String {
    rows.iter()
        .map(|(nic, drv)| format!("{nic} {drv}\n"))
        .collect()
}

pub fn render_changes(changes: &[Change]) -> String {
    changes
        .iter()
        .map(|c| format!("{} {} {}\n", c.wire, c.feature, c.prior))
        .collect()
}

/// The driver recorded for one wire, or `None` when there is no record to read (a run dir from
/// an older version, or one wiped under a running fabric).
pub fn recorded_driver(sys: &mut dyn Sys, run_dir: &str, nic: &str) -> Option<String> {
    let text = sys.read(&drivers_path(run_dir)).ok()?;
    text.lines().find_map(|l| {
        let (n, drv) = l.split_once(' ')?;
        (n == nic).then(|| drv.trim().to_string())
    })
}

/// Every change `up` recorded, in the order it made them. No record = nothing to restore.
pub fn recorded_changes(sys: &mut dyn Sys, run_dir: &str) -> Vec<Change> {
    let Ok(text) = sys.read(&changed_path(run_dir)) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            Some(Change {
                wire: w.next()?.to_string(),
                feature: w.next()?.to_string(),
                prior: w.next()?.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mock::MockSys;

    const REPORT: &str = "Features for eth9:\nrx-checksumming: on\ntx-checksumming: on\n\ttx-checksum-ipv4: off [fixed]\nscatter-gather: on\n\ttx-scatter-gather: on\ntcp-segmentation-offload: on\ngeneric-segmentation-offload: on\ngeneric-receive-offload: on\nlarge-receive-offload: off [fixed]\nrx-vlan-offload: on\n";

    fn ethtool_sys() -> MockSys {
        MockSys::default().on_stdout(&["ethtool", "-k", "eth9"], REPORT)
    }

    #[test]
    fn pairs_are_returned_in_declaration_order() {
        assert_eq!(
            parse("sg off tso off gso off").unwrap(),
            [("sg", "off"), ("tso", "off"), ("gso", "off")]
        );
    }

    #[test]
    fn an_odd_word_count_is_refused_with_the_count_and_the_shape() {
        let err = parse("sg off tso").unwrap_err().to_string();
        assert!(err.contains("3 words"), "{err}");
        assert!(err.contains("<feature> on|off pairs"), "{err}");
    }

    #[test]
    fn a_value_that_is_not_on_or_off_is_refused_naming_the_feature() {
        let err = parse("sg maybe").unwrap_err().to_string();
        assert!(err.contains("'maybe' is not on or off"), "{err}");
        assert!(err.contains("feature sg"), "{err}");
    }

    #[test]
    fn a_feature_name_outside_the_ethtool_alphabet_is_refused() {
        for bad in ["SG", "sg!", "-sg", "9sg"] {
            let err = parse(&format!("{bad} off")).unwrap_err().to_string();
            assert!(
                err.contains("is not an ethtool feature name"),
                "{bad}: {err}"
            );
        }
    }

    /// Permissive by ruling: a feature cfab has never heard of is the operator's business.
    #[test]
    fn an_unknown_but_well_formed_feature_name_is_accepted() {
        assert_eq!(parse("tx-gso-list off").unwrap(), [("tx-gso-list", "off")]);
    }

    #[test]
    fn an_empty_string_is_refused_rather_than_treated_as_no_features() {
        let err = parse("   ").unwrap_err().to_string();
        assert!(err.contains("driver_features is empty"), "{err}");
        assert!(err.contains("omit the key"), "{err}");
    }

    #[test]
    fn short_names_map_to_what_ethtool_k_reports() {
        assert_eq!(reported_name("sg"), "scatter-gather");
        assert_eq!(reported_name("gso"), "generic-segmentation-offload");
        // Not in the table: used as reported.
        assert_eq!(reported_name("rx-fcs"), "rx-fcs");
    }

    #[test]
    fn the_report_keeps_the_parent_value_and_the_fixed_flag() {
        let r = parse_report(REPORT);
        assert_eq!(r["scatter-gather"], ("on".to_string(), false));
        assert_eq!(r["large-receive-offload"], ("off".to_string(), true));
        assert_eq!(r["tx-checksum-ipv4"], ("off".to_string(), true));
        assert!(!r.contains_key("Features for eth9"));
    }

    /// One `ethtool -K` with every word that really needs changing, and a `Change` row per
    /// word carrying the value the NIC had — the record `down` replays.
    #[test]
    fn only_features_that_differ_are_set_and_recorded() {
        let mut sys = ethtool_sys();
        let mut warnings = Vec::new();
        let changes =
            apply_to_wire(&mut sys, "eth9", "sg off tso off gso on", &mut warnings).unwrap();
        assert_eq!(
            changes,
            [
                Change {
                    wire: "eth9".into(),
                    feature: "sg".into(),
                    prior: "on".into()
                },
                Change {
                    wire: "eth9".into(),
                    feature: "tso".into(),
                    prior: "on".into()
                },
            ],
            "gso is already on: not set, not recorded"
        );
        assert_eq!(
            sys.calls,
            ["ethtool -k eth9", "ethtool -K eth9 sg off tso off"]
        );
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_wire_already_at_the_declared_values_is_not_touched_at_all() {
        let mut sys = ethtool_sys();
        let mut warnings = Vec::new();
        let changes = apply_to_wire(&mut sys, "eth9", "sg on lro off", &mut warnings).unwrap();
        assert!(changes.is_empty(), "{changes:?}");
        assert_eq!(sys.calls, ["ethtool -k eth9"], "no `ethtool -K` at all");
    }

    /// `[fixed]` is the driver's answer, not an error: warn, skip, keep going (ruling 4).
    #[test]
    fn a_fixed_feature_warns_and_is_skipped_never_refused() {
        let mut sys = ethtool_sys();
        let mut warnings = Vec::new();
        let changes = apply_to_wire(&mut sys, "eth9", "lro on sg off", &mut warnings).unwrap();
        assert_eq!(changes.len(), 1, "only sg: {changes:?}");
        assert_eq!(sys.calls, ["ethtool -k eth9", "ethtool -K eth9 sg off"]);
        assert_eq!(
            warnings,
            ["WARNING: eth9: driver_features 'lro' is fixed by the driver at off — left alone"]
        );
    }

    /// A value cfab cannot READ is a value it cannot put back, so it is not set either.
    #[test]
    fn a_feature_the_driver_does_not_report_warns_and_is_skipped() {
        let mut sys = ethtool_sys();
        let mut warnings = Vec::new();
        let changes = apply_to_wire(&mut sys, "eth9", "ntuple off", &mut warnings).unwrap();
        assert!(changes.is_empty(), "{changes:?}");
        assert_eq!(sys.calls, ["ethtool -k eth9"]);
        assert_eq!(
            warnings,
            ["WARNING: eth9: driver_features 'ntuple' is not reported by `ethtool -k` — skipped"]
        );
    }

    #[test]
    fn the_records_round_trip() {
        let drivers = vec![
            ("eth9".to_string(), "r8152".to_string()),
            ("eth1".to_string(), "igb".to_string()),
        ];
        let changes = vec![Change {
            wire: "eth9".into(),
            feature: "sg".into(),
            prior: "on".into(),
        }];
        let mut sys = MockSys::default()
            .file(&drivers_path("/run/cfab"), &render_drivers(&drivers))
            .file(&changed_path("/run/cfab"), &render_changes(&changes));
        assert_eq!(
            recorded_driver(&mut sys, "/run/cfab", "eth9"),
            Some("r8152".to_string())
        );
        assert_eq!(recorded_driver(&mut sys, "/run/cfab", "eth0"), None);
        assert_eq!(recorded_changes(&mut sys, "/run/cfab"), changes);
    }

    /// A run dir with no record (an older version, a wiped dir) is not an error: nothing to
    /// restore and nothing to compare, exactly as `mark.backend` reads.
    #[test]
    fn a_missing_record_is_empty_not_an_error() {
        let mut sys = MockSys::default();
        assert_eq!(recorded_driver(&mut sys, "/run/cfab", "eth9"), None);
        assert!(recorded_changes(&mut sys, "/run/cfab").is_empty());
    }

    #[test]
    fn the_driver_is_read_from_ethtool_i() {
        let mut sys = MockSys::default().on_stdout(
            &["ethtool", "-i", "eth9"],
            "driver: r8152\nversion: 6.12.0\n",
        );
        assert_eq!(driver_of(&mut sys, "eth9").unwrap(), "r8152");
    }
}
