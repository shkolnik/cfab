//! Parser for the LITERAL declarations in `fabric.conf`.
//!
//! The file is shell syntax by design — `sh` can source it, so shell tooling can share the
//! declaration — and this parser reads only what is data: top-level `KEY=value` lines whose
//! value is a literal — a bare word, or a double-quoted (possibly multi-line) string.
//! Everything the shell would *compute* (`$(…)`, `${…}`, function definitions, control flow)
//! is skipped and re-derived by the typed model instead. Trailing ` # comment` after a bare
//! value is stripped, as a shell would.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// Raw `KEY=value` literals in file order, before any typing or validation.
#[derive(Debug, Default)]
pub struct RawConfig {
    values: BTreeMap<String, String>,
    /// Keys seen in the file, in order (for unknown-key reporting).
    keys_in_order: Vec<String>,
}

impl RawConfig {
    pub fn parse(text: &str) -> Result<RawConfig> {
        let mut cfg = RawConfig::default();
        let mut lines = text.lines().enumerate().peekable();
        while let Some((lineno, line)) = lines.next() {
            let Some((key, rest)) = split_assignment(line) else {
                continue;
            };
            if let Some(quoted) = rest.strip_prefix('"') {
                // Double-quoted value; may span lines until the closing quote.
                let mut value = String::new();
                if let Some(end) = find_close_quote(quoted) {
                    value.push_str(&quoted[..end]);
                } else {
                    value.push_str(quoted);
                    let mut closed = false;
                    for (_, cont) in lines.by_ref() {
                        value.push('\n');
                        if let Some(end) = find_close_quote(cont) {
                            value.push_str(&cont[..end]);
                            closed = true;
                            break;
                        }
                        value.push_str(cont);
                    }
                    if !closed {
                        return Err(Error::config(format!(
                            "line {}: unterminated quote in {key}",
                            lineno + 1
                        )));
                    }
                }
                if value.contains('$') {
                    continue; // computed by the shell (e.g. CFAB_HOST) — the model derives it
                }
                cfg.insert(key, value);
            } else {
                // Bare value: first word; a trailing comment is not part of it.
                let value = rest.split_whitespace().next().unwrap_or("");
                if value.contains('$') || value.contains('`') {
                    continue; // computed (e.g. CFAB_HOST=${CFAB_HOST:-$(hostname)})
                }
                cfg.insert(key, value.to_string());
            }
        }
        Ok(cfg)
    }

    fn insert(&mut self, key: &str, value: String) {
        if !self.values.contains_key(key) {
            self.keys_in_order.push(key.to_string());
        }
        self.values.insert(key.to_string(), value);
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// A required key: absent = the declaration is broken, fail loud.
    pub fn require(&self, key: &str) -> Result<&str> {
        self.get(key)
            .ok_or_else(|| Error::config(format!("{key} is not declared (or is not a literal)")))
    }

    /// Keys present in the file that the model did not consume — surfaced as a warning so a
    /// literal added for shell tooling is never silently ignored by the binary.
    pub fn unconsumed(&self, consumed: &[&str]) -> Vec<&str> {
        self.keys_in_order
            .iter()
            .map(String::as_str)
            .filter(|k| !consumed.contains(k))
            .collect()
    }
}

/// `KEY=rest` at column 0 with a shell-identifier uppercase key, else None.
fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    let key = &line[..eq];
    if key.is_empty()
        || !key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        || !key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    Some((key, &line[eq + 1..]))
}

/// Position of the closing `"` (no escape handling: fabric.conf's tables never escape quotes).
fn find_close_quote(s: &str) -> Option<usize> {
    s.find('"')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_value_with_trailing_comment() {
        let c = RawConfig::parse("PCP_CTRL=6                   # OSPF/BFD control\n").unwrap();
        assert_eq!(c.get("PCP_CTRL"), Some("6"));
    }

    #[test]
    fn quoted_multiline_table() {
        let c = RawConfig::parse("MEMBER_TABLE=\"\na 1 host e:1 -:0 -:0\n\"\nX=y\n").unwrap();
        assert_eq!(c.get("MEMBER_TABLE"), Some("\na 1 host e:1 -:0 -:0\n"));
        assert_eq!(c.get("X"), Some("y"));
    }

    #[test]
    fn computed_values_are_skipped() {
        let text = "CFAB_HOST=${CFAB_HOST:-$(hostname)}\nFABRIC_MEMBERS=\"$(member_rows)\"\n";
        let c = RawConfig::parse(text).unwrap();
        assert_eq!(c.get("CFAB_HOST"), None);
        assert_eq!(c.get("FABRIC_MEMBERS"), None);
    }

    #[test]
    fn functions_and_control_flow_are_skipped() {
        let text = "member_rows() { printf '%s\\n' \"$MEMBER_TABLE\" | awk 'NF==6'; }\n\
                    if [ -d /run ]; then svc_ctl() { systemctl \"$1\" svc; }\nfi\nA=1\n";
        let c = RawConfig::parse(text).unwrap();
        assert_eq!(c.get("A"), Some("1"));
        assert_eq!(c.unconsumed(&["A"]), Vec::<&str>::new());
    }

    #[test]
    fn unterminated_quote_fails_loud() {
        assert!(RawConfig::parse("T=\"abc\ndef\n").is_err());
    }

    #[test]
    fn unconsumed_keys_are_reported_in_file_order() {
        let c = RawConfig::parse("B=1\nA=2\n").unwrap();
        assert_eq!(c.unconsumed(&[]), vec!["B", "A"]);
    }
}
