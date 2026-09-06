//! The fallback control-egress ceiling rendered for `iptables-legacy-restore`, for the one
//! member class that can need it: a leaf on a kernel without nf_tables (the Synology NAS,
//! Linux 4.4 — no nf_tables, no `-j CLASSIFY`, no `-j DSCP`, no `-m comment`; `-m limit` is
//! there). Ceiling only: the bulk DSCP clamp has no target on that kernel and is skipped,
//! which `status` says out loud.
//!
//! The chain name IS the label — `-m comment` is absent on the NAS, so `cfab-ceil-<zone>`
//! carries what the nft render puts in a comment. Pure text out, like `emit::mark`; the
//! numbers come from `emit::mark::ceilings`, so both backends police the same derived rate.

use crate::derive::View;
use crate::emit::mark;
use crate::error::Result;

/// The chain hung off mangle `OUTPUT`, jumping to one ceiling chain per fallback bond.
pub const OUT_CHAIN: &str = "cfab-out";

/// The per-zone ceiling chain. Every chain cfab owns in the mangle table starts with `cfab-`,
/// which is what teardown and the drift readback filter on — by exact name, never by pattern
/// over foreign chains.
pub fn ceil_chain(zone: &str) -> String {
    format!("cfab-ceil-{zone}")
}

/// Which backend applies the mark state on this member. Recorded at `up` in
/// `<run_dir>/mark.backend` so `status` and `down` never re-probe the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Nft,
    IptablesLegacy,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Nft => "nft",
            Backend::IptablesLegacy => "iptables-legacy",
        }
    }

    /// The one spelling of this condition, shared by `up` and `status` (a `status` reason
    /// line, never a state change: the ceiling is there either way, and the missing bulk clamp
    /// is a known, printed degradation rather than a link-down).
    pub fn status_line(self) -> &'static str {
        match self {
            Backend::Nft => "mark: nft",
            Backend::IptablesLegacy => {
                "mark: iptables-legacy (ceiling only; bulk DSCP clamp unavailable on this kernel)"
            }
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "nft" => Some(Backend::Nft),
            "iptables-legacy" => Some(Backend::IptablesLegacy),
            _ => None,
        }
    }
}

/// `<run_dir>/mark.backend`, the record `up` writes.
pub fn record_path(run_dir: &str) -> String {
    format!("{run_dir}/mark.backend")
}

/// The recorded backend, or `None` when there is no record to read (a run dir from an older
/// version, or one wiped under a running fabric). Callers decide what "no record" means for
/// them — `status` reads it as nft (what every 0.3.0 member ran), `down` attempts both.
pub fn recorded(sys: &mut dyn crate::sys::Sys, run_dir: &str) -> Option<Backend> {
    sys.read(&record_path(run_dir))
        .ok()
        .as_deref()
        .and_then(Backend::parse)
}

/// The `iptables-legacy-restore --noflush` input for this member's ceilings.
///
/// `--noflush` does not flush an existing user chain — a `:name - [0:0]` line creates it if
/// missing and otherwise leaves its rules in place — so without the explicit `-F` lines every
/// re-`up` would append a second copy of every rule.
pub fn generate(view: &View) -> Result<String> {
    let ceilings = mark::ceilings(view);
    let mut out = String::new();
    out.push_str("*mangle\n");
    out.push_str(&format!(":{OUT_CHAIN} - [0:0]\n"));
    for ce in &ceilings {
        out.push_str(&format!(":{} - [0:0]\n", ceil_chain(&ce.zone)));
    }
    out.push_str(&format!("-F {OUT_CHAIN}\n"));
    for ce in &ceilings {
        out.push_str(&format!("-F {}\n", ceil_chain(&ce.zone)));
    }
    // THE JUMP CARRIES THE MATCH. A `cfab-ceil-*` chain ends in an unconditional `-j DROP`
    // (the canonical iptables rate-limit shape: under the limit the packet RETURNs, over it
    // the last rule drops it), so anything that ENTERS the chain and is not passed by the
    // limit is dropped. A bare `-A cfab-out -j cfab-ceil-<zone>` therefore sends every packet
    // this member sends into a drop chain — measured live on pve3 at gate G3 (2026-09-06):
    // the leaf came up FAILED 0/18 with 746 drops and the engine logging EPERM on every
    // interface. OSPF (protocol 89) on the bond only, exactly as the nft render selects: a
    // fallback leg carries no BFD by construction, and policing the zone's island segments
    // would police the fabric this protects.
    for ce in &ceilings {
        out.push_str(&format!(
            "-A {OUT_CHAIN} -o {} -p 89 -j {}\n",
            ce.ifname,
            ceil_chain(&ce.zone)
        ));
    }
    for ce in &ceilings {
        let chain = ceil_chain(&ce.zone);
        // A packet in this chain is by construction OSPF on that bond. Under the rate it
        // RETURNs to `cfab-out`; over it the chain's final DROP counts it — that counter is
        // what `status` reads.
        out.push_str(&format!(
            "-A {chain} -m limit --limit {}/second --limit-burst {} -j RETURN\n",
            ce.rate_pps, ce.burst_pkts
        ));
        out.push_str(&format!("-A {chain} -j DROP\n"));
    }
    out.push_str("COMMIT\n");
    Ok(out)
}

/// The `cfab-` lines of an `iptables-legacy-save -t mangle` dump: the live half of the drift
/// check, and the only lines teardown enumerates chain names from. Foreign chains and the
/// table's built-in policy lines are not ours and are not read.
pub fn ours(save_output: &str) -> String {
    let mut out = String::new();
    for l in save_output.lines() {
        if l.starts_with(":cfab-") || l.starts_with("-A cfab-") {
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

/// Every `cfab-*` chain name present in an `iptables-legacy-save -t mangle` dump, in dump
/// order. Exact names, for a teardown or a stale-chain sweep that must never act on a chain
/// it did not read.
pub fn chains_in(save_output: &str) -> Vec<String> {
    save_output
        .lines()
        .filter_map(|l| l.strip_prefix(":cfab-"))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|name| format!("cfab-{name}"))
        .collect()
}

/// The DROP counter of one zone's ceiling chain from `iptables-legacy-save -c -t mangle`
/// (`[pkts:bytes] -A cfab-ceil-<zone> -j DROP`), or `None` when the rule is not in the dump.
pub fn drop_packets(save_c_output: &str, zone: &str) -> Option<u64> {
    let tail = format!("-A {} -j DROP", ceil_chain(zone));
    save_c_output.lines().find_map(|l| {
        let rest = l.strip_prefix('[')?;
        let (counters, rule) = rest.split_once(']')?;
        (rule.trim() == tail)
            .then(|| counters.split(':').next())
            .flatten()
            .and_then(|p| p.parse().ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::model::Fabric;

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    /// The whole restore input for the shipped example, byte for byte: the same three
    /// ceilings, the same derived rates as the nft render, no bulk rows, and every chain
    /// flushed before it is filled.
    #[test]
    fn the_restore_input_for_the_example_declaration() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        assert_eq!(
            generate(&view).unwrap(),
            "*mangle\n\
             :cfab-out - [0:0]\n\
             :cfab-ceil-storage - [0:0]\n\
             :cfab-ceil-cluster - [0:0]\n\
             :cfab-ceil-mgmt - [0:0]\n\
             -F cfab-out\n\
             -F cfab-ceil-storage\n\
             -F cfab-ceil-cluster\n\
             -F cfab-ceil-mgmt\n\
             -A cfab-out -o cfab-st-fb -p 89 -j cfab-ceil-storage\n\
             -A cfab-out -o cfab-cl-fb -p 89 -j cfab-ceil-cluster\n\
             -A cfab-out -o cfab-mg-fb -p 89 -j cfab-ceil-mgmt\n\
             -A cfab-ceil-storage -m limit --limit 80/second --limit-burst 160 -j RETURN\n\
             -A cfab-ceil-storage -j DROP\n\
             -A cfab-ceil-cluster -m limit --limit 80/second --limit-burst 160 -j RETURN\n\
             -A cfab-ceil-cluster -j DROP\n\
             -A cfab-ceil-mgmt -m limit --limit 80/second --limit-burst 160 -j RETURN\n\
             -A cfab-ceil-mgmt -j DROP\n\
             COMMIT\n"
        );
    }

    /// Both backends police the identical derived rate — the ceiling is a property of the
    /// declaration, never of the kernel that happens to enforce it.
    #[test]
    fn both_backends_render_the_same_rate_and_burst() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let ipt = generate(&view).unwrap();
        for c in mark::ceilings(&view) {
            assert!(
                ipt.contains(&format!(
                    "-A cfab-out -o {} -p 89 -j cfab-ceil-{}\n",
                    c.ifname, c.zone
                )) && ipt.contains(&format!(
                    "-A cfab-ceil-{} -m limit --limit {}/second --limit-burst {} -j RETURN\n\
                     -A cfab-ceil-{} -j DROP\n",
                    c.zone, c.rate_pps, c.burst_pkts, c.zone
                )),
                "{ipt}"
            );
        }
    }

    /// No fallback row, no ceiling: the input still loads (an empty `cfab-out`, flushed), so a
    /// re-`up` on a member that lost its fallback rows removes the old rules rather than
    /// leaving them resident.
    #[test]
    fn a_member_with_no_fallback_row_renders_an_empty_but_flushing_ruleset() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap()
                .replace("cfab-st-fb  any storage 9 300 fallback 5000\n", "")
                .replace("cfab-cl-fb  any cluster 9 301 fallback 5000\n", "")
                .replace("cfab-mg-fb  any mgmt    9 302 fallback 5000\n", "");
        let f = Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap();
        let view = View::new(&f, "pve3-tb").unwrap();
        assert_eq!(
            generate(&view).unwrap(),
            "*mangle\n:cfab-out - [0:0]\n-F cfab-out\nCOMMIT\n"
        );
    }

    /// Nothing in the render marks: no DSCP, no PCP, no `-m comment` (absent on the NAS —
    /// the chain name is the label).
    #[test]
    fn the_render_marks_nothing_and_uses_no_comment_match() {
        let f = fabric();
        let view = View::new(&f, "pve3-tb").unwrap();
        let out = generate(&view).unwrap();
        for absent in ["DSCP", "CLASSIFY", "-m comment", "TOS", "--set-"] {
            assert!(!out.contains(absent), "{absent} in the render: {out}");
        }
    }

    /// The class of defect measured live at G3 (2026-09-06, pve3): a `cfab-ceil-*` chain ends
    /// in an unconditional DROP, so whatever ENTERS it and is not passed by the limit is
    /// dropped. Every jump into one must therefore be selective, and the only unconditional
    /// rule anywhere in these chains is that final DROP. Asserted on the rendered text of a
    /// declaration with three ceilings, and on a leaf and a host alike.
    #[test]
    fn every_jump_into_a_ceiling_chain_is_selective_and_only_the_final_drop_is_unconditional() {
        let f = fabric();
        for member in ["pve1-tb", "pve3-tb"] {
            let view = View::new(&f, member).unwrap();
            let out = generate(&view).unwrap();
            let jumps: Vec<&str> = out
                .lines()
                .filter(|l| l.starts_with("-A cfab-out "))
                .collect();
            assert_eq!(jumps.len(), mark::ceilings(&view).len(), "{out}");
            for j in &jumps {
                let w: Vec<&str> = j.split_whitespace().collect();
                // `-A cfab-out -o <bond> -p 89 -j cfab-ceil-<zone>` — never a bare jump.
                assert!(
                    w.contains(&"-o") && w.contains(&"-p") && w.contains(&"89"),
                    "{member}: an unconditional jump into a drop chain: {j}"
                );
            }
            for l in out.lines().filter(|l| l.starts_with("-A cfab-ceil-")) {
                let unconditional =
                    !l.contains(" -m ") && !l.contains(" -o ") && !l.contains(" -p ");
                assert_eq!(
                    unconditional,
                    l.ends_with(" -j DROP"),
                    "{member}: the only unconditional rule in a ceiling chain is its final \
                     DROP: {l}"
                );
            }
        }
    }

    #[test]
    fn the_readback_filter_keeps_only_our_chains_and_rules() {
        let save = "# Generated\n*mangle\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [7:9]\n\
                    :DOCKER-USER - [0:0]\n:cfab-out - [0:0]\n:cfab-ceil-storage - [0:0]\n\
                    -A OUTPUT -j cfab-out\n-A DOCKER-USER -j RETURN\n\
                    -A cfab-out -j cfab-ceil-storage\n-A cfab-ceil-storage -j DROP\nCOMMIT\n";
        assert_eq!(
            ours(save),
            ":cfab-out - [0:0]\n:cfab-ceil-storage - [0:0]\n\
             -A cfab-out -j cfab-ceil-storage\n-A cfab-ceil-storage -j DROP\n"
        );
        assert_eq!(chains_in(save), vec!["cfab-out", "cfab-ceil-storage"]);
    }

    /// The DROP rule's own counter is the drop count (`status`), read by exact rule text so a
    /// RETURN counter or a foreign chain can never be mistaken for it.
    #[test]
    fn the_drop_counter_is_read_from_the_chains_last_rule() {
        let save = "*mangle\n:cfab-ceil-storage - [0:0]\n\
                    [6:312] -A cfab-ceil-storage -o cfab-st-fb -p 89 -m limit --limit 80/second \
                    --limit-burst 160 -j RETURN\n\
                    [35:1820] -A cfab-ceil-storage -j DROP\n\
                    [99:9] -A cfab-ceil-cluster -j RETURN\nCOMMIT\n";
        assert_eq!(drop_packets(save, "storage"), Some(35));
        assert_eq!(drop_packets(save, "cluster"), None);
        assert_eq!(drop_packets(save, "mgmt"), None);
    }
}
