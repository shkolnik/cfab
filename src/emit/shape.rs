//! The floor+borrow HTB tree for ONE physical NIC. Pure derivation from the model + two
//! observations supplied by the caller (a measured cap, the up-set).
//!
//! Model: one HTB class per DSCP band under a root class capped at the link. rate = the
//! band's floor (a MINIMUM guarantee), ceil = link so idle bands lend. The bulk (cs0) band
//! gets its full floor only on the zone's EFFECTIVE primary (lowest-cost UP wire); elsewhere
//! a 1mbit token. H = L − Σfloors; H<0 = oversubscribed → priority-degrade (band-0 floors
//! protected first). L prefers a MEASURED capacity over the declared table and is scaled to
//! 0.97: shaping at line rate leaves a standing queue (measured).

use crate::derive::View;
use crate::error::{Error, Result};
use crate::model::Dscp;

pub const L_EFF_PCT: u64 = 97;

/// Where L came from — using the declared number is loudly flagged since H computed from it
/// may be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSource {
    Measured,
    Declared,
}

/// How a band's traffic is classified on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BandClass {
    /// A DSCP band (flower ip_tos match on 802.1Q frames); cs0 is the htb default (no filter).
    Dscp(Dscp),
    /// The untagged admin band on the admin NIC (flower `protocol ip` = NOT 802.1Q-tagged).
    Untagged,
}

#[derive(Debug, Clone)]
pub struct Band {
    pub minor: u32,
    pub prio: u32,
    pub floor: u64,
    pub eff: u64,
    pub class: BandClass,
    pub is_default: bool,
    /// The zone name, or "admin".
    pub label: String,
    /// For a demoted bulk band: the zone's effective primary this derivation saw.
    pub effective_primary: Option<String>,
}

#[derive(Debug)]
pub struct Derivation {
    pub dev: String,
    pub l_raw: u64,
    pub l: u64,
    pub source: LinkSource,
    pub bands: Vec<Band>,
    pub default_minor: u32,
    pub sum_eff: u64,
    pub warnings: Vec<String>,
}

/// A zone's EFFECTIVE primary = the lowest-OSPF-cost wire carrying it that is currently UP.
/// Cost ties break on wire name — costs are distinct per zone in any sane declaration; the
/// tiebreak just keeps the choice deterministic.
fn eff_primary_dev(view: &View, zone: &str, up: &dyn Fn(&str) -> bool) -> Option<String> {
    let mut rows: Vec<(u32, String)> = view
        .class_rows()
        .into_iter()
        .filter(|r| r.zone == zone)
        .map(|r| (r.ospf_cost, r.wire))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    rows.into_iter().find(|(_, w)| up(w)).map(|(_, w)| w)
}

/// Derive the tree. `measured_cap` = the cap file's value if present and valid (caller I/O);
/// `up` answers "is this wire carrying traffic right now" (authoritative up-set, carrier, or
/// assume-up when unobservable — never demote on missing information).
pub fn derive(
    view: &View,
    dev: &str,
    measured_cap: Option<u64>,
    up: &dyn Fn(&str) -> bool,
) -> Result<Derivation> {
    let mut warnings = Vec::new();
    let (l_raw, source) = match measured_cap {
        Some(v) if v > 0 => (v, LinkSource::Measured),
        _ => {
            let declared = view.link_speed(dev)? as u64;
            warnings.push(format!(
                "gen-shape: WARNING dev '{dev}' using DECLARED link_speed {declared} Mb/s \
                 (UNMEASURED — run `cfab measure-cap`; H may be wrong)"
            ));
            (declared, LinkSource::Declared)
        }
    };
    let l = l_raw * L_EFF_PCT / 100;

    // Zones whose sub-interfaces sit on this wire, unique + sorted.
    let mut zones: Vec<String> = view
        .class_rows()
        .into_iter()
        .filter(|r| r.wire == dev)
        .map(|r| r.zone)
        .collect();
    zones.sort();
    zones.dedup();
    if zones.is_empty() {
        return Err(Error::config(format!(
            "gen-shape: no CLASS_TABLE zone on wire '{dev}'"
        )));
    }

    // One band per zone, ordered by (band, name); the admin NIC gets the extra untagged band.
    let is_admin = view.admin_if() == Some(dev);
    let mut order: Vec<(u32, String)> = zones
        .iter()
        .map(|z| Ok((view.fabric.zone(z)?.band, z.clone())))
        .collect::<Result<Vec<_>>>()?;
    if is_admin {
        order.push((view.fabric.admin_band, "admin".to_string()));
    }
    order.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut bands = Vec::new();
    let mut default_minor = None;
    let mut sum_floor: u64 = 0;
    for (rank, (band, label)) in order.into_iter().enumerate() {
        let minor = (rank as u32 + 1) * 10;
        let (class, mut floor) = if label == "admin" {
            (BandClass::Untagged, view.fabric.admin_floor_mbit as u64)
        } else {
            let z = view.fabric.zone(&label)?;
            (BandClass::Dscp(z.dscp), z.floor_mbit as u64)
        };
        let is_default = class == BandClass::Dscp(Dscp::Cs0);
        let mut effective_primary = None;
        if is_default {
            default_minor = Some(minor);
            // Bulk: full floor only on the zone's effective primary; else a 1mbit token
            // (the real floor re-derives HERE when this dev becomes the effective primary).
            let ep = eff_primary_dev(view, &label, up);
            if ep.as_deref() != Some(dev) {
                floor = 1;
            }
            effective_primary = ep;
        }
        sum_floor += floor;
        bands.push(Band {
            minor,
            prio: band,
            floor,
            eff: floor,
            class,
            is_default,
            label,
            effective_primary,
        });
    }
    let default_minor = default_minor.ok_or_else(|| {
        Error::config(format!(
            "gen-shape: no default (cs0) band on dev '{dev}' — cannot pick htb default"
        ))
    })?;

    // Priority-degrade: protected = band-0 floors; oversubscribed → scale band>=1 to the
    // leftover; if even protected alone doesn't fit, scale EVERYTHING and warn HARD.
    let protected_sum: u64 = bands.iter().filter(|b| b.prio == 0).map(|b| b.floor).sum();
    let degradable_sum: u64 = bands.iter().filter(|b| b.prio != 0).map(|b| b.floor).sum();
    let degraded = sum_floor > l;
    let hard_warn = degraded && protected_sum > l;
    if degraded {
        if hard_warn {
            warnings.push(format!(
                "gen-shape: HARD WARNING dev '{dev}' oversubscribed AND control floor UNMET: \
                 protected(band0) {protected_sum} > L {l} Mb/s (Sigma-floors {sum_floor}); ALL \
                 floors scaled by L/Sigma-floors — this is a real degraded state, not hidden"
            ));
        } else {
            warnings.push(format!(
                "gen-shape: WARNING dev '{dev}' oversubscribed: Sigma-floors {sum_floor} > L {l} \
                 Mb/s; control (band0) floor {protected_sum} protected in full, band>=1 floors \
                 scaled to the {l}-{protected_sum} leftover"
            ));
        }
        for b in &mut bands {
            b.eff = if hard_warn {
                b.floor * l / sum_floor
            } else if b.prio == 0 {
                b.floor
            } else {
                (b.floor * (l - protected_sum))
                    .checked_div(degradable_sum)
                    .unwrap_or(0)
            };
        }
    }
    let sum_eff = bands.iter().map(|b| b.eff).sum();
    Ok(Derivation {
        dev: dev.to_string(),
        l_raw,
        l,
        source,
        bands,
        default_minor,
        sum_eff,
        warnings,
    })
}

/// HTB quantum: the rate/r2q default exceeds HTB's 200 kB sanity bound above ~1.6 Gb/s, so pin
/// 60000 at high rate; a small floor keeps one MTU.
fn quantum_for(rate: u64) -> u64 {
    if rate >= 1000 { 60000 } else { 1514 }
}

/// HTB rejects "rate 0mbit"; 1kbit is the smallest accepted nonzero rate (floor 0 = pure
/// borrower — still needs SOME rate so the class exists and can borrow up to ceil).
fn rate_str(rate: u64) -> String {
    if rate >= 1 {
        format!("{rate}mbit")
    } else {
        "1kbit".to_string()
    }
}

impl Derivation {
    /// The human derivation (default mode).
    pub fn render_derive(&self, view: &View) -> String {
        let mut out = String::new();
        match self.source {
            LinkSource::Measured => out.push_str(&format!(
                "gen-shape derive: dev {}, link L = {} Mb/s = 0.{} × {} (measured)\n",
                self.dev, self.l, L_EFF_PCT, self.l_raw
            )),
            LinkSource::Declared => out.push_str(&format!(
                "gen-shape derive: dev {}, link L = {} Mb/s = 0.{} × {} (declared for {}:{}, UNMEASURED)\n",
                self.dev, self.l, L_EFF_PCT, self.l_raw, view.member.name, self.dev
            )),
        }
        out.push_str(
            "  bands (one HTB class per DSCP band; rate=effective floor guarantee, ceil=L so idle bands lend):\n",
        );
        for b in &self.bands {
            let (tag, why) = match &b.class {
                BandClass::Dscp(d) if b.is_default => {
                    let why = if b.effective_primary.as_deref() == Some(self.dev.as_str()) {
                        format!(
                            "{} effective-primary on {} -> full floor",
                            b.label, self.dev
                        )
                    } else {
                        format!(
                            "{} not effective-primary on {} -> 1mbit token (real floor re-derives on failover)",
                            b.label, self.dev
                        )
                    };
                    let _ = d;
                    ("default/bulk, no filter (htb default)".to_string(), why)
                }
                BandClass::Untagged => (
                    "filtered on NOT 802.1Q-tagged".to_string(),
                    format!(
                        "untagged admin traffic (SSH/GUI) on admin NIC {} -> full floor",
                        self.dev
                    ),
                ),
                BandClass::Dscp(d) => (
                    format!("filtered on {} / tos {}", d, d.tos()),
                    format!(
                        "{} marked traffic ({} on every sub-if, incl. control) -> full floor",
                        b.label, d
                    ),
                ),
            };
            if b.eff != b.floor {
                out.push_str(&format!(
                    "    1:{}  {}  prio {}  floor {} -> {} Mb/s (degraded, factor {}/{})  [{}]  — {}\n",
                    b.minor, b.label, b.prio, b.floor, b.eff, b.eff, b.floor, tag, why
                ));
            } else {
                out.push_str(&format!(
                    "    1:{}  {}  prio {}  floor {} Mb/s  [{}]  — {}\n",
                    b.minor, b.label, b.prio, b.floor, tag, why
                ));
            }
        }
        out.push_str(&format!(
            "H = L - Sum(effective) = {} - {} = {} Mb/s  (borrowable headroom; H<0 impossible post-degrade)\n",
            self.l,
            self.sum_eff,
            self.l as i64 - self.sum_eff as i64
        ));
        out
    }

    /// The tc program (--tc): text form, for human eyes and diffs. The daemon executes
    /// `tc_argv` instead — same commands, no shell.
    pub fn render_tc(&self) -> String {
        self.tc_argv()
            .into_iter()
            .map(|(line, ignore_err)| {
                if ignore_err {
                    format!("{} 2>/dev/null || true\n", line.join(" "))
                } else {
                    format!("{}\n", line.join(" "))
                }
            })
            .collect()
    }

    /// The tc program as argv vectors: (command, ignore-error). No shell parsing anywhere.
    pub fn tc_argv(&self) -> Vec<(Vec<String>, bool)> {
        let dev = &self.dev;
        let l = self.l;
        let mut cmds: Vec<(Vec<String>, bool)> = Vec::new();
        let split = |s: String| s.split(' ').map(str::to_string).collect::<Vec<_>>();
        // del+add (not replace): HTB refuses to change r2q/quantum on an existing root.
        cmds.push((split(format!("tc qdisc del dev {dev} root")), true));
        cmds.push((
            split(format!(
                "tc qdisc add dev {dev} root handle 1: htb default {}",
                self.default_minor
            )),
            false,
        ));
        cmds.push((
            split(format!(
                "tc class add dev {dev} parent 1: classid 1:1 htb rate {l}mbit ceil {l}mbit burst 64k quantum {}",
                quantum_for(l)
            )),
            false,
        ));
        for b in &self.bands {
            cmds.push((
                split(format!(
                    "tc class add dev {dev} parent 1:1 classid 1:{} htb rate {} ceil {l}mbit prio {} burst 64k quantum {}",
                    b.minor,
                    rate_str(b.eff),
                    b.prio,
                    quantum_for(b.eff)
                )),
                false,
            ));
        }
        for b in &self.bands {
            cmds.push((
                split(format!(
                    "tc qdisc add dev {dev} parent 1:{} handle {}: fq_codel",
                    b.minor, b.minor
                )),
                false,
            ));
        }
        // flower (not u32: u32 `match ip tos` silently misses 802.1Q-tagged sub-if frames) per
        // NON-default band; the default band is caught by htb default.
        let mut fprio = 0;
        for b in &self.bands {
            if b.is_default {
                continue;
            }
            fprio += 1;
            match &b.class {
                BandClass::Untagged => cmds.push((
                    // protocol ip matches only frames whose ethertype IS IPv4, i.e. NOT
                    // 802.1Q-tagged — every tagged zone falls through to its own filter.
                    split(format!(
                        "tc filter add dev {dev} parent 1: protocol ip prio {fprio} flower flowid 1:{}",
                        b.minor
                    )),
                    false,
                )),
                BandClass::Dscp(d) => cmds.push((
                    split(format!(
                        "tc filter add dev {dev} parent 1: protocol 802.1Q prio {fprio} flower vlan_ethtype ip ip_tos {} flowid 1:{}",
                        d.tos(),
                        b.minor
                    )),
                    false,
                )),
            }
        }
        cmds
    }

    /// The "classid effective-rate" lines verify diffs (--expect).
    pub fn render_expect(&self) -> String {
        self.bands
            .iter()
            .map(|b| format!("1:{} {}\n", b.minor, b.eff))
            .collect()
    }
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

    #[test]
    fn all_up_full_floor_on_primary() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let d = derive(&v, "eth9", None, &|_| true).unwrap();
        // eth9 carries storage primary (bulk, full floor), cluster+mgmt backups.
        let storage = d.bands.iter().find(|b| b.label == "storage").unwrap();
        assert_eq!(storage.floor, 2000);
        assert!(storage.is_default);
        assert_eq!(d.source, LinkSource::Declared);
        assert_eq!(d.l, 5000 * 97 / 100);
    }

    #[test]
    fn bulk_token_off_primary_and_promotion_on_failover() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        // eth1 is storage's first backup: token while eth9 is up…
        let d = derive(&v, "eth1", None, &|_| true).unwrap();
        assert_eq!(
            d.bands.iter().find(|b| b.label == "storage").unwrap().floor,
            1
        );
        // …full floor once eth9 is down (the failover promotion).
        let d = derive(&v, "eth1", None, &|w| w != "eth9").unwrap();
        assert_eq!(
            d.bands.iter().find(|b| b.label == "storage").unwrap().floor,
            2000
        );
    }

    #[test]
    fn oversubscribed_protects_band0() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        // eth0 measured at 300: floors mgmt 100 + admin 100 + cluster 200 + storage(token)…
        let d = derive(&v, "eth0", Some(300), &|_| true).unwrap();
        let l = 300 * 97 / 100; // 291
        assert!(
            d.warnings.iter().any(|w| w.contains("oversubscribed")),
            "{:?}",
            d.warnings
        );
        let cluster = d.bands.iter().find(|b| b.label == "cluster").unwrap();
        assert_eq!(cluster.eff, cluster.floor, "band-0 floor protected in full");
        assert!(d.sum_eff <= l);
    }

    #[test]
    fn hard_warn_when_even_control_unfit() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let d = derive(&v, "eth0", Some(100), &|_| true).unwrap(); // L=97 < cluster floor 200
        assert!(
            d.warnings.iter().any(|w| w.contains("HARD WARNING")),
            "{:?}",
            d.warnings
        );
        let cluster = d.bands.iter().find(|b| b.label == "cluster").unwrap();
        assert!(cluster.eff < cluster.floor);
    }

    #[test]
    fn admin_band_only_on_admin_nic() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let on_admin = derive(&v, "eth0", None, &|_| true).unwrap();
        assert!(on_admin.bands.iter().any(|b| b.label == "admin"));
        let on_other = derive(&v, "eth9", None, &|_| true).unwrap();
        assert!(!on_other.bands.iter().any(|b| b.label == "admin"));
        // A leaf shapes nothing, but the derivation for its wire still has no admin band.
        let leaf = View::new(&f, "pve3-tb").unwrap();
        let d = derive(&leaf, "eth0", None, &|_| true).unwrap();
        assert!(!d.bands.iter().any(|b| b.label == "admin"));
    }

    #[test]
    fn unknown_wire_fails_loud() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        // The declared-speed lookup fires first: L is picked before the row scan.
        let err = derive(&v, "eth5", None, &|_| true).unwrap_err();
        assert!(
            err.to_string()
                .contains("no declared link speed for pve1-tb:eth5"),
            "{err}"
        );
        // A wire with a measured cap but no CLASS_TABLE rows hits the no-zone error.
        let err = derive(&v, "eth5", Some(1000), &|_| true).unwrap_err();
        assert!(
            err.to_string()
                .contains("no CLASS_TABLE zone on wire 'eth5'"),
            "{err}"
        );
    }
}
