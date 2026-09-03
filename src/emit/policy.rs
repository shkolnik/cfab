//! The nft forward policy (table inet cfab-fwd) derived from the class table. Default-deny:
//! only FORWARD_ALLOW pairs pass, the admin interface never transits, every drop is counted.
//! Pure text out.

use crate::derive::View;
use crate::error::Result;

pub fn generate(view: &View) -> Result<String> {
    let f = view.fabric;
    let mut out = String::new();
    out.push_str("table inet cfab-fwd\n");
    out.push_str("delete table inet cfab-fwd\n");
    out.push_str("table inet cfab-fwd {\n");
    match view.admin_if() {
        Some(a) => out.push_str(&format!(
            "  set admin {{ type ifname; elements = {{ \"{a}\" }} }}\n"
        )),
        None => out.push_str("  set admin { type ifname; }\n"),
    }
    for z in &f.zones {
        let mut ifs: Vec<String> = view
            .zone_ifs(&z.name)
            .into_iter()
            .map(|i| format!("\"{i}\""))
            .collect();
        if z.name == "storage" && f.vrrp_gw {
            ifs.push(format!("\"{}\"", f.vrrp_if));
        }
        if ifs.is_empty() {
            out.push_str(&format!("  set {} {{ type ifname; }}\n", z.name));
        } else {
            out.push_str(&format!(
                "  set {} {{ type ifname; elements = {{ {} }} }}\n",
                z.name,
                ifs.join(",")
            ));
        }
    }
    out.push_str(
        "  chain forward {\n\
         \x20   type filter hook forward priority filter; policy drop;\n\
         \x20   iifname @admin counter drop comment \"admin-in\"\n\
         \x20   oifname @admin counter drop comment \"admin-out\"\n\
         \x20   ct state invalid counter comment \"ct-invalid-seen\"\n\
         \x20   ct state established,related accept comment \"return-of-allowed\"\n",
    );
    for (from, to) in &f.forward_allow {
        // Zone existence is already validated at parse; emit in declaration order.
        out.push_str(&format!(
            "    iifname @{from} oifname @{to} counter accept comment \"allow-{from}-{to}\"\n"
        ));
    }
    out.push_str("    counter comment \"default-deny\"\n  }\n}\n");
    Ok(out)
}
