use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use cfab::derive::View;
use cfab::model::{MemberKind, Role};
use cfab::sys::RealSys;
use cfab::{Error, commands, emit, load_fabric};

/// cfab — the per-host runtime of the resilient converged fabric.
///
/// fabric.conf declares the fabric; this tool validates it, generates every artifact from it
/// (nft policy/marking, HTB trees, the routing engine's config tree), applies and verifies the fabric on this
/// member, and tears it down.
#[derive(Parser)]
#[command(version, about, max_term_width = 100)]
struct Cli {
    /// Path to fabric.conf (default: next to the binary, else /etc/cfab/fabric.conf, else
    /// ./fabric.conf)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// The MEMBER_TABLE row to run as (default: $CFAB_HOST, else this kernel's hostname)
    #[arg(long, global = true)]
    host: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse and validate fabric.conf; print the resolved view for this member
    Check,
    /// Print the fabric.conf data model as JSON Schema
    Schema,
    /// Print a generated artifact (pure: reads the declaration, changes nothing)
    Gen {
        #[command(subcommand)]
        artifact: GenArtifact,
    },
    /// Apply the fabric on this member (idempotent; root)
    Up,
    /// Remove everything `up` created: stop the routing engine, sweep its routes, tear down (root)
    Down,
    /// Full health check: posture, drift, convergence. Exit 0 OK / 2 degraded / 1 failed
    Verify {
        /// Seconds to wait for BFD/route convergence before failing
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
    /// Membership-reactive shaping daemon (started by `up` as cfab-shape.service)
    ShapeDaemon {
        /// Quiet-gap debounce after a link event burst, in seconds
        #[arg(long, default_value_t = 0.5)]
        debounce: f64,
    },
    /// One fail-closed forwarding-posture check (run by the cfab-fwd-watchdog timer)
    FwdWatchdog,
    /// Cluster config-sync daemon (started by `up` as cfab-conf-sync.service when clustered)
    ConfSync,
    /// Flood a fabric peer on one NIC and record the wire's measured capacity
    MeasureCap {
        /// The physical NIC (a CLASS_TABLE wire)
        dev: String,
        /// Peer address to flood (a fabric segment address on that wire)
        peer: String,
        /// Flood duration in seconds
        #[arg(default_value_t = 6)]
        secs: u64,
    },
    /// Prove the forward policy in throwaway netnses — and prove the proof bites (root)
    PolicyTeeth,
    /// Cluster coordination over pmxcfs (/etc/pve); clean "not clustered" when absent
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Cluster-wide fabric.conf distribution
    Conf {
        #[command(subcommand)]
        action: ConfAction,
    },
    /// The resident routing engine (started by `up` as cfab-engine.service; root)
    Engine {
        /// Gate-0 teeth: install routes without preferred sources (the oracle must go RED)
        #[arg(long, hide = true)]
        unsafe_no_prefsrc: bool,
    },
}

#[derive(Subcommand)]
enum ClusterAction {
    /// Report pmxcfs presence, quorum, members, and the published conf state
    Status,
}

#[derive(Subcommand)]
enum ConfAction {
    /// Validate the local fabric.conf and publish it to /etc/pve/cfab/ (lock + gen bump)
    Publish,
}

#[derive(Subcommand)]
enum GenArtifact {
    /// The nft forward policy (table inet cfab-fwd)
    Policy,
    /// The traffic-class marking (table inet cfab)
    Mark,
    /// This member's routing-engine configuration tree (JSON)
    Engine,
    /// The floor+borrow HTB derivation for one physical NIC
    Shape {
        /// The physical NIC (a CLASS_TABLE wire)
        dev: String,
        /// Print the tc program instead of the derivation
        #[arg(long, conflicts_with = "expect")]
        tc: bool,
        /// Print the "classid effective-rate" lines that `verify` diffs
        #[arg(long)]
        expect: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn config_path(cli_config: &Option<PathBuf>) -> PathBuf {
    if let Some(p) = cli_config {
        return p.clone();
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let beside = dir.join("fabric.conf");
        if beside.exists() {
            return beside;
        }
    }
    // The installed (deb) layout: /usr/bin/cfab + /etc/cfab/fabric.conf.
    let etc = PathBuf::from("/etc/cfab/fabric.conf");
    if etc.exists() {
        return etc;
    }
    PathBuf::from("fabric.conf")
}

fn member_name(cli_host: &Option<String>) -> Result<String, Error> {
    if let Some(h) = cli_host {
        return Ok(h.clone());
    }
    if let Ok(h) = std::env::var("CFAB_HOST")
        && !h.is_empty()
    {
        return Ok(h);
    }
    Ok(std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map_err(|e| Error::fatal(format!("cannot read hostname: {e}")))?
        .trim()
        .to_string())
}

fn run(cli: Cli) -> Result<ExitCode, Error> {
    let path = config_path(&cli.config);
    if let Command::Schema = cli.command {
        // Schema needs no config file at all.
        let schema = schemars::schema_for!(cfab::model::Fabric);
        println!(
            "{}",
            serde_json::to_string_pretty(&schema).expect("schema serializes")
        );
        return Ok(ExitCode::SUCCESS);
    }
    if let Command::Cluster {
        action: ClusterAction::Status,
    } = cli.command
    {
        // Status is about the cluster, not the declaration — no config file needed.
        print!(
            "{}",
            commands::cluster::status(&cfab::cluster::Pmxcfs::new())?
        );
        return Ok(ExitCode::SUCCESS);
    }
    let fabric = load_fabric(&path)?;
    let member = member_name(&cli.host)?;
    let view = View::new(&fabric, &member)?;

    match cli.command {
        Command::Schema | Command::Cluster { .. } => unreachable!("handled above"),
        Command::Conf {
            action: ConfAction::Publish,
        } => {
            // load_fabric + View::new above are the full validation gate: a conf that does
            // not validate for this member never reaches the cluster.
            let mut sys = RealSys;
            let conf_text = std::fs::read_to_string(&path)
                .map_err(|e| Error::fatal(format!("cannot read {}: {e}", path.display())))?;
            print!(
                "{}",
                commands::cluster::publish(&mut sys, &cfab::cluster::Pmxcfs::new(), &conf_text)?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Check => {
            print!("{}", check_report(&fabric, &view));
            Ok(ExitCode::SUCCESS)
        }
        Command::Gen { artifact } => {
            match artifact {
                GenArtifact::Policy => print!("{}", emit::policy::generate(&view)?),
                GenArtifact::Mark => print!("{}", emit::mark::generate(&view)?),
                GenArtifact::Engine => {
                    let tree = emit::engine::generate(&view)?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&tree).map_err(Error::fatal)?
                    )
                }
                GenArtifact::Shape { dev, tc, expect } => {
                    let d = shape_for(&view, &fabric, &dev)?;
                    for w in &d.warnings {
                        eprintln!("{w}");
                    }
                    if tc {
                        print!("{}", d.render_tc());
                    } else if expect {
                        print!("{}", d.render_expect());
                    } else {
                        print!("{}", d.render_derive(&view));
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Up => {
            let mut sys = RealSys;
            let opts = commands::up::UpOpts {
                exe: std::env::current_exe()
                    .map_err(|e| Error::fatal(format!("cannot resolve own path: {e}")))?
                    .to_string_lossy()
                    .into_owned(),
                config: std::fs::canonicalize(&path)
                    .map_err(|e| Error::fatal(format!("cannot resolve {}: {e}", path.display())))?
                    .to_string_lossy()
                    .into_owned(),
                pmxcfs_root: "/etc/pve".to_string(),
            };
            print!("{}", commands::up::run(&mut sys, &view, &opts)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Down => {
            let mut sys = RealSys;
            print!("{}", commands::down::run(&mut sys, &view)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Verify { timeout } => {
            let mut sys = RealSys;
            let report = commands::verify::run(&mut sys, &view, timeout)?;
            print!("{}", report.output);
            Ok(ExitCode::from(report.code))
        }
        Command::ShapeDaemon { debounce } => {
            let mut sys = RealSys;
            commands::shape_daemon::run(
                &mut sys,
                &view,
                std::time::Duration::from_secs_f64(debounce),
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Command::FwdWatchdog => {
            let mut sys = RealSys;
            let report = commands::fwd_watchdog::run(&mut sys, &view)?;
            if let Some(rule) = &report.resolved {
                eprintln!("cfab fwd-watchdog: installed foreign-stack accept: {rule}");
            }
            for b in &report.blocked {
                eprintln!("cfab fwd-watchdog: BLOCKED by a foreign ruleset: {b}");
            }
            match report.failed {
                Some(reason) => {
                    eprintln!("cfab fwd-watchdog: FAIL-CLOSED: {reason}");
                    Ok(ExitCode::FAILURE)
                }
                None if !report.blocked.is_empty() => Ok(ExitCode::FAILURE),
                None => Ok(ExitCode::SUCCESS),
            }
        }
        Command::ConfSync => {
            let mut sys = RealSys;
            let exe = std::env::current_exe()
                .map_err(|e| Error::fatal(format!("cannot resolve own path: {e}")))?
                .to_string_lossy()
                .into_owned();
            commands::conf_sync::run(&mut sys, &view.member.name, &fabric.run_dir, &exe)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::MeasureCap { dev, peer, secs } => {
            let mut sys = RealSys;
            let summary = commands::measure_cap::run(
                &mut sys,
                &view,
                &cfab::cluster::Pmxcfs::new(),
                &dev,
                &peer,
                secs,
                &commands::measure_cap::native_flood,
            )?;
            println!("{summary}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Engine { unsafe_no_prefsrc } => {
            cfab::engine::run(&fabric, &view, unsafe_no_prefsrc)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::PolicyTeeth => {
            let mut sys = RealSys;
            let conf_text = std::fs::read_to_string(&path)
                .map_err(|e| Error::fatal(format!("cannot read {}: {e}", path.display())))?;
            let report = commands::policy_teeth::run(&mut sys, &view, &conf_text)?;
            print!("{}", report.output);
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

/// The two lines `cfab check` prints: the fabric as declared, then what THIS member gets.
/// The second line is the last thing an operator sees before `up` creates the netdevs, so it
/// names every leg `up` will build — the fallback legs included: their slaves fan out per wire,
/// so their count is member-dependent and not derivable from the fabric-wide line.
fn check_report(fabric: &cfab::model::Fabric, view: &View) -> String {
    let kind = match view.kind() {
        MemberKind::Host => "host",
        MemberKind::Leaf => "leaf",
    };
    let fallback_legs = fabric
        .class_table
        .iter()
        .filter(|r| r.role == Role::Fallback)
        .count();
    format!(
        "fabric.conf OK: {} zones, {} segments, {} fallback legs, {} members\n\
         this member: {} (node {}, {kind}); {} segment sub-ifs on wires [{}], {} fallback leg(s), \
         {} ingress leg(s)\n",
        fabric.zones.len(),
        fabric.class_table.len() - fallback_legs,
        fallback_legs,
        fabric.members.len(),
        view.member.name,
        view.node(),
        view.class_rows().len(),
        view.wires().join(" "),
        view.fallback_rows().len(),
        view.gw_rows().len(),
    )
}

/// The manual `gen shape` path: cap chain + up-set from the environment — CFAB_CAP_DIR /
/// CFAB_RUN cap files with the cluster-published cap as the absent-local fallback, and
/// CFAB_UP_IFS as the authoritative up-set, else sysfs carrier, else assume up (never demote
/// on missing information).
fn shape_for<'a>(
    view: &View<'a>,
    fabric: &cfab::model::Fabric,
    dev: &str,
) -> Result<emit::shape::Derivation, Error> {
    let mut sys = RealSys;
    let measured = cfab::caps::read_cap(
        &mut sys,
        &cfab::cluster::Pmxcfs::new(),
        &view.member.name,
        &fabric.run_dir,
        dev,
    );
    let up_env = std::env::var("CFAB_UP_IFS").ok();
    let up = move |w: &str| -> bool {
        if let Some(set) = &up_env {
            return set.split_whitespace().any(|u| u == w);
        }
        match std::fs::read_to_string(format!("/sys/class/net/{w}/carrier")) {
            Ok(s) => s.trim() == "1",
            Err(_) => true,
        }
    };
    emit::shape::derive(view, dev, measured, &up)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfab::config::RawConfig;
    use cfab::model::Fabric;

    fn fabric_from(text: &str) -> Fabric {
        Fabric::from_raw(&RawConfig::parse(text).unwrap()).unwrap()
    }

    fn example() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
            .unwrap()
    }

    /// The per-member line is the only output that says what THIS host will get, and `up`
    /// builds one bond per fallback leg with one slave per wire under it. It must say so.
    #[test]
    fn check_names_this_members_fallback_legs() {
        let f = fabric_from(&example());
        let view = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            check_report(&f, &view),
            "fabric.conf OK: 3 zones, 9 segments, 3 fallback legs, 3 members\n\
             this member: pve1-tb (node 1, host); 9 segment sub-ifs on wires [eth0 eth1 eth9], \
             3 fallback leg(s), 1 ingress leg(s)\n"
        );
    }

    /// A fabric declaring no fallback row: one spelling, counted zero, never absent.
    #[test]
    fn check_on_a_fallback_free_fabric_counts_zero() {
        let text = example()
            .lines()
            .filter(|l| !l.contains(" fallback "))
            .collect::<Vec<_>>()
            .join("\n");
        let f = fabric_from(&text);
        let view = View::new(&f, "pve1-tb").unwrap();
        assert_eq!(
            check_report(&f, &view),
            "fabric.conf OK: 3 zones, 9 segments, 0 fallback legs, 3 members\n\
             this member: pve1-tb (node 1, host); 9 segment sub-ifs on wires [eth0 eth1 eth9], \
             0 fallback leg(s), 1 ingress leg(s)\n"
        );
    }
}
