use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use cfab::derive::View;
use cfab::model::MemberKind;
use cfab::sys::RealSys;
use cfab::{Error, commands, emit, load_fabric};

/// cfab — the per-host runtime of the resilient converged fabric.
///
/// fabric.conf declares the fabric; this tool validates it, generates every artifact from it
/// (nft policy/marking, HTB trees, frr config), applies and verifies the fabric on this
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
    /// Remove everything `up` created, restore FRR to the pre-fabric state (root)
    Down,
}

#[derive(Subcommand)]
enum GenArtifact {
    /// The nft forward policy (table inet cfab-fwd)
    Policy,
    /// The traffic-class marking (table inet cfab)
    Mark,
    /// This member's /etc/frr/frr.conf
    Frr,
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
    let fabric = load_fabric(&path)?;
    let member = member_name(&cli.host)?;
    let view = View::new(&fabric, &member)?;

    match cli.command {
        Command::Schema => unreachable!("handled above"),
        Command::Check => {
            let kind = match view.kind() {
                MemberKind::Host => "host",
                MemberKind::Leaf => "leaf",
            };
            println!(
                "fabric.conf OK: {} zones, {} segments, {} members",
                fabric.zones.len(),
                fabric.class_table.len(),
                fabric.members.len()
            );
            println!(
                "this member: {} (node {}, {kind}); {} segment sub-ifs on wires [{}], {} ingress leg(s)",
                member,
                view.node(),
                view.class_rows().len(),
                view.wires().join(" "),
                view.gw_rows().len()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Gen { artifact } => {
            match artifact {
                GenArtifact::Policy => print!("{}", emit::policy::generate(&view)?),
                GenArtifact::Mark => print!("{}", emit::mark::generate(&view)?),
                GenArtifact::Frr => print!("{}", emit::frr::generate(&view)?),
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
    }
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
