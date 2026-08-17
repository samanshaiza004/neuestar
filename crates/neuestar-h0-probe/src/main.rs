//! `h0-probe` — minimal H0 probe (GATE-H0, H0.P). Unintegrated (candidate
//! `none`), single outcome run: the frozen Campaign 002 child under the exact
//! frozen containment command (shared via neuestar-probe-core), with the
//! Campaign 002 success predicate (helper exit + namespace-change proof +
//! controlled libc) and no display/GPU preflight. Emits `neuestar.h0/v1`.
//!
//! The dedicated security-evidence invocation (CapEff/profile) is reserved
//! for H0.1S and is not part of H0.P.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use neuestar_h0_probe::child::run_child_mode;
use neuestar_h0_probe::containment::{ContainmentError, run_contained};
use neuestar_h0_probe::host::{collect_host, collect_security_state};
use neuestar_h0_probe::record::{Outcome, build};
use neuestar_probe_core::artifact;
use neuestar_probe_core::child_result::{
    ChildResult, read_child_result, valid_successful_child_result,
};
use neuestar_probe_core::command::{contained_command, frozen_child_exec};

const EXIT_OK: u8 = 0;
const EXIT_APPARATUS: u8 = 2;

#[derive(Debug, Parser)]
#[command(version, about = "Run the H0 (Installed Substrate) PREFLIGHT probe")]
struct Cli {
    /// Extracted frozen Campaign 002 artifact directory (read-only input).
    #[arg(long)]
    artifact_root: PathBuf,

    /// Frozen Campaign 002 outer archive SHA-256 (recorded as runtime identity).
    #[arg(long)]
    archive_sha256: String,

    /// Where the neuestar.h0/v1 record is written.
    #[arg(long, default_value = "h0-report.json")]
    report: PathBuf,

    /// ISO/snapshot date of the target profile (YYYY-MM-DD).
    #[arg(long)]
    iso_snapshot_date: String,

    /// Target configuration surface description.
    #[arg(long, default_value = "stock")]
    config_surface: String,

    /// Print the containment argv and exit without executing anything.
    #[arg(long)]
    dry_run: bool,

    /// Internal: reserved for the H0.1S security-evidence invocation.
    #[arg(long, hide = true)]
    child_mode: bool,

    /// Internal: child evidence destination (reserved for H0.1S).
    #[arg(long, hide = true)]
    child_result: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("h0-probe: {error:#}");
            ExitCode::from(EXIT_APPARATUS)
        }
    }
}

fn run(cli: &Cli) -> Result<u8> {
    if cli.child_mode {
        let Some(result) = cli.child_result.as_deref() else {
            anyhow::bail!("--child-result is required with --child-mode");
        };
        run_child_mode(result)?;
        return Ok(EXIT_OK);
    }

    // Canonicalize the artifact root once: relative-path/current-directory
    // behavior must not be an apparatus variable.
    let artifact_root = cli.artifact_root.canonicalize().with_context(|| {
        format!(
            "failed to resolve artifact root {}",
            cli.artifact_root.display()
        )
    })?;
    // Validate the recorded identities so an apparatus record can never be
    // schema-invalid evidence.
    if !neuestar_probe_core::artifact::valid_sha256(&cli.archive_sha256) {
        anyhow::bail!("--archive-sha256 must be 64 lowercase hexadecimal characters");
    }
    if !valid_iso_date(&cli.iso_snapshot_date) {
        anyhow::bail!("--iso-snapshot-date must be YYYY-MM-DD");
    }

    let report_parent = prepare_report_parent(&cli.report)?;
    let host = collect_host();
    let security_state = collect_security_state();
    let timestamp = timestamp();
    let session_id = format!("{timestamp}-{}", std::process::id());
    let parent_user_ns = namespace_identity("/proc/self/ns/user");
    let parent_mount_ns = namespace_identity("/proc/self/ns/mnt");

    // Full frozen artifact preflight (identical to Campaign 002), executed
    // before anything else so a divergence can never be blamed on a weaker
    // verifier. Verification failure is an apparatus-stage failure record.
    let metadata = match artifact::verify_payload(&artifact_root) {
        Ok(metadata) => metadata,
        Err(error) => {
            write_apparatus_failure(
                cli,
                &host,
                &security_state,
                &timestamp,
                &session_id,
                &report_parent,
                "artifact-verification",
                &format!("{error:#}"),
                false,
                &[],
                &parent_user_ns,
                &parent_mount_ns,
            )?;
            return Ok(EXIT_OK);
        }
    };

    // Bundled-helper closure preflight (identical to Campaign 002): the
    // bundled loader must resolve bwrap only inside the controlled artifact.
    if let Err(error) =
        neuestar_probe_core::helper::verify_bundled_helper_resolution(&artifact_root)
    {
        write_apparatus_failure(
            cli,
            &host,
            &security_state,
            &timestamp,
            &session_id,
            &report_parent,
            "helper-closure-verification",
            &format!("{error:#}"),
            false,
            &[],
            &parent_user_ns,
            &parent_mount_ns,
        )?;
        return Ok(EXIT_OK);
    }

    // Stale-evidence rejection: historical files must never influence a new
    // classification (Campaign 002 behavior).
    let child_result_path = report_parent.join("child-result.json");
    let child_evidence_path = report_parent.join("h0-child-evidence.json");
    if child_result_path.exists() || child_evidence_path.exists() {
        write_apparatus_failure(
            cli,
            &host,
            &security_state,
            &timestamp,
            &session_id,
            &report_parent,
            "stale-evidence",
            "evidence directory already contains child-result.json or h0-child-evidence.json; use a fresh evidence directory",
            false,
            &[],
            &parent_user_ns,
            &parent_mount_ns,
        )?;
        return Ok(EXIT_OK);
    }

    let probe_sha256 = sha256_self();
    let mut command = contained_command(
        &report_parent,
        &artifact_root,
        &cli.archive_sha256,
        &metadata,
        &frozen_child_exec(),
    );
    let argv: Vec<String> = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    if cli.dry_run {
        for arg in &argv {
            println!("{arg}");
        }
        return Ok(EXIT_OK);
    }

    let run = match run_contained(&mut command) {
        Ok(run) => run,
        Err(ContainmentError::Spawn(error)) => {
            write_apparatus_failure(
                cli,
                &host,
                &security_state,
                &timestamp,
                &session_id,
                &report_parent,
                "helper-spawn-failed",
                &format!("{error:#}"),
                false,
                &argv,
                &parent_user_ns,
                &parent_mount_ns,
            )?;
            return Ok(EXIT_OK);
        }
        Err(ContainmentError::Wait(error)) => {
            write_apparatus_failure(
                cli,
                &host,
                &security_state,
                &timestamp,
                &session_id,
                &report_parent,
                "helper-wait-failed",
                &format!("{error:#}"),
                true,
                &argv,
                &parent_user_ns,
                &parent_mount_ns,
            )?;
            return Ok(EXIT_OK);
        }
    };
    let helper_started = true;
    let process_stderr = run.process_stderr;

    // Campaign 002 success predicate: helper success, valid bounded child
    // result, x86_64, user AND mount namespace change vs the probe parent,
    // no child failure, controlled libc observed.
    let child_result = read_child_result(&child_result_path).ok();
    let success = run.status == Some(0)
        && child_result.as_ref().is_some_and(|result| {
            valid_successful_child_result(result, &parent_user_ns, &parent_mount_ns)
        });

    let outcome = if success {
        Outcome::Pass
    } else {
        Outcome::BaselineFail {
            code: match &child_result {
                Some(result) if result.contained && result.launch_reached_main => "child-failed",
                _ => "child-unreached",
            },
            message: match &child_result {
                Some(result) if result.contained && result.launch_reached_main => {
                    child_failure_message(result, run.status)
                }
                _ => process_stderr
                    .clone()
                    .unwrap_or_else(|| "no child result and no helper stderr".to_owned()),
            },
        }
    };
    let child_reached = child_result
        .as_ref()
        .is_some_and(|result| result.contained && result.launch_reached_main);

    let post_host_state = format!(
        "probe_parent_user_ns={parent_user_ns}\nprobe_parent_mount_ns={parent_mount_ns}\n{}",
        match &child_result {
            Some(result) => format!(
                "child_user_ns={}\nchild_mount_ns={}\nchild_launch_reached_main={}\nchild_architecture={}\nchild_mapped_libc={}",
                result.user_namespace,
                result.mount_namespace,
                result.launch_reached_main,
                result.architecture,
                result.mapped_libc_paths.join(",")
            ),
            None => "child_user_ns=unavailable\nchild_mount_ns=unavailable\nchild_mapped_libc="
                .to_owned(),
        }
    );
    let pre_host_state = format!(
        "os_release={} {} ({})\nkernel={} {}\nlsm_raw={}\nartifact_outer_sha256={}\nreport_parent={}\n",
        host.distro_id,
        host.distro_version,
        host.pretty_name,
        host.kernel_release,
        host.architecture,
        host.lsm_raw,
        cli.archive_sha256,
        report_parent.display()
    );

    let record = build(
        &host,
        &security_state,
        &timestamp,
        &session_id,
        &cli.archive_sha256,
        &metadata.payload_manifest_sha256,
        &probe_sha256,
        &argv,
        &cli.iso_snapshot_date,
        &cli.config_surface,
        helper_started,
        child_reached,
        child_result.as_ref().map(|result| {
            (
                result.user_namespace.as_str(),
                result.mount_namespace.as_str(),
            )
        }),
        process_stderr.as_deref(),
        &pre_host_state,
        &post_host_state,
        &outcome,
    )?;
    write_json(&cli.report, &record)?;
    Ok(EXIT_OK)
}

/// Emits an apparatus-stage failure record (fail-closed; the report path is
/// writable by construction).
#[allow(clippy::too_many_arguments)]
fn write_apparatus_failure(
    cli: &Cli,
    host: &neuestar_h0_probe::host::HostFacts,
    security_state: &neuestar_h0_probe::host::SecurityState,
    timestamp: &str,
    session_id: &str,
    report_parent: &std::path::Path,
    code: &'static str,
    message: &str,
    helper_started: bool,
    argv: &[String],
    parent_user_ns: &str,
    parent_mount_ns: &str,
) -> Result<()> {
    let record = build(
        host,
        security_state,
        timestamp,
        session_id,
        &cli.archive_sha256,
        "unverified",
        &sha256_self(),
        argv,
        &cli.iso_snapshot_date,
        &cli.config_surface,
        helper_started,
        false,
        None,
        None,
        &format!(
            "artifact_outer_sha256={}\nreport_parent={}",
            cli.archive_sha256,
            report_parent.display()
        ),
        &format!("probe_parent_user_ns={parent_user_ns}\nprobe_parent_mount_ns={parent_mount_ns}"),
        &Outcome::ApparatusFail {
            code,
            message: message.to_owned(),
        },
    )?;
    write_json(&cli.report, &record)
}

fn child_failure_message(result: &ChildResult, status: Option<i32>) -> String {
    if let Some(failure) = &result.failure {
        format!("{}: {}", failure.code, failure.explanation)
    } else {
        format!(
            "child did not produce a successful controlled result (contained={}, launch={}, arch={}, exit={:?})",
            result.contained, result.launch_reached_main, result.architecture, status
        )
    }
}

fn valid_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && (0..10).all(|i| i == 4 || i == 7 || bytes[i].is_ascii_digit())
}

fn namespace_identity(path: &str) -> String {
    std::fs::read_link(path).map_or_else(
        |_| "unavailable".to_owned(),
        |identity| identity.display().to_string(),
    )
}

fn prepare_report_parent(report: &std::path::Path) -> Result<PathBuf> {
    let parent = report
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create report directory {}", parent.display()))?;
    parent
        .canonicalize()
        .with_context(|| format!("failed to resolve report directory {}", parent.display()))
}

fn sha256_self() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| neuestar_probe_core::artifact::sha256_file(&path).ok())
        .unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned()
        })
}

fn timestamp() -> String {
    std::process::Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn write_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    let mut file = std::fs::File::create(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("failed to publish {}", path.display()))
}
