//! `h0-probe` — minimal H0 probe (GATE-H0, H0.P). Unintegrated: candidate
//! `none`. Reproduces the frozen Campaign 002 minimum user+mount containment
//! shape without display/GPU preflight, records host/LSM state, and emits a
//! `neuestar.h0/v1` record. The Campaign 002 artifact is used read-only.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use neuestar_h0_probe::child::{read_child_evidence, run_child_mode};
use neuestar_h0_probe::containment::{
    outcome_argv, outcome_command, run_contained, sha256_file, verify_artifact,
};
use neuestar_h0_probe::host::{collect_host, collect_security_state};
use neuestar_h0_probe::record::{Outcome, build};

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

    /// Frozen Campaign 002 payload manifest SHA-256 (verified against artifact.json).
    #[arg(long)]
    expected_payload_sha256: String,

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

    /// Internal: run as the contained child and write child evidence.
    #[arg(long, hide = true)]
    child_mode: bool,

    /// Internal: child evidence destination (inside /evidence).
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

    let report_parent = prepare_report_parent(&cli.report)?;
    let probe_self = std::env::current_exe().context("failed to locate probe binary")?;
    let argv = outcome_argv(&report_parent, &cli.artifact_root, &probe_self, false);
    if cli.dry_run {
        for arg in argv.as_slice() {
            println!("{arg}");
        }
        return Ok(EXIT_OK);
    }

    let host = collect_host();
    let security_state = collect_security_state();
    let timestamp = timestamp();
    let session_id = format!("{timestamp}-{}", std::process::id());

    // Artifact verification failure is an apparatus-stage failure record
    // (fail-closed), not a silent exit.
    let verified = verify_artifact(&cli.artifact_root, &cli.expected_payload_sha256);
    let (pre_host_state, post_host_state, probe_sha256) = state_dumps(&host, cli, &report_parent);

    if let Err(error) = verified {
        let record = build(
            &host,
            &security_state,
            &timestamp,
            &session_id,
            &cli.archive_sha256,
            &cli.expected_payload_sha256,
            &probe_sha256,
            argv.as_slice(),
            &cli.iso_snapshot_date,
            &cli.config_surface,
            false,
            false,
            None,
            None,
            &pre_host_state,
            &post_host_state,
            &Outcome::Fail {
                stage: "apparatus",
                code: "artifact-verification",
                message: format!("{error:#}"),
            },
        )?;
        write_json(&cli.report, &record)?;
        return Ok(EXIT_OK);
    }

    let parent_user_ns = namespace_identity("/proc/self/ns/user");
    let parent_mount_ns = namespace_identity("/proc/self/ns/mnt");

    // Outcome run: the frozen controlled-glibc child under the minimum
    // user+mount boundary (Campaign 002 equivalence).
    let mut command = outcome_command(&report_parent, &cli.artifact_root, &probe_self, false);
    let run = run_contained(&mut command)?;
    let Some(run) = run else {
        return Ok(EXIT_APPARATUS);
    };
    let helper_started = true;
    let process_stderr = run.process_stderr;

    let child_result_path = report_parent.join("child-result.json");
    let child_result = read_child_result(&child_result_path);

    let outcome = match &child_result {
        Some(result) if valid_successful_child_result(result) => Outcome::Pass,
        Some(result) => Outcome::Fail {
            stage: "baseline",
            code: "child-failed",
            message: child_failure_message(result, run.status),
        },
        None => Outcome::Fail {
            stage: "baseline",
            code: "child-unreached",
            message: match &process_stderr {
                Some(stderr) => stderr.clone(),
                None => "no child result and no helper stderr".to_owned(),
            },
        },
    };
    let child_reached =
        matches!(&child_result, Some(result) if result.contained && result.launch_reached_main);

    // Evidence run (only when the child was reached): the probe re-executes
    // itself inside the SAME boundary to deterministically record ns identity,
    // CapEff, and profile label. If this fails, the apparatus is broken: stop
    // without emitting evidence (fail-closed, no repair).
    let child_evidence = if child_reached {
        let mut evidence_command =
            outcome_command(&report_parent, &cli.artifact_root, &probe_self, true);
        let evidence_run = run_contained(&mut evidence_command)?;
        if evidence_run.is_none() {
            anyhow::bail!("child evidence containment could not start");
        }
        let evidence_path = report_parent.join("h0-child-evidence.json");
        match read_child_evidence(&evidence_path) {
            Ok(evidence) => Some(evidence),
            Err(error) => {
                anyhow::bail!(
                    "child evidence missing after a reached child ({}); apparatus failure",
                    error
                )
            }
        }
    } else {
        None
    };

    let post_host_state = format!(
        "{post_host_state}\nprobe_parent_user_ns={parent_user_ns}\nprobe_parent_mount_ns={parent_mount_ns}\n{}",
        match &child_result {
            Some(result) => format!(
                "child_user_ns={}\nchild_mount_ns={}\nchild_launch_reached_main={}\nchild_mapped_libc={}",
                result.user_namespace,
                result.mount_namespace,
                result.launch_reached_main,
                result.mapped_libc_paths.join(",")
            ),
            None => "child_user_ns=unavailable\nchild_mount_ns=unavailable\nchild_mapped_libc="
                .to_owned(),
        }
    );

    let record = build(
        &host,
        &security_state,
        &timestamp,
        &session_id,
        &cli.archive_sha256,
        &cli.expected_payload_sha256,
        &probe_sha256,
        argv.as_slice(),
        &cli.iso_snapshot_date,
        &cli.config_surface,
        helper_started,
        child_reached,
        child_evidence.as_ref(),
        process_stderr.as_deref(),
        &pre_host_state,
        &post_host_state,
        &outcome,
    )?;
    write_json(&cli.report, &record)?;
    Ok(EXIT_OK)
}

#[derive(Debug)]
struct ChildResult {
    contained: bool,
    launch_reached_main: bool,
    user_namespace: String,
    mount_namespace: String,
    mapped_libc_paths: Vec<String>,
    failure: Option<ChildFailure>,
}

#[derive(Debug)]
struct ChildFailure {
    code: String,
    explanation: String,
}

fn read_child_result(path: &std::path::Path) -> Option<ChildResult> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > 1024 * 1024 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path).ok()?).ok()?;
    if value.get("schema")?.as_str()? != "neuestar.child/v1" {
        return None;
    }
    Some(ChildResult {
        contained: value
            .get("contained")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        launch_reached_main: value
            .get("launch_reached_main")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        user_namespace: value
            .get("user_namespace")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        mount_namespace: value
            .get("mount_namespace")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        mapped_libc_paths: value
            .get("mapped_libc_paths")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        failure: value
            .get("failure")
            .and_then(serde_json::Value::as_object)
            .map(|failure| ChildFailure {
                code: failure
                    .get("code")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                explanation: failure
                    .get("explanation")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            }),
    })
}

fn valid_successful_child_result(result: &ChildResult) -> bool {
    result.contained
        && result.launch_reached_main
        && result.failure.is_none()
        && result
            .mapped_libc_paths
            .iter()
            .any(|path| path.contains("libc.so"))
}

fn child_failure_message(result: &ChildResult, status: Option<i32>) -> String {
    if let Some(failure) = &result.failure {
        format!("{}: {}", failure.code, failure.explanation)
    } else {
        format!(
            "child did not produce a successful controlled result (contained={}, launch={}, exit={:?})",
            result.contained, result.launch_reached_main, status
        )
    }
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

fn state_dumps(
    host: &neuestar_h0_probe::host::HostFacts,
    cli: &Cli,
    report_parent: &std::path::Path,
) -> (String, String, String) {
    let pre = format!(
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
    (pre, String::new(), sha256_self())
}

fn sha256_self() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| sha256_file(&path).ok())
        .unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned()
        })
}

fn timestamp() -> String {
    // No chrono dependency: record the wall clock from the environment the
    // operator can trust; the VM procedure stamps evidence directories anyway.
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
