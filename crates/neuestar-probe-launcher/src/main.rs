//! Static musl launcher for Phase 1 and Gate L0.0 containment evidence.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, Command, ExitCode, ExitStatus, Stdio};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use neuestar_host_inspect::HostMetadata;
use neuestar_probe_core::artifact::{ArtifactMetadata, valid_sha256};
use neuestar_report::{
    Artifact, CaptureEvidence, Classification, ContainmentEvidence, ContainmentSubstage,
    DisplayServer, Distro, FailureStage, GateResults, GateState, GpuVendor, GraphicsEvidence,
    LibcSource, MatrixCell, ObservedHost, PresentationEvidence, RendererKind, Report,
    RuntimeEvidence, SchemaVersion, StructuredFailure, VendorSpecificRule,
};
use serde::{Deserialize, Serialize};

const EXIT_VERIFY: u8 = 65;
const EXIT_UNAVAILABLE: u8 = 69;
const EXIT_CONTAINMENT: u8 = 71;
const PROCESS_STDERR_MAX_BYTES: usize = 64 * 1024;
const PROCESS_STDERR_MAX_CHARS: usize = 4096;
const UNKNOWN_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const UNKNOWN_SOURCE_COMMIT: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, Parser)]
#[command(version, about = "Run the immutable Neuestar Gate L0 probe")]
struct Cli {
    /// Path where the attempt report must be written.
    #[arg(long, default_value = "report.json")]
    report: PathBuf,

    /// SHA-256 of the downloaded canonical archive, verified before extraction.
    #[arg(long)]
    archive_sha256: Option<String>,

    /// Declared distribution label for the physical matrix cell.
    #[arg(long, value_enum)]
    distro: CliDistro,

    /// Declared GPU vendor label for the physical matrix cell.
    #[arg(long, value_enum)]
    gpu: CliGpu,

    /// Declared display-server label for the physical matrix cell.
    #[arg(long, value_enum)]
    display: CliDisplay,

    /// Print and write the containment plan without constructing namespaces.
    #[arg(long)]
    dry_run: bool,

    /// Override artifact root for local verification tests.
    #[arg(long, hide = true)]
    artifact_root: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliDistro {
    Fedora,
    Ubuntu,
    Arch,
    Nixos,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliGpu {
    Intel,
    Amd,
    Nvidia,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliDisplay {
    Wayland,
    X11,
}

#[derive(Debug, Deserialize)]
struct ChildResult {
    schema: String,
    contained: bool,
    launch_reached_main: bool,
    architecture: String,
    user_namespace: String,
    mount_namespace: String,
    mapped_libc_paths: Vec<String>,
    failure: Option<ChildFailure>,
}

#[derive(Debug, Deserialize)]
struct ChildFailure {
    code: String,
    explanation: String,
}

#[derive(Debug, Serialize)]
struct CapturePlan {
    schema: &'static str,
    helper: String,
    runtime_root: String,
    application: String,
    writable_evidence_directory: String,
    namespaces: Vec<&'static str>,
    host_paths_exposed: Vec<String>,
    vendor_specific_rules: Vec<String>,
    distro_specific_rule_count: u8,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("neuestar-probe: {error:#}");
            ExitCode::from(EXIT_UNAVAILABLE)
        }
    }
}

fn run(cli: &Cli) -> Result<u8> {
    let host = neuestar_host_inspect::collect();
    let matrix_cell = matrix_cell(cli);
    let artifact_root = match resolve_artifact_root(cli) {
        Ok(root) => root,
        Err(error) => {
            write_bootstrap_failure(
                &cli.report,
                cli.archive_sha256.as_deref().unwrap_or("unknown"),
                None,
                matrix_cell,
                &host,
                FailureStage::Preflight,
                &format!("{error:#}"),
            )?;
            return Ok(EXIT_VERIFY);
        }
    };

    let metadata = match neuestar_probe_core::artifact::verify_payload(&artifact_root) {
        Ok(metadata) => metadata,
        Err(error) => {
            write_bootstrap_failure(
                &cli.report,
                cli.archive_sha256.as_deref().unwrap_or("unknown"),
                None,
                matrix_cell,
                &host,
                FailureStage::Preflight,
                &format!("{error:#}"),
            )?;
            eprintln!("artifact verification failed: {error:#}");
            return Ok(EXIT_VERIFY);
        }
    };

    let Some(archive_sha256) = validated_archive_hash(cli, &metadata, matrix_cell, &host)? else {
        return Ok(EXIT_VERIFY);
    };
    if !cli.dry_run
        && let Err(error) = validate_declared_host(cli, &host)
    {
        write_bootstrap_failure(
            &cli.report,
            archive_sha256,
            Some(&metadata),
            matrix_cell,
            &host,
            FailureStage::Preflight,
            &format!("declared matrix cell does not match the observed host: {error}"),
        )?;
        return Ok(EXIT_VERIFY);
    }

    let report_parent = prepare_report_parent(&cli.report)?;
    write_json(&report_parent.join("host-metadata.json"), &host)?;
    let plan = capture_plan(cli, &artifact_root, &report_parent);
    let plan_path = report_parent.join("capture-plan.json");
    write_json(&plan_path, &plan)?;

    if cli.dry_run {
        serde_json::to_writer_pretty(std::io::stdout(), &plan)
            .context("failed to print capture plan")?;
        println!();
        return Ok(0);
    }

    execute_contained(
        cli,
        &artifact_root,
        &report_parent,
        archive_sha256,
        &metadata,
        matrix_cell,
        &host,
    )
}

fn resolve_artifact_root(cli: &Cli) -> Result<PathBuf> {
    match &cli.artifact_root {
        Some(path) => path
            .canonicalize()
            .with_context(|| format!("failed to resolve artifact root {}", path.display())),
        None => std::env::current_exe()
            .context("failed to locate launcher")?
            .parent()
            .ok_or_else(|| anyhow!("launcher has no parent directory"))
            .map(Path::to_path_buf),
    }
}

fn validated_archive_hash<'a>(
    cli: &'a Cli,
    metadata: &ArtifactMetadata,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
) -> Result<Option<&'a str>> {
    match cli.archive_sha256.as_deref() {
        Some(hash) if valid_sha256(hash) => Ok(Some(hash)),
        Some(_) => {
            write_bootstrap_failure(
                &cli.report,
                "invalid",
                Some(metadata),
                matrix_cell,
                host,
                FailureStage::Preflight,
                "--archive-sha256 must be 64 lowercase hexadecimal characters",
            )?;
            Ok(None)
        }
        None if cli.dry_run => Ok(Some("dry-run")),
        None => {
            write_bootstrap_failure(
                &cli.report,
                "missing",
                Some(metadata),
                matrix_cell,
                host,
                FailureStage::Preflight,
                "the pre-extraction archive SHA-256 is mandatory for a real run",
            )?;
            Ok(None)
        }
    }
}

fn execute_contained(
    cli: &Cli,
    artifact_root: &Path,
    report_parent: &Path,
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
) -> Result<u8> {
    if let Err(error) = containment_preflight(artifact_root) {
        write_bootstrap_failure(
            &cli.report,
            archive_sha256,
            Some(metadata),
            matrix_cell,
            host,
            FailureStage::Preflight,
            &format!("containment preflight failed: {error}"),
        )?;
        return Ok(EXIT_VERIFY);
    }

    let child_result_path = report_parent.join("child-result.json");
    if reject_stale_evidence(
        &child_result_path,
        &cli.report,
        archive_sha256,
        metadata,
        matrix_cell,
        host,
    )? {
        return Ok(EXIT_VERIFY);
    }
    let parent_user_namespace = namespace_identity("/proc/self/ns/user");
    let parent_mount_namespace = namespace_identity("/proc/self/ns/mnt");
    let mut command = contained_command(report_parent, artifact_root, archive_sha256, metadata);
    let (status, process_stderr) = match run_helper(&mut command) {
        Ok(pair) => pair,
        Err((substage, error)) => {
            write_helper_failure(
                &cli.report,
                archive_sha256,
                metadata,
                matrix_cell,
                host,
                substage,
                &error,
            )?;
            return Ok(EXIT_CONTAINMENT);
        }
    };
    let child_result = read_child_result(&child_result_path).ok();
    if status.success()
        && child_result.as_ref().is_some_and(|result| {
            valid_successful_child_result(result, &parent_user_namespace, &parent_mount_namespace)
        })
    {
        write_success_report(
            &cli.report,
            archive_sha256,
            metadata,
            matrix_cell,
            host,
            artifact_root,
            report_parent,
            child_result.as_ref().expect("checked above"),
            process_stderr,
        )?;
        return Ok(0);
    }

    write_failure_report(
        &cli.report,
        archive_sha256,
        metadata,
        matrix_cell,
        host,
        artifact_root,
        report_parent,
        status,
        child_result.as_ref(),
        &parent_user_namespace,
        &parent_mount_namespace,
        process_stderr,
    )?;
    Ok(EXIT_CONTAINMENT)
}

fn containment_preflight(artifact_root: &Path) -> Result<()> {
    for required in [
        artifact_root.join("libexec/ld-linux-x86-64.so.2"),
        artifact_root.join("libexec/bwrap"),
        artifact_root.join("root"),
        artifact_root.join("app/probe"),
    ] {
        if !required.exists() {
            bail!("required member is missing: {}", required.display());
        }
    }
    neuestar_probe_core::helper::verify_bundled_helper_resolution(artifact_root)
        .context("bundled bubblewrap closure is not self-contained")
}

fn record_host_paths(report: &mut Report, artifact_root: &Path, report_parent: &Path) {
    report.containment.host_paths_exposed = vec![
        artifact_root.join("root").display().to_string(),
        artifact_root.join("app").display().to_string(),
        report_parent.display().to_string(),
    ];
    report.capture.host_path_count = 3;
}

fn contained_command(
    report_parent: &Path,
    artifact_root: &Path,
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
) -> Command {
    neuestar_probe_core::command::contained_command(
        report_parent,
        artifact_root,
        archive_sha256,
        metadata,
        &neuestar_probe_core::command::frozen_child_exec(),
    )
}

fn capture_plan(cli: &Cli, artifact_root: &Path, report_parent: &Path) -> CapturePlan {
    CapturePlan {
        schema: "neuestar.capture-plan/v1",
        helper: artifact_root.join("libexec/bwrap").display().to_string(),
        runtime_root: artifact_root.join("root").display().to_string(),
        application: artifact_root.join("app").display().to_string(),
        writable_evidence_directory: report_parent.display().to_string(),
        namespaces: vec!["user", "mount"],
        host_paths_exposed: vec![
            artifact_root.join("root").display().to_string(),
            artifact_root.join("app").display().to_string(),
            report_parent.display().to_string(),
        ],
        vendor_specific_rules: if matches!(cli.gpu, CliGpu::Nvidia) {
            vec!["nvidia-device-nodes".to_owned()]
        } else {
            Vec::new()
        },
        distro_specific_rule_count: 0,
    }
}

fn matrix_cell(cli: &Cli) -> MatrixCell {
    MatrixCell {
        distro: match cli.distro {
            CliDistro::Fedora => Distro::Fedora,
            CliDistro::Ubuntu => Distro::UbuntuLts,
            CliDistro::Arch => Distro::Arch,
            CliDistro::Nixos => Distro::Nixos,
        },
        gpu_vendor: match cli.gpu {
            CliGpu::Intel => GpuVendor::Intel,
            CliGpu::Amd => GpuVendor::Amd,
            CliGpu::Nvidia => GpuVendor::Nvidia,
        },
        display_server: match cli.display {
            CliDisplay::Wayland => DisplayServer::Wayland,
            CliDisplay::X11 => DisplayServer::X11,
        },
    }
}

fn validate_declared_host(cli: &Cli, host: &HostMetadata) -> Result<()> {
    let expected_distro = match cli.distro {
        CliDistro::Fedora => "fedora",
        CliDistro::Ubuntu => "ubuntu",
        CliDistro::Arch => "arch",
        CliDistro::Nixos => "nixos",
    };
    let observed_distro = host
        .distribution
        .as_ref()
        .and_then(|distribution| distribution.id.as_deref())
        .unwrap_or("unknown");
    if !observed_distro.eq_ignore_ascii_case(expected_distro) {
        bail!("expected distro {expected_distro}, observed {observed_distro}");
    }

    let session = host.session.session_type.as_deref().unwrap_or("unknown");
    let display_matches = match cli.display {
        CliDisplay::Wayland => {
            session.eq_ignore_ascii_case("wayland") || host.session.wayland_display_present
        }
        CliDisplay::X11 => session.eq_ignore_ascii_case("x11") || host.session.display_present,
    };
    if !display_matches {
        bail!(
            "expected display {}, observed {session}",
            matrix_cell(cli).display_server
        );
    }
    Ok(())
}

fn observed_host(host: &HostMetadata) -> ObservedHost {
    let distro_id = host.distribution.as_ref().map_or_else(
        || "unknown".to_owned(),
        |distribution| match (&distribution.id, &distribution.version) {
            (Some(id), Some(version)) => format!("{id}:{version}"),
            (Some(id), None) => id.clone(),
            (None, Some(version)) => format!("unknown:{version}"),
            (None, None) => "unknown".to_owned(),
        },
    );
    ObservedHost {
        distro_id: bounded_observation(&distro_id, "unknown", 128),
        distro_version: host.distribution.as_ref().and_then(|distribution| {
            distribution
                .version
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(|value| bounded_observation(value, "unknown", 64))
        }),
        kernel_release: bounded_observation(
            host.kernel.release.as_deref().unwrap_or("unknown"),
            "unknown",
            128,
        ),
        architecture: bounded_observation(&host.architecture, "unknown", 32),
        gpu_description: "not-observed-phase-1".to_owned(),
        driver_version: None,
        display_server: host
            .session
            .session_type
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| bounded_observation(value, "unknown", 32)),
        current_desktop: host
            .session
            .current_desktop
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| bounded_observation(value, "unknown", 128)),
        desktop_session: host
            .session
            .desktop_session
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| bounded_observation(value, "unknown", 128)),
    }
}

fn bounded_observation(value: &str, fallback: &str, max: usize) -> String {
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value.chars().take(max).collect()
    }
}

fn artifact_evidence(archive_sha256: &str, metadata: Option<&ArtifactMetadata>) -> Artifact {
    Artifact {
        outer_archive_sha256: if valid_sha256(archive_sha256) {
            archive_sha256.to_owned()
        } else {
            UNKNOWN_SHA256.to_owned()
        },
        payload_manifest_sha256: metadata.map_or_else(
            || UNKNOWN_SHA256.to_owned(),
            |value| value.payload_manifest_sha256.clone(),
        ),
        source_commit: metadata.map_or_else(
            || UNKNOWN_SOURCE_COMMIT.to_owned(),
            |value| value.source_commit.clone(),
        ),
        probe_version: metadata.map_or_else(
            || env!("CARGO_PKG_VERSION").to_owned(),
            |value| value.probe_version.clone(),
        ),
    }
}

fn graphics_evidence(cell: MatrixCell) -> GraphicsEvidence {
    GraphicsEvidence {
        renderer: RendererKind::NotDetermined,
        renderer_description: "not-run-phase-1".to_owned(),
        vulkan_loader: None,
        device: "not-run-phase-1".to_owned(),
        icd_library: None,
        vendor_id: None,
        device_id: None,
        driver_name: None,
        driver_version: None,
        device_type: None,
        software_renderer_detected: false,
        icd_manifests: Vec::new(),
        discovered_libraries: Vec::new(),
        vendor_specific_rules: if cell.gpu_vendor == GpuVendor::Nvidia {
            vec![VendorSpecificRule::nvidia_device_nodes(
                "Expose only concrete NVIDIA device nodes discovered on the physical host",
            )]
        } else {
            Vec::new()
        },
        distro_specific_rules: Vec::new(),
    }
}

fn failure_report(
    archive_sha256: &str,
    metadata: Option<&ArtifactMetadata>,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
    failure_stage: FailureStage,
    message: &str,
) -> Report {
    Report {
        schema: SchemaVersion::V2,
        artifact: artifact_evidence(archive_sha256, metadata),
        matrix_cell,
        observed_host: observed_host(host),
        containment: ContainmentEvidence {
            namespace_constructed: false,
            user_namespace_constructed: false,
            mount_namespace_constructed: false,
            user_namespace_id: None,
            mount_namespace_id: None,
            errno: None,
            host_paths_exposed: Vec::new(),
            forbidden_preparation: Vec::new(),
            substage: None,
            process_stderr: None,
        },
        runtime: RuntimeEvidence {
            libc_source: LibcSource::NotDetermined,
            libc_path: None,
            libc_version: None,
            host_glibc_imported: false,
            host_glibc_reason: None,
            host_glibc_paths: Vec::new(),
            host_glibc_path: None,
            interpreter: None,
            unresolved_symbols: Vec::new(),
            loader_diagnostics: Vec::new(),
        },
        graphics: graphics_evidence(matrix_cell),
        presentation: PresentationEvidence {
            frames_requested: 0,
            frames_presented: 0,
            validation_errors: 0,
            device_loss: false,
            present_mode: None,
            timings: None,
        },
        capture: CaptureEvidence {
            capture_rule_sha256: metadata.map_or_else(
                || UNKNOWN_SHA256.to_owned(),
                |value| value.capture_rule_sha256.clone(),
            ),
            captured_concrete_files: Vec::new(),
            capture_reasons: Vec::new(),
            captured_devices: Vec::new(),
            dependency_count: 0,
            vendor_specific_rule_count: u8::from(matrix_cell.gpu_vendor == GpuVendor::Nvidia),
            distro_specific_rule_count: 0,
            host_path_count: 0,
        },
        gates: GateResults {
            l0_0_containment: GateState::Fail,
            l0_1_launch: GateState::NotRun,
            l0_2_acceleration: GateState::NotRun,
            l0_3_present: GateState::NotRun,
            l0_4_churn: GateState::NotRun,
            l0_5_maintenance: GateState::NotRun,
        },
        classification: Classification::Fail,
        failure: Some(StructuredFailure {
            stage: failure_stage,
            code: failure_code(failure_stage).to_owned(),
            message: bounded_message(message),
            details: Vec::new(),
        }),
    }
}

fn phase_one_report(
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
    child: &ChildResult,
) -> Report {
    let mut report = failure_report(
        archive_sha256,
        Some(metadata),
        matrix_cell,
        host,
        FailureStage::Graphics,
        "Phase 1 established containment and controlled-glibc launch; graphics is not implemented",
    );
    report.containment.namespace_constructed = true;
    report.containment.user_namespace_constructed = true;
    report.containment.mount_namespace_constructed = true;
    report.containment.user_namespace_id = Some(child.user_namespace.clone());
    report.containment.mount_namespace_id = Some(child.mount_namespace.clone());
    report.runtime = RuntimeEvidence {
        libc_source: LibcSource::Controlled,
        libc_path: child
            .mapped_libc_paths
            .iter()
            .find(|path| path.contains("libc.so"))
            .cloned(),
        libc_version: Some(metadata.controlled_libc_version.clone()),
        host_glibc_imported: false,
        host_glibc_reason: None,
        host_glibc_paths: Vec::new(),
        host_glibc_path: None,
        interpreter: Some(metadata.child_interpreter.clone()),
        unresolved_symbols: Vec::new(),
        loader_diagnostics: child.mapped_libc_paths.clone(),
    };
    report.gates.l0_0_containment = GateState::Pass;
    report.gates.l0_1_launch = GateState::Pass;
    report
}

fn failure_code(stage: FailureStage) -> &'static str {
    match stage {
        FailureStage::Preflight => "preflight-failed",
        FailureStage::Containment => "containment-failed",
        FailureStage::Launch => "launch-failed",
        FailureStage::Graphics => "graphics-not-implemented",
        FailureStage::Presentation => "presentation-failed",
        FailureStage::Churn => "churn-failed",
        FailureStage::Maintenance => "maintenance-failed",
        FailureStage::Unknown => "unknown-failure",
    }
}

fn bounded_message(message: &str) -> String {
    message.chars().take(2048).collect()
}

fn read_child_result(path: &Path) -> Result<ChildResult> {
    let metadata =
        fs::metadata(path).with_context(|| format!("child did not produce {}", path.display()))?;
    if metadata.len() > 1024 * 1024 {
        bail!("child result exceeds 1 MiB");
    }
    let result: ChildResult =
        serde_json::from_reader(File::open(path)?).context("child result is malformed")?;
    if result.schema != "neuestar.child/v1"
        || result.architecture.is_empty()
        || result.architecture.len() > 32
        || result.user_namespace.len() > 128
        || result.mount_namespace.len() > 128
        || result.mapped_libc_paths.len() > 16
        || result
            .mapped_libc_paths
            .iter()
            .any(|path| path.len() > 1024 || !path.starts_with('/'))
    {
        bail!("child result violates its bounded schema");
    }
    Ok(result)
}

fn valid_successful_child_result(
    result: &ChildResult,
    parent_user_namespace: &str,
    parent_mount_namespace: &str,
) -> bool {
    result.contained
        && result.launch_reached_main
        && result.architecture == "x86_64"
        && namespace_changed(&result.user_namespace, parent_user_namespace, "user:")
        && namespace_changed(&result.mount_namespace, parent_mount_namespace, "mnt:")
        && result.failure.is_none()
        && result
            .mapped_libc_paths
            .iter()
            .any(|path| path.contains("libc.so"))
}

fn namespace_identity(path: &str) -> String {
    fs::read_link(path).map_or_else(
        |_| "unavailable".to_owned(),
        |identity| identity.display().to_string(),
    )
}

fn namespace_changed(child: &str, parent: &str, prefix: &str) -> bool {
    child.starts_with(prefix) && parent.starts_with(prefix) && child != parent
}

fn child_failure_detail(status: ExitStatus, result: Option<&ChildResult>) -> String {
    if let Some(failure) = result.and_then(|value| value.failure.as_ref()) {
        return bounded_message(&format!("{}: {}", failure.code, failure.explanation));
    }
    match status.code() {
        Some(code) => format!("bubblewrap or child exited with status {code}"),
        None => "bubblewrap or child terminated by signal".to_owned(),
    }
}

fn containment_substage(
    status: ExitStatus,
    child_result: Option<&ChildResult>,
) -> ContainmentSubstage {
    match child_result {
        Some(_) => ContainmentSubstage::ChildLaunch,
        None if status.success() => ContainmentSubstage::ChildResultMissing,
        None => ContainmentSubstage::HelperExecution,
    }
}

fn run_helper(
    command: &mut Command,
) -> Result<(ExitStatus, Option<String>), (ContainmentSubstage, anyhow::Error)> {
    command.stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        (
            ContainmentSubstage::HelperPreflight,
            anyhow::Error::new(error).context("failed to spawn bundled bubblewrap"),
        )
    })?;
    let stderr_thread = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(move || capture_process_stderr(stderr)));
    let status = child.wait().map_err(|error| {
        (
            ContainmentSubstage::HelperExecution,
            anyhow::Error::new(error).context("failed to wait for bundled bubblewrap"),
        )
    })?;
    let process_stderr = stderr_thread
        .and_then(|handle| handle.join().ok())
        .flatten();
    Ok((status, process_stderr))
}

/// Drains the helper/child stderr stream to EOF while retaining only a bounded
/// UTF-8-lossy prefix, so the recorder never stops consuming the pipe and
/// cannot perturb the measured process.
fn capture_process_stderr(stderr: ChildStderr) -> Option<String> {
    let mut reader = BufReader::new(stderr);
    let mut retained: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) if retained.len() < PROCESS_STDERR_MAX_BYTES => {
                let room = PROCESS_STDERR_MAX_BYTES - retained.len();
                retained.extend_from_slice(&chunk[..n.min(room)]);
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    let text = String::from_utf8_lossy(&retained);
    let bounded: String = text.chars().take(PROCESS_STDERR_MAX_CHARS).collect();
    (!bounded.is_empty()).then_some(bounded)
}

/// Refuses to start an attempt whose evidence directory already contains a
/// child result from an earlier attempt; historical files must never
/// influence a current classification.
fn ensure_fresh_evidence(child_result_path: &Path) -> Result<()> {
    if child_result_path.exists() {
        bail!(
            "evidence directory is not fresh: {} already exists; use a fresh evidence directory",
            child_result_path.display()
        );
    }
    Ok(())
}

/// Writes the preflight rejection for a contaminated evidence directory and
/// reports whether the attempt must stop before helper execution.
fn reject_stale_evidence(
    child_result_path: &Path,
    report_path: &Path,
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
) -> Result<bool> {
    match ensure_fresh_evidence(child_result_path) {
        Ok(()) => Ok(false),
        Err(error) => {
            write_bootstrap_failure(
                report_path,
                archive_sha256,
                Some(metadata),
                matrix_cell,
                host,
                FailureStage::Preflight,
                &format!("{error:#}"),
            )?;
            Ok(true)
        }
    }
}

/// Writes the containment failure report for a helper that could not start or
/// could not be waited on, using the substage the launcher can prove.
fn write_helper_failure(
    report_path: &Path,
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
    substage: ContainmentSubstage,
    error: &anyhow::Error,
) -> Result<()> {
    let mut report = failure_report(
        archive_sha256,
        Some(metadata),
        matrix_cell,
        host,
        FailureStage::Containment,
        &format!("failed to run bundled bubblewrap: {error:#}"),
    );
    report.containment.substage = Some(substage);
    report
        .validate()
        .context("generated failure report is invalid")?;
    write_json(report_path, &report)
}

// Run-context threading mirrors the existing report writers (failure_report,
// write_bootstrap_failure); the parameters are deliberately not folded into a
// struct to keep this diff scoped to the containment fixes.
#[allow(clippy::too_many_arguments)]
fn write_success_report(
    report_path: &Path,
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
    artifact_root: &Path,
    report_parent: &Path,
    child: &ChildResult,
    process_stderr: Option<String>,
) -> Result<()> {
    let mut report = phase_one_report(archive_sha256, metadata, matrix_cell, host, child);
    if let Some(stderr) = process_stderr {
        report.containment.process_stderr = Some(stderr);
    }
    record_host_paths(&mut report, artifact_root, report_parent);
    report.validate().context("generated report is invalid")?;
    write_json(report_path, &report)
}

#[allow(clippy::too_many_arguments)]
fn write_failure_report(
    report_path: &Path,
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
    artifact_root: &Path,
    report_parent: &Path,
    status: ExitStatus,
    child_result: Option<&ChildResult>,
    parent_user_namespace: &str,
    parent_mount_namespace: &str,
    process_stderr: Option<String>,
) -> Result<()> {
    let substage = containment_substage(status, child_result);
    let detail = child_failure_detail(status, child_result);
    let containment_constructed = child_result.is_some_and(|result| {
        result.contained
            && namespace_changed(&result.user_namespace, parent_user_namespace, "user:")
            && namespace_changed(&result.mount_namespace, parent_mount_namespace, "mnt:")
    });
    let failure_stage = if containment_constructed {
        FailureStage::Launch
    } else {
        FailureStage::Containment
    };
    let mut report = failure_report(
        archive_sha256,
        Some(metadata),
        matrix_cell,
        host,
        failure_stage,
        &detail,
    );
    report.containment.substage = Some(substage);
    if let Some(stderr) = process_stderr {
        report.containment.process_stderr = Some(stderr);
    }
    if containment_constructed {
        report.containment.namespace_constructed = true;
        report.containment.user_namespace_constructed = true;
        report.containment.mount_namespace_constructed = true;
        report.containment.user_namespace_id =
            child_result.map(|result| result.user_namespace.clone());
        report.containment.mount_namespace_id =
            child_result.map(|result| result.mount_namespace.clone());
        report.gates.l0_0_containment = GateState::Pass;
        report.gates.l0_1_launch = GateState::Fail;
        if let Some(result) = child_result {
            report
                .runtime
                .loader_diagnostics
                .clone_from(&result.mapped_libc_paths);
        }
        record_host_paths(&mut report, artifact_root, report_parent);
    }
    report
        .validate()
        .context("generated failure report is invalid")?;
    write_json(report_path, &report)
}

fn prepare_report_parent(report: &Path) -> Result<PathBuf> {
    let parent = report
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create report directory {}", parent.display()))?;
    parent
        .canonicalize()
        .with_context(|| format!("failed to resolve report directory {}", parent.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    let mut file = File::create(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.sync_all()?;
    fs::rename(&temporary, path).with_context(|| format!("failed to publish {}", path.display()))
}

fn write_bootstrap_failure(
    path: &Path,
    archive_sha256: &str,
    metadata: Option<&ArtifactMetadata>,
    matrix_cell: MatrixCell,
    host: &HostMetadata,
    stage: FailureStage,
    message: &str,
) -> Result<()> {
    let report = failure_report(archive_sha256, metadata, matrix_cell, host, stage, message);
    report
        .validate()
        .context("generated failure report is invalid")?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    write_json(path, &report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_failures_are_schema_valid_without_verified_metadata() {
        let host = HostMetadata {
            architecture: "x86_64".to_owned(),
            ..HostMetadata::default()
        };
        let report = failure_report(
            "invalid",
            None,
            MatrixCell {
                distro: Distro::Fedora,
                gpu_vendor: GpuVendor::Intel,
                display_server: DisplayServer::Wayland,
            },
            &host,
            FailureStage::Preflight,
            "artifact invalid",
        );
        report.validate().expect("valid failure report");
        assert_eq!(
            report.artifact.outer_archive_sha256,
            UNKNOWN_SHA256.to_owned()
        );
        assert_eq!(report.gates.l0_0_containment, GateState::Fail);
    }

    #[test]
    fn successful_child_requires_controlled_libc_evidence() {
        let mut child = ChildResult {
            schema: "neuestar.child/v1".to_owned(),
            contained: true,
            launch_reached_main: true,
            architecture: "x86_64".to_owned(),
            user_namespace: "user:[2]".to_owned(),
            mount_namespace: "mnt:[4]".to_owned(),
            mapped_libc_paths: Vec::new(),
            failure: None,
        };
        assert!(!valid_successful_child_result(
            &child, "user:[1]", "mnt:[3]"
        ));
        child.mapped_libc_paths.push("/lib/libc.so.6".to_owned());
        assert!(valid_successful_child_result(&child, "user:[1]", "mnt:[3]"));
    }

    #[test]
    fn declared_distro_and_display_must_match_observation() {
        let cli = Cli {
            report: PathBuf::from("report.json"),
            archive_sha256: None,
            distro: CliDistro::Fedora,
            gpu: CliGpu::Intel,
            display: CliDisplay::Wayland,
            dry_run: false,
            artifact_root: None,
        };
        let mut host = HostMetadata {
            architecture: "x86_64".to_owned(),
            distribution: Some(neuestar_host_inspect::DistributionMetadata {
                id: Some("fedora".to_owned()),
                version: Some("43".to_owned()),
                name: Some("Fedora Linux".to_owned()),
            }),
            ..HostMetadata::default()
        };
        host.session.session_type = Some("wayland".to_owned());
        assert!(validate_declared_host(&cli, &host).is_ok());

        host.distribution.as_mut().unwrap().id = Some("ubuntu".to_owned());
        assert!(validate_declared_host(&cli, &host).is_err());
    }

    #[test]
    fn containment_substage_is_derived_from_controlled_evidence() {
        let result = ChildResult {
            schema: "neuestar.child/v1".to_owned(),
            contained: false,
            launch_reached_main: true,
            architecture: "x86_64".to_owned(),
            user_namespace: "user:[2]".to_owned(),
            mount_namespace: "mnt:[3]".to_owned(),
            mapped_libc_paths: Vec::new(),
            failure: None,
        };
        let failed = Command::new("sh")
            .arg("-c")
            .arg("exit 71")
            .status()
            .expect("spawn sh");
        let succeeded = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .status()
            .expect("spawn sh");
        assert_eq!(
            containment_substage(failed, None),
            ContainmentSubstage::HelperExecution
        );
        assert_eq!(
            containment_substage(succeeded, None),
            ContainmentSubstage::ChildResultMissing
        );
        assert_eq!(
            containment_substage(failed, Some(&result)),
            ContainmentSubstage::ChildLaunch
        );
    }

    #[test]
    fn stale_child_result_blocks_a_fresh_attempt() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("child-result.json");
        fs::write(&path, "{\"schema\":\"neuestar.child/v1\"}").expect("stale fixture");
        assert!(
            ensure_fresh_evidence(&path).is_err(),
            "a stale child result must refuse the attempt"
        );
        fs::remove_file(&path).expect("cleanup");
        assert!(ensure_fresh_evidence(&path).is_ok());
    }

    #[test]
    fn process_stderr_capture_is_bounded_and_preserves_exit_status() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(
                "i=0; while [ $i -lt 4000 ]; do \
                 echo 0123456789abcdefghijklmnopqrstuvwxyz0123456789 >&2; \
                 i=$((i+1)); done; exit 71",
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let stderr = child.stderr.take().expect("piped stderr");
        let handle = thread::spawn(move || capture_process_stderr(stderr));
        let status = child.wait().expect("wait sh");
        let captured = handle.join().expect("stderr thread");
        assert_eq!(status.code(), Some(71), "exit status must be preserved");
        let text = captured.expect("captured stderr");
        assert!(text.chars().count() <= PROCESS_STDERR_MAX_CHARS);
        assert!(text.contains("0123456789abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn capture_plan_lists_only_user_and_mount_namespaces() {
        let cli = Cli {
            report: PathBuf::from("report.json"),
            archive_sha256: Some("a".repeat(64)),
            distro: CliDistro::Nixos,
            gpu: CliGpu::Nvidia,
            display: CliDisplay::Wayland,
            dry_run: false,
            artifact_root: None,
        };
        let plan = capture_plan(&cli, Path::new("/artifact"), Path::new("/evidence"));
        assert_eq!(plan.namespaces, vec!["user", "mount"]);
        assert_eq!(plan.application, "/artifact/app");
    }
}
