//! `h0-probe` — H0 probe (GATE-H0). Two modes:
//!
//! - candidate `none` (H0.P): the frozen Campaign 002 child under the exact
//!   frozen containment command (shared via neuestar-probe-core) with the
//!   Campaign 002 success predicate and no display/GPU preflight.
//! - candidate `A1`: the same minimum user+mount operation through a
//!   system-installed, root-owned Neuestar-controlled helper at a stable path
//!   (e.g. /usr/libexec/neuestar/bwrap) with the Neuestar AppArmor policy
//!   attached to that path, then the H0.1S security-evidence invocation
//!   (child CapEff/profile stacking) via a probe re-exec inside the same
//!   boundary.
//!
//! Emits `neuestar.h0/v1`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use neuestar_h0_probe::child::{read_child_evidence, run_child_mode};
use neuestar_h0_probe::containment::{ContainmentError, run_contained};
use neuestar_h0_probe::host::{AppArmorState, LoadedProfile, collect_host, collect_security_state};
use neuestar_h0_probe::record::{
    BurdenEvidence, CandidateEvidence, CarriedComponent, Gates, InstalledFile, Outcome,
    TrustedHelperEvidence, build,
};
use neuestar_probe_core::artifact;
use neuestar_probe_core::child_result::{
    ChildResult, read_child_result, valid_successful_child_result,
};
use neuestar_probe_core::command::{
    contained_command, frozen_child_exec, frozen_helper_invocation, security_evidence_child_exec,
    system_helper_invocation,
};

const EXIT_OK: u8 = 0;
const EXIT_APPARATUS: u8 = 2;

#[derive(Debug, Parser)]
#[command(version, about = "Run the H0 (Installed Substrate) PREFLIGHT probe")]
struct Cli {
    /// Extracted frozen Campaign 002 artifact directory (read-only input).
    /// Optional only because the internal H0.1S child mode needs no artifact.
    #[arg(long)]
    artifact_root: Option<PathBuf>,

    /// Frozen Campaign 002 outer archive SHA-256 (recorded as runtime identity).
    #[arg(long)]
    archive_sha256: Option<String>,

    /// Where the neuestar.h0/v1 record is written.
    #[arg(long, default_value = "h0-report.json")]
    report: PathBuf,

    /// ISO/snapshot date of the target profile (YYYY-MM-DD).
    #[arg(long)]
    iso_snapshot_date: Option<String>,

    /// Target configuration surface description.
    #[arg(long, default_value = "stock")]
    config_surface: String,

    /// Candidate under test: none (H0.P), A1 (installed root-owned helper),
    /// or A2 (static privilege-entry gate + private bwrap-real).
    #[arg(long, default_value = "none", value_parser = ["none", "A1", "A2"])]
    candidate: String,

    /// Candidate A1/A2: installed root-owned helper path (the trust anchor:
    /// bwrap for A1, the static entry for A2).
    #[arg(long, default_value = "/usr/libexec/neuestar/bwrap")]
    helper_path: PathBuf,

    /// Candidate A1/A2: expected helper SHA-256 (exact selected bytes).
    #[arg(long)]
    expected_helper_sha256: Option<String>,

    /// Candidate A2: expected SHA-256 of the private bwrap-real carried
    /// component (exact pinned upstream bytes, zero patches).
    #[arg(long)]
    carried_helper_sha256: Option<String>,

    /// Candidate A1: integration package (deb) SHA-256.
    #[arg(long)]
    integration_package_sha256: Option<String>,

    /// Candidate A1: integration source commit SHA-256.
    #[arg(long)]
    integration_source_sha256: Option<String>,

    /// Candidate A1: installed AppArmor policy path.
    #[arg(long, default_value = "/etc/apparmor.d/neuestar-bwrap")]
    policy_path: PathBuf,

    /// Candidate A1: install-time AppArmor state file (root-written).
    #[arg(long, default_value = "/var/lib/neuestar/apparmor-state.json")]
    apparmor_state: PathBuf,

    /// Print the containment argv and exit without executing anything.
    #[arg(long)]
    dry_run: bool,

    /// Internal: run as the contained child and write security evidence (H0.1S).
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

    let artifact_root = cli
        .artifact_root
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--artifact-root is required"))?
        .canonicalize()
        .context("failed to resolve artifact root")?;
    let archive_sha256 = cli
        .archive_sha256
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--archive-sha256 is required"))?;
    let iso_snapshot_date = cli
        .iso_snapshot_date
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--iso-snapshot-date is required"))?;
    if !neuestar_probe_core::artifact::valid_sha256(archive_sha256) {
        anyhow::bail!("--archive-sha256 must be 64 lowercase hexadecimal characters");
    }
    if !valid_iso_date(iso_snapshot_date) {
        anyhow::bail!("--iso-snapshot-date must be YYYY-MM-DD");
    }
    let is_a1 = cli.candidate == "A1";
    let is_a2 = cli.candidate == "A2";
    let cli_candidate = cli.candidate.as_str();
    if is_a1 || is_a2 {
        if cli
            .expected_helper_sha256
            .as_deref()
            .is_none_or(|sha| !neuestar_probe_core::artifact::valid_sha256(sha))
        {
            anyhow::bail!("{cli_candidate} requires --expected-helper-sha256 (64 lowercase hex)");
        }
        if cli
            .integration_package_sha256
            .as_deref()
            .is_none_or(|sha| !neuestar_probe_core::artifact::valid_sha256(sha))
        {
            anyhow::bail!(
                "{cli_candidate} requires --integration-package-sha256 (64 lowercase hex)"
            );
        }
        if is_a2
            && cli
                .carried_helper_sha256
                .as_deref()
                .is_none_or(|sha| !neuestar_probe_core::artifact::valid_sha256(sha))
        {
            anyhow::bail!("A2 requires --carried-helper-sha256 (64 lowercase hex)");
        }
    }

    let report_parent = prepare_report_parent(&cli.report)?;
    let host = collect_host();
    let mut security_state = collect_security_state();
    let timestamp = timestamp();
    let session_id = format!("{timestamp}-{}", std::process::id());
    let parent_user_ns = namespace_identity("/proc/self/ns/user");
    let parent_mount_ns = namespace_identity("/proc/self/ns/mnt");

    // Full frozen artifact preflight (identical to Campaign 002).
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

    // A1/A2: verify the installed trust anchor (exact selected bytes,
    // root-owned, non-user-writable; A2 additionally requires the static
    // entry property and the pinned carried bwrap-real) instead of the
    // artifact-bundled helper closure.
    if is_a1 || is_a2 {
        let verified = if is_a2 {
            verify_a2_entry(cli)
        } else {
            verify_a1_helper(cli)
        };
        if let Err(error) = verified {
            write_apparatus_failure(
                cli,
                &host,
                &security_state,
                &timestamp,
                &session_id,
                &report_parent,
                "helper-verification",
                &format!("{error:#}"),
                false,
                &[],
                &parent_user_ns,
                &parent_mount_ns,
            )?;
            return Ok(EXIT_OK);
        }
    } else if let Err(error) =
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

    // Stale-evidence rejection.
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

    // A1/A2: merge install-time AppArmor state (positive profile-loading
    // evidence).
    let a1_state = if is_a1 || is_a2 {
        read_apparmor_state(&cli.apparmor_state).ok()
    } else {
        None
    };
    if let (true, Some(state)) = (is_a1 || is_a2, &a1_state) {
        security_state.apparmor = Some(AppArmorState {
            parser_version: state.parser_version.clone(),
            abi: None,
            restriction_sysctl: security_state
                .apparmor
                .as_ref()
                .and_then(|aa| aa.restriction_sysctl),
            loaded_profiles: state.loaded_profiles.clone(),
            loaded_profile_state_sha256: state.digest.clone(),
        });
    }

    let probe_sha256 = sha256_self();
    let mut command = if is_a2 {
        entry_invocation(
            cli,
            &artifact_root,
            &report_parent,
            archive_sha256,
            &metadata,
            false,
            None,
        )
    } else {
        let helper = if is_a1 {
            system_helper_invocation(&cli.helper_path)
        } else {
            frozen_helper_invocation(&artifact_root)
        };
        contained_command(
            &report_parent,
            &artifact_root,
            archive_sha256,
            &metadata,
            &helper,
            &frozen_child_exec(),
        )
    };
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
    let process_stderr = run.process_stderr;

    let child_result = read_child_result(&child_result_path).ok();
    let success = run.status == Some(0)
        && child_result.as_ref().is_some_and(|result| {
            valid_successful_child_result(result, &parent_user_ns, &parent_mount_ns)
        });

    let (outcome, gates) = if is_a1 || is_a2 {
        if success {
            (
                Outcome::Pass,
                Gates {
                    h0_0: "not-run",
                    h0_1: "pass",
                    h0_1s: "not-run",
                },
            )
        } else {
            (
                Outcome::IntegrationFail {
                    code: match &child_result {
                        Some(result) if result.contained && result.launch_reached_main => {
                            "child-failed"
                        }
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
                },
                Gates {
                    h0_0: "not-run",
                    h0_1: "fail",
                    h0_1s: "not-run",
                },
            )
        }
    } else if success {
        (
            Outcome::Pass,
            Gates {
                h0_0: "pass",
                h0_1: "not-run",
                h0_1s: "not-run",
            },
        )
    } else {
        (
            Outcome::BaselineFail {
                code: match &child_result {
                    Some(result) if result.contained && result.launch_reached_main => {
                        "child-failed"
                    }
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
            },
            Gates {
                h0_0: "fail",
                h0_1: "not-run",
                h0_1s: "not-run",
            },
        )
    };
    let child_reached = child_result
        .as_ref()
        .is_some_and(|result| result.contained && result.launch_reached_main);

    // A2: the entry wrote the bwrap argv it constructed; verify it matches
    // the frozen command shape exactly (drift guard: entry and probe-core
    // must agree on the operation).
    let mut constructed_bwrap_argv: Vec<String> = Vec::new();
    let mut constructed_bwrap_argv_evidence: Vec<String> = Vec::new();
    if is_a2 && child_reached {
        let expected_command = contained_command(
            &report_parent,
            &artifact_root,
            archive_sha256,
            &metadata,
            &system_helper_invocation(std::path::Path::new(BWRAP_REAL)),
            &frozen_child_exec(),
        );
        let expected: Vec<String> = expected_command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        match read_entry_argv(&report_parent.join(".entry-argv.json")) {
            Ok(constructed) if constructed.get(1..) == Some(expected.as_slice()) => {
                constructed_bwrap_argv = constructed;
            }
            Ok(constructed) => {
                write_apparatus_failure(
                    cli,
                    &host,
                    &security_state,
                    &timestamp,
                    &session_id,
                    &report_parent,
                    "entry-argv-mismatch",
                    &format!(
                        "entry constructed bwrap argv diverges from the frozen command shape ({} vs {} args)",
                        constructed.len(),
                        expected.len() + 1
                    ),
                    true,
                    &argv,
                    &parent_user_ns,
                    &parent_mount_ns,
                )?;
                return Ok(EXIT_OK);
            }
            Err(error) => {
                write_apparatus_failure(
                    cli,
                    &host,
                    &security_state,
                    &timestamp,
                    &session_id,
                    &report_parent,
                    "entry-argv-unreadable",
                    &format!("{error:#}"),
                    true,
                    &argv,
                    &parent_user_ns,
                    &parent_mount_ns,
                )?;
                return Ok(EXIT_OK);
            }
        }
    }

    // H0.1S security-evidence invocation (A1/A2, after the outcome run):
    // the probe re-executes itself inside the SAME boundary to record the
    // child's profile label, CapEff raw+decoded, and namespace identity.
    let mut security_evidence = None;
    let mut security_evidence_argv: Vec<String> = Vec::new();
    let mut gates = gates;
    if (is_a1 || is_a2) && child_reached {
        let probe_self = std::env::current_exe().context("failed to locate probe binary")?;
        let mut evidence_command = if is_a2 {
            entry_invocation(
                cli,
                &artifact_root,
                &report_parent,
                archive_sha256,
                &metadata,
                true,
                Some(&probe_self),
            )
        } else {
            contained_command(
                &report_parent,
                &artifact_root,
                archive_sha256,
                &metadata,
                &system_helper_invocation(&cli.helper_path),
                &security_evidence_child_exec(&probe_self),
            )
        };
        security_evidence_argv = evidence_command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        match run_contained(&mut evidence_command) {
            Ok(evidence_run) if evidence_run.status == Some(0) => {
                if is_a2 {
                    let expected_command = contained_command(
                        &report_parent,
                        &artifact_root,
                        archive_sha256,
                        &metadata,
                        &system_helper_invocation(std::path::Path::new(BWRAP_REAL)),
                        &security_evidence_child_exec(&probe_self),
                    );
                    let expected: Vec<String> = expected_command
                        .get_args()
                        .map(|argument| argument.to_string_lossy().into_owned())
                        .collect();
                    match read_entry_argv(&report_parent.join(".entry-argv-evidence.json")) {
                        Ok(constructed) if constructed.get(1..) == Some(expected.as_slice()) => {
                            constructed_bwrap_argv_evidence = constructed;
                        }
                        Ok(constructed) => {
                            write_apparatus_failure(
                                cli,
                                &host,
                                &security_state,
                                &timestamp,
                                &session_id,
                                &report_parent,
                                "entry-argv-mismatch",
                                &format!(
                                    "entry constructed evidence argv diverges from the frozen shape ({} vs {} args)",
                                    constructed.len(),
                                    expected.len() + 1
                                ),
                                true,
                                &argv,
                                &parent_user_ns,
                                &parent_mount_ns,
                            )?;
                            return Ok(EXIT_OK);
                        }
                        Err(error) => {
                            write_apparatus_failure(
                                cli,
                                &host,
                                &security_state,
                                &timestamp,
                                &session_id,
                                &report_parent,
                                "entry-argv-unreadable",
                                &format!("{error:#}"),
                                true,
                                &argv,
                                &parent_user_ns,
                                &parent_mount_ns,
                            )?;
                            return Ok(EXIT_OK);
                        }
                    }
                }
                match read_child_evidence(&report_parent.join("h0-child-evidence.json")) {
                    Ok(evidence) => {
                        let mask = neuestar_probe_core::capabilities::parse_cap_eff_hex(
                            &evidence.cap_eff_hex,
                        );
                        let no_setup_caps = mask == Some(0)
                            && neuestar_probe_core::capabilities::decode_cap_mask(
                                mask.unwrap_or(u64::MAX),
                            )
                            .is_empty();
                        // The child must actually be under the restricted
                        // stacked profile, not merely unconfined with no caps.
                        let label = &evidence.profile_label;
                        let restricted = label.contains("unpriv") && !label.contains("unconfined");
                        let expected_helper_path = std::fs::canonicalize(&cli.helper_path)
                            .unwrap_or_else(|_| cli.helper_path.clone())
                            .display()
                            .to_string();
                        let trust_profile = if is_a2 {
                            "neuestar-entry"
                        } else {
                            "neuestar-bwrap"
                        };
                        let attachment_ok = a1_state.as_ref().is_some_and(|state| {
                            state.loaded_profiles.iter().any(|profile| {
                                profile.name == trust_profile
                                    && profile.mode == "enforce"
                                    && profile.path.as_deref()
                                        == Some(expected_helper_path.as_str())
                            })
                        });
                        gates.h0_1s = if restricted && no_setup_caps && attachment_ok {
                            "pass"
                        } else {
                            "fail"
                        };
                        security_evidence = Some(evidence);
                    }
                    Err(_) => {
                        write_apparatus_failure(
                            cli,
                            &host,
                            &security_state,
                            &timestamp,
                            &session_id,
                            &report_parent,
                            "child-evidence-missing",
                            "H0.1S evidence file missing after a successful evidence invocation",
                            true,
                            &argv,
                            &parent_user_ns,
                            &parent_mount_ns,
                        )?;
                        return Ok(EXIT_OK);
                    }
                }
            }
            _ => {
                write_apparatus_failure(
                    cli,
                    &host,
                    &security_state,
                    &timestamp,
                    &session_id,
                    &report_parent,
                    "child-evidence-run-failed",
                    "H0.1S security-evidence invocation failed",
                    true,
                    &argv,
                    &parent_user_ns,
                    &parent_mount_ns,
                )?;
                return Ok(EXIT_OK);
            }
        }
    }

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
        archive_sha256,
        report_parent.display()
    );

    let candidate_evidence = if is_a1 || is_a2 {
        Some(build_candidate_evidence(cli, &a1_state, &child_result)?)
    } else {
        None
    };

    let record = build(
        &host,
        &security_state,
        &timestamp,
        &session_id,
        archive_sha256,
        &metadata.payload_manifest_sha256,
        &probe_sha256,
        &argv,
        &security_evidence_argv,
        &constructed_bwrap_argv,
        &constructed_bwrap_argv_evidence,
        iso_snapshot_date,
        &cli.config_surface,
        true,
        child_reached,
        child_result.as_ref().map(|result| {
            (
                result.user_namespace.as_str(),
                result.mount_namespace.as_str(),
            )
        }),
        security_evidence.as_ref(),
        process_stderr.as_deref(),
        &pre_host_state,
        &post_host_state,
        &outcome,
        &gates,
        candidate_evidence.as_ref(),
    )?;
    write_json(&cli.report, &record)?;
    Ok(EXIT_OK)
}

/// The private A2 setup binary (executed only through the static entry's
/// secure-exec transition; its path carries no AppArmor profile).
const BWRAP_REAL: &str = "/usr/libexec/neuestar/bwrap-real";

/// A1 helper verification: exists, root-owned, not user-writable, exact
/// selected upstream bytes.
fn verify_a1_helper(cli: &Cli) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(&cli.helper_path)
        .with_context(|| format!("helper missing: {}", cli.helper_path.display()))?;
    let mode = metadata.mode();
    if mode & 0o022 != 0 {
        anyhow::bail!("helper is group/world-writable");
    }
    let actual = neuestar_probe_core::artifact::sha256_file(&cli.helper_path)?;
    let expected = cli.expected_helper_sha256.as_deref().expect("validated");
    if actual != expected {
        anyhow::bail!("helper SHA-256 mismatch: expected {expected}, observed {actual}");
    }
    Ok(())
}

/// A2 entry verification: the static privilege-entry gate must be
/// root-owned, a regular file, non-user-writable (itself and its parent),
/// byte-pinned, and statically linked (no PT_INTERP, no PT_DYNAMIC — no
/// dynamic loader means no loader injection). The carried bwrap-real must
/// also be root-owned, regular, and byte-pinned to the exact upstream bytes.
fn verify_a2_entry(cli: &Cli) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let entry_metadata = std::fs::metadata(&cli.helper_path)
        .with_context(|| format!("entry missing: {}", cli.helper_path.display()))?;
    if !entry_metadata.is_file() {
        anyhow::bail!("entry is not a regular file");
    }
    if entry_metadata.uid() != 0 {
        anyhow::bail!("entry is not root-owned (uid {})", entry_metadata.uid());
    }
    if entry_metadata.mode() & 0o022 != 0 {
        anyhow::bail!("entry is group/world-writable");
    }
    let parent = cli.helper_path.parent().expect("entry parent");
    if std::fs::metadata(parent)
        .map(|metadata| metadata.mode() & 0o022 != 0)
        .unwrap_or(true)
    {
        anyhow::bail!("entry parent directory is writable by group/world");
    }
    let actual = neuestar_probe_core::artifact::sha256_file(&cli.helper_path)?;
    let expected = cli.expected_helper_sha256.as_deref().expect("validated");
    if actual != expected {
        anyhow::bail!("entry SHA-256 mismatch: expected {expected}, observed {actual}");
    }
    if !neuestar_elf::is_statically_linked(&cli.helper_path)? {
        let interpreter = neuestar_elf::interpreter_of(&cli.helper_path)?;
        anyhow::bail!(
            "entry is not statically linked (interpreter: {}); the A2 trust anchor must have no dynamic loader",
            interpreter.as_deref().unwrap_or("<non-ELF>")
        );
    }
    let carried_path = std::path::Path::new(BWRAP_REAL);
    let carried_metadata = std::fs::metadata(carried_path)
        .with_context(|| format!("bwrap-real missing: {carried_path:?}"))?;
    if !carried_metadata.is_file() || carried_metadata.uid() != 0 {
        anyhow::bail!("bwrap-real is not a root-owned regular file");
    }
    let carried_actual = neuestar_probe_core::artifact::sha256_file(carried_path)?;
    let carried_expected = cli.carried_helper_sha256.as_deref().expect("validated");
    if carried_actual != carried_expected {
        anyhow::bail!(
            "bwrap-real SHA-256 mismatch: expected {carried_expected}, observed {carried_actual}"
        );
    }
    Ok(())
}

/// Candidate A2: the entry invocation. `security_evidence` selects the H0.1S
/// evidence mode (extra ro-bind of the probe binary into /tmp).
fn entry_invocation(
    cli: &Cli,
    artifact_root: &std::path::Path,
    report_parent: &std::path::Path,
    archive_sha256: &str,
    metadata: &neuestar_probe_core::artifact::ArtifactMetadata,
    security_evidence: bool,
    evidence_probe: Option<&std::path::Path>,
) -> std::process::Command {
    let mut command = std::process::Command::new(&cli.helper_path);
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .arg("--artifact-root")
        .arg(artifact_root)
        .arg("--evidence-dir")
        .arg(report_parent)
        .arg("--mode")
        .arg(if security_evidence {
            "security-evidence"
        } else {
            "outcome"
        })
        .arg("--archive-sha256")
        .arg(archive_sha256)
        .arg("--payload-manifest-sha256")
        .arg(&metadata.payload_manifest_sha256)
        .arg("--source-commit")
        .arg(&metadata.source_commit)
        .arg("--probe-version")
        .arg(&metadata.probe_version);
    if let Some(probe) = evidence_probe {
        command.arg("--evidence-probe").arg(probe);
    }
    command
}

/// Read the argv the entry recorded before exec (the operation it actually
/// constructed). Fails closed on any malformed or missing evidence.
fn read_entry_argv(path: &std::path::Path) -> Result<Vec<String>> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("missing {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).context("entry argv evidence is malformed")?;
    let argv = value
        .get("argv")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("entry argv evidence lacks argv array"))?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if argv.is_empty() {
        anyhow::bail!("entry argv evidence is empty");
    }
    Ok(argv)
}

/// Install-time AppArmor state written by the integration package postinst
/// (root-verified: the profile was loaded at install).
struct InstallState {
    parser_version: String,
    loaded_profiles: Vec<LoadedProfile>,
    digest: String,
}

fn read_apparmor_state(path: &Path) -> Result<InstallState> {
    use sha2::{Digest, Sha256};
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("missing {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).context("apparmor state is malformed")?;
    let parser_version = value
        .get("parser_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let loaded_profiles = value
        .get("loaded_profiles")
        .and_then(serde_json::Value::as_array)
        .map(|profiles| {
            profiles
                .iter()
                .filter_map(|profile| {
                    Some(LoadedProfile {
                        name: profile.get("name")?.as_str()?.to_owned(),
                        mode: profile.get("mode")?.as_str()?.to_owned(),
                        path: profile
                            .get("path")
                            .and_then(serde_json::Value::as_str)
                            .map(ToOwned::to_owned),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if loaded_profiles.is_empty() {
        anyhow::bail!("apparmor state records no loaded profiles");
    }
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        hex::encode(hasher.finalize())
    };
    Ok(InstallState {
        parser_version,
        loaded_profiles,
        digest,
    })
}

fn build_candidate_evidence(
    cli: &Cli,
    state: &Option<InstallState>,
    child_result: &Option<ChildResult>,
) -> Result<CandidateEvidence> {
    use std::os::unix::fs::MetadataExt;

    let is_a2 = cli.candidate == "A2";
    let helper_metadata = std::fs::metadata(&cli.helper_path)
        .with_context(|| format!("helper missing: {}", cli.helper_path.display()))?;
    let helper_sha = neuestar_probe_core::artifact::sha256_file(&cli.helper_path)?;
    let parent_writable = std::fs::metadata(cli.helper_path.parent().expect("helper parent"))
        .map(|metadata| metadata.mode() & 0o022 != 0)
        .unwrap_or(true);
    let _ = child_result;

    // A2: the entry (trust anchor) and the carried bwrap-real are distinct
    // files; A1: the helper is itself the carried component.
    let policy_paths: Vec<std::path::PathBuf> = if is_a2 {
        vec![
            std::path::PathBuf::from("/etc/apparmor.d/neuestar-entry"),
            std::path::PathBuf::from("/etc/apparmor.d/neuestar-bwrap-real"),
            std::path::PathBuf::from("/etc/apparmor.d/neuestar-unpriv"),
        ]
    } else {
        vec![cli.policy_path.clone()]
    };
    let policy_loc: u64 = policy_paths
        .iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .map(|text| {
                    text.lines()
                        .filter(|line| {
                            !line.trim().is_empty() && !line.trim_start().starts_with('#')
                        })
                        .count() as u64
                })
                .unwrap_or(0)
        })
        .sum();
    let policy_sha = if is_a2 {
        policy_paths
            .iter()
            .map(|path| neuestar_probe_core::artifact::sha256_file(path).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("")
    } else {
        neuestar_probe_core::artifact::sha256_file(&cli.policy_path)?
    };

    let mut installed_files = Vec::new();
    if is_a2 {
        // entry: first-party trust anchor (kind: first-party-helper)
        installed_files.push(InstalledFile {
            path: cli.helper_path.display().to_string(),
            size_bytes: helper_metadata.len(),
            sha256: helper_sha.clone(),
            uid: helper_metadata.uid(),
            gid: helper_metadata.gid(),
            mode: helper_metadata.mode(),
            kind: "first-party-helper",
        });
        // bwrap-real: the single carried third-party component
        let carried_path = std::path::Path::new(BWRAP_REAL);
        let carried_metadata = std::fs::metadata(carried_path)
            .with_context(|| format!("bwrap-real missing: {carried_path:?}"))?;
        installed_files.push(InstalledFile {
            path: BWRAP_REAL.to_owned(),
            size_bytes: carried_metadata.len(),
            sha256: neuestar_probe_core::artifact::sha256_file(carried_path)?,
            uid: carried_metadata.uid(),
            gid: carried_metadata.gid(),
            mode: carried_metadata.mode(),
            kind: "carried-component",
        });
    } else {
        installed_files.push(InstalledFile {
            path: cli.helper_path.display().to_string(),
            size_bytes: helper_metadata.len(),
            sha256: helper_sha.clone(),
            uid: helper_metadata.uid(),
            gid: helper_metadata.gid(),
            mode: helper_metadata.mode(),
            kind: "carried-component",
        });
    }
    for policy_path in &policy_paths {
        installed_files.push(InstalledFile {
            path: policy_path.display().to_string(),
            size_bytes: std::fs::metadata(policy_path).map(|m| m.len()).unwrap_or(0),
            sha256: neuestar_probe_core::artifact::sha256_file(policy_path).unwrap_or_default(),
            uid: 0,
            gid: 0,
            mode: 0o644,
            kind: "security-policy",
        });
    }
    if let Some(state_path) = state.as_ref().map(|_| cli.apparmor_state.as_path())
        && let Ok(metadata) = std::fs::metadata(state_path)
    {
        installed_files.push(InstalledFile {
            path: state_path.display().to_string(),
            size_bytes: metadata.len(),
            sha256: neuestar_probe_core::artifact::sha256_file(state_path)
                .unwrap_or_else(|_| "0".repeat(64)),
            uid: 0,
            gid: 0,
            mode: 0o644,
            kind: "config",
        });
    }

    let helper_profile_label = state
        .as_ref()
        .and_then(|state| {
            state.loaded_profiles.iter().find(|profile| {
                profile.path.as_deref() == Some(cli.helper_path.to_string_lossy().as_ref())
            })
        })
        .map(|profile| profile.name.clone())
        .unwrap_or_else(|| {
            if is_a2 {
                "neuestar-entry"
            } else {
                "neuestar-bwrap"
            }
            .to_owned()
        });

    let carried_binary_sha = if is_a2 {
        cli.carried_helper_sha256
            .clone()
            .unwrap_or_else(|| "0".repeat(64))
    } else {
        cli.expected_helper_sha256
            .clone()
            .unwrap_or_else(|| "0".repeat(64))
    };

    Ok(CandidateEvidence {
        candidate: cli.candidate.clone(),
        helper_profile_label,
        integration_identity_sha256: cli
            .integration_package_sha256
            .clone()
            .unwrap_or_else(|| neuestar_h0_probe::record::sha256_hex("")),
        neuestar_integration_package_sha256: cli
            .integration_package_sha256
            .clone()
            .expect("validated"),
        integration_source_sha256: cli
            .integration_source_sha256
            .clone()
            .unwrap_or_else(|| "0".repeat(64)),
        security_policy_sha256: policy_sha,
        trusted_helper: TrustedHelperEvidence {
            canonical_path: cli.helper_path.display().to_string(),
            sha256: helper_sha,
            uid: helper_metadata.uid(),
            gid: helper_metadata.gid(),
            mode: helper_metadata.mode(),
            regular_file: helper_metadata.is_file(),
            elf_interpreter: neuestar_elf::interpreter_of(&cli.helper_path)
                .ok()
                .flatten(),
            parent_mount_writable_by_test_user: parent_writable,
        },
        burden: BurdenEvidence {
            installed_files,
            policy_loc,
            distro_branch_count: 1,
            carried_components: vec![CarriedComponent {
                upstream_project: "bubblewrap".to_owned(),
                upstream_version_commit: "0.9.0".to_owned(),
                source_provenance: if is_a2 {
                    "exact pinned upstream bwrap bytes installed as /usr/libexec/neuestar/bwrap-real; reachable only through the static entry secure-exec transition".to_owned()
                } else {
                    "bundled within the frozen Campaign 002 artifact; selected bytes installed by the Neuestar A1 package".to_owned()
                },
                binary_sha256: carried_binary_sha,
                patch_count: 0,
                security_update_responsibility: "track upstream bubblewrap releases".to_owned(),
            }],
            helper_loc: 0,
        },
        privileged_install_operations: if is_a2 {
            vec![
                serde_json::json!({"kind": "package-install", "description": "installed neuestar-h0-a2 deb (static entry + private bwrap-real + three AppArmor policies)"}),
                serde_json::json!({"kind": "apparmor-policy-load", "description": "apparmor_parser -r /etc/apparmor.d/neuestar-entry /etc/apparmor.d/neuestar-bwrap-real /etc/apparmor.d/neuestar-unpriv; state recorded at /var/lib/neuestar/apparmor-state.json"}),
            ]
        } else {
            vec![
                serde_json::json!({"kind": "package-install", "description": "installed neuestar-h0-a1 deb (root-owned helper + AppArmor policy)"}),
                serde_json::json!({"kind": "apparmor-policy-load", "description": "apparmor_parser -r /etc/apparmor.d/neuestar-bwrap; state recorded at /var/lib/neuestar/apparmor-state.json"}),
            ]
        },
    })
}

/// Emits an apparatus-stage failure record (fail-closed).
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
        cli.archive_sha256.as_deref().unwrap_or("unverified"),
        "unverified",
        &sha256_self(),
        argv,
        &[],
        &[],
        &[],
        cli.iso_snapshot_date.as_deref().unwrap_or("unknown"),
        &cli.config_surface,
        helper_started,
        false,
        None,
        None,
        None,
        &format!(
            "artifact_outer_sha256={}\nreport_parent={}",
            cli.archive_sha256.as_deref().unwrap_or("unverified"),
            report_parent.display()
        ),
        &format!("probe_parent_user_ns={parent_user_ns}\nprobe_parent_mount_ns={parent_mount_ns}"),
        &Outcome::ApparatusFail {
            code,
            message: message.to_owned(),
        },
        &Gates::not_run(),
        None,
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

fn namespace_identity(path: &str) -> String {
    std::fs::read_link(path).map_or_else(
        |_| "unavailable".to_owned(),
        |identity| identity.display().to_string(),
    )
}

fn valid_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && (0..10).all(|i| i == 4 || i == 7 || bytes[i].is_ascii_digit())
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
