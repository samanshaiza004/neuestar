//! `neuestar.h0/v1` record assembly. The record is validated against
//! schema/h0.schema.json by `h0-check`; this module only guarantees the shape.

use anyhow::Result;
use serde_json::{Value, json};

use crate::child::ChildEvidence;
use crate::host::{HostFacts, SecurityState};

pub const H0_SCHEMA: &str = "neuestar.h0/v1";

/// The attempt outcome. Apparatus failures (before or around containment)
/// must not be recorded as a failed gate: gates only describe what actually
/// ran.
#[derive(Debug, Clone)]
pub enum Outcome {
    Pass,
    /// The frozen child ran under the boundary and failed (H0.0 for the
    /// unintegrated probe; H0.1 for an integrated candidate).
    BaselineFail {
        code: &'static str,
        message: String,
    },
    IntegrationFail {
        code: &'static str,
        message: String,
    },
    ApparatusFail {
        code: &'static str,
        message: String,
    },
}

/// Candidate-specific evidence (Candidate A1; absent for candidate none).
#[derive(Debug, Clone)]
pub struct CandidateEvidence {
    pub candidate: &'static str,
    pub integration_identity_sha256: String,
    pub neuestar_integration_package_sha256: String,
    pub integration_source_sha256: String,
    pub security_policy_sha256: String,
    pub trusted_helper: TrustedHelperEvidence,
    pub burden: BurdenEvidence,
    pub privileged_install_operations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrustedHelperEvidence {
    pub canonical_path: String,
    pub sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub parent_mount_writable_by_test_user: bool,
}

#[derive(Debug, Clone)]
pub struct BurdenEvidence {
    pub installed_files: Vec<InstalledFile>,
    pub policy_loc: u64,
    pub distro_branch_count: u64,
    pub carried_components: Vec<CarriedComponent>,
    pub helper_loc: u64,
}

#[derive(Debug, Clone)]
pub struct InstalledFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub kind: &'static str,
}

#[derive(Debug, Clone)]
pub struct CarriedComponent {
    pub upstream_project: String,
    pub upstream_version_commit: String,
    pub source_provenance: String,
    pub binary_sha256: String,
    pub patch_count: u64,
    pub security_update_responsibility: String,
}

/// Gate results: only the gates that actually ran are pass/fail; everything
/// else is not-run.
#[derive(Debug, Clone)]
pub struct Gates {
    pub h0_0: &'static str,
    pub h0_1: &'static str,
    pub h0_1s: &'static str,
}

impl Gates {
    pub fn not_run() -> Self {
        Gates {
            h0_0: "not-run",
            h0_1: "not-run",
            h0_1s: "not-run",
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    host: &HostFacts,
    security_state: &SecurityState,
    timestamp: &str,
    session_id: &str,
    archive_sha256: &str,
    payload_sha256: &str,
    probe_sha256: &str,
    containment_argv: &[String],
    iso_snapshot_date: &str,
    config_surface: &str,
    helper_started: bool,
    child_reached: bool,
    child_ns: Option<(&str, &str)>,
    security_evidence: Option<&ChildEvidence>,
    process_stderr: Option<&str>,
    pre_host_state: &str,
    post_host_state: &str,
    outcome: &Outcome,
    gates: &Gates,
    candidate: Option<&CandidateEvidence>,
) -> Result<Value> {
    let (classification, failure) = match outcome {
        Outcome::Pass => ("pass", None),
        Outcome::BaselineFail { code, message } => (
            "fail",
            Some(json!({
                "stage": "baseline",
                "code": code,
                "message": bounded(message, 2048),
            })),
        ),
        Outcome::IntegrationFail { code, message } => (
            "fail",
            Some(json!({
                "stage": "integration",
                "code": code,
                "message": bounded(message, 2048),
            })),
        ),
        Outcome::ApparatusFail { code, message } => (
            "fail",
            Some(json!({
                "stage": "apparatus",
                "code": code,
                "message": bounded(message, 2048),
            })),
        ),
    };

    let execution = {
        let mut value = json!({
            "helper_started": helper_started,
            "child_reached": child_reached,
        });
        if let Some((user_ns, mount_ns)) = child_ns {
            value["child_user_namespace_id"] = json!(user_ns);
            value["child_mount_namespace_id"] = json!(mount_ns);
        }
        if let Some(evidence) = security_evidence {
            value["child_profile_label"] = json!(evidence.profile_label);
            let mask = neuestar_probe_core::capabilities::parse_cap_eff_hex(&evidence.cap_eff_hex)
                .ok_or_else(|| {
                    anyhow::anyhow!("child CapEff is unparseable: {}", evidence.cap_eff_hex)
                })?;
            value["child_effective_capabilities"] =
                json!(neuestar_probe_core::capabilities::decode_cap_mask(mask));
            value["child_cap_eff_hex"] = json!(evidence.cap_eff_hex);
            value["child_user_namespace_id"] = json!(evidence.user_namespace);
            value["child_mount_namespace_id"] = json!(evidence.mount_namespace);
        }
        value
    };

    let (candidate_name, integration, trusted_helper, burden, privileged_ops) = match candidate {
        Some(evidence) => (
            evidence.candidate,
            json!({
                "integration_identity_sha256": evidence.integration_identity_sha256,
                "neuestar_integration_package_sha256": evidence.neuestar_integration_package_sha256,
                "integration_source_sha256": evidence.integration_source_sha256,
                "security_policy_sha256": evidence.security_policy_sha256,
            }),
            json!({
                "canonical_path": evidence.trusted_helper.canonical_path,
                "sha256": evidence.trusted_helper.sha256,
                "uid": evidence.trusted_helper.uid,
                "gid": evidence.trusted_helper.gid,
                "mode": evidence.trusted_helper.mode,
                "parent_mount_writable_by_test_user": evidence.trusted_helper.parent_mount_writable_by_test_user,
            }),
            json!({
                "installed_files": evidence.burden.installed_files.iter().map(|file| json!({
                    "path": file.path,
                    "size_bytes": file.size_bytes,
                    "sha256": file.sha256,
                    "uid": file.uid,
                    "gid": file.gid,
                    "mode": file.mode,
                    "kind": file.kind,
                })).collect::<Vec<_>>(),
                "installed_byte_count": evidence.burden.installed_files.iter().map(|f| f.size_bytes).sum::<u64>(),
                "installed_file_count": evidence.burden.installed_files.len(),
                "policy_loc": evidence.burden.policy_loc,
                "distro_branch_count": evidence.burden.distro_branch_count,
                "services": [],
                "additional_host_packages": [],
                "neuestar_maintained_dependencies": [],
                "carried_components": evidence.burden.carried_components.iter().map(|c| json!({
                    "upstream_project": c.upstream_project,
                    "upstream_version_commit": c.upstream_version_commit,
                    "source_provenance": c.source_provenance,
                    "binary_sha256": c.binary_sha256,
                    "patch_count": c.patch_count,
                    "neuestar_specific_patches": 0,
                    "security_update_responsibility": c.security_update_responsibility,
                })).collect::<Vec<_>>(),
                "helper_loc": evidence.burden.helper_loc,
            }),
            evidence.privileged_install_operations.clone(),
        ),
        None => (
            "none",
            json!({
                "integration_identity_sha256": sha256_hex(""),
                "neuestar_integration_package_sha256": null,
                "integration_source_sha256": null,
                "security_policy_sha256": null,
            }),
            Value::Null,
            json!({
                "installed_files": [],
                "installed_byte_count": 0,
                "installed_file_count": 0,
                "policy_loc": 0,
                "distro_branch_count": 0,
                "services": [],
                "additional_host_packages": [],
                "neuestar_maintained_dependencies": [],
                "carried_components": [],
                "helper_loc": 0,
            }),
            Vec::new(),
        ),
    };

    let mut record = json!({
        "schema": H0_SCHEMA,
        "attempt": {
            "timestamp": timestamp,
            "phase": "h0-preflight",
            "integration_source_changed_since_previous": false,
            "session_id": session_id,
        },
        "host": {
            "distro_id": host.distro_id,
            "distro_version": host.distro_version,
            "kernel_release": host.kernel_release,
            "architecture": host.architecture,
            "target_profile": {
                "iso_snapshot_date": iso_snapshot_date,
                "config_surface": config_surface,
            },
        },
        "security_state": security_state,
        "candidate": candidate_name,
        "integration": integration,
        "trusted_helper": trusted_helper,
        "runtime": {
            "runtime_artifact_sha256": archive_sha256,
            "generation_identity": payload_sha256,
            "application_identity": "neuestar-probe-app",
        },
        "burden": burden,
        "privileged_install_operations": privileged_ops,
        "execution": execution,
        "apparatus": {
            "probe_sha256": probe_sha256,
            "containment_argv": containment_argv,
        },
        "gates": {
            "h0_0": gates.h0_0,
            "h0_1": gates.h0_1,
            "h0_1s": gates.h0_1s,
            "h0_2a": "not-run",
            "h0_2b": "not-run",
            "h0_3": "not-run",
            "h0_4": "not-run",
            "h0_4r": "not-run",
            "h0_5": "not-run",
            "h0_6": "not-run",
            "h0_p": "not-run",
        },
        "classification": classification,
        "forbidden_preparation": [],
        "evidence": {
            "stderr": process_stderr.unwrap_or("").chars().take(4096).collect::<String>(),
            "pre_host_state": bounded(pre_host_state, 65536),
            "post_host_state": bounded(post_host_state, 65536),
        },
    });
    if let Some(failure) = failure {
        record["failure"] = failure;
    }
    Ok(record)
}

fn bounded(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

pub fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}
