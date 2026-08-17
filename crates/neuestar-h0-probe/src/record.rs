//! `neuestar.h0/v1` record assembly for the unintegrated probe (candidate
//! `none`). The record is validated against schema/h0.schema.json by
//! `h0-check`; this module only guarantees the shape.

use anyhow::Result;
use serde_json::{Value, json};

use crate::host::{HostFacts, SecurityState};

pub const H0_SCHEMA: &str = "neuestar.h0/v1";

/// The attempt outcome at the gate level.
#[derive(Debug, Clone)]
pub enum Outcome {
    Pass,
    /// The frozen child ran under the minimum boundary and failed; H0.0 = fail.
    BaselineFail {
        code: &'static str,
        message: String,
    },
    /// The apparatus failed before or around containment; H0.0 = not-run.
    ApparatusFail {
        code: &'static str,
        message: String,
    },
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
    process_stderr: Option<&str>,
    pre_host_state: &str,
    post_host_state: &str,
    outcome: &Outcome,
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
        // The H0.P outcome child's namespace identities come from the frozen
        // child result. CapEff/profile evidence is H0.1S-only (dedicated
        // security-evidence invocation) and is added there with strict parsing.
        if let Some((user_ns, mount_ns)) = child_ns {
            value["child_user_namespace_id"] = json!(user_ns);
            value["child_mount_namespace_id"] = json!(mount_ns);
        }
        value
    };

    let h0_0 = match outcome {
        Outcome::Pass => "pass",
        Outcome::BaselineFail { .. } => "fail",
        Outcome::ApparatusFail { .. } => "not-run",
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
        "candidate": "none",
        "integration": {
            "integration_identity_sha256": sha256_hex(""),
            "neuestar_integration_package_sha256": null,
            "integration_source_sha256": null,
            "security_policy_sha256": null,
        },
        "trusted_helper": null,
        "runtime": {
            "runtime_artifact_sha256": archive_sha256,
            "generation_identity": payload_sha256,
            "application_identity": "neuestar-probe-app",
        },
        "burden": {
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
        },
        "privileged_install_operations": [],
        "execution": execution,
        "apparatus": {
            "probe_sha256": probe_sha256,
            "containment_argv": containment_argv,
        },
        "gates": {
            "h0_0": h0_0,
            "h0_1": "not-run",
            "h0_1s": "not-run",
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
