//! Cross-field validation rules for Gate L0 reports.

use crate::model::{
    Artifact, CaptureEvidence, Classification, ContainmentEvidence, GateResults, GateState,
    GraphicsEvidence, LibcSource, ObservedHost, PresentationEvidence, RendererKind, Report,
    RuntimeEvidence, StructuredFailure,
};
use crate::{
    MAX_VENDOR_SPECIFIC_RULES, PRESENT_FRAME_COUNT, SCHEMA_VERSION,
    VENDOR_RULE_CATEGORY_NVIDIA_DEVICE_NODES,
};

/// Reasons a report can be rejected as admissible evidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    /// The report uses an unsupported schema identifier.
    #[error("report schema must be `neuestar.report/v1`; found `{found}`")]
    UnsupportedSchema {
        /// Schema identifier found on the report.
        found: &'static str,
    },
    /// A SHA-256 field is not exactly 64 hexadecimal characters.
    #[error("{field} must be exactly 64 hexadecimal characters")]
    Sha256Format {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// A required string field is empty.
    #[error("{field} must not be empty")]
    EmptyString {
        /// Name of the empty field.
        field: &'static str,
    },
    /// A bounded string field exceeds its maximum length.
    #[error("{field} exceeds the maximum length of {max} characters")]
    StringTooLong {
        /// Name of the oversized field.
        field: &'static str,
        /// Maximum permitted character count.
        max: usize,
    },
    /// A bounded array exceeds its maximum length.
    #[error("{field} exceeds the maximum length of {max} entries")]
    ArrayTooLarge {
        /// Name of the oversized array.
        field: &'static str,
        /// Maximum permitted entry count.
        max: usize,
    },
    /// Host glibc import was classified as a clean pass.
    #[error("host glibc import cannot be classified as clean-pass")]
    HostGlibcCleanPass,
    /// More vendor-specific rules were declared than the predeclared cap.
    #[error("vendor-specific rules must contain at most one rule; found {found}")]
    VendorRuleCount {
        /// Number of vendor-specific rules declared.
        found: usize,
    },
    /// A vendor-specific rule uses an unpermitted category.
    #[error(
        "vendor-specific rule at index {index} must use category `nvidia-device-nodes`; found `{found}`"
    )]
    VendorRuleCategory {
        /// Index of the offending rule.
        index: usize,
        /// Category that was declared.
        found: String,
    },
    /// A distro-specific rule was declared.
    #[error("distro-specific rules are forbidden; found {found}")]
    DistroRuleCount {
        /// Number of distro-specific rules declared.
        found: usize,
    },
    /// Software rendering was claimed as a passing L0.2.
    #[error("software rendering cannot pass gate l0_2")]
    SoftwareRendererPass,
    /// Acceleration passed while the renderer kind was not determined.
    #[error("gate l0_2 pass requires a hardware renderer; found `not-determined`")]
    AccelerationNotDeterminedPass,
    /// L0.0 passed without namespace construction.
    #[error("gate l0_0 pass requires namespace construction")]
    L00NamespaceNotConstructed,
    /// Forbidden preparation did not fail L0.0.
    #[error("forbidden preparation requires gate l0_0 to fail; found {state:?}")]
    ForbiddenPreparationGate {
        /// State actually recorded for gate `l0_0`.
        state: GateState,
    },
    /// Forbidden preparation was not classified as fail.
    #[error("forbidden preparation requires classification fail; found {classification:?}")]
    ForbiddenPreparationClassification {
        /// Classification that was recorded.
        classification: Classification,
    },
    /// L0.3 passed without exactly 300 requested frames.
    #[error("gate l0_3 pass requires exactly 300 requested frames; found {found}")]
    L03RequestedFrames {
        /// Frames requested by the workload.
        found: u32,
    },
    /// L0.3 passed without exactly 300 presented frames.
    #[error("gate l0_3 pass requires exactly 300 presented frames; found {found}")]
    L03PresentedFrames {
        /// Frames presented by the workload.
        found: u32,
    },
    /// L0.3 passed with validation errors.
    #[error("gate l0_3 pass requires zero validation errors; found {found}")]
    L03ValidationErrors {
        /// Validation errors observed.
        found: u32,
    },
    /// L0.3 passed with device loss.
    #[error("gate l0_3 pass cannot record device loss")]
    L03DeviceLoss,
    /// L0.3 passed without complete timings.
    #[error("gate l0_3 pass requires complete presentation timings")]
    L03TimingsMissing,
    /// A timing value was NaN or infinite.
    #[error("{field} must be finite")]
    NonFiniteTiming {
        /// Name of the non-finite timing field.
        field: &'static str,
    },
    /// A timing value was negative.
    #[error("{field} must not be negative")]
    NegativeTiming {
        /// Name of the negative timing field.
        field: &'static str,
    },
    /// A pass classification includes a non-pass functional gate.
    #[error("pass classification requires gate {gate} to pass; found {state:?}")]
    PassFunctionalGateNotPass {
        /// Gate name that was not a pass.
        gate: &'static str,
        /// State actually recorded for the gate.
        state: GateState,
    },
    /// A pass classification includes a failed or inconclusive churn gate.
    #[error("pass classification requires gate {gate} to pass or not-run; found {state:?}")]
    PassChurnGateNotPass {
        /// Gate name that was not pass or not-run.
        gate: &'static str,
        /// State actually recorded for the gate.
        state: GateState,
    },
    /// Conditional-pass was claimed without host glibc.
    #[error("conditional-pass requires host glibc import; found {libc_source:?}")]
    ConditionalPassRequiresHostGlibc {
        /// C runtime source that was recorded.
        libc_source: LibcSource,
    },
    /// Fail was claimed without recorded failure evidence.
    #[error(
        "classification fail requires a failed or inconclusive gate, forbidden preparation, or a structured failure"
    )]
    FailWithoutEvidence,
}

/// Validates a report against every Gate L0 invariant.
///
/// # Errors
///
/// Returns the first [`ReportError`] when the report is not admissible.
pub fn validate(report: &Report) -> Result<(), ReportError> {
    if report.schema.as_str() != SCHEMA_VERSION {
        return Err(ReportError::UnsupportedSchema {
            found: report.schema.as_str(),
        });
    }
    validate_artifact(&report.artifact)?;
    validate_observed_host(&report.observed_host)?;
    validate_containment(&report.containment)?;
    validate_runtime(&report.runtime)?;
    validate_graphics(&report.graphics)?;
    validate_presentation(&report.presentation)?;
    validate_capture(&report.capture)?;
    validate_failure(report.failure.as_ref())?;
    validate_gate_evidence(report)?;
    validate_classification(report)?;
    Ok(())
}

fn validate_artifact(artifact: &Artifact) -> Result<(), ReportError> {
    require_sha256(
        &artifact.outer_archive_sha256,
        "artifact.outer_archive_sha256",
    )?;
    require_sha256(
        &artifact.payload_manifest_sha256,
        "artifact.payload_manifest_sha256",
    )?;
    bounded(&artifact.source_commit, "artifact.source_commit", 64)?;
    bounded(&artifact.probe_version, "artifact.probe_version", 32)?;
    Ok(())
}

fn validate_observed_host(host: &ObservedHost) -> Result<(), ReportError> {
    bounded(&host.distro_id, "observed_host.distro_id", 128)?;
    bounded(&host.kernel_release, "observed_host.kernel_release", 128)?;
    bounded(&host.architecture, "observed_host.architecture", 32)?;
    bounded(&host.gpu_description, "observed_host.gpu_description", 256)?;
    optional_bounded(
        host.driver_version.as_deref(),
        "observed_host.driver_version",
        64,
    )?;
    optional_bounded(
        host.display_server.as_deref(),
        "observed_host.display_server",
        32,
    )?;
    Ok(())
}

fn validate_containment(containment: &ContainmentEvidence) -> Result<(), ReportError> {
    if containment.forbidden_preparation.len() > 64 {
        return Err(ReportError::ArrayTooLarge {
            field: "containment.forbidden_preparation",
            max: 64,
        });
    }
    for preparation in &containment.forbidden_preparation {
        bounded(
            &preparation.description,
            "containment.forbidden_preparation.description",
            512,
        )?;
    }
    Ok(())
}

fn validate_runtime(runtime: &RuntimeEvidence) -> Result<(), ReportError> {
    optional_bounded(
        runtime.host_glibc_path.as_deref(),
        "runtime.host_glibc_path",
        1024,
    )?;
    optional_bounded(runtime.interpreter.as_deref(), "runtime.interpreter", 1024)?;
    bounded_array(
        &runtime.unresolved_symbols,
        "runtime.unresolved_symbols",
        64,
        512,
    )?;
    bounded_array(
        &runtime.loader_diagnostics,
        "runtime.loader_diagnostics",
        64,
        512,
    )
}

fn validate_graphics(graphics: &GraphicsEvidence) -> Result<(), ReportError> {
    bounded(
        &graphics.renderer_description,
        "graphics.renderer_description",
        256,
    )?;
    bounded(&graphics.device, "graphics.device", 256)?;
    bounded_array(&graphics.icd_manifests, "graphics.icd_manifests", 64, 1024)?;
    bounded_array(
        &graphics.discovered_libraries,
        "graphics.discovered_libraries",
        1024,
        1024,
    )?;
    if graphics.vendor_specific_rules.len() > MAX_VENDOR_SPECIFIC_RULES {
        return Err(ReportError::VendorRuleCount {
            found: graphics.vendor_specific_rules.len(),
        });
    }
    for (index, rule) in graphics.vendor_specific_rules.iter().enumerate() {
        if rule.category != VENDOR_RULE_CATEGORY_NVIDIA_DEVICE_NODES {
            return Err(ReportError::VendorRuleCategory {
                index,
                found: rule.category.clone(),
            });
        }
        bounded(
            &rule.description,
            "graphics.vendor_specific_rules.description",
            512,
        )?;
    }
    if !graphics.distro_specific_rules.is_empty() {
        return Err(ReportError::DistroRuleCount {
            found: graphics.distro_specific_rules.len(),
        });
    }
    Ok(())
}

fn validate_presentation(presentation: &PresentationEvidence) -> Result<(), ReportError> {
    if let Some(timings) = &presentation.timings {
        validate_timing(
            timings.elapsed_seconds,
            "presentation.timings.elapsed_seconds",
        )?;
        validate_timing(
            timings.frame_time_median_ms,
            "presentation.timings.frame_time_median_ms",
        )?;
        validate_timing(
            timings.frame_time_p95_ms,
            "presentation.timings.frame_time_p95_ms",
        )?;
        validate_timing(
            timings.frame_time_p99_ms,
            "presentation.timings.frame_time_p99_ms",
        )?;
        validate_timing(
            timings.frame_time_max_ms,
            "presentation.timings.frame_time_max_ms",
        )?;
    }
    Ok(())
}

fn validate_capture(capture: &CaptureEvidence) -> Result<(), ReportError> {
    require_sha256(&capture.capture_rule_sha256, "capture.capture_rule_sha256")?;
    bounded_array(
        &capture.captured_concrete_files,
        "capture.captured_concrete_files",
        1024,
        1024,
    )
}

fn validate_failure(failure: Option<&StructuredFailure>) -> Result<(), ReportError> {
    if let Some(failure) = failure {
        bounded(&failure.message, "failure.message", 2048)?;
        bounded_array(&failure.details, "failure.details", 64, 512)?;
    }
    Ok(())
}

fn validate_gate_evidence(report: &Report) -> Result<(), ReportError> {
    let l00 = report.gates.l0_0_containment;
    if !report.containment.forbidden_preparation.is_empty() && l00 != GateState::Fail {
        return Err(ReportError::ForbiddenPreparationGate { state: l00 });
    }
    if l00 == GateState::Pass && !report.containment.namespace_constructed {
        return Err(ReportError::L00NamespaceNotConstructed);
    }

    if report.gates.l0_2_acceleration == GateState::Pass {
        match report.graphics.renderer {
            RendererKind::Software => return Err(ReportError::SoftwareRendererPass),
            RendererKind::NotDetermined => {
                return Err(ReportError::AccelerationNotDeterminedPass);
            }
            RendererKind::Hardware => {}
        }
    }

    if report.gates.l0_3_present == GateState::Pass {
        let presentation = &report.presentation;
        if presentation.frames_requested != PRESENT_FRAME_COUNT {
            return Err(ReportError::L03RequestedFrames {
                found: presentation.frames_requested,
            });
        }
        if presentation.frames_presented != PRESENT_FRAME_COUNT {
            return Err(ReportError::L03PresentedFrames {
                found: presentation.frames_presented,
            });
        }
        if presentation.validation_errors != 0 {
            return Err(ReportError::L03ValidationErrors {
                found: presentation.validation_errors,
            });
        }
        if presentation.device_loss {
            return Err(ReportError::L03DeviceLoss);
        }
        if presentation.timings.is_none() {
            return Err(ReportError::L03TimingsMissing);
        }
    }
    Ok(())
}

fn validate_classification(report: &Report) -> Result<(), ReportError> {
    match report.classification {
        Classification::CleanPass | Classification::ConditionalPass => {
            if !report.containment.forbidden_preparation.is_empty() {
                return Err(ReportError::ForbiddenPreparationClassification {
                    classification: report.classification,
                });
            }
            match report.classification {
                Classification::CleanPass
                    if report.runtime.libc_source == LibcSource::HostGlibc =>
                {
                    return Err(ReportError::HostGlibcCleanPass);
                }
                Classification::ConditionalPass
                    if report.runtime.libc_source != LibcSource::HostGlibc =>
                {
                    return Err(ReportError::ConditionalPassRequiresHostGlibc {
                        libc_source: report.runtime.libc_source,
                    });
                }
                _ => {}
            }
            for (gate, state) in functional_gates(report.gates) {
                if state != GateState::Pass {
                    return Err(ReportError::PassFunctionalGateNotPass { gate, state });
                }
            }
            for (gate, state) in churn_gates(report.gates) {
                if !matches!(state, GateState::Pass | GateState::NotRun) {
                    return Err(ReportError::PassChurnGateNotPass { gate, state });
                }
            }
        }
        Classification::Fail => {
            let has_evidence = report.failure.is_some()
                || !report.containment.forbidden_preparation.is_empty()
                || functional_gates(report.gates)
                    .into_iter()
                    .chain(churn_gates(report.gates))
                    .any(|(_, state)| matches!(state, GateState::Fail | GateState::Inconclusive));
            if !has_evidence {
                return Err(ReportError::FailWithoutEvidence);
            }
        }
    }
    Ok(())
}

fn functional_gates(gates: GateResults) -> [(&'static str, GateState); 4] {
    [
        ("l0_0_containment", gates.l0_0_containment),
        ("l0_1_launch", gates.l0_1_launch),
        ("l0_2_acceleration", gates.l0_2_acceleration),
        ("l0_3_present", gates.l0_3_present),
    ]
}

fn churn_gates(gates: GateResults) -> [(&'static str, GateState); 2] {
    [
        ("l0_4_churn", gates.l0_4_churn),
        ("l0_5_maintenance", gates.l0_5_maintenance),
    ]
}

fn validate_timing(value: f64, field: &'static str) -> Result<(), ReportError> {
    if !value.is_finite() {
        return Err(ReportError::NonFiniteTiming { field });
    }
    if value < 0.0 {
        return Err(ReportError::NegativeTiming { field });
    }
    Ok(())
}

fn require_sha256(value: &str, field: &'static str) -> Result<(), ReportError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ReportError::Sha256Format { field })
    }
}

fn bounded(value: &str, field: &'static str, max: usize) -> Result<(), ReportError> {
    if value.is_empty() {
        return Err(ReportError::EmptyString { field });
    }
    if value.chars().count() > max {
        return Err(ReportError::StringTooLong { field, max });
    }
    Ok(())
}

fn optional_bounded(
    value: Option<&str>,
    field: &'static str,
    max: usize,
) -> Result<(), ReportError> {
    if let Some(value) = value {
        bounded(value, field, max)?;
    }
    Ok(())
}

fn bounded_array(
    values: &[String],
    field: &'static str,
    max_entries: usize,
    max_element_length: usize,
) -> Result<(), ReportError> {
    if values.len() > max_entries {
        return Err(ReportError::ArrayTooLarge {
            field,
            max: max_entries,
        });
    }
    for value in values {
        bounded(value, field, max_element_length)?;
    }
    Ok(())
}
