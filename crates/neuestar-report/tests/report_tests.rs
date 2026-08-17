//! Report model, validation, and JSON fixture tests.

mod common;

use common::{clean_report, conditional_report};
use neuestar_report::{
    Classification, DistroSpecificRule, GateState, LibcSource, PresentationTimings, RendererKind,
    Report, ReportError, SchemaVersion,
};
use serde_json::{Value, json};

#[test]
fn clean_pass_round_trips_through_json() {
    let report = clean_report();
    assert!(report.validate().is_ok());

    let value = serde_json::to_value(&report).unwrap();
    let decoded: Report = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(decoded, report);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
}

#[test]
fn conditional_pass_with_host_glibc_is_valid() {
    assert!(conditional_report().validate().is_ok());
}

#[test]
fn containment_substage_and_helper_stderr_round_trip_in_reports() {
    let mut report: Report =
        serde_json::from_str(include_str!("fixtures/fail_containment.json")).unwrap();
    report.containment.substage = Some(neuestar_report::ContainmentSubstage::HelperExecution);
    report.containment.helper_stderr =
        Some("bwrap: Can't create file at /app/probe: Read-only file system".to_owned());
    assert!(report.validate().is_ok());
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["containment"]["substage"], json!("helper-execution"));
    assert_eq!(
        value["containment"]["helper_stderr"],
        json!("bwrap: Can't create file at /app/probe: Read-only file system")
    );
    let decoded: Report = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
}

#[test]
fn host_glibc_cannot_be_clean_pass() {
    let mut report = clean_report();
    report.runtime.libc_source = LibcSource::HostGlibc;
    report.runtime.host_glibc_path = Some("/usr/lib/libc.so.6".to_owned());
    report.runtime.host_glibc_imported = true;
    report.runtime.host_glibc_reason = Some("driver ABI".to_owned());
    report.runtime.host_glibc_paths = vec!["/usr/lib/libc.so.6".to_owned()];

    let error = report.validate().unwrap_err();
    assert!(matches!(error, ReportError::HostGlibcCleanPass));
}

#[test]
fn clean_pass_requires_controlled_libc_and_l01_requires_runtime_evidence() {
    let mut unknown = clean_report();
    unknown.runtime.libc_source = LibcSource::NotDetermined;
    unknown.runtime.libc_path = None;
    assert!(matches!(
        unknown.validate().unwrap_err(),
        ReportError::CleanPassRequiresControlledLibc { .. }
            | ReportError::L01RuntimeEvidenceMissing
    ));

    let mut unresolved = clean_report();
    unresolved
        .runtime
        .unresolved_symbols
        .push("missing_symbol".to_owned());
    assert!(matches!(
        unresolved.validate().unwrap_err(),
        ReportError::L01RuntimeEvidenceMissing
    ));
}

#[test]
fn software_renderer_cannot_pass_l02() {
    let mut report = clean_report();
    report.graphics.renderer = RendererKind::Software;
    report.graphics.software_renderer_detected = true;

    let error = report.validate().unwrap_err();
    assert!(matches!(error, ReportError::SoftwareRendererPass));
}

#[test]
fn software_renderer_with_failed_l02_is_recordable() {
    let mut report = clean_report();
    report.graphics.renderer = RendererKind::Software;
    report.graphics.software_renderer_detected = true;
    report.gates.l0_2_acceleration = GateState::Fail;
    report.gates.l0_3_present = GateState::NotRun;
    report.classification = Classification::Fail;
    report.failure = Some(neuestar_report::StructuredFailure {
        stage: neuestar_report::FailureStage::Graphics,
        code: "software-renderer".to_owned(),
        message: "llvmpipe selected".to_owned(),
        details: Vec::new(),
    });
    assert!(report.validate().is_ok());
}

#[test]
fn vendor_rule_cap_and_category_are_enforced() {
    let mut over_cap = clean_report();
    over_cap.graphics.vendor_specific_rules.push(
        neuestar_report::VendorSpecificRule::nvidia_device_nodes("second rule"),
    );
    let error = over_cap.validate().unwrap_err();
    assert!(matches!(error, ReportError::VendorRuleCount { found: 2 }));

    let mut bad_category = clean_report();
    bad_category.graphics.vendor_specific_rules[0].category = "vendor-package".to_owned();
    let error = bad_category.validate().unwrap_err();
    assert!(matches!(
        error,
        ReportError::VendorRuleCategory { index: 0, .. }
    ));
}

#[test]
fn any_distro_rule_is_rejected() {
    let mut report = clean_report();
    report
        .graphics
        .distro_specific_rules
        .push(DistroSpecificRule {
            category: "distro-package".to_owned(),
            description: "not permitted".to_owned(),
        });

    let error = report.validate().unwrap_err();
    assert!(matches!(error, ReportError::DistroRuleCount { found: 1 }));
}

#[test]
fn l03_frame_and_timing_requirements_are_enforced() {
    let mut wrong_requested = clean_report();
    wrong_requested.presentation.frames_requested = 299;
    assert!(matches!(
        wrong_requested.validate().unwrap_err(),
        ReportError::L03RequestedFrames { found: 299 }
    ));

    let mut wrong_presented = clean_report();
    wrong_presented.presentation.frames_presented = 301;
    assert!(matches!(
        wrong_presented.validate().unwrap_err(),
        ReportError::L03PresentedFrames { found: 301 }
    ));

    let mut validation_error = clean_report();
    validation_error.presentation.validation_errors = 1;
    assert!(matches!(
        validation_error.validate().unwrap_err(),
        ReportError::L03ValidationErrors { found: 1 }
    ));

    let mut device_loss = clean_report();
    device_loss.presentation.device_loss = true;
    assert!(matches!(
        device_loss.validate().unwrap_err(),
        ReportError::L03DeviceLoss
    ));

    let mut missing_timings = clean_report();
    missing_timings.presentation.timings = None;
    assert!(matches!(
        missing_timings.validate().unwrap_err(),
        ReportError::L03TimingsMissing
    ));
}

#[test]
fn nan_and_infinity_timings_are_rejected() {
    let mut nan = clean_report();
    nan.presentation.timings.as_mut().unwrap().elapsed_seconds = f64::NAN;
    assert!(matches!(
        nan.validate().unwrap_err(),
        ReportError::NonFiniteTiming { .. }
    ));

    let mut infinite = clean_report();
    infinite
        .presentation
        .timings
        .as_mut()
        .unwrap()
        .frame_time_p99_ms = f64::INFINITY;
    assert!(matches!(
        infinite.validate().unwrap_err(),
        ReportError::NonFiniteTiming { .. }
    ));

    let mut negative = clean_report();
    negative
        .presentation
        .timings
        .as_mut()
        .unwrap()
        .frame_time_max_ms = -1.0;
    assert!(matches!(
        negative.validate().unwrap_err(),
        ReportError::NegativeTiming { .. }
    ));
}

#[test]
fn timing_percentiles_must_be_ordered() {
    let mut report = clean_report();
    report
        .presentation
        .timings
        .as_mut()
        .unwrap()
        .frame_time_p95_ms = 10.0;
    assert!(matches!(
        report.validate().unwrap_err(),
        ReportError::TimingOrder
    ));
}

#[test]
fn forbidden_preparation_requires_l00_fail_and_fail_classification() {
    let mut report = clean_report();
    report
        .containment
        .forbidden_preparation
        .push(neuestar_report::ForbiddenPreparation {
            kind: neuestar_report::ForbiddenPreparationKind::Sudo,
            description: "runner used sudo".to_owned(),
        });
    assert!(matches!(
        report.validate().unwrap_err(),
        ReportError::ForbiddenPreparationGate {
            state: GateState::Pass
        }
    ));

    let mut wrong_classification = report.clone();
    wrong_classification.gates.l0_0_containment = GateState::Fail;
    assert!(matches!(
        wrong_classification.validate().unwrap_err(),
        ReportError::ForbiddenPreparationClassification {
            classification: Classification::CleanPass
        }
    ));

    let mut valid_fail = wrong_classification;
    valid_fail.classification = Classification::Fail;
    assert!(valid_fail.validate().is_ok());
}

#[test]
fn incomplete_attempts_are_recordable_without_inventing_success() {
    let mut report = clean_report();
    report.containment.namespace_constructed = false;
    report.containment.user_namespace_constructed = false;
    report.containment.mount_namespace_constructed = false;
    report.runtime.libc_source = LibcSource::NotDetermined;
    report.runtime.libc_path = None;
    report.runtime.interpreter = None;
    report.graphics.renderer = RendererKind::NotDetermined;
    report.presentation.frames_requested = 0;
    report.presentation.frames_presented = 0;
    report.presentation.timings = None;
    report.gates = neuestar_report::GateResults {
        l0_0_containment: GateState::NotRun,
        l0_1_launch: GateState::NotRun,
        l0_2_acceleration: GateState::NotRun,
        l0_3_present: GateState::NotRun,
        l0_4_churn: GateState::NotRun,
        l0_5_maintenance: GateState::NotRun,
    };
    report.classification = Classification::Fail;
    report.failure = Some(neuestar_report::StructuredFailure {
        stage: neuestar_report::FailureStage::Preflight,
        code: "attempt-incomplete".to_owned(),
        message: "attempt ended before containment".to_owned(),
        details: Vec::new(),
    });
    assert!(report.validate().is_ok());

    let mut invented_success = report.clone();
    invented_success.classification = Classification::CleanPass;
    assert!(matches!(
        invented_success.validate().unwrap_err(),
        ReportError::CleanPassRequiresControlledLibc {
            libc_source: LibcSource::NotDetermined
        }
    ));

    let mut no_evidence = report;
    no_evidence.failure = None;
    assert!(matches!(
        no_evidence.validate().unwrap_err(),
        ReportError::FailWithoutEvidence
    ));
}

#[test]
fn unknown_schema_versions_are_rejected() {
    let mut value = serde_json::to_value(clean_report()).unwrap();
    value["schema"] = json!("neuestar.report/v2");
    assert!(serde_json::from_value::<Report>(value).is_err());
}

#[test]
fn unknown_properties_are_rejected() {
    let mut root = serde_json::to_value(clean_report()).unwrap();
    root["extra"] = json!(true);
    assert!(serde_json::from_value::<Report>(root).is_err());

    let mut nested = serde_json::to_value(clean_report()).unwrap();
    nested["artifact"]["extra"] = json!(true);
    assert!(serde_json::from_value::<Report>(nested).is_err());
}

#[test]
fn missing_and_malformed_reports_are_rejected() {
    assert!(serde_json::from_str::<Report>("{}").is_err());
    assert!(serde_json::from_str::<Report>("{").is_err());

    let mut missing_field = serde_json::to_value(clean_report()).unwrap();
    missing_field.as_object_mut().unwrap().remove("gates");
    assert!(serde_json::from_value::<Report>(missing_field).is_err());

    let mut uppercase_hash = clean_report();
    uppercase_hash.artifact.outer_archive_sha256 = "A".repeat(64);
    assert!(uppercase_hash.validate().is_err());

    let mut malformed_source = clean_report();
    malformed_source.artifact.source_commit = "not-a-git-commit".to_owned();
    assert!(matches!(
        malformed_source.validate().unwrap_err(),
        ReportError::SourceCommitFormat
    ));
}

#[test]
fn schema_fixtures_round_trip_and_validate() {
    let fixtures = [
        include_str!("fixtures/clean_pass.json"),
        include_str!("fixtures/conditional_pass.json"),
        include_str!("fixtures/fail_containment.json"),
    ];
    for fixture in fixtures {
        let value: Value = serde_json::from_str(fixture).unwrap();
        let report: Report = serde_json::from_value(value.clone()).unwrap();
        assert!(report.validate().is_ok(), "{fixture}");
        assert_eq!(serde_json::to_value(&report).unwrap(), value);
    }
}

#[test]
fn schema_identifier_is_exposed() {
    assert_eq!(SchemaVersion::V1.as_str(), "neuestar.report/v1");
    assert_eq!(SchemaVersion::V1.as_str(), neuestar_report::SCHEMA_VERSION);
}

#[test]
fn timing_helpers_are_constructible() {
    let _ = PresentationTimings {
        elapsed_seconds: 1.0,
        frame_time_median_ms: 1.0,
        frame_time_p95_ms: 1.0,
        frame_time_p99_ms: 1.0,
        frame_time_max_ms: 1.0,
    };
}
