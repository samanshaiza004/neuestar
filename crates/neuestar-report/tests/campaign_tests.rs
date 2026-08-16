//! Campaign aggregation validation tests.

mod common;

use common::campaign_with_runs;
use neuestar_report::{
    Campaign, CampaignCell, CampaignError, Classification, DisplayServer, Distro, LibcSource,
    MatrixCell,
};

fn cell() -> MatrixCell {
    MatrixCell {
        distro: Distro::Nixos,
        gpu_vendor: neuestar_report::GpuVendor::Nvidia,
        display_server: DisplayServer::Wayland,
    }
}

#[test]
fn all_unrun_cells_stay_explicit_and_valid() {
    let campaign = campaign_with_runs(&[]);
    assert_eq!(campaign.cells.len(), 24);
    assert!(campaign.validate().is_ok());
}

#[test]
fn mixed_outer_archive_hashes_are_rejected() {
    let cells = [
        cell(),
        MatrixCell {
            display_server: DisplayServer::X11,
            ..cell()
        },
    ];
    let mut campaign = campaign_with_runs(&cells);
    let entry = campaign
        .cells
        .iter_mut()
        .find(|entry| entry.cell == cells[0])
        .unwrap();
    entry.report.as_mut().unwrap().artifact.outer_archive_sha256 = "d".repeat(64);

    let errors = campaign.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::MixedOuterArchiveHashes { .. }))
    );
}

#[test]
fn mixed_payload_hashes_are_rejected() {
    let cells = [
        cell(),
        MatrixCell {
            display_server: DisplayServer::X11,
            ..cell()
        },
    ];
    let mut campaign = campaign_with_runs(&cells);
    let entry = campaign
        .cells
        .iter_mut()
        .find(|entry| entry.cell == cells[0])
        .unwrap();
    entry
        .report
        .as_mut()
        .unwrap()
        .artifact
        .payload_manifest_sha256 = "d".repeat(64);

    let errors = campaign.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::MixedPayloadHashes { .. }))
    );
}

#[test]
fn mixed_capture_source_and_probe_identities_are_rejected() {
    let cells = [
        cell(),
        MatrixCell {
            display_server: DisplayServer::X11,
            ..cell()
        },
    ];
    let mut campaign = campaign_with_runs(&cells);
    let report = campaign
        .cells
        .iter_mut()
        .find(|entry| entry.cell == cells[0])
        .unwrap()
        .report
        .as_mut()
        .unwrap();
    report.capture.capture_rule_sha256 = "d".repeat(64);
    report.artifact.source_commit = "f".repeat(40);
    report.artifact.probe_version = "0.2.0".to_owned();

    let errors = campaign.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::MixedCaptureRuleHashes { .. }))
    );
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::MixedSourceCommits { .. }))
    );
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::MixedProbeVersions { .. }))
    );
}

#[test]
fn duplicate_matrix_cell_identity_is_rejected() {
    let campaign = Campaign {
        cells: vec![
            CampaignCell {
                cell: cell(),
                report: None,
            },
            CampaignCell {
                cell: cell(),
                report: None,
            },
        ],
    };

    let errors = campaign.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::DuplicateCell { .. }))
    );
}

#[test]
fn invalid_reports_are_rejected() {
    let mut campaign = campaign_with_runs(&[cell()]);
    let entry = campaign
        .cells
        .iter_mut()
        .find(|entry| entry.cell == cell())
        .unwrap();
    entry.report.as_mut().unwrap().runtime.libc_source = LibcSource::HostGlibc;

    let errors = campaign.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::InvalidReport { .. }))
    );
}

#[test]
fn omitted_cells_are_rejected() {
    let mut campaign = campaign_with_runs(&[]);
    campaign.cells.retain(|entry| entry.cell != cell());

    let errors = campaign.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::MissingCell { .. }))
    );
}

#[test]
fn report_cell_mismatch_is_rejected() {
    let other = MatrixCell {
        distro: Distro::Fedora,
        ..cell()
    };
    let mut campaign = campaign_with_runs(&[cell()]);
    let entry = campaign
        .cells
        .iter_mut()
        .find(|entry| entry.cell == cell())
        .unwrap();
    entry.report.as_mut().unwrap().matrix_cell = other;
    entry.report.as_mut().unwrap().classification = Classification::Fail;
    entry.report.as_mut().unwrap().gates.l0_0_containment = neuestar_report::GateState::Fail;
    entry.report.as_mut().unwrap().failure = Some(neuestar_report::StructuredFailure {
        stage: neuestar_report::FailureStage::Containment,
        code: "cell-mismatch".to_owned(),
        message: "cell mismatch".to_owned(),
        details: Vec::new(),
    });

    let errors = campaign.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, CampaignError::ReportCellMismatch { .. }))
    );
}
