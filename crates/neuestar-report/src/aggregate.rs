//! Campaign aggregation validation for the fixed Gate L0 matrix.

use crate::checks::{ReportError, validate as validate_report};
use crate::model::{Campaign, MatrixCell};
use std::collections::HashSet;

/// Reasons a campaign aggregation can be rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CampaignError {
    /// The same matrix cell appears more than once.
    #[error("duplicate matrix cell {cell}")]
    DuplicateCell {
        /// Duplicated cell identity.
        cell: MatrixCell,
    },
    /// A fixed matrix cell is omitted entirely.
    #[error("campaign omits expected matrix cell {cell}")]
    MissingCell {
        /// Cell that is missing from the campaign.
        cell: MatrixCell,
    },
    /// A report's declared cell differs from its campaign slot.
    #[error("report for {cell} declares matrix cell {report_cell}")]
    ReportCellMismatch {
        /// Campaign slot identity.
        cell: MatrixCell,
        /// Identity declared inside the report.
        report_cell: MatrixCell,
    },
    /// A report failed individual validation.
    #[error("invalid report for {cell}: {error}")]
    InvalidReport {
        /// Cell containing the invalid report.
        cell: MatrixCell,
        /// Report validation error.
        error: ReportError,
    },
    /// Reports in the campaign use more than one outer archive hash.
    #[error("mixed outer archive SHA-256 across reports: {first} and {second}")]
    MixedOuterArchiveHashes {
        /// First outer archive hash observed.
        first: String,
        /// Second outer archive hash observed.
        second: String,
    },
    /// Reports in the campaign use more than one payload manifest hash.
    #[error("mixed payload manifest SHA-256 across reports: {first} and {second}")]
    MixedPayloadHashes {
        /// First payload manifest hash observed.
        first: String,
        /// Second payload manifest hash observed.
        second: String,
    },
}

/// Validates a campaign and returns every violation found.
///
/// # Errors
///
/// Returns all [`CampaignError`] violations when the campaign is not
/// admissible.
pub fn validate(campaign: &Campaign) -> Result<(), Vec<CampaignError>> {
    let mut errors = Vec::new();
    let mut seen = HashSet::with_capacity(24);
    for entry in &campaign.cells {
        if !seen.insert(entry.cell) {
            errors.push(CampaignError::DuplicateCell { cell: entry.cell });
            continue;
        }
        if let Some(report) = &entry.report {
            if report.matrix_cell != entry.cell {
                errors.push(CampaignError::ReportCellMismatch {
                    cell: entry.cell,
                    report_cell: report.matrix_cell,
                });
            }
            if let Err(error) = validate_report(report) {
                errors.push(CampaignError::InvalidReport {
                    cell: entry.cell,
                    error,
                });
            }
        }
    }
    for expected in MatrixCell::all() {
        if !seen.contains(&expected) {
            errors.push(CampaignError::MissingCell { cell: expected });
        }
    }
    collect_mixed_hashes(campaign, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn collect_mixed_hashes(campaign: &Campaign, errors: &mut Vec<CampaignError>) {
    let mut outer_first = None;
    let mut outer_second = None;
    let mut payload_first = None;
    let mut payload_second = None;
    for entry in &campaign.cells {
        let Some(report) = &entry.report else {
            continue;
        };
        record_hash(
            &mut outer_first,
            &mut outer_second,
            &report.artifact.outer_archive_sha256,
        );
        record_hash(
            &mut payload_first,
            &mut payload_second,
            &report.artifact.payload_manifest_sha256,
        );
    }
    if let (Some(first), Some(second)) = (outer_first, outer_second) {
        errors.push(CampaignError::MixedOuterArchiveHashes { first, second });
    }
    if let (Some(first), Some(second)) = (payload_first, payload_second) {
        errors.push(CampaignError::MixedPayloadHashes { first, second });
    }
}

fn record_hash(first: &mut Option<String>, second: &mut Option<String>, hash: &str) {
    if first.is_none() {
        *first = Some(hash.to_owned());
    } else if second.is_none() && first.as_deref() != Some(hash) {
        *second = Some(hash.to_owned());
    }
}
