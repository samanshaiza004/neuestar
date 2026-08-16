//! Versioned machine-readable Gate L0 evidence model.
//!
//! This crate defines the `neuestar.report/v1` report, the cross-field
//! validation rules that keep reports admissible as scientific evidence, and
//! campaign aggregation checks for the fixed physical matrix. A report that is
//! malformed, internally contradictory, or claims success without supporting
//! evidence is rejected rather than repaired.

mod aggregate;
mod checks;
mod model;

pub use aggregate::{CampaignError, validate as validate_campaign};
pub use checks::{ReportError, validate as validate_report};
pub use model::{
    Artifact, Campaign, CampaignCell, CaptureEvidence, Classification, ContainmentEvidence,
    DisplayServer, Distro, DistroSpecificRule, FailureStage, ForbiddenPreparation,
    ForbiddenPreparationKind, GateResults, GateState, GpuVendor, GraphicsEvidence, LibcSource,
    MatrixCell, ObservedHost, PresentationEvidence, PresentationTimings, RendererKind, Report,
    RuntimeEvidence, SchemaVersion, StructuredFailure, VendorSpecificRule,
};

/// Current report schema identifier.
pub const SCHEMA_VERSION: &str = "neuestar.report/v1";

/// Exact number of frames a passing L0.3 gate must request and present.
pub const PRESENT_FRAME_COUNT: u32 = 300;

/// Hard cap on predeclared vendor-specific graphics rules.
pub const MAX_VENDOR_SPECIFIC_RULES: usize = 1;

/// The only permitted vendor-specific rule category.
pub const VENDOR_RULE_CATEGORY_NVIDIA_DEVICE_NODES: &str = "nvidia-device-nodes";
