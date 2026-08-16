//! Serialization model for the versioned Gate L0 report.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{SCHEMA_VERSION, VENDOR_RULE_CATEGORY_NVIDIA_DEVICE_NODES};

/// Accepted report schema identifiers.
///
/// Unknown identifiers are rejected by deserialization and by
/// [`Report::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SchemaVersion {
    /// Version 1 of the Gate L0 report schema.
    #[serde(rename = "neuestar.report/v1")]
    V1,
}

impl SchemaVersion {
    /// Returns the on-wire schema identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => SCHEMA_VERSION,
        }
    }
}

/// Distribution half of a matrix cell identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Distro {
    /// Fedora.
    Fedora,
    /// Ubuntu LTS.
    #[serde(rename = "ubuntu-lts")]
    UbuntuLts,
    /// Arch Linux.
    Arch,
    /// NixOS.
    Nixos,
}

impl fmt::Display for Distro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fedora => "fedora",
            Self::UbuntuLts => "ubuntu-lts",
            Self::Arch => "arch",
            Self::Nixos => "nixos",
        })
    }
}

/// GPU vendor half of a matrix cell identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GpuVendor {
    /// Intel integrated graphics.
    Intel,
    /// AMD graphics.
    Amd,
    /// NVIDIA graphics.
    Nvidia,
}

impl fmt::Display for GpuVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Intel => "intel",
            Self::Amd => "amd",
            Self::Nvidia => "nvidia",
        })
    }
}

/// Display server half of a matrix cell identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisplayServer {
    /// Wayland.
    Wayland,
    /// X11.
    X11,
}

impl fmt::Display for DisplayServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wayland => "wayland",
            Self::X11 => "x11",
        })
    }
}

/// Identity of one fixed physical matrix cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixCell {
    /// Declared distribution.
    pub distro: Distro,
    /// Declared GPU vendor.
    pub gpu_vendor: GpuVendor,
    /// Declared display server.
    pub display_server: DisplayServer,
}

impl MatrixCell {
    /// Returns every cell in the fixed 24-cell campaign matrix.
    #[must_use]
    pub fn all() -> Vec<Self> {
        let mut cells = Vec::with_capacity(24);
        for distro in [
            Distro::Fedora,
            Distro::UbuntuLts,
            Distro::Arch,
            Distro::Nixos,
        ] {
            for gpu_vendor in [GpuVendor::Intel, GpuVendor::Amd, GpuVendor::Nvidia] {
                for display_server in [DisplayServer::Wayland, DisplayServer::X11] {
                    cells.push(Self {
                        distro,
                        gpu_vendor,
                        display_server,
                    });
                }
            }
        }
        cells
    }
}

impl fmt::Display for MatrixCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.distro, self.gpu_vendor, self.display_server
        )
    }
}

/// State of a single Gate L0 gate.
///
/// `not-run` is explicit and is never interpreted as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateState {
    /// The gate has no evidence yet.
    NotRun,
    /// The gate passed.
    Pass,
    /// The gate failed.
    Fail,
    /// Evidence was inconclusive.
    Inconclusive,
}

/// Results of the six fixed Gate L0 gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GateResults {
    /// L0.0 containment.
    pub l0_0_containment: GateState,
    /// L0.1 native launch.
    pub l0_1_launch: GateState,
    /// L0.2 real hardware acceleration.
    pub l0_2_acceleration: GateState,
    /// L0.3 exact-frame presentation.
    pub l0_3_present: GateState,
    /// L0.4 archive-hash churn.
    pub l0_4_churn: GateState,
    /// L0.5 capture/maintenance stability.
    pub l0_5_maintenance: GateState,
}

/// Overall classification of an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Classification {
    /// Controlled Neuestar libc remains authoritative and functional gates pass.
    CleanPass,
    /// Functional gates pass only with host glibc assimilated.
    ConditionalPass,
    /// Workload failure or any hard kill condition.
    Fail,
}

/// Canonical artifact identity verified before and after extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// SHA-256 of the outer archive supplied to every runner.
    pub outer_archive_sha256: String,
    /// SHA-256 of the embedded canonical payload manifest.
    pub payload_manifest_sha256: String,
    /// Canonical source commit used to build the artifact.
    pub source_commit: String,
    /// Probe implementation version that produced the report.
    pub probe_version: String,
}

/// Observed host metadata, independent of declared matrix labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedHost {
    /// Observed distribution identifier, including a version when known.
    pub distro_id: String,
    /// Observed kernel release.
    pub kernel_release: String,
    /// Observed CPU architecture.
    pub architecture: String,
    /// Observed GPU description.
    pub gpu_description: String,
    /// Observed userspace driver version, when determinable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    /// Observed display server, when determinable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_server: Option<String>,
}

/// Evidence for L0.0 namespace construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentEvidence {
    /// Whether the ordinary extracted download constructed the namespace.
    pub namespace_constructed: bool,
    /// Forbidden preparation actions that were actually attempted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_preparation: Vec<ForbiddenPreparation>,
}

/// One recorded forbidden preparation action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenPreparation {
    /// Category of the forbidden action.
    pub kind: ForbiddenPreparationKind,
    /// Human-readable evidence for the action.
    pub description: String,
}

/// Predeclared forbidden preparation categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForbiddenPreparationKind {
    /// Any use of `sudo` or equivalent privilege escalation.
    Sudo,
    /// Sysctl, `AppArmor`, or equivalent policy changes.
    SysctlOrAppArmor,
    /// Installing a setuid helper.
    SetuidInstall,
    /// Installing distribution compatibility packages.
    DistroCompatibilityPackages,
    /// Installing or relying on nix-ld.
    NixLd,
    /// Manually installing bubblewrap.
    ManualBubblewrap,
    /// Creating driver symlinks.
    DriverSymlinks,
    /// Per-host ELF patching.
    HostElfPatching,
    /// Neuestar-specific driver preparation.
    NeuestarDriverPreparation,
}

/// Origin of the C runtime used by the native child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LibcSource {
    /// Controlled Neuestar libc remains authoritative.
    Controlled,
    /// Host glibc or an equivalent host C-runtime closure was assimilated.
    HostGlibc,
    /// The C runtime was not determined before the attempt ended.
    NotDetermined,
}

/// Runtime and ELF loading evidence for L0.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvidence {
    /// Which C runtime the child executed against.
    pub libc_source: LibcSource,
    /// Concrete host glibc path when `libc_source` is `host-glibc`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_glibc_path: Option<String>,
    /// Resolved ELF interpreter, when the child launched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    /// Unresolved dynamic symbols observed before launch ended.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_symbols: Vec<String>,
    /// Loader diagnostics captured during launch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loader_diagnostics: Vec<String>,
}

/// Vulkan renderer kind observed for L0.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RendererKind {
    /// A software rasterizer such as llvmpipe or lavapipe.
    Software,
    /// Real hardware acceleration.
    Hardware,
    /// The renderer could not be determined.
    NotDetermined,
}

/// Graphics evidence for L0.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphicsEvidence {
    /// Kind of renderer selected.
    pub renderer: RendererKind,
    /// Renderer description reported by the Vulkan stack.
    pub renderer_description: String,
    /// Selected Vulkan device description.
    pub device: String,
    /// Explicit ICD manifests used by generic discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icd_manifests: Vec<String>,
    /// Generically discovered concrete libraries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_libraries: Vec<String>,
    /// Predeclared vendor-specific rules, at most one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vendor_specific_rules: Vec<VendorSpecificRule>,
    /// Distro-specific rules; validation requires this to remain empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distro_specific_rules: Vec<DistroSpecificRule>,
}

/// A predeclared vendor-specific graphics rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorSpecificRule {
    /// Rule category; must be `nvidia-device-nodes`.
    pub category: String,
    /// Rule description.
    pub description: String,
}

impl VendorSpecificRule {
    /// Returns the sole permitted predeclared NVIDIA device-node rule.
    #[must_use]
    pub fn nvidia_device_nodes(description: impl Into<String>) -> Self {
        Self {
            category: VENDOR_RULE_CATEGORY_NVIDIA_DEVICE_NODES.to_owned(),
            description: description.into(),
        }
    }
}

/// A distro-specific rule; validation requires that none exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistroSpecificRule {
    /// Rule category.
    pub category: String,
    /// Rule description.
    pub description: String,
}

/// Evidence for L0.3 exact-frame presentation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationEvidence {
    /// Frames requested by the presentation workload.
    pub frames_requested: u32,
    /// Frames actually presented.
    pub frames_presented: u32,
    /// Vulkan validation errors observed.
    pub validation_errors: u32,
    /// Whether the Vulkan device was lost.
    pub device_loss: bool,
    /// Complete timing summary; required for a passing L0.3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<PresentationTimings>,
}

/// Timing summary for a presented frame batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationTimings {
    /// Total elapsed presentation time in seconds.
    pub elapsed_seconds: f64,
    /// Median frame time in milliseconds.
    pub frame_time_median_ms: f64,
    /// P95 frame time in milliseconds.
    pub frame_time_p95_ms: f64,
    /// P99 frame time in milliseconds.
    pub frame_time_p99_ms: f64,
    /// Maximum frame time in milliseconds.
    pub frame_time_max_ms: f64,
}

/// Capture and maintenance evidence for L0.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEvidence {
    /// SHA-256 of the capture-rule set.
    pub capture_rule_sha256: String,
    /// Concrete files captured by generic discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub captured_concrete_files: Vec<String>,
}

/// Optional structured failure attached to a failed attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredFailure {
    /// Stage in which the failure occurred.
    pub stage: FailureStage,
    /// Short failure message.
    pub message: String,
    /// Additional diagnostic detail.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// Stage in which an attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureStage {
    /// Preflight verification of the artifact or environment.
    Preflight,
    /// L0.0 containment.
    Containment,
    /// L0.1 launch.
    Launch,
    /// L0.2 graphics.
    Graphics,
    /// L0.3 presentation.
    Presentation,
    /// L0.4 churn.
    Churn,
    /// L0.5 maintenance.
    Maintenance,
    /// The stage could not be determined.
    Unknown,
}

/// Versioned Gate L0 report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Report schema identifier; must be `neuestar.report/v1`.
    pub schema: SchemaVersion,
    /// Canonical artifact identity.
    pub artifact: Artifact,
    /// Declared physical matrix cell.
    pub matrix_cell: MatrixCell,
    /// Observed host metadata.
    pub observed_host: ObservedHost,
    /// L0.0 containment evidence.
    pub containment: ContainmentEvidence,
    /// L0.1 runtime and glibc evidence.
    pub runtime: RuntimeEvidence,
    /// L0.2 graphics evidence.
    pub graphics: GraphicsEvidence,
    /// L0.3 presentation evidence.
    pub presentation: PresentationEvidence,
    /// L0.5 capture evidence.
    pub capture: CaptureEvidence,
    /// Results of all six gates.
    pub gates: GateResults,
    /// Overall classification.
    pub classification: Classification,
    /// Structured failure, when one was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<StructuredFailure>,
}

impl Report {
    /// Validates every structural and cross-field Gate L0 invariant.
    ///
    /// # Errors
    ///
    /// Returns the first [`crate::ReportError`] when the report is not
    /// admissible evidence.
    pub fn validate(&self) -> Result<(), crate::ReportError> {
        crate::checks::validate(self)
    }
}

/// One matrix cell in a campaign, with an explicit unrun state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCell {
    /// Matrix cell identity.
    pub cell: MatrixCell,
    /// Report for the cell, or `None` when the cell is explicitly unrun.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
}

/// Aggregated campaign over the fixed physical matrix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Campaign {
    /// All cells, including explicit unrun cells.
    pub cells: Vec<CampaignCell>,
}

impl Campaign {
    /// Validates aggregation invariants and returns every violation found.
    ///
    /// # Errors
    ///
    /// Returns all [`crate::CampaignError`] violations when the campaign is
    /// not admissible.
    pub fn validate(&self) -> Result<(), Vec<crate::CampaignError>> {
        crate::aggregate::validate(self)
    }
}
