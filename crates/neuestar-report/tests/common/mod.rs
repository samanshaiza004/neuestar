//! Shared report builders for integration tests.
#![allow(dead_code)]

use neuestar_report::{
    Artifact, Campaign, CampaignCell, CaptureEvidence, Classification, ContainmentEvidence,
    DisplayServer, Distro, GateResults, GateState, GraphicsEvidence, LibcSource, MatrixCell,
    ObservedHost, PresentationEvidence, PresentationTimings, RendererKind, Report, RuntimeEvidence,
    SchemaVersion, VendorSpecificRule,
};

#[allow(clippy::too_many_lines)]
pub fn clean_report() -> Report {
    Report {
        schema: SchemaVersion::V1,
        artifact: Artifact {
            outer_archive_sha256: "a".repeat(64),
            payload_manifest_sha256: "b".repeat(64),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            probe_version: "0.1.0".to_owned(),
        },
        matrix_cell: MatrixCell {
            distro: Distro::Nixos,
            gpu_vendor: neuestar_report::GpuVendor::Nvidia,
            display_server: DisplayServer::Wayland,
        },
        observed_host: ObservedHost {
            distro_id: "nixos 25.05".to_owned(),
            distro_version: Some("25.05".to_owned()),
            kernel_release: "6.12.0".to_owned(),
            architecture: "x86_64".to_owned(),
            gpu_description: "NVIDIA GeForce RTX 3080".to_owned(),
            driver_version: Some("580.82.09".to_owned()),
            display_server: Some("wayland".to_owned()),
            current_desktop: Some("sway".to_owned()),
            desktop_session: Some("sway".to_owned()),
        },
        containment: ContainmentEvidence {
            namespace_constructed: true,
            user_namespace_constructed: true,
            mount_namespace_constructed: true,
            user_namespace_id: Some("user:[2]".to_owned()),
            mount_namespace_id: Some("mnt:[4]".to_owned()),
            errno: None,
            host_paths_exposed: Vec::new(),
            forbidden_preparation: Vec::new(),
            substage: None,
            helper_stderr: None,
        },
        runtime: RuntimeEvidence {
            libc_source: LibcSource::Controlled,
            libc_path: Some("/lib/libc.so.6".to_owned()),
            libc_version: Some("2.39".to_owned()),
            host_glibc_imported: false,
            host_glibc_reason: None,
            host_glibc_paths: Vec::new(),
            host_glibc_path: None,
            interpreter: Some("/neuestar/ld-linux-x86-64.so.2".to_owned()),
            unresolved_symbols: Vec::new(),
            loader_diagnostics: Vec::new(),
        },
        graphics: GraphicsEvidence {
            renderer: RendererKind::Hardware,
            renderer_description: "NVIDIA Vulkan driver".to_owned(),
            vulkan_loader: Some("/lib/libvulkan.so.1".to_owned()),
            device: "NVIDIA GeForce RTX 3080".to_owned(),
            icd_library: Some("/host-driver/libvulkan_nvidia.so".to_owned()),
            vendor_id: Some(0x10de),
            device_id: Some(0x2206),
            driver_name: Some("NVIDIA".to_owned()),
            driver_version: Some("580.82.09".to_owned()),
            device_type: Some("discrete-gpu".to_owned()),
            software_renderer_detected: false,
            icd_manifests: Vec::new(),
            discovered_libraries: Vec::new(),
            vendor_specific_rules: vec![VendorSpecificRule::nvidia_device_nodes(
                "Expose already-existing NVIDIA device nodes",
            )],
            distro_specific_rules: Vec::new(),
        },
        presentation: PresentationEvidence {
            frames_requested: 300,
            frames_presented: 300,
            validation_errors: 0,
            device_loss: false,
            present_mode: Some("fifo".to_owned()),
            timings: Some(PresentationTimings {
                elapsed_seconds: 8.42,
                frame_time_median_ms: 24.9,
                frame_time_p95_ms: 31.2,
                frame_time_p99_ms: 34.8,
                frame_time_max_ms: 41.7,
            }),
        },
        capture: CaptureEvidence {
            capture_rule_sha256: "c".repeat(64),
            captured_concrete_files: Vec::new(),
            capture_reasons: Vec::new(),
            captured_devices: Vec::new(),
            dependency_count: 0,
            vendor_specific_rule_count: 1,
            distro_specific_rule_count: 0,
            host_path_count: 0,
        },
        gates: GateResults {
            l0_0_containment: GateState::Pass,
            l0_1_launch: GateState::Pass,
            l0_2_acceleration: GateState::Pass,
            l0_3_present: GateState::Pass,
            l0_4_churn: GateState::NotRun,
            l0_5_maintenance: GateState::NotRun,
        },
        classification: Classification::CleanPass,
        failure: None,
    }
}

pub fn conditional_report() -> Report {
    let mut report = clean_report();
    report.runtime.libc_source = LibcSource::HostGlibc;
    report.runtime.libc_path = Some("/usr/lib/x86_64-linux-gnu/libc.so.6".to_owned());
    report.runtime.host_glibc_imported = true;
    report.runtime.host_glibc_reason = Some("driver requires host symbol versions".to_owned());
    report.runtime.host_glibc_paths = vec!["/usr/lib/x86_64-linux-gnu/libc.so.6".to_owned()];
    report.runtime.host_glibc_path = Some("/usr/lib/x86_64-linux-gnu/libc.so.6".to_owned());
    report.classification = Classification::ConditionalPass;
    report
}

pub fn campaign_with_runs(cells: &[MatrixCell]) -> Campaign {
    let entries = MatrixCell::all()
        .into_iter()
        .map(|cell| {
            let report = if cells.contains(&cell) {
                let mut report = clean_report();
                report.matrix_cell = cell;
                Some(report)
            } else {
                None
            };
            CampaignCell { cell, report }
        })
        .collect();
    Campaign { cells: entries }
}
