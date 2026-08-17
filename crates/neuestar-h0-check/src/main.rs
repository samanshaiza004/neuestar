//! `h0-check` — H0 checker: validates a `neuestar.h0/v1` record against the
//! schema (structural validity) and against the frozen GATE-H0 /
//! H0-KILL-CONDITIONS policy thresholds (admissibility). Verdict:
//! PASS (0) / FAIL (1, policy violations, exactly representable) / INVALID
//! (2, schema-invalid record).
//!
//! The schema records reality; this checker decides whether that reality
//! violates frozen policy. An over-threshold observation (9 MiB package,
//! third-party repo, version pin, local patch, etc.) must therefore remain a
//! valid record whose verdict is FAIL with the exact violation.

use std::process::ExitCode;

use anyhow::{Context, Result};
use serde_json::{Value, json};

const SCHEMA: &str = include_str!("../../../schema/h0.schema.json");

/// Frozen policy ceilings (GATE-H0 §8 / H0-KILL-CONDITIONS).
const MAX_INSTALLED_BYTES: u64 = 8 * 1024 * 1024;
const MAX_INSTALLED_FILES: u64 = 20;
const MAX_POLICY_LOC: u64 = 200;
const MAX_DISTRO_BRANCHES: u64 = 2;
const MAX_HOST_PACKAGES: usize = 2;
const MAX_CARRIED_COMPONENTS: usize = 1;
const MAX_HELPER_LOC: u64 = 2000;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(record_path) = args.next() else {
        eprintln!("usage: h0-check <record.json>");
        return ExitCode::from(2);
    };
    let record_path = std::path::PathBuf::from(record_path);
    match run(&record_path) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("h0-check: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run(record_path: &std::path::Path) -> Result<u8> {
    let record: Value = serde_json::from_reader(
        std::fs::File::open(record_path)
            .with_context(|| format!("cannot open {}", record_path.display()))?,
    )
    .context("record is not valid JSON")?;

    let mut violations: Vec<Value> = Vec::new();
    let schema_valid = validate_schema(&record, &mut violations);
    if !schema_valid {
        print_verdict("INVALID", &violations);
        return Ok(2);
    }

    let mut policy_violations = Vec::new();
    check_policy(&record, &mut policy_violations);
    let pass = policy_violations.is_empty();
    print_verdict(if pass { "PASS" } else { "FAIL" }, &policy_violations);
    Ok(if pass { 0 } else { 1 })
}

fn validate_schema(record: &Value, violations: &mut Vec<Value>) -> bool {
    let schema: Value = serde_json::from_str(SCHEMA).expect("embedded schema is valid");
    let validator = match jsonschema::validator_for(&schema) {
        Ok(validator) => validator,
        Err(error) => {
            violations.push(json!({
                "stage": "schema",
                "code": "schema-invalid",
                "message": format!("embedded schema is invalid: {error}"),
            }));
            return false;
        }
    };
    let errors: Vec<_> = validator.iter_errors(record).take(16).collect();
    if errors.is_empty() {
        return true;
    }
    for error in errors {
        violations.push(json!({
            "stage": "schema",
            "code": "structural",
            "message": error.to_string(),
        }));
    }
    false
}

fn check_policy(record: &Value, violations: &mut Vec<Value>) {
    let burden = &record["burden"];

    // Manifest-derived totals: recompute instead of trusting the record.
    let manifest_bytes: u64 = burden["installed_files"]
        .as_array()
        .map(|files| {
            files
                .iter()
                .map(|file| file["size_bytes"].as_u64().unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);
    let manifest_files = burden["installed_files"]
        .as_array()
        .map_or(0, |files| files.len() as u64);
    let reported_bytes = burden["installed_byte_count"].as_u64().unwrap_or(0);
    let reported_files = burden["installed_file_count"].as_u64().unwrap_or(0);
    if manifest_bytes != reported_bytes || manifest_files != reported_files {
        violations.push(json!({
            "stage": "apparatus",
            "code": "manifest-total-mismatch",
            "message": format!(
                "installed_files implies {manifest_bytes} bytes / {manifest_files} files; record reports {reported_bytes} / {reported_files}"
            ),
        }));
    }
    // Thresholds use the manifest-derived totals so the manifest is the truth.
    if manifest_bytes > MAX_INSTALLED_BYTES {
        violations.push(json!({
            "stage": "threshold",
            "code": "installed-byte-count",
            "message": format!("installed bytes {manifest_bytes} exceed frozen ceiling {MAX_INSTALLED_BYTES}"),
        }));
    }
    if manifest_files > MAX_INSTALLED_FILES {
        violations.push(json!({
            "stage": "threshold",
            "code": "installed-file-count",
            "message": format!("installed files {manifest_files} exceed frozen ceiling {MAX_INSTALLED_FILES}"),
        }));
    }
    check_bounded(
        record,
        violations,
        "policy_loc",
        MAX_POLICY_LOC,
        "policy-loc",
    );
    check_bounded(
        record,
        violations,
        "distro_branch_count",
        MAX_DISTRO_BRANCHES,
        "distro-branch-count",
    );
    check_bounded(
        record,
        violations,
        "helper_loc",
        MAX_HELPER_LOC,
        "helper-loc",
    );

    if !burden["services"]
        .as_array()
        .is_none_or(|services| services.is_empty())
    {
        violations.push(json!({
            "stage": "threshold",
            "code": "services-introduced",
            "message": "services/daemons introduced by the integration violate the frozen zero ceiling",
        }));
    }
    if !burden["neuestar_maintained_dependencies"]
        .as_array()
        .is_none_or(|deps| deps.is_empty())
    {
        violations.push(json!({
            "stage": "threshold",
            "code": "neuestar-maintained-dependencies",
            "message": "Neuestar-maintained dependencies violate the frozen zero ceiling",
        }));
    }

    let host_packages = burden["additional_host_packages"]
        .as_array()
        .map_or(0, Vec::len);
    if host_packages > MAX_HOST_PACKAGES {
        violations.push(json!({
            "stage": "threshold",
            "code": "host-package-count",
            "message": format!("{host_packages} host packages exceed the frozen ceiling {MAX_HOST_PACKAGES}"),
        }));
    }
    for package in burden["additional_host_packages"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if package["from_distro_repo"].as_bool() != Some(true) {
            violations.push(json!({
                "stage": "threshold",
                "code": "forbidden-third-party-repository",
                "message": format!("host package {} is not from a distro-supported repository", package["name"]),
            }));
        }
        if package["version_pinned"].as_bool() == Some(true) {
            violations.push(json!({
                "stage": "threshold",
                "code": "forbidden-version-pin",
                "message": format!("host package {} is exactly version-pinned", package["name"]),
            }));
        }
    }

    let carried = burden["carried_components"].as_array();
    if carried.is_some_and(|components| components.len() > MAX_CARRIED_COMPONENTS) {
        violations.push(json!({
            "stage": "threshold",
            "code": "carried-component-count",
            "message": format!("more than {MAX_CARRIED_COMPONENTS} carried third-party components"),
        }));
    }
    for component in carried.into_iter().flatten() {
        if component["neuestar_specific_patches"].as_u64().unwrap_or(0) > 0 {
            violations.push(json!({
                "stage": "threshold",
                "code": "forbidden-local-patches",
                "message": format!(
                    "carried component {} has {} local patches; frozen requirement is zero",
                    component["upstream_project"], component["neuestar_specific_patches"]
                ),
            }));
        }
    }

    // Forbidden preparation: any recorded forbidden action is a policy
    // failure (frozen invariants A-L, H0-KILL-CONDITIONS).
    if record["forbidden_preparation"]
        .as_array()
        .is_some_and(|actions| !actions.is_empty())
    {
        violations.push(json!({
            "stage": "threshold",
            "code": "forbidden-preparation",
            "message": "forbidden preparation actions were recorded",
        }));
    }

    // Candidate-specific policy (definitional constraints are schema-side;
    // numeric/maintenance rules live here).
    match record["candidate"].as_str() {
        Some("A2") => {
            if carried.is_some_and(|components| !components.is_empty()) {
                violations.push(json!({
                    "stage": "threshold",
                    "code": "a2-carried-components",
                    "message": "A2 may not carry third-party components unless separately justified",
                }));
            }
        }
        Some("none") | Some("B")
            if burden["installed_byte_count"].as_u64().unwrap_or(0) != 0
                || burden["installed_file_count"].as_u64().unwrap_or(0) != 0
                || burden["policy_loc"].as_u64().unwrap_or(0) != 0
                || burden["distro_branch_count"].as_u64().unwrap_or(0) != 0 =>
        {
            violations.push(json!({
                "stage": "threshold",
                "code": "zero-integration-violation",
                "message": format!("candidate {} must record zero integration", record["candidate"]),
            }));
        }
        _ => {}
    }

    // H0.1S: a passing security-preservation gate requires the child to
    // retain no setup capabilities (empty CapEff, in its namespace context).
    if record["gates"]["h0_1s"].as_str() == Some("pass") {
        let caps_array = record["execution"]["child_effective_capabilities"].as_array();
        let caps = caps_array.map_or(0, Vec::len);
        let raw = record["execution"]["child_cap_eff_hex"]
            .as_str()
            .unwrap_or("");
        // Raw mask must be numerically zero, decoded set must be empty, and
        // the decoded set must agree with the raw mask (apparatus consistency).
        let raw_zero = neuestar_probe_core::capabilities::parse_cap_eff_hex(raw) == Some(0);
        let decoded = neuestar_probe_core::capabilities::decode_cap_mask(
            neuestar_probe_core::capabilities::parse_cap_eff_hex(raw).unwrap_or(u64::MAX),
        );
        let recorded: Vec<String> = caps_array
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .collect();
        let agrees = decoded == recorded;
        if !raw_zero || caps != 0 || !agrees {
            violations.push(json!({
                "stage": "security-preservation",
                "code": "h0.1s-retained-setup-capabilities",
                "message": format!(
                    "H0.1S pass with retained or inconsistent capabilities: raw={raw} decoded={decoded:?} recorded={recorded:?}"
                ),
            }));
        }
    }
}

fn check_bounded(
    record: &Value,
    violations: &mut Vec<Value>,
    field: &str,
    ceiling: u64,
    code: &str,
) {
    let value = record["burden"][field].as_u64().unwrap_or(0);
    if value > ceiling {
        violations.push(json!({
            "stage": "threshold",
            "code": code,
            "message": format!("{field} {value} exceeds frozen ceiling {ceiling}"),
        }));
    }
}

fn print_verdict(verdict: &str, violations: &[Value]) {
    let output = json!({
        "schema": "neuestar.h0.verdict/v1",
        "verdict": verdict,
        "violations": violations,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("verdict serializes")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn validate(record: &Value) -> (bool, Vec<Value>) {
        let mut violations = Vec::new();
        let valid = validate_schema(record, &mut violations);
        (valid, violations)
    }

    fn policy(record: &Value) -> Vec<Value> {
        let mut violations = Vec::new();
        check_policy(record, &mut violations);
        violations
    }

    fn execution_value(child_reached: bool) -> Value {
        let mut execution = json!({"helper_started": true, "child_reached": child_reached, "helper_profile_label": "neuestar-host"});
        if child_reached {
            // H0.P outcome evidence: namespace identities only.
            execution["child_user_namespace_id"] = json!("user:[2]");
            execution["child_mount_namespace_id"] = json!("mnt:[4]");
        }
        execution
    }

    fn add_security_evidence(record: &mut Value) {
        record["gates"]["h0_1s"] = json!("pass");
        record["execution"]["child_profile_label"] = json!("child");
        record["execution"]["child_effective_capabilities"] = json!([]);
        record["execution"]["child_cap_eff_hex"] = json!("0000000000000000");
    }

    fn base(
        candidate: &str,
        integration_shas: Option<&str>,
        trusted: bool,
        child_reached: bool,
    ) -> Value {
        let files = if candidate == "A1" {
            json!([{"path": "/usr/libexec/neuestar/bwrap", "size_bytes": 1_832_910, "sha256": S, "uid": 0, "gid": 0, "mode": 493, "kind": "carried-component"}])
        } else {
            json!([])
        };
        let carried = if candidate == "A1" {
            json!([{"upstream_project": "bubblewrap", "upstream_version_commit": "0.9.0", "source_provenance": "https://github.com/containers/bubblewrap", "binary_sha256": S, "patch_count": 0, "neuestar_specific_patches": 0, "security_update_responsibility": "track upstream"}])
        } else {
            json!([])
        };
        let sha = integration_shas.map_or(Value::Null, |_| json!(S));
        json!({
            "schema": "neuestar.h0/v1",
            "attempt": {"timestamp": "2026-08-16T23:00:00Z", "phase": "h0-preflight", "integration_source_changed_since_previous": false},
            "host": {"distro_id": "ubuntu", "distro_version": "26.04", "kernel_release": "7.0.0-29-generic", "architecture": "x86_64",
                     "target_profile": {"iso_snapshot_date": "2026-08-01", "config_surface": "stock"}},
            "security_state": {"lsm": "apparmor", "apparmor": {"parser_version": "4.0.1", "abi": "abi 5.0", "restriction_sysctl": 1,
                 "loaded_profiles": [{"name": "neuestar-host", "mode": "enforce"}], "loaded_profile_state_sha256": S}},
            "candidate": candidate,
            "integration": {"integration_identity_sha256": S, "neuestar_integration_package_sha256": sha,
                            "integration_source_sha256": sha, "security_policy_sha256": sha},
            "trusted_helper": if trusted {
                json!({"canonical_path": "/usr/libexec/neuestar/bwrap", "sha256": S, "uid": 0, "gid": 0, "mode": 493, "parent_mount_writable_by_test_user": false})
            } else {
                Value::Null
            },
            "runtime": {"runtime_artifact_sha256": S, "generation_identity": S, "application_identity": "app"},
            "burden": {"installed_files": files, "installed_byte_count": if files.as_array().is_some_and(|f| !f.is_empty()) { 1_832_910 } else { 0 },
                       "installed_file_count": if files.as_array().is_some_and(|f| !f.is_empty()) { 1 } else { 0 },
                       "policy_loc": if candidate == "A1" { 80 } else { 0 }, "distro_branch_count": if candidate == "A1" { 1 } else { 0 },
                       "services": [], "additional_host_packages": [], "neuestar_maintained_dependencies": [],
                       "carried_components": carried, "helper_loc": 0},
            "privileged_install_operations": [],
            "execution": execution_value(child_reached),
            "apparatus": {"probe_sha256": S, "containment_argv": ["bwrap", "--unshare-user"]},
            "gates": {"h0_0": "pass", "h0_1": "not-run", "h0_1s": "not-run", "h0_2a": "not-run", "h0_2b": "not-run",
                      "h0_3": "not-run", "h0_4": "not-run", "h0_4r": "not-run", "h0_5": "not-run", "h0_6": "not-run", "h0_p": "not-run"},
            "classification": "pass",
            "forbidden_preparation": [],
            "evidence": {"stderr": "", "pre_host_state": "", "post_host_state": ""},
        })
    }

    fn fail_record(record: Value, stage: &str, code: &str, message: &str) -> Value {
        let mut record = record;
        record["classification"] = json!("fail");
        record["failure"] = json!({"stage": stage, "code": code, "message": message});
        record
    }

    #[test]
    fn schema_cases_from_review_rounds() {
        // valid A1
        assert!(validate(&base("A1", Some("s"), true, true)).0);
        // A1 trusted_helper omitted -> schema-invalid
        let mut r = base("A1", Some("s"), true, true);
        r.as_object_mut().unwrap().remove("trusted_helper");
        assert!(!validate(&r).0);
        // A1 null integration sha -> schema-invalid
        let r = base("A1", None, true, true);
        assert!(!validate(&r).0);
        // A1 zero carried components -> schema-invalid (definitional)
        let mut r = base("A1", Some("s"), true, true);
        r["burden"]["carried_components"] = json!([]);
        assert!(!validate(&r).0);
        // early failure before child -> schema-valid, fail
        let r = fail_record(
            base("A1", Some("s"), true, false),
            "baseline",
            "uid-map-denied",
            "bwrap: setting up uid map: Permission denied",
        );
        assert!(validate(&r).0);
        // child reached but missing namespace identities -> schema-invalid (H0.P)
        let mut r = base("A1", Some("s"), true, true);
        r["execution"]
            .as_object_mut()
            .unwrap()
            .remove("child_user_namespace_id");
        assert!(!validate(&r).0);
        // H0.P record without CapEff/profile evidence -> schema-valid
        let mut r = base("A1", Some("s"), true, true);
        r["execution"]
            .as_object_mut()
            .unwrap()
            .remove("child_profile_label");
        assert!(
            validate(&r).0,
            "H0.P must not require H0.1S security evidence"
        );
        // H0.1S evaluated without security evidence -> schema-invalid
        let mut r = base("A1", Some("s"), true, true);
        r["gates"]["h0_1s"] = json!("pass");
        assert!(!validate(&r).0);
        // B: null package sha property required
        let mut r = base("B", None, false, false);
        r.as_object_mut().unwrap().remove("integration");
        assert!(!validate(&r).0);
        // none: zero integration record is valid
        assert!(validate(&base("none", None, false, false)).0);
        // apparmor missing loaded_policy_sha256 -> schema-invalid
        let mut r = base("A1", Some("s"), true, true);
        r["security_state"]["apparmor"]
            .as_object_mut()
            .unwrap()
            .remove("loaded_profile_state_sha256");
        assert!(!validate(&r).0);
        // apparatus missing containment_argv -> schema-invalid
        let mut r = base("A1", Some("s"), true, true);
        r["apparatus"]
            .as_object_mut()
            .unwrap()
            .remove("containment_argv");
        assert!(!validate(&r).0);
        // evidence missing pre_host_state -> schema-invalid
        let mut r = base("A1", Some("s"), true, true);
        r["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("pre_host_state");
        assert!(!validate(&r).0);
        // fail without failure -> schema-invalid
        let r = base("A1", Some("s"), true, true).pipe_fail_without_failure();
        assert!(!validate(&r).0);
        // pass with failure -> schema-invalid
        let mut r = base("A1", Some("s"), true, true);
        r["failure"] = json!({"stage": "threshold", "code": "x", "message": "y"});
        assert!(!validate(&r).0);
    }

    trait PipeFail {
        fn pipe_fail_without_failure(self) -> Value;
    }
    impl PipeFail for Value {
        fn pipe_fail_without_failure(mut self) -> Value {
            self["classification"] = json!("fail");
            self
        }
    }

    #[test]
    fn over_threshold_reality_is_representable_and_fails_policy() {
        // 9 MiB integration: schema-valid, checker FAIL with exact violation
        let mut r = base("A1", Some("s"), true, true);
        r["burden"]["installed_files"][0]["size_bytes"] = json!(9 * 1024 * 1024);
        r["burden"]["installed_byte_count"] = json!(9 * 1024 * 1024);
        assert!(validate(&r).0, "over-threshold must remain schema-valid");
        let violations = policy(&r);
        assert!(
            violations
                .iter()
                .any(|v| v["code"] == "installed-byte-count")
        );
    }

    #[test]
    fn policy_violations_are_exact() {
        // third-party repo
        let mut r = base("A1", Some("s"), true, true);
        r["burden"]["additional_host_packages"] = json!([{"name": "x", "version": "1", "from_distro_repo": false, "repository_origin": "evil.example.com", "version_pinned": false}]);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "forbidden-third-party-repository")
        );
        // version pin
        let mut r = base("A1", Some("s"), true, true);
        r["burden"]["additional_host_packages"] = json!([{"name": "x", "version": "1", "from_distro_repo": true, "repository_origin": "fedora", "version_pinned": true}]);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "forbidden-version-pin")
        );
        // local patches
        let mut r = base("A1", Some("s"), true, true);
        r["burden"]["carried_components"][0]["neuestar_specific_patches"] = json!(1);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "forbidden-local-patches")
        );
        // A2 helper_loc over ceiling (representable; checker fails)
        let mut r = base("A2", Some("s"), true, true);
        r["burden"]["helper_loc"] = json!(2001);
        assert!(validate(&r).0);
        assert!(policy(&r).iter().any(|v| v["code"] == "helper-loc"));
        // A2 carried component
        let mut r = base("A2", Some("s"), true, true);
        r["burden"]["carried_components"] =
            base("A1", Some("s"), true, true)["burden"]["carried_components"].clone();
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "a2-carried-components")
        );
        // manifest-total mismatch
        let mut r = base("A1", Some("s"), true, true);
        r["burden"]["installed_byte_count"] = json!(1);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "manifest-total-mismatch")
        );
        // services introduced
        let mut r = base("A1", Some("s"), true, true);
        r["burden"]["services"] = json!(["neuestar-host.service"]);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "services-introduced")
        );
        // zero-integration violation for none
        let mut r = base("none", None, false, false);
        r["burden"]["installed_byte_count"] = json!(100);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "zero-integration-violation")
        );
    }

    #[test]
    fn h01s_pass_requires_no_retained_capabilities() {
        let mut r = base("A1", Some("s"), true, true);
        add_security_evidence(&mut r);
        assert!(
            policy(&r).is_empty(),
            "empty CapEff with h0_1s pass is clean"
        );
        let mut r = base("A1", Some("s"), true, true);
        add_security_evidence(&mut r);
        r["execution"]["child_effective_capabilities"] = json!(["CAP_SYS_ADMIN"]);
        r["execution"]["child_cap_eff_hex"] = json!("0000000000200000");
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "h0.1s-retained-setup-capabilities")
        );
    }

    #[test]
    fn apparatus_failure_records_are_schema_valid_and_gate_truthful() {
        // artifact-verification: no command constructed -> [] argv allowed,
        // helper_started=false, h0_0 = not-run
        let mut r = base("none", None, false, false);
        r["execution"] = json!({"helper_started": false, "child_reached": false});
        r["apparatus"] = json!({"probe_sha256": S, "containment_argv": []});
        r["classification"] = json!("fail");
        r["failure"] =
            json!({"stage": "apparatus", "code": "artifact-verification", "message": "x"});
        r["gates"]["h0_0"] = json!("not-run");
        assert!(
            validate(&r).0,
            "pre-command apparatus record with [] argv must be schema-valid"
        );
        assert!(
            policy(&r).is_empty(),
            "apparatus record must not trip policy"
        );
        assert_eq!(
            r["gates"]["h0_0"],
            json!("not-run"),
            "apparatus failure must not claim H0.0 ran"
        );

        // spawn failure: helper_started=false, command WAS constructed -> argv recorded
        let mut r = base("none", None, false, false);
        r["execution"] = json!({"helper_started": false, "child_reached": false});
        r["apparatus"] =
            json!({"probe_sha256": S, "containment_argv": ["ld-linux", "--inhibit-cache"]});
        r["classification"] = json!("fail");
        r["failure"] = json!({"stage": "apparatus", "code": "helper-spawn-failed", "message": "x"});
        r["gates"]["h0_0"] = json!("not-run");
        assert!(
            validate(&r).0,
            "spawn-failure record with recorded argv must be schema-valid"
        );

        // wait failure: helper_started=true -> argv REQUIRED non-empty
        let mut r = base("none", None, false, false);
        r["execution"] = json!({"helper_started": true, "child_reached": false});
        r["apparatus"] =
            json!({"probe_sha256": S, "containment_argv": ["ld-linux", "--inhibit-cache"]});
        r["classification"] = json!("fail");
        r["failure"] = json!({"stage": "apparatus", "code": "helper-wait-failed", "message": "x"});
        r["gates"]["h0_0"] = json!("not-run");
        assert!(
            validate(&r).0,
            "wait-failure record (helper_started=true) must be schema-valid"
        );
        let mut r = base("none", None, false, false);
        r["execution"] = json!({"helper_started": true, "child_reached": false});
        r["apparatus"] = json!({"probe_sha256": S, "containment_argv": []});
        assert!(
            !validate(&r).0,
            "helper_started=true requires non-empty argv"
        );

        // baseline uid-map failure -> h0_0 = fail
        let mut b = base("none", None, false, false);
        b["execution"] = json!({"helper_started": true, "child_reached": false});
        b["apparatus"] =
            json!({"probe_sha256": S, "containment_argv": ["bwrap", "--unshare-user"]});
        b["classification"] = json!("fail");
        b["failure"] = json!({"stage": "baseline", "code": "child-unreached", "message": "bwrap: setting up uid map: Permission denied"});
        b["gates"]["h0_0"] = json!("fail");
        assert!(validate(&b).0);
        assert_eq!(
            b["gates"]["h0_0"],
            json!("fail"),
            "baseline failure must record H0.0 as fail"
        );
    }

    #[test]
    fn h01s_raw_cap_eff_must_be_numerically_zero() {
        // raw = 1 (CAP_CHOWN) with decoded [] -> must FAIL (raw is the truth)
        let mut r = base("A1", Some("s"), true, true);
        add_security_evidence(&mut r);
        r["execution"]["child_cap_eff_hex"] = json!("1");
        r["execution"]["child_effective_capabilities"] = json!([]);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "h0.1s-retained-setup-capabilities")
        );
        // raw = 0 with decoded [CAP_CHOWN] -> must FAIL (raw/decoded agreement)
        let mut r = base("A1", Some("s"), true, true);
        add_security_evidence(&mut r);
        r["execution"]["child_effective_capabilities"] = json!(["CAP_CHOWN"]);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "h0.1s-retained-setup-capabilities")
        );
    }

    #[test]
    fn forbidden_preparation_is_a_policy_failure() {
        let mut r = base("A1", Some("s"), true, true);
        r["forbidden_preparation"] =
            json!([{"kind": "sysctl", "description": "disabled userns restriction"}]);
        assert!(
            policy(&r)
                .iter()
                .any(|v| v["code"] == "forbidden-preparation")
        );
    }
}
