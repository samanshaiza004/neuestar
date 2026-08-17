//! JSON Schema draft and fixture shape tests.

use serde_json::{Value, json};

const SCHEMA: &str = include_str!("../../../schema/report.schema.json");

#[test]
fn schema_is_draft_2020_12_with_disallowed_unknown_properties() {
    let root: Value = serde_json::from_str(SCHEMA).unwrap();
    assert_eq!(
        root["$schema"],
        json!("https://json-schema.org/draft/2020-12/schema")
    );
    assert_eq!(root["additionalProperties"], json!(false));
    assert_eq!(
        root["properties"]["schema"]["const"],
        json!("neuestar.report/v1")
    );
}

#[test]
fn schema_enforces_gate_states_classification_and_rule_caps() {
    let root: Value = serde_json::from_str(SCHEMA).unwrap();
    assert_eq!(
        root["$defs"]["gateState"]["enum"],
        json!(["not-run", "pass", "fail", "inconclusive"])
    );
    assert_eq!(
        root["properties"]["classification"]["enum"],
        json!(["clean-pass", "conditional-pass", "fail"])
    );
    assert_eq!(
        root["$defs"]["graphicsEvidence"]["properties"]["vendor_specific_rules"]["maxItems"],
        json!(1)
    );
    assert_eq!(
        root["$defs"]["graphicsEvidence"]["properties"]["distro_specific_rules"]["maxItems"],
        json!(0)
    );
    assert_eq!(
        root["$defs"]["vendorSpecificRule"]["properties"]["category"]["const"],
        json!("nvidia-device-nodes")
    );
    assert_eq!(
        root["$defs"]["artifact"]["properties"]["source_commit"]["pattern"],
        json!("^[0-9a-f]{40}$")
    );
    assert!(
        root["$defs"]["runtimeEvidence"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("host_glibc_imported"))
    );
    assert_eq!(
        root["$defs"]["captureEvidence"]["properties"]["distro_specific_rule_count"]["const"],
        json!(0)
    );
}

#[test]
fn schema_declares_containment_substage_and_bounded_helper_stderr() {
    let root: Value = serde_json::from_str(SCHEMA).unwrap();
    let containment = &root["$defs"]["containmentEvidence"]["properties"];
    assert_eq!(
        containment["substage"]["enum"],
        json!([
            "helper-preflight",
            "helper-execution",
            "child-result-missing",
            "child-launch"
        ])
    );
    assert_eq!(containment["helper_stderr"]["minLength"], json!(1));
    assert_eq!(containment["helper_stderr"]["maxLength"], json!(4096));
}

#[test]
fn schema_shape_matches_serialized_fixtures() {
    let root: Value = serde_json::from_str(SCHEMA).unwrap();
    let fixtures = [
        include_str!("fixtures/clean_pass.json"),
        include_str!("fixtures/conditional_pass.json"),
        include_str!("fixtures/fail_containment.json"),
    ];
    for fixture in fixtures {
        let value: Value = serde_json::from_str(fixture).unwrap();
        assert_shape(&value, &root, &root, "$");
    }
}

fn assert_shape(value: &Value, schema: &Value, root: &Value, path: &str) {
    let resolved = resolve(schema, root);
    match value {
        Value::Object(map) => {
            assert_eq!(
                resolved.get("additionalProperties"),
                Some(&Value::Bool(false)),
                "{path} must disallow unknown properties"
            );
            let properties = resolved
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{path} must have schema properties"));
            for (key, child) in map {
                let property = properties
                    .get(key)
                    .unwrap_or_else(|| panic!("{path}.{key} is not declared in the schema"));
                assert_shape(child, property, root, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            let item = resolved
                .get("items")
                .unwrap_or_else(|| panic!("{path} must have schema items"));
            for (index, child) in items.iter().enumerate() {
                assert_shape(child, item, root, &format!("{path}[{index}]"));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn resolve<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let name = reference
                .strip_prefix("#/$defs/")
                .unwrap_or_else(|| panic!("unexpected reference {reference}"));
            root.get("$defs")
                .and_then(|defs| defs.get(name))
                .unwrap_or_else(|| panic!("missing schema definition {name}"))
        }
        None => schema,
    }
}
