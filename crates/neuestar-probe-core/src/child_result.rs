//! Bounded Campaign 002 child-result parsing and the exact success predicate,
//! shared verbatim by the frozen launcher and the H0 probe so equivalence is
//! literally the same code.

use std::fs::{self, File};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct ChildResult {
    pub schema: String,
    pub contained: bool,
    pub launch_reached_main: bool,
    pub architecture: String,
    pub user_namespace: String,
    pub mount_namespace: String,
    pub mapped_libc_paths: Vec<String>,
    pub failure: Option<ChildFailure>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChildFailure {
    pub code: String,
    pub explanation: String,
}

/// Reads and validates a child result under the Campaign 002 bounded contract:
/// file size, schema identifier, and bounded/absolute fields.
pub fn read_child_result(path: &Path) -> Result<ChildResult> {
    let metadata =
        fs::metadata(path).with_context(|| format!("child did not produce {}", path.display()))?;
    if metadata.len() > 1024 * 1024 {
        bail!("child result exceeds 1 MiB");
    }
    let result: ChildResult =
        serde_json::from_reader(File::open(path)?).context("child result is malformed")?;
    if result.schema != "neuestar.child/v1"
        || result.architecture.is_empty()
        || result.architecture.len() > 32
        || result.user_namespace.len() > 128
        || result.mount_namespace.len() > 128
        || result.mapped_libc_paths.len() > 16
        || result
            .mapped_libc_paths
            .iter()
            .any(|path| path.len() > 1024 || !path.starts_with('/'))
    {
        bail!("child result violates its bounded schema");
    }
    Ok(result)
}

/// The exact Campaign 002 success predicate: contained, launch reached,
/// x86_64, user AND mount namespace changed versus the parent, no child
/// failure, and controlled libc observed.
pub fn valid_successful_child_result(
    result: &ChildResult,
    parent_user_namespace: &str,
    parent_mount_namespace: &str,
) -> bool {
    result.contained
        && result.launch_reached_main
        && result.architecture == "x86_64"
        && namespace_changed(&result.user_namespace, parent_user_namespace, "user:")
        && namespace_changed(&result.mount_namespace, parent_mount_namespace, "mnt:")
        && result.failure.is_none()
        && result
            .mapped_libc_paths
            .iter()
            .any(|path| path.contains("libc.so"))
}

pub fn namespace_changed(child: &str, parent: &str, prefix: &str) -> bool {
    child.starts_with(prefix) && parent.starts_with(prefix) && child != parent
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result() -> ChildResult {
        ChildResult {
            schema: "neuestar.child/v1".to_owned(),
            contained: true,
            launch_reached_main: true,
            architecture: "x86_64".to_owned(),
            user_namespace: "user:[2]".to_owned(),
            mount_namespace: "mnt:[4]".to_owned(),
            mapped_libc_paths: vec!["/lib/libc.so.6".to_owned()],
            failure: None,
        }
    }

    #[test]
    fn successful_child_requires_controlled_libc_and_namespace_change() {
        let mut child = result();
        assert!(valid_successful_child_result(&child, "user:[1]", "mnt:[3]"));
        // same user namespace as parent -> not successful
        assert!(!valid_successful_child_result(
            &child, "user:[2]", "mnt:[3]"
        ));
        // no libc -> not successful
        child.mapped_libc_paths.clear();
        assert!(!valid_successful_child_result(
            &child, "user:[1]", "mnt:[3]"
        ));
    }

    #[test]
    fn read_child_result_enforces_the_bounded_contract() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("child-result.json");

        let mut bounded = result();
        bounded.schema = "neuestar.child/v1".to_owned();
        fs::write(&path, serde_json::to_vec(&bounded).expect("serialize")).expect("fixture");
        assert!(read_child_result(&path).is_ok());

        // oversized mapped path -> rejected
        let mut bad = result();
        bad.mapped_libc_paths = vec!["/".repeat(2000)];
        fs::write(&path, serde_json::to_vec(&bad).expect("serialize")).expect("fixture");
        assert!(read_child_result(&path).is_err());

        // non-absolute mapped path -> rejected
        let mut bad = result();
        bad.mapped_libc_paths = vec!["libc.so.6".to_owned()];
        fs::write(&path, serde_json::to_vec(&bad).expect("serialize")).expect("fixture");
        assert!(read_child_result(&path).is_err());

        // too many mapped paths -> rejected
        let mut bad = result();
        bad.mapped_libc_paths = (0..17).map(|i| format!("/lib/{i}")).collect();
        fs::write(&path, serde_json::to_vec(&bad).expect("serialize")).expect("fixture");
        assert!(read_child_result(&path).is_err());

        // wrong schema -> rejected
        let mut bad = result();
        bad.schema = "neuestar.other/v1".to_owned();
        fs::write(&path, serde_json::to_vec(&bad).expect("serialize")).expect("fixture");
        assert!(read_child_result(&path).is_err());
    }
}
