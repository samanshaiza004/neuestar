//! Minimum user+mount containment command construction (the frozen Campaign
//! 002 shape, extracted verbatim from the launcher). The outer loader
//! environment is cleared and explicitly supplied; the contained environment
//! carries the Campaign identity variables. Only the final child execution is
//! parameterized.

use std::path::Path;
use std::process::Command;

use crate::artifact::ArtifactMetadata;

/// The final child execution inside the containment (chdir + argv).
#[derive(Debug, Clone)]
pub struct ChildExec {
    pub chdir: &'static str,
    pub argv: Vec<String>,
}

/// The frozen Campaign 002 contained child execution.
pub fn frozen_child_exec() -> ChildExec {
    ChildExec {
        chdir: "/app",
        argv: vec![
            "/app/probe".to_owned(),
            "--result".to_owned(),
            "/evidence/child-result.json".to_owned(),
        ],
    }
}

pub fn contained_command(
    report_parent: &Path,
    artifact_root: &Path,
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
    child_exec: &ChildExec,
) -> Command {
    let mut command = Command::new(artifact_root.join("libexec/ld-linux-x86-64.so.2"));
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("LD_BIND_NOW", "1")
        .arg("--inhibit-cache")
        .arg("--library-path")
        .arg(artifact_root.join("libexec/lib"))
        .arg(artifact_root.join("libexec/bwrap"))
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--ro-bind",
        ])
        .arg(artifact_root.join("root"))
        .arg("/")
        .args(["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"])
        .arg("--ro-bind")
        .arg(artifact_root.join("app"))
        .arg("/app")
        .arg("--bind")
        .arg(report_parent)
        .arg("/evidence")
        .args([
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--setenv",
            "LD_BIND_NOW",
            "1",
            "--setenv",
            "NEUESTAR_CONTAINED",
            "1",
            "--setenv",
            "NEUESTAR_REPORT_SCHEMA",
            "neuestar.report/v2",
            "--setenv",
            "NEUESTAR_ARCHIVE_SHA256",
        ])
        .arg(archive_sha256)
        .args(["--setenv", "NEUESTAR_PAYLOAD_MANIFEST_SHA256"])
        .arg(&metadata.payload_manifest_sha256)
        .args(["--setenv", "NEUESTAR_SOURCE_COMMIT"])
        .arg(&metadata.source_commit)
        .args(["--setenv", "NEUESTAR_PROBE_VERSION"])
        .arg(&metadata.probe_version)
        .args(["--chdir"])
        .arg(child_exec.chdir)
        .args(&child_exec.argv)
        .current_dir(artifact_root);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> ArtifactMetadata {
        ArtifactMetadata {
            schema: "neuestar.artifact/v1".to_owned(),
            artifact_sha256: "a".repeat(64),
            payload_manifest_sha256: "b".repeat(64),
            source_commit: "c".repeat(40),
            probe_version: "0.2.0".to_owned(),
            runtime_root_manifest_sha256: "d".repeat(64),
            capture_rule_sha256: "e".repeat(64),
            child_interpreter: "/lib64/ld-linux-x86-64.so.2".to_owned(),
            controlled_libc_version: "2.39".to_owned(),
        }
    }

    #[test]
    fn contained_command_uses_minimum_namespaces_and_app_directory_bind() {
        let command = contained_command(
            Path::new("/evidence"),
            Path::new("/artifact"),
            &"a".repeat(64),
            &metadata(),
            &frozen_child_exec(),
        );
        let args: Vec<String> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|arg| arg == "--unshare-user"));
        for flag in [
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
        ] {
            assert!(
                !args.iter().any(|arg| arg == flag),
                "{flag} was removed for Campaign 002"
            );
        }
        let bind = args
            .windows(3)
            .find(|window| window[0] == "--ro-bind" && window[2] == "/app")
            .unwrap_or_else(|| panic!("app directory bind is missing"));
        assert_eq!(bind[1], "/artifact/app");
        assert!(
            !args
                .windows(3)
                .any(|window| window[0] == "--ro-bind" && window[2] == "/app/probe"),
            "the per-file app/probe bind was replaced by the app directory bind"
        );
        let joined = args.join(" ");
        assert!(joined.contains("--chdir /app /app/probe --result /evidence/child-result.json"));
        // exact outer loader environment
        assert!(command.get_envs().all(|(key, value)| {
            matches!(
                (key.to_string_lossy().as_ref(), value.map(|v| v.to_string_lossy().into_owned())),
                ("LANG", Some(v)) if v == "C"
            ) || matches!(
                (key.to_string_lossy().as_ref(), value.map(|v| v.to_string_lossy().into_owned())),
                ("LC_ALL", Some(v)) if v == "C"
            ) || matches!(
                (key.to_string_lossy().as_ref(), value.map(|v| v.to_string_lossy().into_owned())),
                ("LD_BIND_NOW", Some(v)) if v == "1"
            )
        }), "outer environment must be exactly LANG=C, LC_ALL=C, LD_BIND_NOW=1");
        assert!(
            command.get_envs().count() == 3,
            "outer environment must be cleared first"
        );
        // contained environment includes the Campaign identity variables
        assert!(joined.contains("--setenv NEUESTAR_REPORT_SCHEMA neuestar.report/v2"));
        assert!(joined.contains("--setenv NEUESTAR_ARCHIVE_SHA256"));
        assert!(joined.contains("--setenv NEUESTAR_PAYLOAD_MANIFEST_SHA256"));
        assert!(joined.contains("--setenv NEUESTAR_SOURCE_COMMIT"));
        assert!(joined.contains("--setenv NEUESTAR_PROBE_VERSION"));
    }
}
