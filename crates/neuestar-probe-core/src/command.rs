//! Minimum user+mount containment command construction (the frozen Campaign
//! 002 shape, extracted verbatim from the launcher and extended for Candidate
//! A1). The outer loader/helper environment is cleared and explicitly
//! supplied; the contained environment carries the Campaign identity
//! variables. The helper invocation and the final child execution are
//! parameterized so the launcher, H0.P, and A1 cannot drift.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::artifact::ArtifactMetadata;

/// How to start the helper: the artifact-bundled loader invocation (Campaign
/// 002 / H0.P) or a direct exec of the installed root-owned helper (A1).
#[derive(Debug, Clone)]
pub struct HelperInvocation {
    pub argv: Vec<OsString>,
}

/// The frozen artifact-bundled helper invocation (bundled loader + bwrap).
pub fn frozen_helper_invocation(artifact_root: &Path) -> HelperInvocation {
    HelperInvocation {
        argv: vec![
            artifact_root.join("libexec/ld-linux-x86-64.so.2").into(),
            "--inhibit-cache".into(),
            "--library-path".into(),
            artifact_root.join("libexec/lib").into(),
            artifact_root.join("libexec/bwrap").into(),
        ],
    }
}

/// Direct exec of an installed root-owned helper (Candidate A1).
pub fn system_helper_invocation(helper_path: &Path) -> HelperInvocation {
    HelperInvocation {
        argv: vec![helper_path.as_os_str().to_owned()],
    }
}

/// The final child execution inside the containment (chdir + argv), plus any
/// extra read-only binds inserted before the environment section (e.g., the
/// H0.1S evidence probe binary bound into /tmp).
#[derive(Debug, Clone)]
pub struct ChildExec {
    pub chdir: &'static str,
    pub argv: Vec<String>,
    pub extra_ro_binds: Vec<(PathBuf, &'static str)>,
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
        extra_ro_binds: Vec::new(),
    }
}

/// The H0.1S security-evidence child execution: the probe re-executes itself
/// inside the SAME boundary (with an extra ro-bind of the probe binary into
/// the writable /tmp) to deterministically record CapEff, profile label, and
/// namespace identity.
pub fn security_evidence_child_exec(probe_binary: &Path) -> ChildExec {
    ChildExec {
        chdir: "/tmp",
        argv: vec![
            "/tmp/h0-probe-evidence".to_owned(),
            "--child-mode".to_owned(),
            "--child-result".to_owned(),
            "/evidence/h0-child-evidence.json".to_owned(),
        ],
        extra_ro_binds: vec![(probe_binary.to_path_buf(), "/tmp/h0-probe-evidence")],
    }
}

#[allow(clippy::too_many_arguments)]
pub fn contained_command(
    report_parent: &Path,
    artifact_root: &Path,
    archive_sha256: &str,
    metadata: &ArtifactMetadata,
    helper: &HelperInvocation,
    child_exec: &ChildExec,
) -> Command {
    let mut command = Command::new(&helper.argv[0]);
    command.args(&helper.argv[1..]);
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("LD_BIND_NOW", "1")
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
        .arg("/evidence");
    for (source, destination) in &child_exec.extra_ro_binds {
        command.arg("--ro-bind").arg(source).arg(destination);
    }
    command
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

    fn argv_of(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn contained_command_uses_minimum_namespaces_and_app_directory_bind() {
        let command = contained_command(
            Path::new("/evidence"),
            Path::new("/artifact"),
            &"a".repeat(64),
            &metadata(),
            &frozen_helper_invocation(Path::new("/artifact")),
            &frozen_child_exec(),
        );
        let args = argv_of(&command);
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
        let joined = args.join(" ");
        assert!(joined.contains("--chdir /app /app/probe --result /evidence/child-result.json"));
        // exact outer loader environment
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

    #[test]
    fn a1_system_helper_and_security_evidence_run() {
        // A1 outcome run: direct exec of the installed root-owned helper.
        let command = contained_command(
            Path::new("/evidence"),
            Path::new("/artifact"),
            &"a".repeat(64),
            &metadata(),
            &system_helper_invocation(Path::new("/usr/libexec/neuestar/bwrap")),
            &frozen_child_exec(),
        );
        let args = argv_of(&command);
        assert_eq!(
            command.get_program().to_string_lossy(),
            "/usr/libexec/neuestar/bwrap"
        );
        assert!(args.iter().any(|arg| arg == "--unshare-user"));
        assert!(
            args.join(" ")
                .contains("--chdir /app /app/probe --result /evidence/child-result.json")
        );

        // H0.1S evidence run: probe binary bound into /tmp and executed.
        let command = contained_command(
            Path::new("/evidence"),
            Path::new("/artifact"),
            &"a".repeat(64),
            &metadata(),
            &system_helper_invocation(Path::new("/usr/libexec/neuestar/bwrap")),
            &security_evidence_child_exec(Path::new("/proc/self/exe")),
        );
        let args = argv_of(&command);
        assert!(args.windows(3).any(|w| w[0] == "--ro-bind"
            && w[1] == "/proc/self/exe"
            && w[2] == "/tmp/h0-probe-evidence"));
        assert!(
            args.join(" ")
                .contains("--chdir /tmp /tmp/h0-probe-evidence --child-mode")
        );
    }
}
