//! Minimum user+mount containment invocation (the frozen Campaign 002 shape:
//! GATE-H0 H0.P) plus observational stderr capture.

use std::path::Path;
use std::process::{ChildStderr, Command, Stdio};
use std::thread;

use anyhow::{Context, Result};
use std::io::{BufReader, Read};

const PROCESS_STDERR_MAX_BYTES: usize = 64 * 1024;
const PROCESS_STDERR_MAX_CHARS: usize = 4096;

/// The full containment argv, recorded in the H0 record (`apparatus`).
#[derive(Debug, Clone)]
pub struct ContainmentArgv {
    argv: Vec<String>,
}

impl ContainmentArgv {
    pub fn as_slice(&self) -> &[String] {
        &self.argv
    }
}

/// Outcome of one containment invocation.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub status: Option<i32>,
    pub process_stderr: Option<String>,
}

/// Builds the minimum user+mount containment command mirroring the frozen
/// Campaign 002 shape:
///
/// ```text
/// ld-linux --inhibit-cache --library-path <artifact>/libexec/lib <artifact>/libexec/bwrap \
///   --die-with-parent --new-session --unshare-user \
///   --ro-bind <artifact>/root / \
///   --dev /dev --proc /proc --tmpfs /tmp \
///   --ro-bind <artifact>/app /app \
///   --bind <report_parent> /evidence \
///   --clearenv ... NEUESTAR_CONTAINED 1 ... \
///   --chdir /app /app/probe --result /evidence/child-result.json
/// ```
///
/// No display/GPU preflight exists here; the probe declares no display.
#[allow(clippy::too_many_arguments)]
pub fn outcome_command(
    report_parent: &Path,
    artifact_root: &Path,
    probe_self: &Path,
    evidence_run: bool,
) -> Command {
    let mut argv: Vec<std::ffi::OsString> = Vec::new();
    argv.push(artifact_root.join("libexec/ld-linux-x86-64.so.2").into());
    argv.extend(["--inhibit-cache".into(), "--library-path".into()]);
    argv.push(artifact_root.join("libexec/lib").into());
    argv.push(artifact_root.join("libexec/bwrap").into());
    argv.extend([
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-user".into(),
        "--ro-bind".into(),
    ]);
    argv.push(artifact_root.join("root").into());
    argv.push("/".into());
    argv.extend([
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
        "--tmpfs".into(),
        "/tmp".into(),
    ]);
    argv.extend(["--ro-bind".into()]);
    argv.push(artifact_root.join("app").into());
    argv.push("/app".into());
    argv.extend(["--bind".into()]);
    argv.push(report_parent.as_os_str().to_owned());
    argv.push("/evidence".into());
    if evidence_run {
        // Bind the probe binary into the writable tmpfs so it can re-exec
        // itself inside the same boundary for deterministic child evidence.
        argv.extend(["--ro-bind".into()]);
        argv.push(probe_self.as_os_str().to_owned());
        argv.push("/tmp/h0-probe-evidence".into());
    }
    argv.extend([
        "--clearenv".into(),
        "--setenv".into(),
        "PATH".into(),
        "/usr/bin:/bin".into(),
        "--setenv".into(),
        "HOME".into(),
        "/nonexistent".into(),
        "--setenv".into(),
        "LD_BIND_NOW".into(),
        "1".into(),
        "--setenv".into(),
        "NEUESTAR_CONTAINED".into(),
        "1".into(),
    ]);
    if evidence_run {
        argv.extend([
            "--chdir".into(),
            "/tmp".into(),
            "/tmp/h0-probe-evidence".into(),
            "--child-mode".into(),
            "--child-result".into(),
            "/evidence/h0-child-evidence.json".into(),
        ]);
    } else {
        argv.extend([
            "--chdir".into(),
            "/app".into(),
            "/app/probe".into(),
            "--result".into(),
            "/evidence/child-result.json".into(),
        ]);
    }

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.current_dir(artifact_root);
    command
}

/// Returns the argv as strings (for the H0 record's `apparatus`).
pub fn outcome_argv(
    report_parent: &Path,
    artifact_root: &Path,
    probe_self: &Path,
    evidence_run: bool,
) -> ContainmentArgv {
    let command = outcome_command(report_parent, artifact_root, probe_self, evidence_run);
    ContainmentArgv {
        argv: command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect(),
    }
}

/// Runs the containment command, draining stderr observationally (to EOF,
/// bounded prefix retained) so the recorder never perturbs the measured
/// process. `Ok(None)` reports a spawn failure (`helper_started=false`).
pub fn run_contained(command: &mut Command) -> Result<Option<RunOutcome>> {
    command.stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("h0-probe: failed to spawn containment: {error:#}");
            return Ok(None);
        }
    };
    let stderr_thread = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(move || capture_process_stderr(stderr)));
    let status = child.wait().context("failed to wait for containment")?;
    let process_stderr = stderr_thread
        .and_then(|handle| handle.join().ok())
        .flatten();
    Ok(Some(RunOutcome {
        status: status.code(),
        process_stderr,
    }))
}

/// Drains the helper/child stderr to EOF while retaining only a bounded
/// UTF-8-lossy prefix.
pub fn capture_process_stderr(stderr: ChildStderr) -> Option<String> {
    let mut reader = BufReader::new(stderr);
    let mut retained: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) if retained.len() < PROCESS_STDERR_MAX_BYTES => {
                let room = PROCESS_STDERR_MAX_BYTES - retained.len();
                retained.extend_from_slice(&chunk[..n.min(room)]);
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    let text = String::from_utf8_lossy(&retained);
    let bounded: String = text.chars().take(PROCESS_STDERR_MAX_CHARS).collect();
    (!bounded.is_empty()).then_some(bounded)
}

/// Light artifact verification: artifact.json identity consistency and the
/// required containment members, without the full per-file payload walk (the
/// frozen archive is verified by SHA-256 at copy time in the VM procedure).
pub fn verify_artifact(artifact_root: &Path, expected_payload_sha256: &str) -> Result<()> {
    for required in [
        artifact_root.join("libexec/ld-linux-x86-64.so.2"),
        artifact_root.join("libexec/bwrap"),
        artifact_root.join("libexec/lib"),
        artifact_root.join("root"),
        artifact_root.join("app/probe"),
    ] {
        if !required.exists() {
            anyhow::bail!("required artifact member missing: {}", required.display());
        }
    }
    let metadata: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(artifact_root.join("artifact.json"))
            .context("missing artifact.json")?,
    )
    .context("artifact.json is malformed")?;
    let payload = metadata
        .get("payload_manifest_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("artifact.json has no payload_manifest_sha256"))?;
    if payload != expected_payload_sha256 {
        anyhow::bail!("artifact payload identity does not match the expected frozen payload");
    }
    let manifest_hash = sha256_file(&artifact_root.join("SHA256SUMS"))?;
    if manifest_hash != payload {
        anyhow::bail!("SHA256SUMS hash does not match artifact.json payload identity");
    }
    let root_manifest = metadata
        .get("runtime_root_manifest_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("artifact.json has no runtime_root_manifest_sha256"))?;
    let rootfs_hash = sha256_file(&artifact_root.join("rootfs.SHA256SUMS"))?;
    if rootfs_hash != root_manifest {
        anyhow::bail!("rootfs.SHA256SUMS hash does not match artifact.json runtime-root identity");
    }
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file =
        std::fs::File::open(path).with_context(|| format!("missing {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv_of(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn outcome_argv_matches_minimum_containment_shape() {
        let args = argv_of(&outcome_command(
            Path::new("/evidence-host"),
            Path::new("/artifact"),
            Path::new("/probe-self"),
            false,
        ));
        let joined = args.join(" ");
        assert!(joined.contains("--unshare-user"));
        for flag in [
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
        ] {
            assert!(!joined.contains(flag), "{flag} must not be requested");
        }
        assert!(
            args.windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == "/artifact/root" && w[2] == "/")
        );
        assert!(
            args.windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == "/artifact/app" && w[2] == "/app")
        );
        assert!(
            args.windows(3)
                .any(|w| w[0] == "--bind" && w[2] == "/evidence")
        );
        assert!(args.windows(3).any(|w| w[0] == "--proc" && w[1] == "/proc"));
        assert!(joined.contains("--chdir /app /app/probe --result /evidence/child-result.json"));
        // no display/GPU machinery
        assert!(
            !joined.contains("display")
                && !joined.contains("vulkan")
                && !joined.contains("wayland")
        );
    }

    #[test]
    fn evidence_run_binds_probe_into_tmpfs() {
        let args = argv_of(&outcome_command(
            Path::new("/evidence-host"),
            Path::new("/artifact"),
            Path::new("/probe-self"),
            true,
        ));
        assert!(args.windows(3).any(|w| w[0] == "--ro-bind"
            && w[1] == "/probe-self"
            && w[2] == "/tmp/h0-probe-evidence"));
        assert!(args.windows(3).any(|w| w[0] == "--chdir" && w[1] == "/tmp"));
        assert!(joined_contains(&args, "--child-mode"));
    }

    fn joined_contains(args: &[String], needle: &str) -> bool {
        args.join(" ").contains(needle)
    }

    #[test]
    fn artifact_verification_rejects_missing_members() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("libexec")).expect("mkdir");
        std::fs::create_dir_all(root.join("root")).expect("mkdir");
        std::fs::create_dir_all(root.join("app")).expect("mkdir");
        assert!(verify_artifact(root, &"a".repeat(64)).is_err());
    }
}
