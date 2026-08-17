//! Candidate A2a: static privilege-entry gate.
//!
//! The discovered failure class (A1/B): a dynamically linked helper receives
//! namespace-setup authority before user-controlled loader state has been
//! neutralized, so a hostile LD_PRELOAD constructor runs under the setup
//! profile. A2a fixes the class by ensuring **no user-controlled code can
//! execute while setup authority exists**:
//!
//! 1. this binary is statically linked (no dynamic loader → no loader
//!    injection, verified mechanically by PT_INTERP/PT_DYNAMIC absence);
//! 2. it sanitizes the environment (constructed from scratch) and closes all
//!    inherited file descriptors;
//! 3. it constructs a **fixed operation** (the frozen Campaign 002 minimum
//!    user+mount containment) and records the constructed argv;
//! 4. it execs the private `bwrap-real` through a secure-exec (Px) AppArmor
//!    transition, so even at that boundary the loader sees a scrubbed
//!    environment;
//! 5. `bwrap-real` holds the setup authority only through that transition
//!    (its path has no profile), and its children are stacked into the
//!    capability-denying `neuestar-unpriv` profile.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::exit;

const BWRAP_REAL: &str = "/usr/libexec/neuestar/bwrap-real";
const ARGV_JSON_OUTCOME: &str = ".entry-argv.json";
const ARGV_JSON_EVIDENCE: &str = ".entry-argv-evidence.json";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Outcome,
    SecurityEvidence,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Outcome => "outcome",
            Mode::SecurityEvidence => "security-evidence",
        }
    }
    fn argv_json_name(self) -> &'static str {
        match self {
            Mode::Outcome => ARGV_JSON_OUTCOME,
            Mode::SecurityEvidence => ARGV_JSON_EVIDENCE,
        }
    }
}

struct Args {
    artifact_root: PathBuf,
    evidence_dir: PathBuf,
    mode: Mode,
    archive_sha256: String,
    payload_manifest_sha256: String,
    source_commit: String,
    probe_version: String,
    evidence_probe: Option<PathBuf>,
}

fn usage() -> ! {
    eprintln!(
        "usage: entry --artifact-root <dir> --evidence-dir <dir> --mode outcome|security-evidence \
         --archive-sha256 <64hex> --payload-manifest-sha256 <64hex> --source-commit <40hex> \
         --probe-version <ver> [--evidence-probe <path>]"
    );
    exit(2);
}

fn take_value(args: &[OsString], index: &mut usize, flag: &str) -> String {
    *index += 1;
    args.get(*index)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            eprintln!("entry: missing value for {flag}");
            usage();
        })
}

fn parse_args() -> Args {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut artifact_root = None;
    let mut evidence_dir = None;
    let mut mode = None;
    let mut archive_sha256 = None;
    let mut payload_manifest_sha256 = None;
    let mut source_commit = None;
    let mut probe_version = None;
    let mut evidence_probe = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].to_string_lossy().into_owned();
        match flag.as_str() {
            "--artifact-root" => {
                artifact_root = Some(PathBuf::from(take_value(&args, &mut index, &flag)))
            }
            "--evidence-dir" => {
                evidence_dir = Some(PathBuf::from(take_value(&args, &mut index, &flag)))
            }
            "--mode" => {
                let value = take_value(&args, &mut index, &flag);
                mode = Some(match value.as_str() {
                    "outcome" => Mode::Outcome,
                    "security-evidence" => Mode::SecurityEvidence,
                    other => {
                        eprintln!("entry: unknown mode {other}");
                        usage();
                    }
                });
            }
            "--archive-sha256" => archive_sha256 = Some(take_value(&args, &mut index, &flag)),
            "--payload-manifest-sha256" => {
                payload_manifest_sha256 = Some(take_value(&args, &mut index, &flag))
            }
            "--source-commit" => source_commit = Some(take_value(&args, &mut index, &flag)),
            "--probe-version" => probe_version = Some(take_value(&args, &mut index, &flag)),
            "--evidence-probe" => {
                evidence_probe = Some(PathBuf::from(take_value(&args, &mut index, &flag)))
            }
            _ => {
                eprintln!("entry: unknown argument {flag}");
                usage();
            }
        }
        index += 1;
    }
    let Some(artifact_root) = artifact_root else {
        eprintln!("entry: --artifact-root required");
        usage();
    };
    let Some(evidence_dir) = evidence_dir else {
        eprintln!("entry: --evidence-dir required");
        usage();
    };
    let Some(mode) = mode else {
        eprintln!("entry: --mode required");
        usage();
    };
    let Some(archive_sha256) = archive_sha256 else {
        eprintln!("entry: --archive-sha256 required");
        usage();
    };
    let Some(payload_manifest_sha256) = payload_manifest_sha256 else {
        eprintln!("entry: --payload-manifest-sha256 required");
        usage();
    };
    let Some(source_commit) = source_commit else {
        eprintln!("entry: --source-commit required");
        usage();
    };
    let Some(probe_version) = probe_version else {
        eprintln!("entry: --probe-version required");
        usage();
    };
    if mode == Mode::SecurityEvidence && evidence_probe.is_none() {
        eprintln!("entry: --evidence-probe required with --mode security-evidence");
        usage();
    }
    Args {
        artifact_root,
        evidence_dir,
        mode,
        archive_sha256,
        payload_manifest_sha256,
        source_commit,
        probe_version,
        evidence_probe,
    }
}

/// Close every inherited file descriptor above 2 (hostile memfds, pipes,
/// eventfds, sockets). Uses close_range when available, /proc scan otherwise.
fn close_inherited_fds() {
    // SAFETY: close_range(3, u32::MAX, 0) is a plain syscall on fd numbers;
    // it cannot affect memory or other processes.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, 3usize, u32::MAX as usize, 0usize) };
    if rc == 0 {
        return;
    }
    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Ok(fd) = name.parse::<i32>() {
                if fd > 2 {
                    // SAFETY: closing our own fd numbers above the stdio set.
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
        }
    }
}

/// Sanitize the environment: build the minimal env the frozen operation
/// needs, from scratch. No caller-controlled variables survive.
fn sanitized_env() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("HOME"), OsString::from("/nonexistent")),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LD_BIND_NOW"), OsString::from("1")),
    ]
}

fn build_bwrap_argv(args: &Args) -> (String, Vec<String>) {
    let mut argv = vec![BWRAP_REAL.to_owned()];
    argv.extend([
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
        "--unshare-user".to_owned(),
        "--ro-bind".to_owned(),
    ]);
    argv.push(args.artifact_root.join("root").display().to_string());
    argv.extend(["/".to_owned(), "--dev".to_owned(), "/dev".to_owned()]);
    argv.extend([
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
    ]);
    argv.extend(["--ro-bind".to_owned()]);
    argv.push(args.artifact_root.join("app").display().to_string());
    argv.extend(["/app".to_owned(), "--bind".to_owned()]);
    argv.push(args.evidence_dir.display().to_string());
    argv.push("/evidence".to_owned());
    if args.mode == Mode::SecurityEvidence {
        let probe = args
            .evidence_probe
            .as_ref()
            .expect("validated: --evidence-probe required");
        argv.extend(["--ro-bind".to_owned()]);
        argv.push(probe.display().to_string());
        argv.push("/tmp/h0-probe-evidence".to_owned());
    }
    argv.extend([
        "--clearenv".to_owned(),
        "--setenv".to_owned(),
        "PATH".to_owned(),
        "/usr/bin:/bin".to_owned(),
        "--setenv".to_owned(),
        "HOME".to_owned(),
        "/nonexistent".to_owned(),
        "--setenv".to_owned(),
        "LD_BIND_NOW".to_owned(),
        "1".to_owned(),
        "--setenv".to_owned(),
        "NEUESTAR_CONTAINED".to_owned(),
        "1".to_owned(),
        "--setenv".to_owned(),
        "NEUESTAR_REPORT_SCHEMA".to_owned(),
        "neuestar.report/v2".to_owned(),
        "--setenv".to_owned(),
        "NEUESTAR_ARCHIVE_SHA256".to_owned(),
    ]);
    argv.push(args.archive_sha256.clone());
    argv.extend([
        "--setenv".to_owned(),
        "NEUESTAR_PAYLOAD_MANIFEST_SHA256".to_owned(),
    ]);
    argv.push(args.payload_manifest_sha256.clone());
    argv.extend(["--setenv".to_owned(), "NEUESTAR_SOURCE_COMMIT".to_owned()]);
    argv.push(args.source_commit.clone());
    argv.extend(["--setenv".to_owned(), "NEUESTAR_PROBE_VERSION".to_owned()]);
    argv.push(args.probe_version.clone());
    argv.extend(["--chdir".to_owned()]);
    let (chdir, child) = match args.mode {
        Mode::Outcome => (
            "/app".to_owned(),
            vec![
                "/app/probe".to_owned(),
                "--result".to_owned(),
                "/evidence/child-result.json".to_owned(),
            ],
        ),
        Mode::SecurityEvidence => (
            "/tmp".to_owned(),
            vec![
                "/tmp/h0-probe-evidence".to_owned(),
                "--child-mode".to_owned(),
                "--child-result".to_owned(),
                "/evidence/h0-child-evidence.json".to_owned(),
            ],
        ),
    };
    argv.push(chdir);
    argv.extend(child);
    (BWRAP_REAL.to_owned(), argv)
}

/// Record the constructed argv in the evidence dir (host context, before any
/// namespace setup) so the probe can freeze and cross-check the operation.
fn write_argv_evidence(args: &Args, argv: &[String]) {
    let evidence = serde_json::json!({
        "schema": "neuestar.h0.entry-argv/v1",
        "mode": args.mode.as_str(),
        "artifact_root": args.artifact_root.display().to_string(),
        "evidence_dir": args.evidence_dir.display().to_string(),
        "argv": argv,
    });
    let path = args.evidence_dir.join(args.mode.argv_json_name());
    let mut text = serde_json::to_string_pretty(&evidence).unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    if std::fs::write(&path, text).is_err() {
        eprintln!("entry: cannot write {}", path.display());
        exit(2);
    }
}

fn main() {
    let args = parse_args();
    close_inherited_fds();

    let (_, argv) = build_bwrap_argv(&args);
    write_argv_evidence(&args, &argv);

    // Change to the artifact root (mirrors the frozen command's cwd) and
    // exec bwrap-real through the secure-exec transition. exec() replaces
    // this process; it only returns on failure.
    let _ = std::env::set_current_dir(&args.artifact_root);
    let error = std::process::Command::new(BWRAP_REAL)
        .args(&argv[1..])
        .env_clear()
        .envs(sanitized_env())
        .exec();
    eprintln!("entry: exec of {BWRAP_REAL} failed: {error}");
    exit(2);
}
