//! Thin containment runner for the H0 probe. Command construction and artifact
//! verification live in `neuestar-probe-core` (shared verbatim with the frozen
//! Campaign 002 launcher so the H0.P environment cannot drift); this module
//! only runs the containment observationally and records the argv.

use std::process::{ChildStderr, Command, Stdio};
use std::thread;

use std::io::{BufReader, Read};

use anyhow::Error as AnyhowError;

const PROCESS_STDERR_MAX_BYTES: usize = 64 * 1024;
const PROCESS_STDERR_MAX_CHARS: usize = 4096;

#[derive(Debug)]
pub enum ContainmentError {
    Spawn(AnyhowError),
    Wait(AnyhowError),
}

impl std::fmt::Display for ContainmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainmentError::Spawn(error) => write!(f, "failed to spawn containment: {error}"),
            ContainmentError::Wait(error) => write!(f, "failed to wait for containment: {error}"),
        }
    }
}

#[derive(Debug)]
pub struct RunOutcome {
    pub status: Option<i32>,
    pub process_stderr: Option<String>,
}

/// Runs the containment command, draining stderr observationally (to EOF,
/// bounded prefix retained). Distinguishes spawn failure (helper never
/// started) from wait failure (helper started) for structured apparatus
/// records.
pub fn run_contained(command: &mut Command) -> Result<RunOutcome, ContainmentError> {
    command.stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        ContainmentError::Spawn(AnyhowError::new(error).context("failed to spawn containment"))
    })?;
    let stderr_thread = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(move || capture_process_stderr(stderr)));
    let status = child.wait().map_err(|error| {
        ContainmentError::Wait(AnyhowError::new(error).context("failed to wait for containment"))
    })?;
    let process_stderr = stderr_thread
        .and_then(|handle| handle.join().ok())
        .flatten();
    Ok(RunOutcome {
        status: status.code(),
        process_stderr,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_stderr_capture_is_bounded_and_preserves_exit_status() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(
                "i=0; while [ $i -lt 4000 ]; do \
                 echo 0123456789abcdefghijklmnopqrstuvwxyz0123456789 >&2; \
                 i=$((i+1)); done; exit 71",
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let stderr = child.stderr.take().expect("piped stderr");
        let handle = thread::spawn(move || capture_process_stderr(stderr));
        let status = child.wait().expect("wait sh");
        let captured = handle.join().expect("stderr thread");
        assert_eq!(status.code(), Some(71), "exit status must be preserved");
        let text = captured.expect("captured stderr");
        assert!(text.chars().count() <= PROCESS_STDERR_MAX_CHARS);
        assert!(text.contains("0123456789abcdefghijklmnopqrstuvwxyz"));
    }
}
