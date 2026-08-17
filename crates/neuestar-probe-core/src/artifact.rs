//! Frozen Campaign 002 artifact verification (extracted verbatim from the
//! launcher): full payload-manifest walk, manifest completeness, metadata
//! identity, and path-safety rules.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_MANIFEST_ENTRIES: usize = 4096;

#[derive(Debug, Deserialize)]
pub struct ArtifactMetadata {
    pub schema: String,
    pub artifact_sha256: String,
    pub payload_manifest_sha256: String,
    pub source_commit: String,
    pub probe_version: String,
    pub runtime_root_manifest_sha256: String,
    pub capture_rule_sha256: String,
    pub child_interpreter: String,
    pub controlled_libc_version: String,
}

pub fn verify_payload(root: &Path) -> Result<ArtifactMetadata> {
    let manifest_path = root.join("SHA256SUMS");
    let manifest_metadata = fs::metadata(&manifest_path)
        .with_context(|| format!("missing {}", manifest_path.display()))?;
    if manifest_metadata.len() > MAX_MANIFEST_BYTES {
        bail!("payload manifest exceeds {MAX_MANIFEST_BYTES} bytes");
    }

    let file = File::open(&manifest_path)?;
    let reader = BufReader::new(file);
    let mut paths = HashSet::new();
    let mut entry_count = 0_usize;
    for (line_number, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("failed to read manifest line {}", line_number + 1))?;
        let (expected, raw_path) = line
            .split_once("  ")
            .ok_or_else(|| anyhow!("malformed manifest line {}", line_number + 1))?;
        if !valid_sha256(expected) {
            bail!("invalid hash on manifest line {}", line_number + 1);
        }
        let relative = raw_path.strip_prefix("./").unwrap_or(raw_path);
        let path = Path::new(relative);
        if !safe_relative_path(path) {
            bail!("unsafe manifest path on line {}", line_number + 1);
        }
        if !paths.insert(path.to_path_buf()) {
            bail!("duplicate manifest path: {}", path.display());
        }
        entry_count += 1;
        if entry_count > MAX_MANIFEST_ENTRIES {
            bail!("payload manifest has too many entries");
        }
        let actual = sha256_file(&root.join(path))?;
        if actual != expected {
            bail!("payload hash mismatch for {}", path.display());
        }
    }
    if entry_count == 0 {
        bail!("payload manifest is empty");
    }
    for required in [
        "neuestar-probe",
        "app/probe",
        "libexec/bwrap",
        "libexec/ld-linux-x86-64.so.2",
        "runtime.toml",
        "capture-rules.json",
        "rootfs.SHA256SUMS",
    ] {
        if !paths.contains(Path::new(required)) {
            bail!("payload manifest omits required member {required}");
        }
    }
    verify_manifest_completeness(root, &paths)?;

    verify_metadata(root, &paths, &sha256_file(&manifest_path)?)
}

pub fn verify_manifest_completeness(root: &Path, paths: &HashSet<PathBuf>) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            entries += 1;
            if entries > MAX_MANIFEST_ENTRIES * 4 {
                bail!("artifact filesystem has too many entries");
            }
            if metadata.file_type().is_symlink() {
                bail!("artifact contains a symlink: {}", entry.path().display());
            }
            if metadata.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !metadata.is_file() {
                bail!(
                    "artifact contains a special file: {}",
                    entry.path().display()
                );
            }
            let relative = entry.path().strip_prefix(root)?.to_path_buf();
            if relative != Path::new("artifact.json")
                && relative != Path::new("SHA256SUMS")
                && !paths.contains(&relative)
            {
                bail!(
                    "artifact contains an unmanifested file: {}",
                    relative.display()
                );
            }
        }
    }
    Ok(())
}

pub fn verify_metadata(
    root: &Path,
    paths: &HashSet<PathBuf>,
    manifest_hash: &str,
) -> Result<ArtifactMetadata> {
    let metadata_path = root.join("artifact.json");
    let metadata: ArtifactMetadata = serde_json::from_reader(
        File::open(&metadata_path)
            .with_context(|| format!("missing {}", metadata_path.display()))?,
    )
    .context("artifact.json is malformed")?;
    if metadata.schema != "neuestar.artifact/v1" {
        bail!("unsupported artifact metadata schema: {}", metadata.schema);
    }
    if metadata.payload_manifest_sha256 != manifest_hash
        || metadata.artifact_sha256 != manifest_hash
    {
        bail!("artifact identity does not match SHA256SUMS");
    }
    if !valid_sha256(&metadata.runtime_root_manifest_sha256) {
        bail!("runtime root manifest hash is malformed");
    }
    if sha256_file(&root.join("rootfs.SHA256SUMS"))? != metadata.runtime_root_manifest_sha256 {
        bail!("runtime root manifest identity does not match rootfs.SHA256SUMS");
    }
    if !valid_sha256(&metadata.capture_rule_sha256) {
        bail!("capture rule hash is malformed");
    }
    if sha256_file(&root.join("capture-rules.json"))? != metadata.capture_rule_sha256 {
        bail!("capture rule identity does not match capture-rules.json");
    }
    if metadata.source_commit.len() != 40
        || !metadata
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || metadata.probe_version.is_empty()
        || metadata.probe_version.len() > 32
    {
        bail!("artifact source identity is malformed");
    }
    if metadata.controlled_libc_version.is_empty() || metadata.controlled_libc_version.len() > 128 {
        bail!("controlled glibc version is malformed");
    }
    let interpreter = Path::new(&metadata.child_interpreter);
    let Some(interpreter_relative) = interpreter.strip_prefix("/").ok() else {
        bail!("child interpreter is not an absolute path");
    };
    if !safe_relative_path(interpreter_relative)
        || metadata.child_interpreter.len() > 1024
        || !root.join("root").join(interpreter_relative).is_file()
        || !paths.contains(&Path::new("root").join(interpreter_relative))
    {
        bail!("child interpreter is not present in the controlled root");
    }
    Ok(metadata)
}

pub fn safe_relative_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    !text.is_empty()
        && text
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("missing payload file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("payload member is not a regular file: {}", path.display());
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
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

    #[test]
    fn sha256_validation_is_strict() {
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"A".repeat(64)));
        assert!(!valid_sha256(&"a".repeat(63)));
        assert!(!valid_sha256(&format!("{}g", "a".repeat(63))));
    }

    #[test]
    fn manifest_paths_cannot_escape() {
        assert!(safe_relative_path(Path::new("app/probe")));
        assert!(!safe_relative_path(Path::new("../probe")));
        assert!(!safe_relative_path(Path::new("/app/probe")));
        assert!(!safe_relative_path(Path::new("app/./probe")));
    }

    #[test]
    fn computes_known_hash() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("value");
        fs::write(&path, b"abc").expect("fixture");
        assert_eq!(
            sha256_file(&path).expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
