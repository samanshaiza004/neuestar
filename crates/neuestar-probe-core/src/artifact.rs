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

/// Cryptographic binding between the supplied outer archive identity
/// (`--archive-sha256`) and the extracted artifact bytes: the outer archive
/// file must be present in the artifact root, its SHA-256 must equal the
/// supplied identity, and the artifact.json / SHA256SUMS embedded in the
/// archive must be byte-identical to the extracted ones. Fail closed: a
/// missing tarball or any mismatch is an error, so a run can never combine
/// an outer identity with unrelated extracted payload bytes.
pub fn verify_outer_binding(root: &Path, expected_outer_sha: &str) -> Result<()> {
    let tarball = root.join("neuestar-probe-x86_64.tar.zst");
    let actual_outer = sha256_file(&tarball)
        .with_context(|| format!("outer archive missing at {}", tarball.display()))?;
    if actual_outer != expected_outer_sha {
        bail!(
            "outer archive SHA-256 mismatch: expected {expected_outer_sha}, observed {actual_outer}"
        );
    }

    let mut compressed = File::open(&tarball)?;
    let mut decoder =
        ruzstd::StreamingDecoder::new(&mut compressed).context("outer archive is not zstd")?;
    let mut archive_bytes = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut archive_bytes)
        .context("outer archive failed to decompress")?;

    let embedded = tar_entries(&archive_bytes)?;
    for name in ["artifact.json", "SHA256SUMS"] {
        // the archive may nest entries under a top directory (e.g.
        // ./neuestar-probe/artifact.json); match on the basename
        let embedded_bytes = embedded
            .iter()
            .find(|(entry_name, _)| {
                *entry_name == name || entry_name.ends_with(&format!("/{name}"))
            })
            .map(|(_, bytes)| bytes)
            .ok_or_else(|| anyhow!("outer archive lacks {name}"))?;
        let extracted = std::fs::read(root.join(name))
            .with_context(|| format!("extracted artifact lacks {name}"))?;
        if embedded_bytes.as_slice() != extracted.as_slice() {
            bail!("outer archive {name} differs from the extracted {name}");
        }
    }
    Ok(())
}

/// Minimal ustar extraction for the few embedded files we compare.
fn tar_entries(archive: &[u8]) -> Result<std::collections::HashMap<String, Vec<u8>>> {
    let mut entries = std::collections::HashMap::new();
    let mut offset = 0usize;
    while offset + 512 <= archive.len() {
        let header = &archive[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break; // end of archive
        }
        let name = header[..100]
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as char)
            .collect::<String>();
        let size_text = std::str::from_utf8(&header[124..136])
            .ok()
            .map(|text| text.trim_end_matches('\0').trim())
            .unwrap_or("");
        let size = usize::from_str_radix(size_text, 8).unwrap_or(0);
        let kind = header[156];
        offset += 512;
        match kind {
            b'0' | b'\0' => {
                let data = archive
                    .get(offset..offset + size)
                    .ok_or_else(|| anyhow!("truncated tar entry {name}"))?;
                entries.insert(name, data.to_vec());
                offset += size.div_ceil(512) * 512;
            }
            _ => {
                offset += size.div_ceil(512) * 512;
            }
        }
    }
    Ok(entries)
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
                && relative != Path::new("neuestar-probe-x86_64.tar.zst")
                && relative != Path::new("neuestar-probe-x86_64.tar.zst.sha256")
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
    fn outer_binding_missing_archive_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let error = verify_outer_binding(dir.path(), &"a".repeat(64)).unwrap_err();
        assert!(
            error.to_string().contains("outer archive missing"),
            "{error}"
        );
    }

    #[test]
    fn outer_binding_sha_mismatch_fails() {
        let dir = tempfile::tempdir().unwrap();
        let tarball = dir.path().join("neuestar-probe-x86_64.tar.zst");
        std::fs::write(&tarball, b"not the right archive").unwrap();
        let error = verify_outer_binding(dir.path(), &"a".repeat(64)).unwrap_err();
        assert!(error.to_string().contains("SHA-256 mismatch"), "{error}");
    }

    #[test]
    fn outer_binding_rejects_extracted_payload_mismatch() {
        // A valid zstd tarball whose embedded artifact.json differs from the
        // extracted one must be rejected (the C001/C002 combination).
        let dir = tempfile::tempdir().unwrap();
        // pre-encoded zstd tarball (embedded fixture) carrying artifact.json
        // with probe_version 9.9.9
        let tarball_bytes: Vec<u8> = vec![
            40, 181, 47, 253, 100, 0, 39, 77, 5, 0, 146, 72, 29, 29, 96, 107, 30, 216, 199, 190,
            247, 239, 68, 140, 241, 199, 12, 10, 1, 29, 224, 170, 162, 136, 76, 25, 213, 182, 142,
            38, 41, 76, 1, 0, 196, 113, 30, 81, 8, 45, 82, 38, 202, 75, 229, 177, 183, 154, 215,
            249, 107, 231, 27, 9, 133, 232, 154, 11, 6, 113, 31, 9, 42, 168, 96, 10, 36, 166, 153,
            149, 74, 134, 65, 38, 13, 117, 146, 99, 191, 49, 31, 81, 153, 87, 124, 93, 132, 232,
            63, 117, 177, 140, 118, 121, 183, 230, 125, 206, 238, 26, 51, 111, 189, 189, 184, 189,
            102, 204, 49, 51, 47, 211, 212, 132, 122, 14, 191, 204, 135, 126, 17, 0, 239, 63, 186,
            122, 232, 4, 42, 84, 3, 49, 87, 4, 185, 93, 99, 64, 121, 240, 226, 0, 121, 12, 6, 38,
            239, 56, 80, 135, 6, 40, 27, 10, 15, 0, 205, 2, 32, 13, 192, 44, 96, 178, 98, 25, 51,
            1, 37, 50, 220, 185, 88,
        ];
        let tarball = dir.path().join("neuestar-probe-x86_64.tar.zst");
        std::fs::write(&tarball, &tarball_bytes).unwrap();
        let outer_sha = sha256_file(&tarball).unwrap();
        // extracted artifact.json disagrees with the archive's
        std::fs::write(
            dir.path().join("artifact.json"),
            br#"{"probe_version":"0.1.0"}"#,
        )
        .unwrap();
        let error = verify_outer_binding(dir.path(), &outer_sha).unwrap_err();
        assert!(
            error.to_string().contains("differs from the extracted"),
            "{error}"
        );
    }

    #[test]
    fn outer_binding_passes_when_archive_matches_extraction() {
        let dir = tempfile::tempdir().unwrap();
        // pre-encoded zstd tarball (embedded fixture) carrying the matching
        // artifact.json + SHA256SUMS
        let tarball_bytes: Vec<u8> = vec![
            40, 181, 47, 253, 100, 0, 39, 21, 5, 0, 34, 136, 27, 27, 96, 75, 30, 216, 231, 66, 35,
            119, 71, 223, 63, 206, 160, 52, 201, 16, 78, 94, 69, 90, 202, 33, 163, 32, 136, 128,
            166, 0, 132, 210, 71, 144, 49, 11, 132, 137, 242, 80, 113, 203, 169, 150, 248, 17, 10,
            175, 177, 36, 24, 60, 126, 156, 70, 9, 245, 9, 28, 57, 163, 173, 144, 97, 128, 201,
            172, 244, 56, 248, 27, 241, 17, 86, 190, 226, 45, 27, 83, 255, 218, 5, 183, 225, 86,
            206, 188, 185, 37, 231, 141, 245, 74, 204, 217, 85, 51, 231, 107, 181, 238, 110, 150,
            211, 38, 208, 61, 252, 18, 111, 253, 17, 0, 239, 63, 186, 122, 232, 4, 42, 84, 3, 49,
            87, 4, 185, 93, 99, 64, 37, 160, 195, 1, 242, 24, 12, 76, 222, 113, 160, 14, 13, 80,
            54, 20, 30, 0, 154, 5, 64, 26, 128, 89, 192, 100, 197, 50, 102, 2, 74, 47, 206, 79,
            100,
        ];
        let tarball = dir.path().join("neuestar-probe-x86_64.tar.zst");
        std::fs::write(&tarball, &tarball_bytes).unwrap();
        let outer_sha = sha256_file(&tarball).unwrap();
        std::fs::write(
            dir.path().join("artifact.json"),
            br#"{"probe_version":"0.2.0"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("SHA256SUMS"),
            b"deadbeef  ./app/probe
",
        )
        .unwrap();
        verify_outer_binding(dir.path(), &outer_sha).unwrap();
    }

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
