//! Bundled bubblewrap closure resolution (extracted verbatim from the
//! launcher): the bundled loader must resolve bwrap's dependencies only
//! inside the controlled artifact.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

pub fn verify_bundled_helper_resolution(artifact_root: &Path) -> Result<()> {
    let loader = artifact_root.join("libexec/ld-linux-x86-64.so.2");
    let helper = artifact_root.join("libexec/bwrap");
    let helper_lib = artifact_root.join("libexec/lib");
    let output = Command::new(&loader)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("LD_BIND_NOW", "1")
        .args(["--inhibit-cache", "--library-path"])
        .arg(&helper_lib)
        .arg("--list")
        .arg(&helper)
        .output()
        .context("failed to inspect bundled bubblewrap dependency resolution")?;
    if !output.status.success() {
        bail!(
            "dynamic loader --list failed: {}",
            bounded_message(&String::from_utf8_lossy(&output.stderr))
        );
    }
    validate_helper_list(
        &String::from_utf8(output.stdout).context("loader list output is not UTF-8")?,
        &loader,
        &helper,
        &helper_lib,
    )
}

pub fn validate_helper_list(
    output: &str,
    loader: &Path,
    helper: &Path,
    helper_lib: &Path,
) -> Result<()> {
    for line in output.lines() {
        if line.contains("=> not found") {
            bail!("unresolved helper dependency: {line}");
        }
        let candidate = line
            .split_once("=>")
            .map_or(line, |(_, resolved)| resolved)
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if !candidate.starts_with('/') {
            continue;
        }
        let path = Path::new(candidate);
        if path != loader && path != helper && !path.starts_with(helper_lib) {
            bail!("helper resolved a host path: {candidate}");
        }
    }
    Ok(())
}

fn bounded_message(message: &str) -> String {
    message.chars().take(2048).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_helper_resolution_rejects_host_libraries() {
        let loader = Path::new("/artifact/libexec/ld-linux-x86-64.so.2");
        let helper = Path::new("/artifact/libexec/bwrap");
        let helper_lib = Path::new("/artifact/libexec/lib");
        assert!(
            validate_helper_list(
                "libc.so.6 => /artifact/libexec/lib/libc.so.6 (0x1)",
                loader,
                helper,
                helper_lib,
            )
            .is_ok()
        );
        assert!(
            validate_helper_list(
                "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1)",
                loader,
                helper,
                helper_lib,
            )
            .is_err()
        );
    }
}
