//! Minimal glibc-linked child used to establish Gate L0.1 after containment.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::Serialize;

const EXIT_ENVIRONMENT: u8 = 72;
const EXIT_REPORT: u8 = 73;

#[derive(Debug, Parser)]
#[command(version, about = "Neuestar Phase 1 glibc-linked child")]
struct Cli {
    /// Path for the bounded child result consumed by the static launcher.
    #[arg(long)]
    result: PathBuf,
}

#[derive(Debug, Serialize)]
struct ChildResult {
    schema: &'static str,
    contained: bool,
    launch_reached_main: bool,
    architecture: &'static str,
    user_namespace: String,
    mount_namespace: String,
    mapped_libc_paths: Vec<String>,
    failure: Option<ChildFailure>,
}

#[derive(Debug, Serialize)]
struct ChildFailure {
    code: &'static str,
    explanation: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, error)) => {
            eprintln!("probe child: {error:#}");
            ExitCode::from(code)
        }
    }
}

fn run(cli: &Cli) -> Result<(), (u8, anyhow::Error)> {
    let contained = std::env::var("NEUESTAR_CONTAINED").as_deref() == Ok("1");
    if !contained {
        let result = ChildResult {
            schema: "neuestar.child/v1",
            contained: false,
            launch_reached_main: true,
            architecture: std::env::consts::ARCH,
            user_namespace: namespace_identity("/proc/self/ns/user"),
            mount_namespace: namespace_identity("/proc/self/ns/mnt"),
            mapped_libc_paths: mapped_libc_paths(),
            failure: Some(ChildFailure {
                code: "containment-marker-missing",
                explanation: "child was invoked without the launcher's containment marker".into(),
            }),
        };
        write_result(&cli.result, &result).map_err(|error| (EXIT_REPORT, error))?;
        return Err((
            EXIT_ENVIRONMENT,
            anyhow::anyhow!("containment marker is missing"),
        ));
    }

    let result = ChildResult {
        schema: "neuestar.child/v1",
        contained: true,
        launch_reached_main: true,
        architecture: std::env::consts::ARCH,
        user_namespace: namespace_identity("/proc/self/ns/user"),
        mount_namespace: namespace_identity("/proc/self/ns/mnt"),
        mapped_libc_paths: mapped_libc_paths(),
        failure: None,
    };
    write_result(&cli.result, &result).map_err(|error| (EXIT_REPORT, error))
}

fn namespace_identity(path: &str) -> String {
    fs::read_link(path).map_or_else(
        |_| "unavailable".to_owned(),
        |identity| identity.display().to_string(),
    )
}

fn mapped_libc_paths() -> Vec<String> {
    let Ok(maps) = fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };
    let mut paths: Vec<String> = maps
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|path| path.starts_with('/') && path.contains("libc.so"))
        .map(ToOwned::to_owned)
        .collect();
    paths.sort_unstable();
    paths.dedup();
    paths.truncate(16);
    paths
}

fn write_result(path: &Path, result: &ChildResult) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let temporary = path.with_extension("json.tmp");
    if temporary == path {
        bail!("result path cannot use the reserved .json.tmp suffix");
    }
    let mut file = File::create(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    serde_json::to_writer_pretty(&mut file, result)?;
    file.sync_all()?;
    fs::rename(&temporary, path).with_context(|| format!("failed to publish {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_paths_are_bounded_and_unique() {
        let paths = mapped_libc_paths();
        assert!(paths.len() <= 16);
        assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn result_serialization_is_bounded_shape() {
        let result = ChildResult {
            schema: "neuestar.child/v1",
            contained: true,
            launch_reached_main: true,
            architecture: "x86_64",
            user_namespace: "user:[1]".to_owned(),
            mount_namespace: "mnt:[2]".to_owned(),
            mapped_libc_paths: Vec::new(),
            failure: None,
        };
        let value = serde_json::to_value(result).expect("serialize");
        assert_eq!(value["schema"], "neuestar.child/v1");
        assert_eq!(value["launch_reached_main"], true);
    }
}
