//! Fail-closed aggregation of explicit physical Gate L0 reports.

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use neuestar_report::{Campaign, CampaignCell, MatrixCell, Report};
use serde::Serialize;

const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DISCOVERED_REPORTS: usize = 1024;

#[derive(Debug, Parser)]
#[command(about = "Aggregate explicit Gate L0 reports without inventing missing evidence")]
struct Cli {
    #[arg(long)]
    campaign: String,
    #[arg(long)]
    reports_dir: PathBuf,
    #[arg(long)]
    archive_sha: String,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Serialize)]
struct CampaignOutput {
    schema: &'static str,
    campaign_id: String,
    expected_outer_archive_sha256: String,
    report_count: usize,
    unrun_count: usize,
    campaign: Campaign,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.campaign.is_empty() || cli.campaign.chars().count() > 128 {
        bail!("campaign must contain between 1 and 128 characters");
    }
    if !valid_sha256(&cli.archive_sha) {
        bail!("archive-sha must be 64 lowercase hexadecimal characters");
    }
    let paths = discover_reports(&cli.reports_dir)?;
    if paths.is_empty() {
        bail!("no report.json files were found");
    }
    let campaign = assemble_campaign(&paths, &cli.archive_sha)?;
    campaign
        .validate()
        .map_err(|errors| anyhow::anyhow!(format_campaign_errors(&errors)))?;
    let report_count = campaign
        .cells
        .iter()
        .filter(|cell| cell.report.is_some())
        .count();
    let output = CampaignOutput {
        schema: "neuestar.campaign/v1",
        campaign_id: cli.campaign,
        expected_outer_archive_sha256: cli.archive_sha,
        report_count,
        unrun_count: campaign.cells.len() - report_count,
        campaign,
    };
    write_output(&cli.output, &output)
}

fn discover_reports(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut reports = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() && entry.file_name() == "report.json" {
                reports.push(entry.path());
                if reports.len() > MAX_DISCOVERED_REPORTS {
                    bail!("more than {MAX_DISCOVERED_REPORTS} reports were discovered");
                }
            }
        }
    }
    reports.sort_unstable();
    Ok(reports)
}

fn assemble_campaign(paths: &[PathBuf], archive_sha: &str) -> Result<Campaign> {
    let mut reports = HashMap::new();
    for path in paths {
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_REPORT_BYTES {
            bail!("report exceeds 4 MiB: {}", path.display());
        }
        let report: Report = serde_json::from_reader(
            File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
        )
        .with_context(|| format!("invalid report JSON: {}", path.display()))?;
        report
            .validate()
            .with_context(|| format!("inadmissible report: {}", path.display()))?;
        if report.artifact.outer_archive_sha256 != archive_sha {
            bail!("outer archive hash mismatch in {}", path.display());
        }
        let cell = report.matrix_cell;
        if reports.insert(cell, report).is_some() {
            bail!("duplicate report for matrix cell {cell}");
        }
    }
    Ok(Campaign {
        cells: MatrixCell::all()
            .into_iter()
            .map(|cell| CampaignCell {
                cell,
                report: reports.remove(&cell),
            })
            .collect(),
    })
}

fn format_campaign_errors(errors: &[neuestar_report::CampaignError]) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_output(path: &Path, value: &CampaignOutput) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    let mut file = File::create(&temporary)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}
