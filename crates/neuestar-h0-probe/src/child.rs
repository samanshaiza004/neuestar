//! Child-mode evidence: the H0 probe re-executes itself inside the SAME
//! minimum containment boundary to deterministically record namespace
//! identity, CapEff, and the active profile label of a process running under
//! that boundary (H0.1S evidence; the frozen Campaign 002 child cannot be
//! modified to report these).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Evidence written by the probe's child mode into the bound `/evidence` dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildEvidence {
    pub schema: String,
    pub user_namespace: String,
    pub mount_namespace: String,
    pub cap_eff_hex: String,
    pub profile_label: String,
}

pub fn run_child_mode(result_path: &Path) -> Result<()> {
    if std::env::var("NEUESTAR_CONTAINED").as_deref() != Ok("1") {
        bail!("child mode requires the containment marker");
    }
    let evidence = ChildEvidence {
        schema: "neuestar.h0-child/v1".to_owned(),
        user_namespace: namespace_identity("/proc/self/ns/user"),
        mount_namespace: namespace_identity("/proc/self/ns/mnt"),
        cap_eff_hex: neuestar_probe_core::capabilities::self_cap_eff_hex()
            .unwrap_or_else(|| "unavailable".to_owned()),
        profile_label: fs::read_to_string("/proc/self/attr/current")
            .unwrap_or_else(|_| "unknown".to_owned())
            .trim()
            .to_owned(),
    };
    write_json(result_path, &evidence)
}

/// Reads the child evidence file produced by a previous child-mode run.
pub fn read_child_evidence(path: &Path) -> Result<ChildEvidence> {
    let value: ChildEvidence =
        serde_json::from_reader(fs::File::open(path).context("child evidence missing")?)
            .context("child evidence is malformed")?;
    if value.schema != "neuestar.h0-child/v1" {
        bail!("unexpected child evidence schema");
    }
    Ok(value)
}

fn namespace_identity(path: &str) -> String {
    fs::read_link(path).map_or_else(
        |_| "unavailable".to_owned(),
        |identity| identity.display().to_string(),
    )
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
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
    let mut file = fs::File::create(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.sync_all()?;
    fs::rename(&temporary, path).with_context(|| format!("failed to publish {}", path.display()))
}
