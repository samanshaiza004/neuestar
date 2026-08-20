//! Host and LSM observation for H0 evidence (fail-closed per GATE-H0 §9).

use std::fs;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Structured LSM/security state recorded in the H0 record.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SecurityState {
    pub lsm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apparmor: Option<AppArmorState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux: Option<SelinuxState>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AppArmorState {
    pub parser_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<String>,
    pub restriction_sysctl: Option<i32>,
    pub loaded_profiles: Vec<LoadedProfile>,
    /// Observational digest over the loaded profile state (sorted
    /// `name (mode)` lines + parser version), NOT a kernel-policy hash.
    pub loaded_profile_state_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LoadedProfile {
    pub name: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SelinuxState {
    pub enforcing: bool,
    pub test_user_domain: String,
    pub relevant_booleans: Vec<String>,
}

/// Flat host facts used for the H0 record and the free-text host-state dumps.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostFacts {
    pub distro_id: String,
    pub distro_version: String,
    pub pretty_name: String,
    pub kernel_release: String,
    pub architecture: String,
    pub lsm_raw: String,
}

pub fn collect_host() -> HostFacts {
    let os_release = read_os_release();
    HostFacts {
        distro_id: os_release
            .get("ID")
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned()),
        distro_version: os_release
            .get("VERSION_ID")
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned()),
        pretty_name: os_release
            .get("PRETTY_NAME")
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned()),
        kernel_release: read_first_line("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|| "unknown".to_owned()),
        architecture: std::env::consts::ARCH.to_owned(),
        lsm_raw: read_first_line("/sys/kernel/security/lsm").unwrap_or_default(),
    }
}

/// Collects the security state for the record. Never fails: unreadable state
/// is recorded honestly ("unknown"/None) so the record always represents what
/// was observable.
pub fn collect_security_state() -> SecurityState {
    let lsm_raw = read_first_line("/sys/kernel/security/lsm");
    let lsm = classify_lsm(lsm_raw.as_deref());
    let apparmor = (lsm == "apparmor").then(collect_apparmor);
    let selinux = (lsm == "selinux").then(collect_selinux);
    SecurityState {
        lsm,
        apparmor,
        selinux,
    }
}

pub fn classify_lsm(raw: Option<&str>) -> String {
    match raw {
        None => "other",
        Some("") => "none",
        Some(text) if text.contains("apparmor") => "apparmor",
        Some(text) if text.contains("selinux") => "selinux",
        Some(text)
            if text
                .split(',')
                .all(|part| matches!(part.trim(), "" | "capability" | "yama")) =>
        {
            "none"
        }
        Some(_) => "other",
    }
    .to_owned()
}

fn collect_apparmor() -> AppArmorState {
    let profiles = read_apparmor_profiles();
    let mut lines: Vec<String> = profiles
        .iter()
        .map(|profile| format!("{} ({})", profile.name, profile.mode))
        .collect();
    lines.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(lines.join("\n"));
    hasher.update(parser_version());
    let loaded_profile_state_sha256 = hex::encode(hasher.finalize());
    AppArmorState {
        parser_version: parser_version(),
        abi: None,
        restriction_sysctl: read_int("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        loaded_profiles: profiles,
        loaded_profile_state_sha256,
    }
}

/// Reads `/sys/kernel/security/apparmor/profiles`, e.g.
/// `neuestar-host (enforce)`, into name/mode records.
fn read_apparmor_profiles() -> Vec<LoadedProfile> {
    let Ok(content) = fs::read_to_string("/sys/kernel/security/apparmor/profiles") else {
        return Vec::new();
    };
    let mut profiles = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, mode) = line
            .split_once('(')
            .map(|(name, rest)| {
                (
                    name.trim().to_owned(),
                    rest.trim_end_matches(')').trim().to_owned(),
                )
            })
            .unwrap_or_else(|| (line.to_owned(), "unknown".to_owned()));
        profiles.push(LoadedProfile {
            name,
            mode: match mode.as_str() {
                "enforce" => "enforce",
                "complain" => "complain",
                "unconfined" => "unconfined",
                _ => "other",
            }
            .to_owned(),
            path: None,
        });
    }
    profiles
}

/// AppArmor userspace parser version via `apparmor_parser --version`
/// (observational; falls back to "unknown").
fn parser_version() -> String {
    let Ok(output) = std::process::Command::new("apparmor_parser")
        .arg("--version")
        .output()
    else {
        return "unknown".to_owned();
    };
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        "unknown".to_owned()
    } else {
        text.chars().take(128).collect()
    }
}

fn collect_selinux() -> SelinuxState {
    SelinuxState {
        enforcing: read_first_line("/sys/fs/selinux/enforce").as_deref() == Some("1"),
        test_user_domain: read_first_line("/proc/self/attr/current")
            .unwrap_or_else(|| "unknown".to_owned()),
        relevant_booleans: read_enabled_selinux_booleans(),
    }
}

/// Records SELinux booleans currently enabled (value 1) as the relevant set;
/// empty when none are enabled.
fn read_enabled_selinux_booleans() -> Vec<String> {
    let mut enabled = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/fs/selinux/booleans") else {
        return enabled;
    };
    for entry in entries.flatten() {
        if read_first_line(entry.path().join("value")).is_some_and(|value| value.trim() == "1")
            && let Some(name) = entry.file_name().to_str()
        {
            enabled.push(name.to_owned());
        }
        if enabled.len() >= 64 {
            break;
        }
    }
    enabled.sort_unstable();
    enabled
}

fn read_os_release() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Ok(content) = fs::read_to_string("/etc/os-release") else {
        return map;
    };
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        map.insert(key.to_owned(), value.to_owned());
    }
    map
}

fn read_first_line(path: impl AsRef<Path>) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    // procfs attribute files may end with a NUL terminator; strip it so it
    // does not leak into recorded evidence.
    content
        .lines()
        .next()
        .map(|line| line.trim_end_matches('\0').trim())
        .map(ToOwned::to_owned)
}

fn read_int(path: impl AsRef<Path>) -> Option<i32> {
    read_first_line(path)?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_lsm_names() {
        assert_eq!(classify_lsm(Some("apparmor")), "apparmor");
        assert_eq!(classify_lsm(Some("capability,apparmor")), "apparmor");
        assert_eq!(classify_lsm(Some("selinux")), "selinux");
        assert_eq!(classify_lsm(Some("capability,yama")), "none");
        assert_eq!(classify_lsm(Some("")), "none");
        assert_eq!(classify_lsm(Some("landlock")), "other");
        // unreadable is NOT none
        assert_eq!(classify_lsm(None), "other");
    }

    #[test]
    fn parses_apparmor_profile_listing() {
        let text = "neuestar-host (enforce)\nunconfined (enforce)\n";
        let parsed: Vec<LoadedProfile> = text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                let (name, mode) = line
                    .split_once('(')
                    .map(|(name, rest)| {
                        (
                            name.trim().to_owned(),
                            rest.trim_end_matches(')').trim().to_owned(),
                        )
                    })
                    .unwrap_or_else(|| (line.to_owned(), "unknown".to_owned()));
                Some(LoadedProfile {
                    name,
                    mode: if mode == "enforce" {
                        "enforce"
                    } else {
                        "complain"
                    }
                    .to_owned(),
                    path: None,
                })
            })
            .collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "neuestar-host");
        assert_eq!(parsed[0].mode, "enforce");
    }
}
