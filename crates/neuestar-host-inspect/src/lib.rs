//! Safe, read-only collection of host metadata for Gate L0 evidence.
//!
//! This crate only records observations. It deliberately does not classify a
//! host, select a compatibility table, or infer a runner or distribution
//! family. [`HostInspector`] accepts paths and an environment snapshot so
//! callers can test collection without mutating process-global state.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current host-inspection phase identifier.
pub const PHASE: &str = "phase-1-observed-metadata";

/// Maximum bytes retained for one observed value.
pub const MAX_VALUE_BYTES: usize = 4096;
const MAX_ENV_VALUE_BYTES: usize = 1024;
const MAX_OS_RELEASE_FIELDS: usize = 128;

/// A bounded observation failure. `Unavailable` means a source could not be
/// read; `Malformed` means that it was present but not parseable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationError {
    /// The source does not exist or could not be read.
    Unavailable(String),
    /// The source exists but has invalid content.
    Malformed(String),
}

impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(f, "unavailable: {message}"),
            Self::Malformed(message) => write!(f, "malformed: {message}"),
        }
    }
}

/// A snapshot of selected process environment variables.
///
/// Using a snapshot rather than calling `set_var` in tests keeps collection
/// deterministic and avoids mutating global process state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSnapshot {
    values: BTreeMap<String, String>,
}

impl EnvironmentSnapshot {
    /// Capture the current process environment once.
    #[must_use]
    pub fn current() -> Self {
        Self {
            values: std::env::vars()
                .filter(|(_, value)| value.len() <= MAX_VALUE_BYTES)
                .collect(),
        }
    }

    /// Build a snapshot from key/value pairs, retaining bounded values only.
    #[must_use]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            values: pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .filter(|(_, value)| value.len() <= MAX_VALUE_BYTES)
                .collect(),
        }
    }

    /// Return one captured variable.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// Return whether a variable was present, including when its value was
    /// empty.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }
}

/// Kernel identity observed through safe procfs files where available.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelMetadata {
    /// Kernel operating-system name, such as `Linux`.
    pub sysname: Option<String>,
    /// Kernel release string.
    pub release: Option<String>,
    /// Kernel build/version string.
    pub version: Option<String>,
    /// Host machine architecture as observed by the process.
    pub machine: Option<String>,
}

/// Generic distribution fields from an os-release file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionMetadata {
    /// `ID`, when present.
    pub id: Option<String>,
    /// `VERSION_ID`, when present.
    pub version: Option<String>,
    /// `NAME`, when present.
    pub name: Option<String>,
}

/// Alias using the common short name.
pub type DistroMetadata = DistributionMetadata;

/// Session and desktop environment observations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// `XDG_SESSION_TYPE`, if explicitly supplied.
    pub session_type: Option<String>,
    /// Value of `WAYLAND_DISPLAY`, if supplied.
    pub wayland_display: Option<String>,
    /// Whether `WAYLAND_DISPLAY` was present in the snapshot.
    pub wayland_display_present: bool,
    /// Value of `DISPLAY`, if supplied.
    pub display: Option<String>,
    /// Whether `DISPLAY` was present in the snapshot.
    pub display_present: bool,
    /// `XDG_CURRENT_DESKTOP`, if supplied.
    pub current_desktop: Option<String>,
    /// `DESKTOP_SESSION`, if supplied.
    pub desktop_session: Option<String>,
}

/// A trimmed sysctl value, retaining raw text and an integer parse when
/// possible. No policy is inferred from the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysctlObservation {
    /// Trimmed value as read.
    pub raw: String,
    /// Signed integer interpretation, when the complete value is an integer.
    pub integer: Option<i64>,
}

/// User-namespace policy files that happen to be present on the host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserNamespaceMetadata {
    /// `/proc/sys/kernel/unprivileged_userns_clone`.
    pub unprivileged_userns_clone: Option<SysctlObservation>,
    /// `/proc/sys/user/max_user_namespaces`.
    pub max_user_namespaces: Option<SysctlObservation>,
    /// `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`.
    pub apparmor_restrict_unprivileged_userns: Option<SysctlObservation>,
    /// `/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined`.
    pub apparmor_restrict_unprivileged_unconfined: Option<SysctlObservation>,
}

/// The complete bounded host observation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostMetadata {
    /// Compile-target architecture string.
    pub architecture: String,
    /// Kernel identity observations.
    pub kernel: KernelMetadata,
    /// Distribution fields, if a valid os-release source was available.
    pub distribution: Option<DistributionMetadata>,
    /// Error from trying the configured os-release paths, if any.
    pub distribution_error: Option<ObservationError>,
    /// Session and desktop observations.
    pub session: SessionMetadata,
    /// Generic user-namespace policy observations.
    pub user_namespace: UserNamespaceMetadata,
}

/// Explicit inputs for a host inspection.
#[derive(Debug, Clone)]
pub struct InspectionOptions {
    /// os-release paths tried in order. The first readable, valid file wins.
    pub os_release_paths: Vec<PathBuf>,
    /// Procfs root used for kernel and policy observations.
    pub proc_root: PathBuf,
    /// Environment captured by the caller.
    pub environment: EnvironmentSnapshot,
}

impl Default for InspectionOptions {
    fn default() -> Self {
        Self {
            os_release_paths: vec![
                PathBuf::from("/etc/os-release"),
                PathBuf::from("/usr/lib/os-release"),
            ],
            proc_root: PathBuf::from("/proc"),
            environment: EnvironmentSnapshot::current(),
        }
    }
}

/// Read-only host metadata collector.
#[derive(Debug, Clone)]
pub struct HostInspector {
    options: InspectionOptions,
}

impl HostInspector {
    /// Construct a collector from explicit inputs.
    #[must_use]
    pub fn new(options: InspectionOptions) -> Self {
        Self { options }
    }

    /// Collect host metadata; unavailable optional sources are represented in
    /// the returned observation instead of aborting collection.
    #[must_use]
    pub fn collect(&self) -> HostMetadata {
        let (distribution, distribution_error) = read_distribution(&self.options.os_release_paths);
        HostMetadata {
            architecture: std::env::consts::ARCH.to_owned(),
            kernel: read_kernel(&self.options.proc_root),
            distribution,
            distribution_error,
            session: read_session(&self.options.environment),
            user_namespace: read_user_namespace(&self.options.proc_root),
        }
    }
}

/// Collect metadata using runtime defaults.
#[must_use]
pub fn collect_host_metadata() -> HostMetadata {
    HostInspector::new(InspectionOptions::default()).collect()
}

/// Short alias for [`collect_host_metadata`].
#[must_use]
pub fn collect() -> HostMetadata {
    collect_host_metadata()
}

/// Collect metadata from explicit fixture or runtime inputs.
#[must_use]
pub fn collect_with_options(options: InspectionOptions) -> HostMetadata {
    HostInspector::new(options).collect()
}

/// Parse an os-release document. Duplicate keys use a deterministic last-one-
/// wins policy; malformed fields fail the whole document.
///
/// # Errors
///
/// Returns [`OsReleaseParseError`] when a field is malformed or the bounded
/// parser budget is exceeded.
pub fn parse_os_release(input: &str) -> Result<BTreeMap<String, String>, OsReleaseParseError> {
    let mut values = BTreeMap::new();
    if input.len() > MAX_OS_RELEASE_FIELDS * MAX_VALUE_BYTES {
        return Err(OsReleaseParseError::TooLarge);
    }
    for (index, original) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = original.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(OsReleaseParseError::Malformed {
                line: line_number,
                reason: "missing '='".to_owned(),
            });
        };
        if !valid_key(key) {
            return Err(OsReleaseParseError::Malformed {
                line: line_number,
                reason: format!("invalid key {key:?}"),
            });
        }
        let value = parse_value(value).map_err(|reason| OsReleaseParseError::Malformed {
            line: line_number,
            reason,
        })?;
        if value.len() > MAX_VALUE_BYTES {
            return Err(OsReleaseParseError::Malformed {
                line: line_number,
                reason: "value exceeds bound".to_owned(),
            });
        }
        if values.len() >= MAX_OS_RELEASE_FIELDS && !values.contains_key(key) {
            return Err(OsReleaseParseError::TooManyFields);
        }
        values.insert(key.to_owned(), value);
    }
    Ok(values)
}

/// Errors produced by [`parse_os_release`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OsReleaseParseError {
    /// A line had invalid key/value syntax.
    #[error("malformed os-release line {line}: {reason}")]
    Malformed {
        /// One-based line number.
        line: usize,
        /// Explanation of the invalid syntax.
        reason: String,
    },
    /// Input exceeded the bounded parser budget.
    #[error("os-release input is too large")]
    TooLarge,
    /// Input contained more distinct fields than the bounded parser allows.
    #[error("os-release contains too many fields")]
    TooManyFields,
}

fn valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('A'..='Z' | '_'))
        && chars.all(|character| matches!(character, 'A'..='Z' | '0'..='9' | '_'))
}

fn parse_value(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.starts_with('"') {
        if !value.ends_with('"') || value.len() < 2 {
            return Err("unterminated quoted value".to_owned());
        }
        let body = &value[1..value.len() - 1];
        let mut output = String::with_capacity(body.len());
        let mut escaped = false;
        for character in body.chars() {
            if escaped {
                output.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else {
                output.push(character);
            }
        }
        if escaped {
            return Err("trailing escape in quoted value".to_owned());
        }
        Ok(output)
    } else if value.contains('"') || value.chars().any(char::is_whitespace) {
        Err("invalid unquoted value".to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn read_distribution(
    paths: &[PathBuf],
) -> (Option<DistributionMetadata>, Option<ObservationError>) {
    let mut last_error = None;
    let mut malformed_error = None;
    for path in paths {
        match fs::read_to_string(path) {
            Ok(contents) => match parse_os_release(&contents) {
                Ok(values) => {
                    return (
                        Some(DistributionMetadata {
                            id: values.get("ID").cloned(),
                            version: values.get("VERSION_ID").cloned(),
                            name: values.get("NAME").cloned(),
                        }),
                        None,
                    );
                }
                Err(error) => {
                    let observation = ObservationError::Malformed(error.to_string());
                    malformed_error = Some(observation.clone());
                    last_error = Some(observation);
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if malformed_error.is_none() {
                    last_error = Some(ObservationError::Unavailable(path.display().to_string()));
                }
            }
            Err(error) => {
                if malformed_error.is_none() {
                    last_error = Some(ObservationError::Unavailable(format!(
                        "{}: {error}",
                        path.display()
                    )));
                }
            }
        }
    }
    (None, last_error)
}

fn read_kernel(proc_root: &Path) -> KernelMetadata {
    let read = |relative: &str| read_trimmed(&proc_root.join(relative)).ok();
    KernelMetadata {
        sysname: read("sys/sysname")
            .or_else(|| read("sys/kernel/ostype"))
            .or_else(|| {
                if cfg!(target_os = "linux") {
                    Some("Linux".to_owned())
                } else {
                    None
                }
            }),
        release: read("sys/kernel/osrelease"),
        version: read("version").or_else(|| read("sys/kernel/version")),
        machine: Some(std::env::consts::ARCH.to_owned()),
    }
}

fn read_session(environment: &EnvironmentSnapshot) -> SessionMetadata {
    let bounded = |key: &str| {
        environment
            .get(key)
            .filter(|value| !value.is_empty() && value.len() <= MAX_ENV_VALUE_BYTES)
            .map(str::to_owned)
    };
    SessionMetadata {
        session_type: bounded("XDG_SESSION_TYPE"),
        wayland_display: bounded("WAYLAND_DISPLAY"),
        wayland_display_present: environment.contains("WAYLAND_DISPLAY"),
        display: bounded("DISPLAY"),
        display_present: environment.contains("DISPLAY"),
        current_desktop: bounded("XDG_CURRENT_DESKTOP"),
        desktop_session: bounded("DESKTOP_SESSION"),
    }
}

fn read_user_namespace(proc_root: &Path) -> UserNamespaceMetadata {
    let read = |relative: &str| read_sysctl(&proc_root.join(relative)).ok();
    UserNamespaceMetadata {
        unprivileged_userns_clone: read("sys/kernel/unprivileged_userns_clone"),
        max_user_namespaces: read("sys/user/max_user_namespaces"),
        apparmor_restrict_unprivileged_userns: read(
            "sys/kernel/apparmor_restrict_unprivileged_userns",
        ),
        apparmor_restrict_unprivileged_unconfined: read(
            "sys/kernel/apparmor_restrict_unprivileged_unconfined",
        ),
    }
}

fn read_trimmed(path: &Path) -> Result<String, ObservationError> {
    let value = fs::read_to_string(path)
        .map_err(|error| ObservationError::Unavailable(error.to_string()))?;
    let value = value.trim();
    if value.len() > MAX_VALUE_BYTES {
        return Err(ObservationError::Malformed(
            "value exceeds bound".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn read_sysctl(path: &Path) -> Result<SysctlObservation, ObservationError> {
    let input = fs::read_to_string(path)
        .map_err(|error| ObservationError::Unavailable(error.to_string()))?;
    parse_sysctl_value(&input)
}

/// Parse one sysctl value without reading or changing host state.
///
/// # Errors
///
/// Returns [`ObservationError::Malformed`] for an empty value or a value over
/// the bounded observation size.
pub fn parse_sysctl_value(input: &str) -> Result<SysctlObservation, ObservationError> {
    let raw = input.trim();
    if raw.len() > MAX_VALUE_BYTES {
        return Err(ObservationError::Malformed(
            "value exceeds bound".to_owned(),
        ));
    }
    if raw.is_empty() {
        return Err(ObservationError::Malformed("empty sysctl value".to_owned()));
    }
    Ok(SysctlObservation {
        integer: raw.parse().ok(),
        raw: raw.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_quoted_escaped_values_and_duplicate_last_wins() {
        let values =
            parse_os_release("NAME=first\nNAME=\"A \\\"quoted\\\" name\"\nID=test\n").unwrap();
        assert_eq!(values.get("NAME"), Some(&"A \"quoted\" name".to_owned()));
    }

    #[test]
    fn malformed_fields_are_reported() {
        let error = parse_os_release("NAME=ok\nthis is bad\n").unwrap_err();
        assert!(matches!(
            error,
            OsReleaseParseError::Malformed { line: 2, .. }
        ));
    }

    #[test]
    fn fixture_paths_fall_back_after_unavailable_source() {
        let directory = tempfile::tempdir().unwrap();
        let fallback = directory.path().join("os-release");
        fs::write(&fallback, "ID=fixture\nVERSION_ID=1\nNAME=Fixture\n").unwrap();
        let options = InspectionOptions {
            os_release_paths: vec![directory.path().join("missing"), fallback],
            proc_root: directory.path().to_owned(),
            environment: EnvironmentSnapshot::default(),
        };
        let metadata = HostInspector::new(options).collect();
        assert_eq!(
            metadata.distribution.unwrap().id.as_deref(),
            Some("fixture")
        );
    }

    #[test]
    fn environment_snapshot_is_isolated() {
        let snapshot = EnvironmentSnapshot::from_pairs([(
            String::from("XDG_SESSION_TYPE"),
            String::from("wayland"),
        )]);
        let session = read_session(&snapshot);
        assert_eq!(session.session_type.as_deref(), Some("wayland"));
    }

    #[test]
    fn sysctl_values_are_trimmed_and_parsed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("value");
        fs::write(&path, " 42 \n").unwrap();
        assert_eq!(read_sysctl(&path).unwrap().integer, Some(42));
    }
}
