//! Linux capability bitmask decoding (CapEff evidence, H0.1S).

/// Capability names indexed by their numeric value (Linux 5.9+).
const CAP_NAMES: &[&str] = &[
    "CAP_CHOWN",              // 0
    "CAP_DAC_OVERRIDE",       // 1
    "CAP_DAC_READ_SEARCH",    // 2
    "CAP_FOWNER",             // 3
    "CAP_FSETID",             // 4
    "CAP_KILL",               // 5
    "CAP_SETGID",             // 6
    "CAP_SETUID",             // 7
    "CAP_SETPCAP",            // 8
    "CAP_LINUX_IMMUTABLE",    // 9
    "CAP_NET_BIND_SERVICE",   // 10
    "CAP_NET_BROADCAST",      // 11
    "CAP_NET_ADMIN",          // 12
    "CAP_NET_RAW",            // 13
    "CAP_IPC_LOCK",           // 14
    "CAP_IPC_OWNER",          // 15
    "CAP_SYS_MODULE",         // 16
    "CAP_SYS_RAWIO",          // 17
    "CAP_SYS_CHROOT",         // 18
    "CAP_SYS_PTRACE",         // 19
    "CAP_SYS_PACCT",          // 20
    "CAP_SYS_ADMIN",          // 21
    "CAP_SYS_BOOT",           // 22
    "CAP_SYS_NICE",           // 23
    "CAP_SYS_RESOURCE",       // 24
    "CAP_SYS_TIME",           // 25
    "CAP_SYS_TTY_CONFIG",     // 26
    "CAP_MKNOD",              // 27
    "CAP_LEASE",              // 28
    "CAP_AUDIT_WRITE",        // 29
    "CAP_AUDIT_CONTROL",      // 30
    "CAP_SETFCAP",            // 31
    "CAP_MAC_OVERRIDE",       // 32
    "CAP_MAC_ADMIN",          // 33
    "CAP_SYSLOG",             // 34
    "CAP_WAKE_ALARM",         // 35
    "CAP_BLOCK_SUSPEND",      // 36
    "CAP_AUDIT_READ",         // 37
    "CAP_PERFMON",            // 38
    "CAP_BPF",                // 39
    "CAP_CHECKPOINT_RESTORE", // 40
];

/// Parses a CapEff hex string (as printed by /proc/<pid>/status, e.g.
/// `00000000a80425fb`) into its raw mask.
pub fn parse_cap_eff_hex(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.is_empty() || text.len() > 16 {
        return None;
    }
    u64::from_str_radix(text, 16).ok()
}

/// Decodes a capability mask into the set capability names.
pub fn decode_cap_mask(mask: u64) -> Vec<String> {
    let mut names = Vec::new();
    for (index, name) in CAP_NAMES.iter().enumerate() {
        if mask & (1_u64 << index) != 0 {
            names.push((*name).to_owned());
        }
    }
    names
}

/// Extracts CapEff from the text of /proc/<pid>/status.
pub fn cap_eff_from_status(status: &str) -> Option<String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Reads the current process CapEff mask from /proc/self/status.
pub fn self_cap_eff_hex() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    cap_eff_from_status(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_decodes_cap_hex() {
        assert_eq!(parse_cap_eff_hex("0000000000000000"), Some(0));
        // CAP_CHOWN | CAP_DAC_OVERRIDE | CAP_NET_ADMIN | CAP_SYS_ADMIN
        let mask = (1 << 0) | (1 << 1) | (1 << 12) | (1 << 21);
        let names = decode_cap_mask(mask);
        assert!(names.contains(&"CAP_CHOWN".to_owned()));
        assert!(names.contains(&"CAP_DAC_OVERRIDE".to_owned()));
        assert!(names.contains(&"CAP_NET_ADMIN".to_owned()));
        assert!(names.contains(&"CAP_SYS_ADMIN".to_owned()));
        assert!(!names.contains(&"CAP_MKNOD".to_owned()));
    }

    #[test]
    fn rejects_malformed_hex() {
        assert!(parse_cap_eff_hex("").is_none());
        assert!(parse_cap_eff_hex("xyz").is_none());
        assert!(parse_cap_eff_hex("00000000000000000000").is_none());
    }

    #[test]
    fn extracts_cap_eff_from_status() {
        let status = "Name:\tprobe\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(
            cap_eff_from_status(status).as_deref(),
            Some("000001ffffffffff")
        );
    }
}
