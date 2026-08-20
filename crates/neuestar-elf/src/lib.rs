//! Generic ELF metadata inspection (Gate L0 driver capture + H0 Candidate A2
//! static-property evidence). Pure std; reads only the ELF headers.

use std::path::Path;

/// Marker for the (still unimplemented) Gate L0 capture phase.
pub const PHASE: &str = "phase-3-not-implemented";

const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;

/// The ELF interpreter path (`PT_INTERP`), or `None` for a static binary.
///
/// # Errors
/// Returns an I/O error when the file cannot be read.
pub fn interpreter_of(path: &Path) -> std::io::Result<Option<String>> {
    let data = std::fs::read(path)?;
    Ok(elf64_interpreter(&data))
}

/// True when the binary has a `PT_INTERP` (dynamic interpreter).
///
/// # Errors
/// Returns an I/O error when the file cannot be read.
pub fn has_elf_interpreter(path: &Path) -> std::io::Result<bool> {
    Ok(interpreter_of(path)?.is_some())
}

/// True when the binary is statically linked: no `PT_INTERP` and no
/// `PT_DYNAMIC` (no dynamic loader, no dynamic section at all).
///
/// # Errors
/// Returns an I/O error when the file cannot be read.
pub fn is_statically_linked(path: &Path) -> std::io::Result<bool> {
    let data = std::fs::read(path)?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
        return Ok(false);
    }
    Ok(elf64_program_types(&data)
        .iter()
        .all(|t| *t != PT_INTERP && *t != PT_DYNAMIC))
}

fn elf64_interpreter(data: &[u8]) -> Option<String> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
        // not an ELFCLASS64 file
        return None;
    }
    let phoff: usize = convert_usize(u64::from_le_bytes(data[32..40].try_into().ok()?));
    let phentsize: usize = u16::from_le_bytes(data[54..56].try_into().ok()?) as usize;
    let phnum: usize = u16::from_le_bytes(data[56..58].try_into().ok()?) as usize;
    if phentsize < 56 {
        return None;
    }
    for index in 0..phnum {
        let offset = phoff.saturating_add(index * phentsize);
        let Some(header) = data.get(offset..offset + 56) else {
            break;
        };
        let p_type = u32::from_le_bytes(header[0..4].try_into().ok()?);
        if p_type == PT_INTERP {
            let p_offset = convert_usize(u64::from_le_bytes(header[8..16].try_into().ok()?));
            let p_filesz = convert_usize(u64::from_le_bytes(header[32..40].try_into().ok()?));
            let segment = data.get(p_offset..p_offset.saturating_add(p_filesz))?;
            let text = String::from_utf8_lossy(segment);
            return Some(text.trim_end_matches('\0').to_string());
        }
    }
    None
}

/// 64-bit ELF offsets cannot realistically exceed `usize` here; saturate to
/// avoid clippy truncation warnings on 32-bit targets.
fn convert_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn elf64_program_types(data: &[u8]) -> Vec<u32> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
        return Vec::new();
    }
    let phoff: usize = convert_usize(u64::from_le_bytes(
        data[32..40].try_into().unwrap_or(0u64.to_le_bytes()),
    ));
    let phentsize =
        u16::from_le_bytes(data[54..56].try_into().unwrap_or(56u16.to_le_bytes())) as usize;
    let phnum = u16::from_le_bytes(data[56..58].try_into().unwrap_or(0u16.to_le_bytes())) as usize;
    if phentsize < 56 {
        return Vec::new();
    }
    let mut types = Vec::new();
    for index in 0..phnum {
        let offset = phoff.saturating_add(index * phentsize);
        let Some(header) = data.get(offset..offset + 56) else {
            break;
        };
        types.push(u32::from_le_bytes(
            header[0..4].try_into().unwrap_or(0u32.to_le_bytes()),
        ));
    }
    types
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        let path = std::env::temp_dir().join("not-elf");
        std::fs::write(&path, b"plain text").unwrap();
        assert_eq!(interpreter_of(&path).unwrap(), None);
        assert!(!is_statically_linked(&path).unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parses_elf64_program_headers() {
        // Minimal synthetic ELF64: ehdr + one PT_LOAD + one PT_INTERP.
        let mut data = vec![0u8; 64 + 56 * 2];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // little endian
        data[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        data[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        data[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
        // PT_LOAD
        data[64..68].copy_from_slice(&1u32.to_le_bytes());
        // PT_INTERP at second header, pointing at a trailing string
        let interp_offset = 64 + 56 * 2;
        data.extend_from_slice(b"/lib64/ld-linux-x86-64.so.2\0");
        data[64 + 56..64 + 60].copy_from_slice(&PT_INTERP.to_le_bytes());
        data[64 + 56 + 8..64 + 56 + 16].copy_from_slice(&(interp_offset as u64).to_le_bytes());
        let interp_filesz = data.len() - interp_offset;
        data[64 + 56 + 32..64 + 56 + 40].copy_from_slice(&(interp_filesz as u64).to_le_bytes());
        let path = std::env::temp_dir().join("synthetic-elf");
        std::fs::write(&path, &data).unwrap();
        assert_eq!(
            interpreter_of(&path).unwrap().as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert!(has_elf_interpreter(&path).unwrap());
        assert!(!is_statically_linked(&path).unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn static_binary_has_no_interpreter() {
        // PT_LOAD only: statically linked shape.
        let mut data = vec![0u8; 64 + 56];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        data[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        let path = std::env::temp_dir().join("synthetic-static");
        std::fs::write(&path, &data).unwrap();
        assert_eq!(interpreter_of(&path).unwrap(), None);
        assert!(is_statically_linked(&path).unwrap());
        std::fs::remove_file(&path).ok();
    }
}
