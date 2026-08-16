//! Minimal glibc-linked Phase 1 child. Graphics arrives only after L0.0.

fn main() {
    eprintln!("probe app is scaffolded; Gate L0.1 has not been run");
    std::process::exit(70);
}

