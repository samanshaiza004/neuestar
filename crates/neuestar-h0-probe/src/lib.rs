//! H0 probe library: host/LSM observation, minimum user+mount containment,
//! capability decoding, child-mode evidence, and `neuestar.h0/v1` assembly.
//!
//! This is the H0 apparatus (GATE-H0, H0.P). It deliberately shares no
//! display/GPU/campaign-preflight semantics with the Campaign 002 launcher;
//! the only shared shape is the minimum user+mount containment argv.

pub mod child;
pub mod containment;
pub mod host;
pub mod record;
