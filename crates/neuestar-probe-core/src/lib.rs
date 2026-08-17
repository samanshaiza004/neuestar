//! Shared Campaign 002 containment core, extracted so the frozen launcher and
//! the H0 probe cannot drift: frozen artifact verification (full payload walk),
//! bundled-helper closure resolution, and the minimum user+mount containment
//! command construction.

pub mod artifact;
pub mod command;
pub mod helper;
