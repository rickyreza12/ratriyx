//! Boundary with the user: argument parsing, diagnostics rendering, setup reporting.
pub(crate) mod cli;
pub(crate) mod diagnostics;
#[cfg(windows)]
pub(crate) mod installer;
pub(crate) mod setup;
pub(crate) mod terminal;
