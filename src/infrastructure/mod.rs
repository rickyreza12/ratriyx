//! Adapters: config, filesystem, network, services, shells, and external tools.
pub(crate) mod config;
pub(crate) mod fsutil;
pub(crate) mod hash;
pub(crate) mod managed;
pub(crate) mod network;
pub(crate) mod opencode;
pub(crate) mod platform;
pub(crate) mod privoxy;
pub(crate) mod redact;
pub(crate) mod runner;
pub(crate) mod service;
pub(crate) mod shell;
pub(crate) mod tor_control;
// Windows-targeted; exercised cross-platform by its tests.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) mod winmanaged;
pub(crate) mod winpkg;
