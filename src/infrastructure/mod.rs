//! Adapters: config, filesystem, network, services, shells, and external tools.
pub(crate) mod config;
pub(crate) mod desktop_profiles;
#[cfg(windows)]
pub(crate) mod desktop_windows;
pub(crate) mod embedded_proxy;
pub(crate) mod fsutil;
pub(crate) mod hash;
#[cfg(windows)]
pub(crate) mod isolated_tor;
pub(crate) mod managed;
pub(crate) mod network;
pub(crate) mod opencode;
pub(crate) mod platform;
pub(crate) mod privoxy;
pub(crate) mod redact;
pub(crate) mod runner;
pub(crate) mod service;
pub(crate) mod shell;
pub(crate) mod strict_guard;
pub(crate) mod tor_control;
#[cfg(windows)]
pub(crate) mod windows_documents;
// Windows-targeted; exercised cross-platform by its tests.
#[cfg(windows)]
pub(crate) mod job_windows;
#[cfg(windows)]
pub(crate) mod wfp_windows;
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) mod winmanaged;
pub(crate) mod winpkg;
