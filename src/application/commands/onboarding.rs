//! Interactive first-run setup. This is deliberately not a Cargo build hook:
//! compiling/installing the crate must never modify the user's machine.

use super::{maintenance, path_var};
use crate::domain::error::{Error, Result};
use crate::infrastructure::config::Config;
use crate::infrastructure::{fsutil, shell};
use crate::interface::{cli, diagnostics, setup};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

const MARKER: &str = "first-run-v1";

fn remember(path: &Path, choice: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Io("cannot determine first-run state directory".into()))?;
    fs::create_dir_all(parent).map_err(fsutil::io_err)?;
    fsutil::atomic_write(path, choice.as_bytes(), true)
}

/// Only an explicit "y" or "yes" authorizes dependency installation.
fn ask<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> Result<bool> {
    writer
        .write_all(b"Install and configure managed Tor now? [y/N]: ")
        .map_err(fsutil::io_err)?;
    writer.flush().map_err(fsutil::io_err)?;
    let mut response = String::new();
    reader.read_line(&mut response).map_err(fsutil::io_err)?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Called only from an interactive, no-argument invocation of the CLI.
pub fn run(cfg: &Config) -> Result<i32> {
    let state = shell::require_state_dir()?;
    let marker = state.join(MARKER);
    if marker.exists() {
        show!("{}", cli::HELP);
        return Ok(0);
    }

    say!("Welcome to Ratriyx {}!", env!("CARGO_PKG_VERSION"));
    say!("First-run setup (no changes without your approval).");
    let facts = setup::gather(&path_var(), cfg);
    say!("  Platform: {}", facts.platform);
    say!(
        "  Tor on PATH: {}",
        if facts.tor_installed { "yes" } else { "no" }
    );
    let already_verified = (|| -> Result<bool> {
        let socks = cfg
            .tor_socks_addr()
            .parse()
            .map_err(|_| Error::Config("invalid Tor SOCKS5 socket address".into()))?;
        let proxy = crate::infrastructure::embedded_proxy::EmbeddedProxy::start(socks)?;
        let mut probe_cfg = cfg.clone();
        probe_cfg.proxy_host = proxy.address().ip().to_string();
        probe_cfg.proxy_port = proxy.address().port();
        Ok(diagnostics::verify_route_with_timeout(&probe_cfg, 5).is_none())
    })()
    .unwrap_or(false);
    if already_verified {
        remember(&marker, "configured\n")?;
        say!("Tor routing already verified (IsTor true); nothing to install.");
        say!("Run 'ratriyx doctor' or 'ratriyx ip' to inspect your route.");
        return Ok(0);
    }

    // The existing managed installer is the one source of truth for actions.
    // Without --yes it only reports its plan, never downloads or starts daemons.
    match maintenance::setup_install(cfg, false) {
        Err(Error::Approval(preview)) => say!("{preview}"),
        Err(err) => {
            eprintln!("ratriyx: automatic setup is unavailable: {err}");
            eprintln!("ratriyx: use 'ratriyx setup --dry-run' for manual next steps.");
            return Ok(err.exit_code());
        }
        Ok(_) => {
            eprintln!("ratriyx: dependencies appear installed, but Tor routing is not verified.");
            eprintln!("ratriyx: run 'ratriyx doctor --mode tor' to diagnose the route.");
            return Ok(4);
        }
    }

    let approved = ask(&mut io::stdin().lock(), &mut io::stdout().lock())?;
    if !approved {
        remember(&marker, "skipped\n")?;
        say!("Skipped. No dependencies installed or changed.");
        say!("To configure later: 'ratriyx setup --install' (preview), then 'ratriyx setup --install --yes'.");
        return Ok(0);
    }

    // The user has explicitly approved the exact plan printed above.
    // setup_install owns backups, checksums, service tracking and route verification.
    let code = maintenance::setup_install(cfg, true)?;
    if code == 0 {
        remember(&marker, "configured\n")?;
        say!("Setup completed. Run 'ratriyx doctor' and 'ratriyx ip' to inspect the connection.");
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn answer(input: &str) -> bool {
        let mut reader = Cursor::new(input.as_bytes());
        let mut output = Vec::new();
        let decision = ask(&mut reader, &mut output).unwrap();
        assert!(String::from_utf8_lossy(&output).contains("[y/N]"));
        decision
    }

    #[test]
    fn approval_requires_explicit_yes() {
        assert!(answer("y\n"));
        assert!(answer("YES\n"));
        assert!(!answer("no\n"));
        assert!(!answer("\n"));
        assert!(!answer("maybe\n"));
        assert!(!answer(""));
    }

    #[test]
    fn choice_marker_keeps_success_and_skip_distinct() {
        let root =
            std::env::temp_dir().join(format!("ratriyx-onboarding-test-{}", std::process::id()));
        let marker = root.join("first-run-v1");
        let _ = fs::remove_dir_all(&root);
        remember(&marker, "skipped\n").unwrap();
        assert_eq!(fs::read_to_string(&marker).unwrap(), "skipped\n");
        remember(&marker, "configured\n").unwrap();
        assert_eq!(fs::read_to_string(&marker).unwrap(), "configured\n");
        let _ = fs::remove_dir_all(&root);
    }
}
