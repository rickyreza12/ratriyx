use super::path_var;
use crate::domain::error::{Error, Result};
use crate::domain::route::{self, Mode, Verify};
use crate::infrastructure::config::Config;
use crate::infrastructure::opencode;
use crate::infrastructure::runner;
use crate::infrastructure::shell;
use crate::infrastructure::strict_guard;
use crate::interface::cli::ShellKind;
use crate::interface::diagnostics;

pub fn run(
    cfg: &Config,
    mode: Mode,
    verify: Verify,
    strict: bool,
    opencode: bool,
    program: &str,
    args: &[String],
) -> Result<i32> {
    // Acquire the enforcement lease BEFORE any child process is launched.
    // Environment proxy variables cannot substitute for OS isolation.
    // Keep the lease alive until the launched application exits.
    let _guard = if strict {
        Some(strict_guard::acquire(program)?)
    } else {
        None
    };
    let path = path_var();
    let interop = opencode::program_is_interop(program, &path);
    if opencode && args.iter().any(|a| a == "--standalone") {
        let resolution = opencode::resolve(&path);
        if resolution.standalone != Some(true) {
            return Err(Error::Usage(
                "this opencode does not list --standalone; remove the flag or check the installed version".into(),
            ));
        }
    }
    let probe_needed = mode == Mode::Tor && !(interop && verify == Verify::Require);
    let failure = if probe_needed {
        diagnostics::verify_route(cfg)
    } else {
        None
    };
    let verified = probe_needed && failure.is_none();
    match route::decide(mode, verify, verified, interop) {
        route::Decision::Refuse(msg) => Err(Error::Verification(match failure {
            Some(reason) => format!("{msg}; the proxied check said: {reason}"),
            None => msg,
        })),
        route::Decision::Launch(label) => {
            let mode_name = match mode {
                Mode::Direct => "direct",
                Mode::Tor => "tor",
            };
            eprintln!("ratriyx: route {} ({mode_name} mode)", label.text());
            if opencode {
                for note in route::opencode_boundary_notes() {
                    eprintln!("ratriyx: {note}");
                }
            }
            let plan = route::mode_env(mode, &cfg.proxy_url());
            runner::run_child(program, args, &plan)
        }
    }
}

pub fn env(cfg: &Config, shell_kind: ShellKind, mode: Mode, session: &str) -> Result<i32> {
    let dir = shell::require_state_dir()?;
    shell::ensure_snapshot_for(&dir, shell_kind, session)?;
    let plan = route::mode_env(mode, &cfg.proxy_url());
    show!("{}", shell::render_plan(shell_kind, &plan));
    eprintln!(
        "ratriyx: review the lines above, then eval or source them in your shell. Undo with `ratriyx off --session {session}`. Processes already running keep their environment."
    );
    Ok(0)
}

pub fn off(shell_kind: ShellKind, session: &str) -> Result<i32> {
    let dir = shell::require_state_dir()?;
    let snapshot = shell::snapshot_path_for(&dir, shell_kind, session);
    if snapshot.exists() {
        say!("{}", shell::source_line(shell_kind, &snapshot));
    } else {
        show!(
            "{}",
            shell::render_plan(shell_kind, &route::mode_env(Mode::Direct, ""))
        );
        eprintln!("ratriyx: no snapshot found; unsetting proxy variables instead");
    }
    Ok(0)
}
