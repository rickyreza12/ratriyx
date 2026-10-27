mod diagnose;
mod launch;
mod maintenance;
mod onboarding;
mod proxy;
mod uninstall;

use crate::domain::error::Result;
use crate::infrastructure::config::{self, Config};
use crate::infrastructure::service;
use crate::interface::cli::Command;
use crate::interface::setup;
use std::env;
use std::ffi::OsString;

pub fn first_run() -> Result<i32> {
    onboarding::run(&load_config()?)
}

pub fn dispatch(command: Command) -> Result<i32> {
    let cfg = load_config()?;
    match command {
        Command::Doctor { json, mode, app } => diagnose::doctor(&cfg, json, mode, app.as_deref()),
        Command::Ip => diagnose::ip(&cfg),
        Command::Status => diagnose::status(&cfg),
        Command::Run {
            mode,
            verify,
            strict,
            opencode,
            program,
            args,
        } => launch::run(&cfg, mode, verify, strict, opencode, &program, &args),
        Command::Env {
            shell,
            mode,
            session,
        } => launch::env(&cfg, shell, mode, &session),
        Command::Off { shell, session } => launch::off(shell, &session),
        Command::Recover { target, apply, yes } => maintenance::recover(&cfg, target, apply, yes),
        Command::Setup { install, yes } => {
            if install {
                maintenance::setup_install(&cfg, yes)
            } else {
                say!("{}", setup::report(&setup::gather(&path_var(), &cfg)));
                Ok(0)
            }
        }
        Command::Configure {
            dry_run,
            yes,
            restart,
            file,
        } => proxy::configure(&cfg, dry_run, yes, restart, file.as_deref()),
        Command::Service { action, unit, yes } => {
            say!("{}", service::control(&action, &unit, yes)?);
            Ok(0)
        }
        Command::Restore { yes, file } => proxy::restore(&cfg, yes, file.as_deref()),
        Command::Uninstall {
            yes,
            remove_managed,
            remove_tor,
            remove_privoxy,
            remove_untracked_privoxy,
        } => {
            if remove_managed {
                maintenance::uninstall_remove_managed(yes)
            } else {
                uninstall::run(yes, remove_tor, remove_privoxy, remove_untracked_privoxy)
            }
        }
        Command::Rotate { yes } => diagnose::rotate(&cfg, yes),
        Command::ConfigMigrate { yes } => maintenance::config_migrate(yes),
        Command::Help | Command::Version => Ok(0),
    }
}

fn load_config() -> Result<Config> {
    match config::config_file() {
        Some(path) => {
            if !path.exists() {
                if let Some(legacy) = config::legacy_config_file().filter(|p| p.exists()) {
                    eprintln!(
                        "ratriyx: found legacy config {}; run `ratriyx config migrate` to preview a copy",
                        legacy.display()
                    );
                }
            }
            config::load(&path)
        }
        None => Ok(Config::default()),
    }
}

fn path_var() -> OsString {
    env::var_os("PATH").unwrap_or_default()
}
