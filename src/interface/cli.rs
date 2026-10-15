use crate::domain::error::{Error, Result};
use crate::domain::route::{Mode, Verify};

pub const HELP: &str = "\
ratriyx: per-process privacy routing through Tor and Privoxy (Linux, Windows, macOS)

USAGE:
  ratriyx doctor [--json] [--mode direct|tor] [--app opencode]
  ratriyx ip
  ratriyx status
  ratriyx run [--mode direct|tor] [--require-tor|--allow-unverified] -- <program> [args...]
  ratriyx run --opencode [--mode direct|tor] [--allow-unverified] [-- args...]
  ratriyx env --shell bash|zsh|fish|powershell [--mode direct|tor] [--session NAME]
  ratriyx on  [--shell bash|zsh|fish|powershell] [--session NAME]
  ratriyx off [--shell bash|zsh|fish|powershell] [--session NAME]
  ratriyx recover --target direct|tor [--dry-run] [--apply] [--yes]
  ratriyx setup --dry-run
  ratriyx configure [--dry-run] [--yes] [--restart] [--file PATH]
  ratriyx service start|stop|restart|status [tor|privoxy] [--yes]
  ratriyx restore [--file PATH] [--yes]
  ratriyx uninstall [--yes]
  ratriyx rotate [--yes]
  ratriyx config migrate [--yes]
  ratriyx --help | --version

Ratriyx changes only the environment of the processes it starts. It never edits
system-wide proxy settings. Privileged actions need --yes after review.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    Doctor {
        json: bool,
        mode: Mode,
        app: Option<String>,
    },
    Ip,
    Status,
    Run {
        mode: Mode,
        verify: Verify,
        opencode: bool,
        program: String,
        args: Vec<String>,
    },
    Env {
        shell: ShellKind,
        mode: Mode,
        session: String,
    },
    Off {
        shell: ShellKind,
        session: String,
    },
    Recover {
        target: Mode,
        apply: bool,
        yes: bool,
    },
    Setup,
    Configure {
        dry_run: bool,
        yes: bool,
        restart: bool,
        file: Option<String>,
    },
    Service {
        action: String,
        unit: String,
        yes: bool,
    },
    Restore {
        yes: bool,
        file: Option<String>,
    },
    Uninstall {
        yes: bool,
    },
    Rotate {
        yes: bool,
    },
    ConfigMigrate {
        yes: bool,
    },
}

struct Scan<'a> {
    items: &'a [String],
    pos: usize,
}

impl<'a> Scan<'a> {
    fn new(items: &'a [String]) -> Self {
        Scan { items, pos: 0 }
    }

    fn take(&mut self) -> Option<&'a str> {
        let item = self.items.get(self.pos)?;
        self.pos += 1;
        Some(item.as_str())
    }

    fn value(&mut self, flag: &str) -> Result<&'a str> {
        self.take()
            .ok_or_else(|| Error::Usage(format!("{flag} needs a value")))
    }

    fn rest(&self) -> &'a [String] {
        &self.items[self.pos.min(self.items.len())..]
    }
}

fn unknown(command: &str, arg: &str) -> Error {
    Error::Usage(format!(
        "unknown option '{arg}' for {command}; run ratriyx --help"
    ))
}

fn parse_mode(value: &str) -> Result<Mode> {
    match value {
        "direct" => Ok(Mode::Direct),
        "tor" => Ok(Mode::Tor),
        other => Err(Error::Usage(format!(
            "mode must be direct or tor, got {other}"
        ))),
    }
}

fn parse_shell(value: &str) -> Result<ShellKind> {
    match value {
        "bash" => Ok(ShellKind::Bash),
        "zsh" => Ok(ShellKind::Zsh),
        "fish" => Ok(ShellKind::Fish),
        "powershell" => Ok(ShellKind::PowerShell),
        other => Err(Error::Usage(format!(
            "shell must be bash, zsh, fish, or powershell, got {other}"
        ))),
    }
}

fn no_extra_args(command: &str, scan: &mut Scan) -> Result<()> {
    match scan.take() {
        None => Ok(()),
        Some(arg) => Err(unknown(command, arg)),
    }
}

pub fn parse(args: &[String]) -> Result<Command> {
    let Some((first, rest)) = args.split_first() else {
        return Ok(Command::Help);
    };
    let mut s = Scan::new(rest);
    match first.as_str() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "-V" | "--version" | "version" => Ok(Command::Version),
        "doctor" => {
            let (mut json, mut mode, mut app) = (false, Mode::Tor, None);
            while let Some(arg) = s.take() {
                match arg {
                    "--json" => json = true,
                    "--mode" => mode = parse_mode(s.value("--mode")?)?,
                    "--app" => app = Some(s.value("--app")?.to_string()),
                    other => return Err(unknown("doctor", other)),
                }
            }
            Ok(Command::Doctor { json, mode, app })
        }
        "ip" => {
            no_extra_args("ip", &mut s)?;
            Ok(Command::Ip)
        }
        "status" => {
            no_extra_args("status", &mut s)?;
            Ok(Command::Status)
        }
        "run" => parse_run(&mut s),
        "env" => {
            let (mut shell, mut mode, mut session) =
                (ShellKind::Bash, Mode::Direct, "default".to_string());
            while let Some(arg) = s.take() {
                match arg {
                    "--shell" => shell = parse_shell(s.value("--shell")?)?,
                    "--mode" => mode = parse_mode(s.value("--mode")?)?,
                    "--session" => session = s.value("--session")?.to_string(),
                    other => return Err(unknown("env", other)),
                }
            }
            Ok(Command::Env {
                shell,
                mode,
                session,
            })
        }
        "on" => {
            let (mut shell, mut session) = (ShellKind::Bash, "default".to_string());
            while let Some(arg) = s.take() {
                match arg {
                    "--shell" => shell = parse_shell(s.value("--shell")?)?,
                    "--session" => session = s.value("--session")?.to_string(),
                    other => return Err(unknown("on", other)),
                }
            }
            Ok(Command::Env {
                shell,
                mode: Mode::Tor,
                session,
            })
        }
        "off" => {
            let (mut shell, mut session) = (ShellKind::Bash, "default".to_string());
            while let Some(arg) = s.take() {
                match arg {
                    "--shell" => shell = parse_shell(s.value("--shell")?)?,
                    "--session" => session = s.value("--session")?.to_string(),
                    other => return Err(unknown("off", other)),
                }
            }
            Ok(Command::Off { shell, session })
        }
        "recover" => {
            let (mut target, mut apply, mut yes) = (None, false, false);
            while let Some(arg) = s.take() {
                match arg {
                    "--target" => target = Some(parse_mode(s.value("--target")?)?),
                    "--dry-run" => apply = false,
                    "--apply" => apply = true,
                    "--yes" => yes = true,
                    other => return Err(unknown("recover", other)),
                }
            }
            let target =
                target.ok_or_else(|| Error::Usage("recover needs --target direct|tor".into()))?;
            Ok(Command::Recover { target, apply, yes })
        }
        "setup" => {
            let mut dry_run = false;
            while let Some(arg) = s.take() {
                match arg {
                    "--dry-run" => dry_run = true,
                    other => return Err(unknown("setup", other)),
                }
            }
            if !dry_run {
                return Err(Error::Usage(
                    "setup only previews in this build; pass --dry-run".into(),
                ));
            }
            Ok(Command::Setup)
        }
        "configure" => {
            let (mut dry_run, mut yes, mut restart, mut file) = (false, false, false, None);
            while let Some(arg) = s.take() {
                match arg {
                    "--dry-run" => dry_run = true,
                    "--yes" => yes = true,
                    "--restart" => restart = true,
                    "--file" => file = Some(s.value("--file")?.to_string()),
                    other => return Err(unknown("configure", other)),
                }
            }
            Ok(Command::Configure {
                dry_run,
                yes,
                restart,
                file,
            })
        }
        "service" => {
            let action = s
                .take()
                .ok_or_else(|| {
                    Error::Usage("service needs start, stop, restart, or status".into())
                })?
                .to_string();
            let (mut unit, mut yes) = ("tor@default".to_string(), false);
            while let Some(arg) = s.take() {
                match arg {
                    "tor" | "tor@default" => unit = "tor@default".into(),
                    "privoxy" => unit = "privoxy".into(),
                    "--yes" => yes = true,
                    other => return Err(unknown("service", other)),
                }
            }
            Ok(Command::Service { action, unit, yes })
        }
        "restore" => {
            let (mut yes, mut file) = (false, None);
            while let Some(arg) = s.take() {
                match arg {
                    "--yes" => yes = true,
                    "--file" => file = Some(s.value("--file")?.to_string()),
                    other => return Err(unknown("restore", other)),
                }
            }
            Ok(Command::Restore { yes, file })
        }
        "uninstall" => Ok(Command::Uninstall {
            yes: parse_yes(&mut s, "uninstall")?,
        }),
        "rotate" => Ok(Command::Rotate {
            yes: parse_yes(&mut s, "rotate")?,
        }),
        "config" => match s.take() {
            Some("migrate") => Ok(Command::ConfigMigrate {
                yes: parse_yes(&mut s, "config migrate")?,
            }),
            _ => Err(Error::Usage("config supports only: migrate".into())),
        },
        other => Err(Error::Usage(format!(
            "unknown command '{other}'; run ratriyx --help"
        ))),
    }
}

fn parse_yes(s: &mut Scan, command: &str) -> Result<bool> {
    let mut yes = false;
    while let Some(arg) = s.take() {
        match arg {
            "--yes" => yes = true,
            other => return Err(unknown(command, other)),
        }
    }
    Ok(yes)
}

fn parse_run(s: &mut Scan) -> Result<Command> {
    let (mut mode, mut require, mut allow, mut opencode) = (Mode::Tor, false, false, false);
    loop {
        match s.take() {
            None if opencode => break,
            None => return Err(Error::Usage("run needs -- <program> [args...]".into())),
            Some("--") => break,
            Some("--mode") => mode = parse_mode(s.value("--mode")?)?,
            Some("--require-tor") => require = true,
            Some("--allow-unverified") => allow = true,
            Some("--opencode") => opencode = true,
            Some(other) => return Err(unknown("run", other)),
        }
    }
    if require && allow {
        return Err(Error::Usage(
            "--require-tor and --allow-unverified are mutually exclusive".into(),
        ));
    }
    let verify = if allow {
        Verify::Allow
    } else {
        Verify::Require
    };
    let rest = s.rest();
    let (program, args) = if opencode {
        let args = match rest.first().map(String::as_str) {
            Some("opencode") => rest[1..].to_vec(),
            _ => rest.to_vec(),
        };
        ("opencode".to_string(), args)
    } else {
        let (program, args) = rest
            .split_first()
            .ok_or_else(|| Error::Usage("run needs a program after --".into()))?;
        (program.clone(), args.to_vec())
    };
    Ok(Command::Run {
        mode,
        verify,
        opencode,
        program,
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_arguments_shows_help() {
        assert_eq!(parse(&[]).unwrap(), Command::Help);
    }

    #[test]
    fn doctor_defaults_to_tor_mode() {
        let cmd = parse(&argv(&["doctor"])).unwrap();
        assert_eq!(
            cmd,
            Command::Doctor {
                json: false,
                mode: Mode::Tor,
                app: None
            }
        );
    }

    #[test]
    fn doctor_accepts_json_mode_and_app() {
        let cmd = parse(&argv(&[
            "doctor", "--json", "--mode", "direct", "--app", "opencode",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Doctor {
                json: true,
                mode: Mode::Direct,
                app: Some("opencode".into())
            }
        );
    }

    #[test]
    fn run_keeps_arguments_verbatim_after_separator() {
        let cmd = parse(&argv(&[
            "run", "--mode", "direct", "--", "echo", "--mode", "x y",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Run {
                mode: Mode::Direct,
                verify: Verify::Require,
                opencode: false,
                program: "echo".into(),
                args: argv(&["--mode", "x y"]),
            }
        );
    }

    #[test]
    fn run_without_separator_is_usage_error() {
        let err = parse(&argv(&["run", "opencode"])).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn run_rejects_both_verification_flags() {
        assert!(parse(&argv(&[
            "run",
            "--require-tor",
            "--allow-unverified",
            "--",
            "x"
        ]))
        .is_err());
    }

    #[test]
    fn run_opencode_accepts_no_separator() {
        let cmd = parse(&argv(&["run", "--opencode"])).unwrap();
        assert!(
            matches!(cmd, Command::Run { opencode: true, ref program, .. } if program == "opencode")
        );
    }

    #[test]
    fn on_defaults_to_tor_mode_and_bash() {
        assert_eq!(
            parse(&argv(&["on"])).unwrap(),
            Command::Env {
                shell: ShellKind::Bash,
                mode: Mode::Tor,
                session: "default".into(),
            }
        );
        assert!(matches!(
            parse(&argv(&["env", "--session", "term-a"])).unwrap(),
            Command::Env { session, .. } if session == "term-a"
        ));
    }

    #[test]
    fn recover_requires_target() {
        assert!(parse(&argv(&["recover"])).is_err());
        assert!(matches!(
            parse(&argv(&["recover", "--target", "direct"])).unwrap(),
            Command::Recover {
                target: Mode::Direct,
                apply: false,
                yes: false
            }
        ));
    }

    #[test]
    fn setup_without_dry_run_is_refused() {
        assert!(parse(&argv(&["setup"])).is_err());
    }

    #[test]
    fn service_maps_tor_to_instance_unit() {
        let cmd = parse(&argv(&["service", "status"])).unwrap();
        assert_eq!(
            cmd,
            Command::Service {
                action: "status".into(),
                unit: "tor@default".into(),
                yes: false
            }
        );
    }

    #[test]
    fn service_accepts_full_instance_unit_name() {
        let cmd = parse(&argv(&["service", "status", "tor@default"])).unwrap();
        assert_eq!(
            cmd,
            Command::Service {
                action: "status".into(),
                unit: "tor@default".into(),
                yes: false
            }
        );
    }

    #[test]
    fn unknown_command_is_usage_error() {
        let err = parse(&argv(&["frobnicate"])).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn unknown_shell_is_usage_error() {
        assert!(parse(&argv(&["env", "--shell", "tcsh"])).is_err());
    }
}
