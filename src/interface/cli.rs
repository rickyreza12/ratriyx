use crate::domain::error::{Error, Result};
use crate::domain::route::{Mode, Verify};

pub const HELP: &str = "\
ratriyx: per-process privacy routing through Tor (Linux, Windows, macOS)

USAGE:
  ratriyx doctor [--json] [--mode direct|tor] [--app opencode]
  ratriyx ip [--privoxy]
  ratriyx status
  ratriyx privacy check [--json]
  ratriyx desktop serve [--port 8119]
  ratriyx desktop on|off --target windows|powershell|pwsh|zed [--port 8119] [--yes]
  ratriyx run [--mode direct|tor] [--require-tor|--allow-unverified] [--strict] [--embedded-proxy|--privoxy] -- <program> [args...]
  ratriyx run --opencode [--mode direct|tor] [--allow-unverified] [--strict] [--embedded-proxy|--privoxy] [-- args...]
  ratriyx env --shell bash|zsh|fish|powershell [--mode direct|tor] [--session NAME]
  ratriyx on  [--shell bash|zsh|fish|powershell] [--session NAME]
  ratriyx off [--shell bash|zsh|fish|powershell] [--session NAME]
  ratriyx recover --target direct|tor [--dry-run] [--apply] [--yes]
  ratriyx setup [--dry-run|--install [--yes]]
  ratriyx configure [--dry-run] [--yes] [--restart] [--file PATH]
  ratriyx service start|stop|restart|status [tor|privoxy] [--yes]
  ratriyx restore [--file PATH] [--yes]
  ratriyx uninstall [--yes] [--remove-tor] [--remove-privoxy]
  ratriyx uninstall --yes --remove-untracked-privoxy
  ratriyx uninstall --remove-managed [--yes]
  ratriyx rotate [--yes] | ratriyx rotate status
  ratriyx strict check
  ratriyx config migrate [--yes]
  ratriyx --help | --version

Per-process run does not change system settings. Desktop integrations are opt-in,
require --yes, and use a verified foreground proxy. Windows is current-user WinINet,
not WinHTTP, all protocols, or a firewall. Restore settings with desktop off.
--strict requires OS enforcement and currently refuses to launch.
Tor run, ip, doctor and status use a temporary embedded Rust HTTP-to-Tor SOCKS5 proxy.
Windows run restarts installed Ratriyx-managed Tor when its listener is absent.
--privoxy explicitly selects the historical external HTTP proxy. --embedded-proxy is retained.
--allow-unverified requires an explicit --privoxy opt-in. Neither path is a leak-proof firewall.
env/on in Tor mode are refused because their shell cannot own a temporary proxy;
use ratriyx run --mode tor instead.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopTarget {
    Windows,
    PowerShell,
    Pwsh,
    Zed,
}

fn desktop_target(name: &str) -> Result<DesktopTarget> {
    match name {
        "windows" => Ok(DesktopTarget::Windows),
        "powershell" => Ok(DesktopTarget::PowerShell),
        "pwsh" => Ok(DesktopTarget::Pwsh),
        "zed" => Ok(DesktopTarget::Zed),
        _ => Err(Error::Usage(
            "desktop target must be windows, powershell, pwsh, or zed".into(),
        )),
    }
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
    Ip {
        privoxy: bool,
    },
    Status,
    PrivacyCheck {
        json: bool,
    },
    DesktopServe {
        port: u16,
    },
    DesktopChange {
        target: DesktopTarget,
        enable: bool,
        yes: bool,
        port: u16,
    },
    Run {
        mode: Mode,
        verify: Verify,
        strict: bool,
        embedded_proxy: bool,
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
    Setup {
        install: bool,
        yes: bool,
    },
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
        remove_managed: bool,
        remove_tor: bool,
        remove_privoxy: bool,
        remove_untracked_privoxy: bool,
    },
    Rotate {
        yes: bool,
    },
    RotateStatus,
    StrictCheck,
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
        "ip" => match s.take() {
            None => Ok(Command::Ip { privoxy: false }),
            Some("--privoxy") if s.take().is_none() => Ok(Command::Ip { privoxy: true }),
            Some(other) => Err(unknown("ip", other)),
        },
        "status" => {
            no_extra_args("status", &mut s)?;
            Ok(Command::Status)
        }
        "privacy" => match s.take() {
            Some("check") => {
                let mut json = false;
                while let Some(arg) = s.take() {
                    match arg {
                        "--json" => json = true,
                        other => return Err(unknown("privacy check", other)),
                    }
                }
                Ok(Command::PrivacyCheck { json })
            }
            _ => Err(Error::Usage("privacy supports only: check [--json]".into())),
        },
        "desktop" => {
            let action = s
                .take()
                .ok_or_else(|| Error::Usage("desktop requires serve, on, or off".into()))?;
            if !matches!(action, "serve" | "on" | "off") {
                return Err(Error::Usage("desktop requires serve, on, or off".into()));
            }
            let (mut port, mut yes, mut target) = (8119u16, false, None);
            while let Some(arg) = s.take() {
                match arg {
                    "--port" => {
                        port = s
                            .value("--port")?
                            .parse()
                            .map_err(|_| Error::Usage("desktop --port requires 1..65535".into()))?
                    }
                    "--yes" if action != "serve" => yes = true,
                    "--target" if action != "serve" => {
                        target = Some(desktop_target(s.value("--target")?)?)
                    }
                    other => return Err(unknown("desktop", other)),
                }
            }
            if action == "serve" {
                Ok(Command::DesktopServe { port })
            } else {
                Ok(Command::DesktopChange {
                    target: target
                        .ok_or_else(|| Error::Usage("desktop on/off needs --target".into()))?,
                    enable: action == "on",
                    yes,
                    port,
                })
            }
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
            let (mut dry_run, mut install, mut yes) = (false, false, false);
            while let Some(arg) = s.take() {
                match arg {
                    "--dry-run" => dry_run = true,
                    "--install" => install = true,
                    "--yes" => yes = true,
                    other => return Err(unknown("setup", other)),
                }
            }
            if dry_run && install {
                return Err(Error::Usage(
                    "--dry-run and --install are mutually exclusive".into(),
                ));
            }
            if !dry_run && !install {
                return Err(Error::Usage(
                    "setup previews with --dry-run or installs with --install".into(),
                ));
            }
            Ok(Command::Setup { install, yes })
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
        "uninstall" => {
            let (mut yes, mut remove_managed, mut remove_tor, mut remove_privoxy, mut untracked) =
                (false, false, false, false, false);
            while let Some(arg) = s.take() {
                match arg {
                    "--yes" => yes = true,
                    "--remove-managed" => remove_managed = true,
                    "--remove-tor" => remove_tor = true,
                    "--remove-privoxy" => remove_privoxy = true,
                    "--remove-untracked-privoxy" => untracked = true,
                    other => return Err(unknown("uninstall", other)),
                }
            }
            if remove_managed && (remove_tor || remove_privoxy || untracked) {
                return Err(Error::Usage(
                    "--remove-managed cannot be combined with dependency uninstall flags".into(),
                ));
            }
            if untracked && (remove_privoxy || !yes) {
                return Err(Error::Usage(
                    "--remove-untracked-privoxy requires --yes and cannot be combined with --remove-privoxy".into(),
                ));
            }
            Ok(Command::Uninstall {
                yes,
                remove_managed,
                remove_tor,
                remove_privoxy,
                remove_untracked_privoxy: untracked,
            })
        }
        "rotate" => {
            if s.rest().first().map(String::as_str) == Some("status") {
                s.take();
                no_extra_args("rotate status", &mut s)?;
                Ok(Command::RotateStatus)
            } else {
                Ok(Command::Rotate {
                    yes: parse_yes(&mut s, "rotate")?,
                })
            }
        }
        "strict" => match s.take() {
            Some("check") if s.take().is_none() => Ok(Command::StrictCheck),
            _ => Err(Error::Usage("strict supports only: check".into())),
        },
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
    let (
        mut mode,
        mut require,
        mut allow,
        mut strict,
        mut explicit_embedded,
        mut privoxy,
        mut opencode,
    ) = (Mode::Tor, false, false, false, false, false, false);
    loop {
        match s.take() {
            None if opencode => break,
            None => return Err(Error::Usage("run needs -- <program> [args...]".into())),
            Some("--") => break,
            Some("--mode") => mode = parse_mode(s.value("--mode")?)?,
            Some("--require-tor") => require = true,
            Some("--allow-unverified") => allow = true,
            Some("--strict") => strict = true,
            Some("--embedded-proxy") => explicit_embedded = true,
            Some("--privoxy") => privoxy = true,
            Some("--opencode") => opencode = true,
            Some(other) => return Err(unknown("run", other)),
        }
    }
    if require && allow {
        return Err(Error::Usage(
            "--require-tor and --allow-unverified are mutually exclusive".into(),
        ));
    }
    if strict && (mode != Mode::Tor || allow) {
        return Err(Error::Usage(
            "--strict requires --mode tor and cannot combine with --allow-unverified".into(),
        ));
    }
    if explicit_embedded && privoxy {
        return Err(Error::Usage(
            "--embedded-proxy and --privoxy are mutually exclusive".into(),
        ));
    }
    if (explicit_embedded || privoxy) && mode != Mode::Tor {
        return Err(Error::Usage(
            "proxy backend flags require --mode tor".into(),
        ));
    }
    let embedded_proxy = mode == Mode::Tor && !privoxy;
    if embedded_proxy && allow {
        return Err(Error::Usage(
            "embedded proxy requires verified Tor routing; --allow-unverified needs explicit --privoxy".into(),
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
        strict,
        embedded_proxy,
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
    fn uninstall_dependencies_require_separate_flags() {
        assert_eq!(
            parse(&argv(&[
                "uninstall",
                "--yes",
                "--remove-tor",
                "--remove-privoxy"
            ]))
            .unwrap(),
            Command::Uninstall {
                yes: true,
                remove_managed: false,
                remove_tor: true,
                remove_privoxy: true,
                remove_untracked_privoxy: false,
            }
        );
        assert_eq!(
            parse(&argv(&["uninstall"])).unwrap(),
            Command::Uninstall {
                yes: false,
                remove_managed: false,
                remove_tor: false,
                remove_privoxy: false,
                remove_untracked_privoxy: false,
            }
        );
        assert!(parse(&argv(&["uninstall", "--remove-managed", "--remove-tor"])).is_err());
        assert_eq!(
            parse(&argv(&["uninstall", "--yes", "--remove-untracked-privoxy"])).unwrap(),
            Command::Uninstall {
                yes: true,
                remove_managed: false,
                remove_tor: false,
                remove_privoxy: false,
                remove_untracked_privoxy: true,
            }
        );
        assert!(parse(&argv(&["uninstall", "--remove-untracked-privoxy"])).is_err());
        assert!(parse(&argv(&[
            "uninstall",
            "--yes",
            "--remove-privoxy",
            "--remove-untracked-privoxy"
        ]))
        .is_err());
    }

    #[test]
    fn strict_check_is_read_only_command() {
        assert_eq!(
            parse(&argv(&["strict", "check"])).unwrap(),
            Command::StrictCheck
        );
        assert!(parse(&argv(&["strict", "apply"])).is_err());
        assert!(parse(&argv(&["strict", "check", "--yes"])).is_err());
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
                strict: false,
                embedded_proxy: false,
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
    fn tor_run_defaults_to_embedded_and_legacy_is_explicit() {
        assert!(matches!(
            parse(&argv(&["run", "--", "curl.exe"])).unwrap(),
            Command::Run {
                mode: Mode::Tor,
                embedded_proxy: true,
                verify: Verify::Require,
                ..
            }
        ));
        assert!(matches!(
            parse(&argv(&["run", "--opencode"])).unwrap(),
            Command::Run {
                mode: Mode::Tor,
                embedded_proxy: true,
                opencode: true,
                ..
            }
        ));
        assert!(matches!(
            parse(&argv(&["run", "--privoxy", "--", "curl.exe"])).unwrap(),
            Command::Run {
                embedded_proxy: false,
                ..
            }
        ));
        assert!(matches!(
            parse(&argv(&["run", "--mode", "direct", "--", "curl.exe"])).unwrap(),
            Command::Run {
                mode: Mode::Direct,
                embedded_proxy: false,
                ..
            }
        ));
    }

    #[test]
    fn backend_flags_and_unverified_mode_do_not_silently_downgrade() {
        assert!(parse(&argv(&["run", "--privoxy", "--embedded-proxy", "--", "x"])).is_err());
        assert!(parse(&argv(&["run", "--mode", "direct", "--privoxy", "--", "x"])).is_err());
        assert!(parse(&argv(&["run", "--allow-unverified", "--", "x"])).is_err());
        assert!(matches!(
            parse(&argv(&[
                "run",
                "--privoxy",
                "--allow-unverified",
                "--",
                "x"
            ]))
            .unwrap(),
            Command::Run {
                embedded_proxy: false,
                verify: Verify::Allow,
                ..
            }
        ));
        assert!(parse(&argv(&[
            "run",
            "--strict",
            "--allow-unverified",
            "--privoxy",
            "--",
            "x"
        ]))
        .is_err());
    }

    #[test]
    fn ip_defaults_to_embedded_and_legacy_requires_a_flag() {
        assert_eq!(
            parse(&argv(&["ip"])).unwrap(),
            Command::Ip { privoxy: false }
        );
        assert_eq!(
            parse(&argv(&["ip", "--privoxy"])).unwrap(),
            Command::Ip { privoxy: true }
        );
        assert!(parse(&argv(&["ip", "--privoxy", "extra"])).is_err());
    }

    #[test]
    fn rotate_status_is_read_only_and_yes_applies_only_to_rotate() {
        assert_eq!(
            parse(&argv(&["rotate", "status"])).unwrap(),
            Command::RotateStatus
        );
        assert!(parse(&argv(&["rotate", "status", "--yes"])).is_err());
        assert_eq!(
            parse(&argv(&["rotate", "--yes"])).unwrap(),
            Command::Rotate { yes: true }
        );
    }

    #[test]
    fn desktop_flags_are_scoped_and_mutations_require_a_target() {
        assert_eq!(
            parse(&argv(&["desktop", "serve", "--port", "18119"])).unwrap(),
            Command::DesktopServe { port: 18119 }
        );
        assert_eq!(
            parse(&argv(&[
                "desktop",
                "on",
                "--target",
                "powershell",
                "--port",
                "8119"
            ]))
            .unwrap(),
            Command::DesktopChange {
                target: DesktopTarget::PowerShell,
                enable: true,
                yes: false,
                port: 8119,
            }
        );
        assert!(matches!(
            parse(&argv(&["desktop", "off", "--target", "pwsh", "--yes"])).unwrap(),
            Command::DesktopChange {
                target: DesktopTarget::Pwsh,
                enable: false,
                yes: true,
                ..
            }
        ));
        assert!(parse(&argv(&["desktop", "on", "--yes"])).is_err());
        assert!(parse(&argv(&["desktop", "serve", "--yes"])).is_err());
        assert!(parse(&argv(&["privacy", "check", "--json"])).is_ok());
        assert!(parse(&argv(&["privacy", "check", "--unsafe"])).is_err());
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
    fn strict_mode_parses_but_requires_tor_without_unverified_override() {
        assert!(matches!(
            parse(&argv(&["run", "--strict", "--", "opencode"])).unwrap(),
            Command::Run {
                strict: true,
                mode: Mode::Tor,
                ..
            }
        ));
        assert!(matches!(
            parse(&argv(&["run", "--opencode", "--strict"])).unwrap(),
            Command::Run {
                strict: true,
                opencode: true,
                ..
            }
        ));
        assert!(parse(&argv(&[
            "run", "--mode", "direct", "--strict", "--", "opencode"
        ]))
        .is_err());
        assert!(parse(&argv(&[
            "run",
            "--allow-unverified",
            "--strict",
            "--",
            "opencode"
        ]))
        .is_err());
        assert!(matches!(
            parse(&argv(&["run", "--", "opencode", "--strict"])).unwrap(),
            Command::Run { strict: false, ref args, .. } if args == &argv(&["--strict"])
        ));
    }

    #[test]
    fn embedded_proxy_requires_verified_tor_and_preserves_child_args() {
        assert!(matches!(
            parse(&argv(&["run", "--embedded-proxy", "--", "opencode", "--standalone"])).unwrap(),
            Command::Run { embedded_proxy: true, args, .. } if args == argv(&["--standalone"])
        ));
        assert!(parse(&argv(&[
            "run",
            "--mode",
            "direct",
            "--embedded-proxy",
            "--",
            "x"
        ]))
        .is_err());
        assert!(parse(&argv(&[
            "run",
            "--allow-unverified",
            "--embedded-proxy",
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
        assert_eq!(
            parse(&argv(&["setup", "--dry-run"])).unwrap(),
            Command::Setup {
                install: false,
                yes: false
            }
        );
        assert_eq!(
            parse(&argv(&["setup", "--install", "--yes"])).unwrap(),
            Command::Setup {
                install: true,
                yes: true
            }
        );
        assert!(parse(&argv(&["setup", "--dry-run", "--install"])).is_err());
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
