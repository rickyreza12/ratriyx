use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Native,
    Script,
    InteropLauncher,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub path: Option<PathBuf>,
    pub kind: Kind,
    pub version: Option<String>,
    pub standalone: Option<bool>,
    /// Running local server: Some(true) running, Some(false) stopped,
    /// None when the installed CLI offers no status probe.
    pub server: Option<bool>,
}

impl Kind {
    pub fn text(self) -> &'static str {
        match self {
            Kind::Native => "native executable",
            Kind::Script => "shell script",
            Kind::InteropLauncher => "Windows interop launcher",
            Kind::Unknown => "unknown",
        }
    }
}

/// Windows executables, and anything under the WSL `/mnt/` drive mounts, run through interop.
pub fn is_interop_path(path: &Path) -> bool {
    if cfg!(windows) {
        return false;
    }
    let text = path.to_string_lossy().to_ascii_lowercase();
    text.ends_with(".exe") || text.starts_with("/mnt/")
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Classifies a file from its first bytes. Scripts that call a `.exe` count as interop.
pub fn classify_content(bytes: &[u8]) -> Kind {
    if bytes.starts_with(b"\x7fELF") {
        Kind::Native
    } else if bytes.starts_with(b"MZ") {
        if cfg!(windows) {
            Kind::Native
        } else {
            Kind::InteropLauncher
        }
    } else if bytes.starts_with(b"#!") {
        if contains(bytes, ".exe") {
            Kind::InteropLauncher
        } else {
            Kind::Script
        }
    } else {
        Kind::Unknown
    }
}

/// Searches the PATH value for the first existing file named `name`.
pub fn find_on_path(name: &str, path_var: &OsStr) -> Option<PathBuf> {
    env::split_paths(path_var)
        .flat_map(|dir| {
            if cfg!(windows) {
                // Unlike PowerShell, Command::new does not automatically
                // resolve extensionless names using PATHEXT. Prefer native
                // executables and then the documented cmd/bat npm shims.
                // Do not run the Unix shell shim that npm also installs.
                let lower = name.to_ascii_lowercase();
                if [".exe", ".com", ".cmd", ".bat"]
                    .iter()
                    .any(|s| lower.ends_with(s))
                {
                    return vec![dir.join(name)];
                }
                return [".exe", ".com", ".cmd", ".bat"]
                    .iter()
                    .map(|ext| dir.join(format!("{name}{ext}")))
                    .collect();
            }
            vec![dir.join(name)]
        })
        .find(|candidate| candidate.is_file())
}

/// Used by `run` to decide whether a program is an interop launcher before it starts.
pub fn program_is_interop(program: &str, path_var: &OsStr) -> bool {
    if cfg!(windows) {
        // Native Windows applications inherit proxy variables; WSL processes
        // are a distinct environment and cannot be assumed to inherit them.
        return is_wsl_launcher(program);
    }
    let direct = Path::new(program);
    if is_interop_path(direct) {
        return true;
    }
    let resolved = if direct.components().count() > 1 {
        Some(direct.to_path_buf())
    } else {
        find_on_path(program, path_var)
    };
    match resolved {
        Some(path) if is_interop_path(&path) => true,
        Some(path) => match read_head(&path) {
            Some(bytes) => classify_content(&bytes) == Kind::InteropLauncher,
            None => true,
        },
        // An unresolvable program is treated as interop, which is the conservative choice.
        None => true,
    }
}

#[cfg(windows)]
fn is_wsl_launcher(program: &str) -> bool {
    Path::new(program).file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        name.eq_ignore_ascii_case("wsl") || name.eq_ignore_ascii_case("wsl.exe")
    })
}

fn read_head(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Looks for `--standalone` as an option name in `opencode --help` output.
pub fn help_lists_standalone(text: &str) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("--standalone")
            && trimmed[12..].chars().next().is_none_or(char::is_whitespace)
    })
}

fn run_capture(path: &Path, arg: &str) -> Option<String> {
    let out = Command::new(path).arg(arg).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// Parse `opencode service status` output. Returns None when the text says
/// nothing conclusive about a local server.
pub fn parse_server_status(text: &str) -> Option<bool> {
    let lower = text.to_ascii_lowercase();
    // Negative indicators first: "not running", "no server", "stopped".
    if lower.contains("not running")
        || lower.contains("no server")
        || lower.contains("no active server")
        || lower.contains("stopped")
    {
        return Some(false);
    }
    if lower.contains("running") || lower.contains("listening") || lower.contains("active") {
        return Some(true);
    }
    None
}

/// Read-only server probe using only the documented `service status`
/// subcommand. Never starts, stops, or restarts anything.
pub fn server_running(path: &Path) -> Option<bool> {
    let out = Command::new(path)
        .args(["service", "status"])
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    parse_server_status(&text)
}

/// Read-only inspection: file type, version, and whether `--standalone` is listed.
pub fn resolve(path_var: &OsStr) -> Resolution {
    let Some(path) = find_on_path("opencode", path_var) else {
        return Resolution {
            path: None,
            kind: Kind::Unknown,
            version: None,
            standalone: None,
            server: None,
        };
    };
    let kind = if is_interop_path(&path) {
        Kind::InteropLauncher
    } else {
        read_head(&path)
            .map(|bytes| classify_content(&bytes))
            .unwrap_or(Kind::Unknown)
    };
    let version = run_capture(&path, "--version").map(|s| s.trim().to_string());
    let standalone = run_capture(&path, "--help").map(|help| help_lists_standalone(&help));
    // Server probe last: it may take a moment and is advisory only.
    let server = server_running(&path);
    Resolution {
        path: Some(path),
        kind,
        version,
        standalone,
        server,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn windows_launcher_paths_are_interop_from_linux() {
        assert!(is_interop_path(Path::new(
            "/mnt/c/Users/x/AppData/npm/opencode"
        )));
        assert!(is_interop_path(Path::new("C:\\tools\\opencode.exe")));
        assert!(!is_interop_path(Path::new("/usr/bin/opencode")));
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_exe_is_not_wsl_interop() {
        assert!(!is_interop_path(Path::new(r"C:\Windows\System32\curl.exe")));
        assert_eq!(classify_content(b"MZ\x90\x00"), Kind::Native);
        assert!(!program_is_interop(
            "curl.exe",
            OsStr::new(r"C:\Windows\System32")
        ));
        assert!(!program_is_interop("opencode.exe", OsStr::new("")));
        assert!(program_is_interop("wsl.exe", OsStr::new("")));
        assert!(program_is_interop(
            r"C:\Windows\System32\wsl.exe",
            OsStr::new("")
        ));
    }

    #[test]
    fn script_calling_exe_is_interop() {
        let launcher =
            b"#!/bin/sh\nexec \"$basedir/node_modules/@opencode/cli/bin/opencode.exe\" \"$@\"\n";
        assert_eq!(classify_content(launcher), Kind::InteropLauncher);
    }

    #[test]
    fn plain_script_and_elf_are_classified() {
        assert_eq!(classify_content(b"#!/bin/sh\necho hi\n"), Kind::Script);
        assert_eq!(classify_content(b"\x7fELF\x02\x01"), Kind::Native);
    }

    #[test]
    fn standalone_is_detected_only_as_an_option_name() {
        let help = "  --print-logs    Print logs\n  --standalone    Run with a private server\n";
        assert!(help_lists_standalone(help));
        assert!(!help_lists_standalone("  --standalone-mode-off\n"));
        assert!(!help_lists_standalone("no such flag here"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_flags_a_windows_launcher_script_found_on_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ratriyx-oc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let launcher = dir.join("opencode");
        fs::write(
            &launcher,
            "#!/bin/sh\n# exec opencode.exe\ncase \"$1\" in --version) echo 9.9.9;; --help) echo '  --standalone  private server';; esac\n",
        )
        .unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
        let found = resolve(dir.as_os_str());
        assert_eq!(found.kind, Kind::InteropLauncher);
        assert_eq!(found.version.as_deref(), Some("9.9.9"));
        assert_eq!(found.standalone, Some(true));
        assert!(program_is_interop("opencode", dir.as_os_str()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_resolution_prefers_exe_then_cmd_over_extensionless_sh() {
        let dir = std::env::temp_dir().join(format!("ratriyx-windows-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("testcli"), "#!/bin/sh").unwrap();
        fs::write(dir.join("testcli.cmd"), "@echo off").unwrap();
        assert_eq!(
            find_on_path("testcli", dir.as_os_str()),
            Some(dir.join("testcli.cmd"))
        );
        fs::write(dir.join("testcli.exe"), "MZ").unwrap();
        assert_eq!(
            find_on_path("testcli", dir.as_os_str()),
            Some(dir.join("testcli.exe"))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_status_text_is_classified() {
        assert_eq!(
            parse_server_status("server running on 127.0.0.1:4096"),
            Some(true)
        );
        assert_eq!(parse_server_status("No server is running"), Some(false));
        assert_eq!(parse_server_status("unrelated help text"), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn unresolvable_program_is_treated_as_interop_from_linux() {
        assert!(program_is_interop(
            "definitely-missing-program-xyz",
            OsStr::new("")
        ));
    }
}
