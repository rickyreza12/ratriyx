use crate::domain::error::{Error, Result};
use crate::domain::route::{EnvPlan, PROXY_VARS};
use crate::infrastructure::fsutil::io_err;
use crate::interface::cli::ShellKind;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub fn quote_posix(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn quote_powershell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn quote(shell: ShellKind, value: &str) -> String {
    match shell {
        ShellKind::PowerShell => quote_powershell(value),
        _ => quote_posix(value),
    }
}

fn set_line(shell: ShellKind, name: &str, value: &str) -> String {
    match shell {
        ShellKind::Bash | ShellKind::Zsh => format!("export {name}={}", quote(shell, value)),
        ShellKind::Fish => format!("set -gx {name} {}", quote(shell, value)),
        ShellKind::PowerShell => format!("$env:{name} = {}", quote(shell, value)),
    }
}

fn unset_line(shell: ShellKind, name: &str) -> String {
    match shell {
        ShellKind::Bash | ShellKind::Zsh => format!("unset {name}"),
        ShellKind::Fish => format!("set -e {name}"),
        ShellKind::PowerShell => format!("Remove-Item Env:{name} -ErrorAction SilentlyContinue"),
    }
}

/// Lines that apply `plan` in `shell`. Print them, then eval or source them.
pub fn render_plan(shell: ShellKind, plan: &EnvPlan) -> String {
    let mut lines: Vec<String> = plan
        .set
        .iter()
        .map(|(name, value)| set_line(shell, name, value))
        .collect();
    lines.extend(plan.unset.iter().map(|name| unset_line(shell, name)));
    lines.push(String::new());
    lines.join("\n")
}

/// Current values of the proxy variables, captured before ratriyx changes anything.
pub fn current_values() -> Vec<(String, Option<String>)> {
    PROXY_VARS
        .iter()
        .map(|name| (name.to_string(), env::var(name).ok()))
        .collect()
}

/// Restore script stored in the private snapshot file. It removes itself after it runs.
pub fn snapshot_script(
    shell: ShellKind,
    prior: &[(String, Option<String>)],
    self_path: &Path,
) -> String {
    let mut lines: Vec<String> = prior
        .iter()
        .map(|(name, value)| match value {
            Some(v) => set_line(shell, name, v),
            None => unset_line(shell, name),
        })
        .collect();
    let path = self_path.display().to_string();
    lines.push(match shell {
        ShellKind::PowerShell => format!(
            "Remove-Item -LiteralPath {} -ErrorAction SilentlyContinue",
            quote_powershell(&path)
        ),
        _ => format!("rm -f -- {}", quote_posix(&path)),
    });
    lines.push(String::new());
    lines.join("\n")
}

pub fn source_line(shell: ShellKind, path: &Path) -> String {
    let path = path.display().to_string();
    match shell {
        ShellKind::Fish => format!("source {}", quote_posix(&path)),
        ShellKind::PowerShell => format!(". {}", quote_powershell(&path)),
        _ => format!(". {}", quote_posix(&path)),
    }
}

fn shell_ext(shell: ShellKind) -> &'static str {
    match shell {
        ShellKind::Bash => "bash",
        ShellKind::Zsh => "zsh",
        ShellKind::Fish => "fish",
        ShellKind::PowerShell => "ps1",
    }
}

pub fn state_dir() -> Option<PathBuf> {
    if let Some(xdg) = env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg).join("ratriyx"));
    }
    if cfg!(windows) {
        if let Some(local) = env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(local).join("ratriyx").join("state"));
        }
    }
    env::var_os("HOME").filter(|v| !v.is_empty()).map(|home| {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("ratriyx")
    })
}

pub fn snapshot_path(dir: &Path, shell: ShellKind) -> PathBuf {
    snapshot_path_for(dir, shell, "default")
}

/// Per-session snapshot path. Two terminals use different `--session` names
/// so one terminal cannot restore or delete the other's proxy values.
/// Names that need cleaning get a hash suffix so `evil` and `../../evil` never share a file.
pub fn snapshot_path_for(dir: &Path, shell: ShellKind, session: &str) -> PathBuf {
    let clean = sanitize_session(session);
    let ext = shell_ext(shell);
    if clean == "default" {
        return dir.join(format!("env-snapshot.{ext}"));
    }
    if clean == session {
        return dir.join(format!("env-snapshot-{clean}.{ext}"));
    }
    let digest = crate::infrastructure::hash::sha256_hex(session.as_bytes());
    dir.join(format!("env-snapshot-{clean}-{}.{ext}", &digest[..8]))
}

/// Snapshot names are file-name safe: anything else becomes `default`.
pub fn sanitize_session(session: &str) -> String {
    let clean: String = session
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(40)
        .collect();
    if clean.is_empty() {
        "default".to_string()
    } else {
        clean
    }
}

/// Writes the snapshot once, first writer wins. A second `on` keeps the original values.
pub fn ensure_snapshot_for(dir: &Path, shell: ShellKind, session: &str) -> Result<PathBuf> {
    let path = snapshot_path_for(dir, shell, session);
    if path.exists() {
        return Ok(path);
    }
    fs::create_dir_all(dir).map_err(io_err)?;
    let script = snapshot_script(shell, &current_values(), &path);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            use std::io::Write as _;
            file.write_all(script.as_bytes()).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
            drop(file);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(io_err)?;
            }
            Ok(path)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(path),
        Err(e) => Err(io_err(e)),
    }
}

pub fn require_state_dir() -> Result<PathBuf> {
    state_dir().ok_or_else(|| Error::Config("cannot find a state directory; set HOME".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::route::{mode_env, Mode};

    #[test]
    fn posix_quoting_escapes_single_quotes() {
        assert_eq!(quote_posix("it's"), "'it'\\''s'");
        assert_eq!(quote_posix("$HOME `x`"), "'$HOME `x`'");
    }

    #[test]
    fn powershell_quoting_doubles_single_quotes() {
        assert_eq!(quote_powershell("it's"), "'it''s'");
    }

    #[test]
    fn tor_mode_bash_snippet_sets_loopback_and_all_proxy() {
        let text = render_plan(
            ShellKind::Bash,
            &mode_env(Mode::Tor, "http://127.0.0.1:8118"),
        );
        assert!(text.contains("export HTTP_PROXY='http://127.0.0.1:8118'"));
        assert!(text.contains("export NO_PROXY='localhost,127.0.0.1,::1'"));
        assert!(text.contains("export ALL_PROXY='http://127.0.0.1:8118'"));
    }

    #[test]
    fn direct_mode_fish_snippet_erases_every_variable() {
        let text = render_plan(
            ShellKind::Fish,
            &mode_env(Mode::Direct, "http://127.0.0.1:8118"),
        );
        assert_eq!(text.matches("set -e ").count(), 8);
    }

    #[test]
    fn powershell_snippet_uses_env_drive() {
        let text = render_plan(
            ShellKind::PowerShell,
            &mode_env(Mode::Tor, "http://127.0.0.1:8118"),
        );
        assert!(text.contains("$env:HTTPS_PROXY = 'http://127.0.0.1:8118'"));
    }

    #[test]
    fn snapshot_restores_absent_variables_by_unsetting_them() {
        let prior = vec![
            ("HTTP_PROXY".to_string(), Some("http://old:1".to_string())),
            ("ALL_PROXY".to_string(), None),
        ];
        let script = snapshot_script(ShellKind::Bash, &prior, Path::new("/tmp/snap"));
        assert!(script.contains("export HTTP_PROXY='http://old:1'"));
        assert!(script.contains("unset ALL_PROXY"));
        assert!(script.contains("rm -f -- '/tmp/snap'"));
    }

    #[test]
    fn snapshot_is_written_once_and_kept_private() {
        let dir = env::temp_dir().join(format!("ratriyx-shell-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = ensure_snapshot_for(&dir, ShellKind::Bash, "default").unwrap();
        let before = fs::read_to_string(&first).unwrap();
        let second = ensure_snapshot_for(&dir, ShellKind::Bash, "default").unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::read_to_string(&second).unwrap(), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&first).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn snapshot_values_are_not_exported_to_child_processes() {
        let dir = env::temp_dir().join(format!("ratriyx-shell-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = ensure_snapshot_for(&dir, ShellKind::Bash, "default").unwrap();
        let mut command = if cfg!(windows) {
            let mut cmd = std::process::Command::new("cmd");
            cmd.args(["/C", "set"]);
            cmd
        } else {
            std::process::Command::new("env")
        };

        let out = command.output().unwrap();
        assert!(out.status.success());

        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains(path.to_string_lossy().as_ref()));
    }

    #[test]
    fn two_sessions_do_not_share_a_snapshot() {
        let dir = env::temp_dir().join(format!("ratriyx-shell-2sess-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let a = ensure_snapshot_for(&dir, ShellKind::Bash, "term-a").unwrap();
        let b = ensure_snapshot_for(&dir, ShellKind::Bash, "term-b").unwrap();
        assert_ne!(a, b);
        assert_eq!(sanitize_session("../../evil"), "evil");
        assert_eq!(sanitize_session(""), "default");
        assert_ne!(
            snapshot_path_for(&dir, ShellKind::Bash, "evil"),
            snapshot_path_for(&dir, ShellKind::Bash, "../../evil")
        );
    }

    #[test]
    fn source_line_quotes_the_path() {
        assert_eq!(
            source_line(ShellKind::Zsh, Path::new("/a b/c")),
            ". '/a b/c'"
        );
    }
}
