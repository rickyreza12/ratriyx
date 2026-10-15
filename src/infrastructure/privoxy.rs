use crate::domain::error::{Error, Result};
use crate::infrastructure::fsutil::{atomic_write, file_owner, io_err, try_chown};
use crate::infrastructure::hash::sha256_hex;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
pub const DESIRED_RULE: &str = "forward-socks5t / 127.0.0.1:9050 .";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub line: usize,
    pub kind: String,
    pub pattern: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwState {
    Present,
    Absent,
    Conflicting(Vec<Rule>),
    Unreadable(String),
}

/// Parses `forward` and `forward-socks5t` lines. Comments after `#` are ignored.
pub fn parse_rules(text: &str) -> Vec<Rule> {
    text.lines()
        .enumerate()
        .filter_map(|(index, raw)| {
            let line = raw.split('#').next().unwrap_or("").trim();
            let mut parts = line.split_whitespace();
            let kind = parts.next()?;
            if kind != "forward" && kind != "forward-socks5t" {
                return None;
            }
            let pattern = parts.next()?.to_string();
            let target = parts.collect::<Vec<_>>().join(" ");
            if target.is_empty() {
                return None;
            }
            Some(Rule {
                line: index + 1,
                kind: kind.to_string(),
                pattern,
                target,
            })
        })
        .collect()
}

fn is_desired_for(rule: &Rule, desired: &str) -> bool {
    let mut parts = desired.split_whitespace();
    let (Some(kind), Some(pattern)) = (parts.next(), parts.next()) else {
        return false;
    };
    let target: Vec<&str> = parts.collect();
    rule.kind == kind && rule.pattern == pattern && rule.target == target.join(" ")
}

/// A rule routes everything (`/`) somewhere else, or sends a destination direct (`.`).
fn is_conflict_for(rule: &Rule, desired: &str) -> bool {
    !is_desired_for(rule, desired)
        && (rule.pattern == "/" || (rule.kind == "forward" && rule.target == "."))
}

#[cfg(test)]
pub fn classify(rules: &[Rule]) -> FwState {
    classify_for(rules, DESIRED_RULE)
}

pub fn classify_for(rules: &[Rule], desired: &str) -> FwState {
    let conflicts: Vec<Rule> = rules
        .iter()
        .filter(|r| is_conflict_for(r, desired))
        .cloned()
        .collect();
    if !conflicts.is_empty() {
        FwState::Conflicting(conflicts)
    } else if rules.iter().any(|r| is_desired_for(r, desired)) {
        FwState::Present
    } else {
        FwState::Absent
    }
}

pub fn read_effective_for(path: &Path, desired: &str) -> FwState {
    match fs::read_to_string(path) {
        Ok(text) => classify_for(&parse_rules(&text), desired),
        Err(e) => FwState::Unreadable(format!("{}: {}", path.display(), e.kind())),
    }
}

/// Appends the desired rule to the end of the file. Callers check `Absent` first.
pub fn insert_rule_for(text: &str, desired: &str) -> String {
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(desired);
    out.push('\n');
    out
}

/// Structural validation before any write or restart: the edited text must
/// contain exactly the desired rule and no conflicting rule.
pub fn validate_config_text(text: &str, desired: &str) -> Result<()> {
    match classify_for(&parse_rules(text), desired) {
        FwState::Present => Ok(()),
        FwState::Absent => Err(Error::Verification(
            "the edited configuration would not contain the desired rule; nothing written".into(),
        )),
        FwState::Conflicting(rules) => Err(Error::Verification(format!(
            "the edited configuration has conflicting rules at lines {}; nothing written",
            rules
                .iter()
                .map(|r| r.line.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        FwState::Unreadable(msg) => Err(Error::Io(msg)),
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn backup_path(path: &Path, stamp: u128) -> PathBuf {
    PathBuf::from(format!("{}.ratriyx-bak-{stamp}", path.display()))
}

fn meta_path(backup: &Path) -> PathBuf {
    PathBuf::from(format!("{}.meta", backup.display()))
}

fn meta_value(meta: &str, key: &str) -> Option<String> {
    meta.lines()
        .find_map(|line| {
            line.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
        })
        .map(str::to_string)
}

/// Newest backup created by ratriyx for `path`, if any.
pub fn latest_backup(path: &Path) -> Option<PathBuf> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path.file_name()?.to_string_lossy().to_string();
    let prefix = format!("{name}.ratriyx-bak-");
    fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter_map(|p| {
            let file = p.file_name()?.to_string_lossy().to_string();
            let stamp: u128 = file.strip_prefix(&prefix)?.parse().ok()?;
            Some((stamp, p))
        })
        .max_by_key(|(stamp, _)| *stamp)
        .map(|(_, p)| p)
}

/// Adds the desired forwarding rule. Dry run by default; writing needs `yes`.
/// The rule is built from configuration, so a custom SOCKS endpoint does not
/// get the default 127.0.0.1:9050 target.
pub fn configure_file_for(path: &Path, desired: &str, dry_run: bool, yes: bool) -> Result<String> {
    configure_at_for(path, desired, dry_run, yes, now_millis())
}

fn configure_at_for(
    path: &Path,
    desired: &str,
    dry_run: bool,
    yes: bool,
    stamp: u128,
) -> Result<String> {
    let original = fs::read_to_string(path)
        .map_err(|e| Error::Io(format!("cannot read {}: {}", path.display(), e.kind())))?;
    match classify_for(&parse_rules(&original), desired) {
        FwState::Present => Ok(format!(
            "{}: desired forwarding is already present; no change",
            path.display()
        )),
        FwState::Unreadable(msg) => Err(Error::Io(msg)),
        FwState::Conflicting(rules) => {
            let lines: Vec<String> = rules.iter().map(|r| r.line.to_string()).collect();
            Err(Error::Verification(format!(
                "{}: rules at lines {} route destinations directly or catch all traffic; review them by hand, then re-run",
                path.display(),
                lines.join(", ")
            )))
        }
        FwState::Absent => {
            if dry_run {
                return Ok(format!(
                    "dry run: would append `{desired}` to {} after backing up the file; no change made",
                    path.display()
                ));
            }
            if !yes {
                return Err(Error::Approval(format!(
                    "appending a rule to {} changes Privoxy's configuration; review the dry run, then re-run with --yes",
                    path.display()
                )));
            }
            let backup = backup_path(path, stamp);
            let updated = insert_rule_for(&original, desired);
            validate_config_text(&updated, desired)?;
            let (mode, uid, gid) = file_owner(path);
            let meta = format!(
                "sha256_before={}\nsha256_after={}\nsource={}\nversion={}\nmode_before={}\nuid_before={}\ngid_before={}\ndesired_rule={desired}\n",
                sha256_hex(original.as_bytes()),
                sha256_hex(updated.as_bytes()),
                path.display(),
                env!("CARGO_PKG_VERSION"),
                mode.map(|m| m.to_string()).unwrap_or_default(),
                uid.map(|u| u.to_string()).unwrap_or_default(),
                gid.map(|g| g.to_string()).unwrap_or_default(),
            );
            atomic_write(&backup, original.as_bytes(), true)?;
            atomic_write(&meta_path(&backup), meta.as_bytes(), true)?;
            atomic_write(path, updated.as_bytes(), false)?;
            try_chown(path, uid, gid);
            let written = fs::read(path).map_err(io_err)?;
            if sha256_hex(&written) != sha256_hex(updated.as_bytes()) {
                atomic_write(path, original.as_bytes(), false)?;
                try_chown(path, uid, gid);
                return Err(Error::Verification(format!(
                    "{} did not read back as written; the original was put back",
                    path.display()
                )));
            }
            Ok(format!(
                "appended `{desired}` to {}; backup at {}; restore with `ratriyx restore --file {}`",
                path.display(),
                backup.display(),
                path.display()
            ))
        }
    }
}

/// Restores the backup only if the file still matches what ratriyx wrote.
pub fn restore_file(path: &Path, backup: &Path, yes: bool) -> Result<String> {
    let meta = fs::read_to_string(meta_path(backup)).map_err(|e| {
        Error::Io(format!(
            "missing backup record for {}: {}",
            backup.display(),
            e.kind()
        ))
    })?;
    let before = meta_value(&meta, "sha256_before")
        .ok_or_else(|| Error::Io("backup record incomplete".into()))?;
    let after = meta_value(&meta, "sha256_after")
        .ok_or_else(|| Error::Io("backup record incomplete".into()))?;
    let backup_bytes = fs::read(backup).map_err(io_err)?;
    if sha256_hex(&backup_bytes) != before {
        return Err(Error::Io(
            "backup content does not match its record; refusing to restore".into(),
        ));
    }
    let current = fs::read(path).map_err(io_err)?;
    if sha256_hex(&current) != after {
        return Err(Error::Approval(format!(
            "{} changed after ratriyx edited it; not restoring automatically. Review it and restore by hand",
            path.display()
        )));
    }
    if !yes {
        return Err(Error::Approval(format!(
            "restoring {} from {} replaces the current file; re-run with --yes",
            path.display(),
            backup.display()
        )));
    }
    atomic_write(path, &backup_bytes, false)?;
    let uid = meta_value(&meta, "uid_before").and_then(|v| v.parse::<u32>().ok());
    let gid = meta_value(&meta, "gid_before").and_then(|v| v.parse::<u32>().ok());
    try_chown(path, uid, gid);
    Ok(format!(
        "restored {} from {}",
        path.display(),
        backup.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configure_file(path: &Path, dry_run: bool, yes: bool) -> Result<String> {
        configure_file_for(path, DESIRED_RULE, dry_run, yes)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ratriyx-privoxy-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn desired_rule_is_present() {
        let text = "listen-address 127.0.0.1:8118\nforward-socks5t / 127.0.0.1:9050 .\n";
        assert_eq!(classify(&parse_rules(text)), FwState::Present);
    }

    #[test]
    fn missing_rule_is_absent_and_comments_do_not_count() {
        let text = "# forward-socks5t / 127.0.0.1:9050 .\nforwarded-connect-retries 0\n";
        assert_eq!(classify(&parse_rules(text)), FwState::Absent);
    }

    #[test]
    fn catch_all_direct_rule_is_a_conflict() {
        let text = "forward / .\nforward-socks5t / 127.0.0.1:9050 .\n";
        match classify(&parse_rules(text)) {
            FwState::Conflicting(rules) => assert_eq!(rules[0].line, 1),
            other => panic!("expected conflict, got {other:?}"),
        }
    }

    #[test]
    fn direct_bypass_for_one_destination_is_a_conflict() {
        let text = "forward .internal.example .\n";
        assert!(matches!(
            classify(&parse_rules(text)),
            FwState::Conflicting(_)
        ));
    }

    #[test]
    fn insert_rule_is_idempotent_through_classification() {
        let once = insert_rule_for("listen-address 127.0.0.1:8118", DESIRED_RULE);
        assert_eq!(classify(&parse_rules(&once)), FwState::Present);
        assert!(!once.contains("forward-socks5t / 127.0.0.1:9050 .\nforward-socks5t"));
    }

    #[test]
    fn configure_dry_run_does_not_write() {
        let dir = scratch("dry");
        let path = dir.join("config");
        fs::write(&path, "listen-address 127.0.0.1:8118\n").unwrap();
        let report = configure_file(&path, true, false).unwrap();
        assert!(report.contains("no change made"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "listen-address 127.0.0.1:8118\n"
        );
    }

    #[test]
    fn configure_without_yes_is_an_approval_error() {
        let dir = scratch("noyes");
        let path = dir.join("config");
        fs::write(&path, "listen-address 127.0.0.1:8118\n").unwrap();
        let err = configure_file(&path, false, false).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn configure_with_yes_backs_up_then_restore_round_trips() {
        let dir = scratch("roundtrip");
        let path = dir.join("config");
        let original = "listen-address 127.0.0.1:8118\n";
        fs::write(&path, original).unwrap();

        configure_file(&path, false, true).unwrap();
        assert_eq!(
            classify(&parse_rules(&fs::read_to_string(&path).unwrap())),
            FwState::Present
        );

        let backup = latest_backup(&path).expect("backup written");
        restore_file(&path, &backup, true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn restore_refuses_when_the_file_changed_since_the_edit() {
        let dir = scratch("tamper");
        let path = dir.join("config");
        fs::write(&path, "listen-address 127.0.0.1:8118\n").unwrap();
        configure_file(&path, false, true).unwrap();
        let backup = latest_backup(&path).unwrap();
        fs::write(&path, "someone else edited this\n").unwrap();
        let err = restore_file(&path, &backup, true).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[cfg(unix)]
    #[test]
    fn configure_keeps_the_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let path = dir.join("config");
        fs::write(&path, "listen-address 127.0.0.1:8118\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        configure_file(&path, false, true).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let backup = latest_backup(&path).unwrap();
        let backup_mode = fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
        assert_eq!(backup_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn failed_backup_leaves_the_original_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("nobackup");
        let path = dir.join("config");
        let original = "listen-address 127.0.0.1:8118\n";
        fs::write(&path, original).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let probe = dir.join("probe");
        let writable = fs::write(&probe, b"x").is_ok();
        let result = configure_file(&path, false, true);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        if writable {
            return; // running as root: directory modes are not enforced
        }
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(latest_backup(&path).is_none());
    }

    #[test]
    fn failure_between_backup_and_write_leaves_the_original_untouched() {
        let dir = scratch("midway");
        let path = dir.join("config");
        let original = "listen-address 127.0.0.1:8118\n";
        fs::write(&path, original).unwrap();
        // A directory where the metadata file belongs makes the second step fail.
        fs::create_dir_all(meta_path(&backup_path(&path, 42))).unwrap();
        let err = configure_at_for(&path, DESIRED_RULE, false, true, 42).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn concurrent_edit_after_configure_blocks_restore() {
        let dir = scratch("concurrent");
        let path = dir.join("config");
        fs::write(&path, "listen-address 127.0.0.1:8118\n").unwrap();
        configure_file(&path, false, true).unwrap();
        let backup = latest_backup(&path).unwrap();
        let mut edited = fs::read_to_string(&path).unwrap();
        edited.push_str("# another tool\n");
        fs::write(&path, &edited).unwrap();
        assert!(restore_file(&path, &backup, true).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), edited);
    }

    #[test]
    fn custom_socks_endpoint_builds_its_own_rule() {
        let desired = "forward-socks5t / 127.0.0.1:9150 .";
        let text = "listen-address 127.0.0.1:8118\n";
        assert_eq!(classify_for(&parse_rules(text), desired), FwState::Absent);
        let updated = insert_rule_for(text, desired);
        assert_eq!(
            classify_for(&parse_rules(&updated), desired),
            FwState::Present
        );
        // The default rule does not satisfy a custom endpoint.
        assert!(matches!(
            classify(&parse_rules(&updated)),
            FwState::Conflicting(_)
        ));
    }

    #[test]
    fn edited_text_is_validated_before_any_write() {
        assert!(validate_config_text("forward-socks5t / 127.0.0.1:9050 .\n", DESIRED_RULE).is_ok());
        assert!(validate_config_text("listen-address 127.0.0.1:8118\n", DESIRED_RULE).is_err());
        assert!(validate_config_text("forward / .\n", DESIRED_RULE).is_err());
    }

    #[test]
    fn conflicting_file_is_not_edited() {
        let dir = scratch("conflict");
        let path = dir.join("config");
        fs::write(&path, "forward / .\n").unwrap();
        let err = configure_file(&path, false, true).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert_eq!(fs::read_to_string(&path).unwrap(), "forward / .\n");
    }
}
