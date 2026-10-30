//! Ownership record for Ratriyx-managed dependencies (`docs/managed-ownership.md`).
//! Only files and services recorded here may be touched by update, rollback,
//! or dependency uninstall. Pre-existing user installations are never recorded.

use crate::domain::error::{Error, Result};
use crate::infrastructure::fsutil::{atomic_write, io_err};
use std::fs;
use std::path::{Path, PathBuf};

pub const RECORD_VERSION: u32 = 1;
pub const RECORD_NAME: &str = "managed.toml";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {
    pub ratriyx_version: String,
    pub platform: String,
    pub arch: String,
    pub dependencies: Vec<Dependency>,
    pub files: Vec<ManagedFile>,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub source: String,
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedFile {
    pub path: String,
    pub sha256_after: String,
    pub backup: String,
}

pub fn record_path(dir: &Path) -> PathBuf {
    dir.join(RECORD_NAME)
}

/// Missing file means nothing managed yet. Unknown versions and corrupt
/// content stop the caller instead of guessing.
pub fn load(dir: &Path) -> Result<Option<Record>> {
    let path = record_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).map_err(io_err)?;
    parse(&text, &path)
}

fn parse(text: &str, path: &Path) -> Result<Option<Record>> {
    let mut rec = Record::default();
    let mut section = String::new();
    let mut seen_version = false;
    let mut dep: Option<Dependency> = None;
    let mut file: Option<ManagedFile> = None;
    let flush_dep = |rec: &mut Record, dep: &mut Option<Dependency>| {
        if let Some(d) = dep.take() {
            rec.dependencies.push(d);
        }
    };
    let flush_file = |rec: &mut Record, file: &mut Option<ManagedFile>| {
        if let Some(f) = file.take() {
            rec.files.push(f);
        }
    };
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at =
            |msg: String| Error::Config(format!("{} line {}: {msg}", path.display(), index + 1));
        if let Some(name) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
            flush_dep(&mut rec, &mut dep);
            flush_file(&mut rec, &mut file);
            section = name.trim().to_string();
            match section.as_str() {
                "dependency" => {
                    dep = Some(Dependency {
                        name: String::new(),
                        source: String::new(),
                        version: String::new(),
                        sha256: String::new(),
                    })
                }
                "file" => {
                    file = Some(ManagedFile {
                        path: String::new(),
                        sha256_after: String::new(),
                        backup: String::new(),
                    })
                }
                "service" => {}
                other => return Err(at(format!("unknown table {other}"))),
            }
            continue;
        }
        if line.starts_with('[') {
            return Err(at("unexpected section header".into()));
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| at("expected key = value".into()))?;
        let value = value.trim().trim_matches('"').to_string();
        match (section.as_str(), key.trim()) {
            ("", "version") => {
                seen_version = true;
                if value != RECORD_VERSION.to_string() {
                    return Err(at(format!(
                        "unsupported record version {value}; back it up and recreate it"
                    )));
                }
            }
            ("", "ratriyx_version") => rec.ratriyx_version = value,
            ("", "platform") => rec.platform = value,
            ("", "arch") => rec.arch = value,
            ("dependency", "name") => {
                dep.as_mut()
                    .ok_or_else(|| at("name outside table".into()))?
                    .name = value
            }
            ("dependency", "source") => {
                dep.as_mut()
                    .ok_or_else(|| at("source outside table".into()))?
                    .source = value
            }
            ("dependency", "version") => {
                dep.as_mut()
                    .ok_or_else(|| at("version outside table".into()))?
                    .version = value
            }
            ("dependency", "sha256") => {
                dep.as_mut()
                    .ok_or_else(|| at("sha256 outside table".into()))?
                    .sha256 = value
            }
            ("file", "path") => {
                file.as_mut()
                    .ok_or_else(|| at("path outside table".into()))?
                    .path = value
            }
            ("file", "sha256_after") => {
                file.as_mut()
                    .ok_or_else(|| at("sha256_after outside table".into()))?
                    .sha256_after = value
            }
            ("file", "backup") => {
                file.as_mut()
                    .ok_or_else(|| at("backup outside table".into()))?
                    .backup = value
            }
            ("service", "name") => rec.services.push(value),
            _ => return Err(at(format!("unknown key {key} in {section}"))),
        }
    }
    flush_dep(&mut rec, &mut dep);
    flush_file(&mut rec, &mut file);
    if !seen_version {
        return Err(Error::Config(format!(
            "{} has no version field; refusing to trust it",
            path.display()
        )));
    }
    Ok(Some(rec))
}

fn render(rec: &Record) -> String {
    let mut out = format!(
        "version = {}\nratriyx_version = \"{}\"\nplatform = \"{}\"\narch = \"{}\"\n",
        RECORD_VERSION, rec.ratriyx_version, rec.platform, rec.arch
    );
    for d in &rec.dependencies {
        out.push_str(&format!(
            "\n[[dependency]]\nname = \"{}\"\nsource = \"{}\"\nversion = \"{}\"\nsha256 = \"{}\"\n",
            d.name, d.source, d.version, d.sha256
        ));
    }
    for f in &rec.files {
        out.push_str(&format!(
            "\n[[file]]\npath = \"{}\"\nsha256_after = \"{}\"\nbackup = \"{}\"\n",
            f.path, f.sha256_after, f.backup
        ));
    }
    for s in &rec.services {
        out.push_str(&format!("\n[[service]]\nname = \"{s}\"\n"));
    }
    out
}

fn save(dir: &Path, rec: &Record) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(io_err)?;
    atomic_write(&record_path(dir), render(rec).as_bytes(), true)
}

fn update(dir: &Path, f: impl FnOnce(&mut Record)) -> Result<()> {
    let mut rec = load(dir)?.unwrap_or_default();
    f(&mut rec);
    save(dir, &rec)
}

/// Fills record identity once. Safe to call on every managed run.
pub fn stamp(dir: &Path) -> Result<()> {
    update(dir, |rec| {
        if rec.ratriyx_version.is_empty() {
            rec.ratriyx_version = env!("CARGO_PKG_VERSION").to_string();
        }
        if rec.platform.is_empty() {
            rec.platform = crate::infrastructure::platform::detect().os;
        }
        if rec.arch.is_empty() {
            rec.arch = std::env::consts::ARCH.to_string();
        }
    })
}

/// Records a dependency Ratriyx installed. Never records pre-existing tools.
pub fn record_dependency(
    dir: &Path,
    name: &str,
    source: &str,
    version: &str,
    sha256: &str,
) -> Result<()> {
    let dep = Dependency {
        name: name.to_string(),
        source: source.to_string(),
        version: version.to_string(),
        sha256: sha256.to_string(),
    };
    update(dir, |rec| {
        rec.dependencies.retain(|d| d.name != dep.name);
        rec.dependencies.push(dep.clone());
    })
}

/// Records a config file Ratriyx just edited, with the backup that restores it.
pub fn record_file(dir: &Path, path: &Path, sha256_after: &str, backup: &Path) -> Result<()> {
    update(dir, |rec| {
        rec.files.retain(|f| f.path != path.display().to_string());
        rec.files.push(ManagedFile {
            path: path.display().to_string(),
            sha256_after: sha256_after.to_string(),
            backup: backup.display().to_string(),
        });
    })
}

/// Forget a dependency only after its uninstall has completed.
/// Keep other dependencies and the ownership record for safe retries.
#[cfg(any(windows, test))]
pub fn forget_dependency(dir: &Path, name: &str, created_file: &Path) -> Result<()> {
    let Some(_) = load(dir)? else {
        return Err(Error::Config("no managed ownership record found".into()));
    };
    let recorded_file = created_file.display().to_string();
    update(dir, |rec| {
        rec.dependencies.retain(|dep| dep.name != name);
        rec.files.retain(|file| file.path != recorded_file);
    })
}

/// Records a service Ratriyx started. Never records a service it did not start.
#[cfg(test)]
pub fn record_service(dir: &Path, unit: &str) -> Result<()> {
    update(dir, |rec| {
        if !rec.services.iter().any(|s| s == unit) {
            rec.services.push(unit.to_string());
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ratriyx-managed-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn missing_record_means_nothing_managed() {
        assert!(load(&dir("missing")).unwrap().is_none());
    }

    #[test]
    fn record_round_trips_and_replaces_same_path() {
        let d = dir("roundtrip");
        let target = d.join("privoxy.conf");
        record_file(&d, &target, "aaa", &d.join("bak-1")).unwrap();
        record_file(&d, &target, "bbb", &d.join("bak-2")).unwrap();
        record_service(&d, "tor@default").unwrap();
        record_service(&d, "tor@default").unwrap();
        let rec = load(&d).unwrap().unwrap();
        assert_eq!(rec.files.len(), 1);
        assert_eq!(rec.files[0].sha256_after, "bbb");
        assert_eq!(rec.services, vec!["tor@default".to_string()]);
    }

    #[test]
    fn forgetting_one_dependency_preserves_the_other() {
        let dir = dir("forget-one");
        let torrc = dir.join("torrc");
        let proxy = dir.join("privoxy.conf");
        record_dependency(
            &dir,
            "tor",
            "official-download:tor-expert-bundle",
            "15.0.25",
            "abc",
        )
        .unwrap();
        record_dependency(
            &dir,
            "privoxy",
            "winget:Privoxy.Privoxy",
            "unknown",
            "package-manager",
        )
        .unwrap();
        record_file(&dir, &torrc, "", Path::new("")).unwrap();
        record_file(&dir, &proxy, "", Path::new("")).unwrap();
        forget_dependency(&dir, "tor", &torrc).unwrap();
        let rec = load(&dir).unwrap().unwrap();
        assert_eq!(rec.dependencies.len(), 1);
        assert_eq!(rec.dependencies[0].name, "privoxy");
        assert_eq!(rec.files.len(), 1);
        assert_eq!(rec.files[0].path, proxy.display().to_string());
    }

    #[test]
    fn corrupt_and_versionless_records_stop_the_caller() {
        let d = dir("corrupt");
        fs::write(record_path(&d), "nonsense without equals\n").unwrap();
        assert!(load(&d).is_err());
        fs::write(record_path(&d), "ratriyx_version = \"0.2.0\"\n").unwrap();
        assert!(load(&d).is_err());
        fs::write(record_path(&d), "version = 99\n").unwrap();
        assert!(load(&d).is_err());
    }
}
