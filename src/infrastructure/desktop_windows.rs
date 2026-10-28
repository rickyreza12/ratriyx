//! Opt-in WinINet current-user system proxy with a durable rollback snapshot.
//! WinHTTP, UDP, DNS, running processes and applications that ignore the OS
//! setting remain outside the scope of this integration.
use crate::domain::error::{Error, Result};
use crate::infrastructure::fsutil::io_err;
use crate::infrastructure::shell;
use std::fs;
use std::io::Write;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
};

const INTERNET_SETTINGS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const BACKUP_NAME: &str = "desktop-wininet.snapshot";
const NAMES: [&str; 3] = ["ProxyEnable", "ProxyServer", "ProxyOverride"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Value {
    typ: u32,
    data: Vec<u8>,
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn winerr(label: &str, code: u32) -> Error {
    Error::Io(format!("Windows proxy {label} returned error 0x{code:08X}"))
}

struct Key(HKEY);
impl Key {
    fn open() -> Result<Self> {
        let mut key = null_mut();
        // SAFETY: HKCU is valid, the UTF-16 path is NUL-terminated, and the output handle is writable.
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wide(INTERNET_SETTINGS).as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut key,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(winerr("open HKCU Internet Settings", code));
        }
        Ok(Self(key))
    }

    fn get(&self, name: &str) -> Result<Option<Value>> {
        let label = wide(name);
        let mut typ = 0;
        let mut size = 0;
        // SAFETY: valid registry key and NUL-terminated value name.
        let code = unsafe {
            RegQueryValueExW(
                self.0,
                label.as_ptr(),
                null(),
                &mut typ,
                null_mut(),
                &mut size,
            )
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if code != ERROR_SUCCESS {
            return Err(winerr("read value size", code));
        }
        if size > 65536 {
            return Err(Error::Config(
                "Windows proxy registry value exceeds maximum snapshot size".into(),
            ));
        }
        let mut data = vec![0u8; size as usize];
        let code = unsafe {
            RegQueryValueExW(
                self.0,
                label.as_ptr(),
                null(),
                &mut typ,
                data.as_mut_ptr(),
                &mut size,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(winerr("read value", code));
        }
        data.truncate(size as usize);
        Ok(Some(Value { typ, data }))
    }

    fn put(&self, name: &str, value: Option<&Value>) -> Result<()> {
        let label = wide(name);
        let code = match value {
            // SAFETY: buffers remain valid throughout the synchronous registry call.
            Some(v) => unsafe {
                RegSetValueExW(
                    self.0,
                    label.as_ptr(),
                    0,
                    v.typ,
                    v.data.as_ptr(),
                    v.data.len() as u32,
                )
            },
            // SAFETY: the registry key and value label are valid.
            None => unsafe { RegDeleteValueW(self.0, label.as_ptr()) },
        };
        if code == ERROR_SUCCESS || (value.is_none() && code == ERROR_FILE_NOT_FOUND) {
            Ok(())
        } else {
            Err(winerr("write value", code))
        }
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: handle came from successful RegOpenKeyExW.
        unsafe { RegCloseKey(self.0) };
    }
}

fn dword(value: u32) -> Value {
    Value {
        typ: REG_DWORD,
        data: value.to_le_bytes().to_vec(),
    }
}

fn string(value: &str) -> Value {
    let data = wide(value).iter().flat_map(|c| c.to_le_bytes()).collect();
    Value { typ: REG_SZ, data }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|v| format!("{v:02x}")).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.len() > 131072 {
        return Err(Error::Config("invalid WinINet backup hex length".into()));
    }
    // Even length is validated above; the remainder from as_chunks is empty.
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair)
                .map_err(|_| Error::Config("invalid backup encoding".into()))?;
            u8::from_str_radix(pair, 16).map_err(|_| Error::Config("invalid backup hex".into()))
        })
        .collect()
}

fn encode(values: &[Option<Value>; 3], port: u16) -> String {
    let mut result = format!("RATRIYX-WININET-V1\nPORT {port}\n");
    for (name, value) in NAMES.iter().zip(values.iter()) {
        match value {
            Some(v) => result.push_str(&format!("{name} {} {}\n", v.typ, hex(&v.data))),
            None => result.push_str(&format!("{name} - -\n")),
        }
    }
    result
}

fn decode(text: &str) -> Result<([Option<Value>; 3], u16)> {
    let mut lines = text.lines();
    if lines.next() != Some("RATRIYX-WININET-V1") {
        return Err(Error::Config(
            "unknown Windows proxy snapshot format".into(),
        ));
    }
    let port: u16 = lines
        .next()
        .and_then(|v| v.strip_prefix("PORT "))
        .and_then(|v| v.parse().ok())
        .filter(|v| *v != 0)
        .ok_or_else(|| Error::Config("invalid Windows proxy snapshot port".into()))?;
    let mut values: [Option<Value>; 3] = [None, None, None];
    for (name, slot) in NAMES.iter().zip(values.iter_mut()) {
        let line = lines
            .next()
            .ok_or_else(|| Error::Config("incomplete proxy snapshot".into()))?;
        let pieces: Vec<&str> = line.split(' ').collect();
        if pieces.len() != 3 || pieces[0] != *name {
            return Err(Error::Config("corrupt proxy snapshot value".into()));
        }
        if pieces[1] != "-" {
            let typ = pieces[1]
                .parse::<u32>()
                .map_err(|_| Error::Config("corrupt proxy snapshot type".into()))?;
            *slot = Some(Value {
                typ,
                data: from_hex(pieces[2])?,
            });
        }
    }
    if lines.next().is_some() {
        return Err(Error::Config("unexpected proxy snapshot content".into()));
    }
    Ok((values, port))
}

fn notify() {
    // SAFETY: WinINet option notifications take a null global session handle.
    unsafe {
        InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null_mut(), 0);
        InternetSetOptionW(null_mut(), INTERNET_OPTION_REFRESH, null_mut(), 0);
    }
}

fn backup_path() -> Result<std::path::PathBuf> {
    Ok(shell::require_state_dir()?.join(BACKUP_NAME))
}

pub fn enable(port: u16) -> Result<String> {
    let path = backup_path()?;
    if path.exists() {
        return Err(Error::Config("Ratriyx Windows proxy snapshot already exists. Run desktop off --target windows before enabling again.".into()));
    }
    let key = Key::open()?;
    let originals = [key.get(NAMES[0])?, key.get(NAMES[1])?, key.get(NAMES[2])?];
    if key.get("AutoConfigURL")?.is_some() {
        return Err(Error::Config("An existing Windows proxy auto-config URL is present; refusing to replace the current network policy".into()));
    }
    if originals[0]
        .as_ref()
        .is_some_and(|v| v.typ == REG_DWORD && v.data == 1u32.to_le_bytes())
    {
        return Err(Error::Config(
            "An existing Windows user proxy is already enabled; refusing to overwrite it".into(),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_err)?;
    }
    // Reserve the snapshot before any registry changes, so rollback survives crashes.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(io_err)?;
    file.write_all(encode(&originals, port).as_bytes())
        .map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    drop(file);
    let result = (|| -> Result<()> {
        key.put("ProxyServer", Some(&string(&format!("127.0.0.1:{port}"))))?;
        key.put(
            "ProxyOverride",
            Some(&string("<local>;localhost;127.0.0.1;[::1]")),
        )?;
        key.put("ProxyEnable", Some(&dword(1)))?;
        Ok(())
    })();
    if let Err(error) = result {
        for (name, old) in NAMES.iter().zip(originals.iter()) {
            let _ = key.put(name, old.as_ref());
        }
        notify();
        return Err(error);
    }
    notify();
    Ok(format!("Windows current-user system proxy enabled on 127.0.0.1:{port}; run desktop off --target windows --yes to restore"))
}

pub fn disable() -> Result<String> {
    let path = backup_path()?;
    let data = fs::read_to_string(&path)
        .map_err(|_| Error::Config("No Windows system-proxy snapshot to restore".into()))?;
    let (originals, port) = decode(&data)?;
    let key = Key::open()?;
    if key.get("ProxyServer")? != Some(string(&format!("127.0.0.1:{port}")))
        || key.get("ProxyEnable")? != Some(dword(1))
    {
        return Err(Error::Config("Windows proxy values were changed externally; refusing to overwrite them. Restore manually using the saved snapshot.".into()));
    }
    for (name, old) in NAMES.iter().zip(originals.iter()) {
        key.put(name, old.as_ref())?;
    }
    notify();
    fs::remove_file(&path).map_err(io_err)?;
    Ok("Windows current-user proxy settings restored from the Ratriyx snapshot".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_backup_round_trip_preserves_missing_and_binary_values() {
        let before = [Some(dword(0)), None, Some(string("*.internal;<local>"))];
        let (after, port) = decode(&encode(&before, 8119)).unwrap();
        assert_eq!((after, port), (before, 8119));
    }
    #[test]
    fn corrupted_backup_is_rejected_without_mutations() {
        assert!(decode("unexpected contents").is_err());
        assert!(decode("RATRIYX-WININET-V1\nPORT 8119\nProxyEnable 4 BAD\n").is_err());
    }
}
