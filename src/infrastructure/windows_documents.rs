//! Resolve the user's real Documents known folder, including OneDrive moves.
//! Building USERPROFILE\Documents is incorrect when folder redirection is on.
use crate::domain::error::{Error, Result};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use windows_sys::Win32::System::Com::{
    CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_APARTMENTTHREADED,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_Documents, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

pub fn documents_dir() -> Result<PathBuf> {
    // Initialize COM as required by Windows known-folder API. An already
    // initialized thread with another apartment model is also usable.
    let hr = unsafe { CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32) };
    const RPC_E_CHANGED_MODE: i32 = -2147417850;
    if hr < 0 && hr != RPC_E_CHANGED_MODE {
        return Err(Error::Io(format!(
            "cannot initialize COM for Windows Documents folder (0x{:08X})",
            hr as u32
        )));
    }
    struct ComGuard(bool);
    impl Drop for ComGuard {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: COM initialization succeeded on this thread.
                unsafe { CoUninitialize() };
            }
        }
    }
    let _com = ComGuard(hr >= 0);
    let mut raw: *mut u16 = null_mut();
    // SAFETY: the GUID is a static known-folder ID, the output pointer is
    // valid, and null current-user token requests the current user's folder.
    let status = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_Documents,
            KF_FLAG_DEFAULT as u32,
            null_mut(),
            &mut raw,
        )
    };
    struct Memory(*mut u16);
    impl Drop for Memory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by SHGetKnownFolderPath.
                unsafe { CoTaskMemFree(self.0.cast()) };
            }
        }
    }
    let _memory = Memory(raw);
    if status != 0 || raw.is_null() {
        return Err(Error::Io(format!(
            "Windows Documents known-folder lookup failed (0x{:08X}); refusing to guess a profile path",
            status as u32
        )));
    }
    // The Win32 API guarantees NUL termination on success. Bound the scan
    // to avoid reading an unexpectedly huge result.
    let len = (0..32768)
        .find(|&i| unsafe { *raw.add(i) == 0 })
        .ok_or_else(|| Error::Io("Windows Documents path was not terminated".into()))?;
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, len)
    }));
    if !path.is_absolute() {
        return Err(Error::Io(
            "Windows Documents known folder is not absolute".into(),
        ));
    }
    Ok(path)
}
