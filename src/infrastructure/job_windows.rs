//! Windows Job Object lifecycle for child cleanup and future strict launch.
//!
//! Ordinary launches attach a child after spawning it. This ensures Windows
//! closes its job descendants if Ratriyx exits, but is not a network guard.
//! JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ensures the kernel terminates job members
//! when the final handle closes. It does NOT enforce proxy routing by itself.
//!
//! Strict launch still needs suspended creation and OS network enforcement.
use crate::domain::error::{Error, Result};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::ptr::null;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

pub struct WindowsJob {
    handle: HANDLE,
    _not_send: PhantomData<*mut ()>,
}

impl WindowsJob {
    fn new_empty() -> Result<Self> {
        // SAFETY: anonymous job; no security attributes, no existing name.
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(last_error("CreateJobObjectW"));
        }
        let object = Self {
            handle,
            _not_send: PhantomData,
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: configured struct is fully initialized and valid.
        let ok = unsafe {
            SetInformationJobObject(
                object.handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(last_error("SetInformationJobObject"));
        }
        Ok(object)
    }

    pub fn attach(child: &Child) -> Result<Self> {
        let job = Self::new_empty()?;
        // SAFETY: The Rust Child owns a live Windows process HANDLE. The job
        // owns an anonymous kernel handle configured with kill-on-close.
        let ok = unsafe { AssignProcessToJobObject(job.handle, child.as_raw_handle() as HANDLE) };
        if ok == 0 {
            return Err(last_error("AssignProcessToJobObject"));
        }
        Ok(job)
    }
}

impl Drop for WindowsJob {
    fn drop(&mut self) {
        // SAFETY: handle returned by successful CreateJobObjectW. The caller
        // holds the handle until the routed child exits or the parent closes.
        unsafe { CloseHandle(self.handle) };
    }
}

fn last_error(operation: &str) -> Error {
    // SAFETY: reads the thread-local last error immediately after API failure.
    let code = unsafe { GetLastError() };
    Error::Unsupported(format!("Windows Job Object {operation} failed: {code}"))
}

/// Creates an EMPTY temporary job, configures kill-on-close, then destroys it.
/// This preflight starts or stops no other process.
pub fn preflight() -> Result<&'static str> {
    let _empty = WindowsJob::new_empty()?;
    Ok("Windows kill-on-close Job Object is available (empty probe only)")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_job_configures_and_drops_without_processes() {
        // Only creates a kernel job object that has never had any processes.
        let job = WindowsJob::new_empty().expect("Windows job object is available");
        drop(job);
    }
}
