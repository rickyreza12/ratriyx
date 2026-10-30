//! Read-only WFP preflight and transaction-safe filter primitives.
//!
//! Windows WFP ALE_APP_ID identifies an executable, NOT a process tree.
//! Filtering opencode executable alone does not protect Node/Bun/plugins and
//! could interfere with unrelated sessions of the same executable.
//! No WFP filtering policy is installed by this module yet.
//!
//! Strict mode must keep refusing to launch until proper OS isolation exists.

use crate::domain::error::{Error, Result};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT16,
    FWP_UINT32, FWP_UINT8, FWP_VALUE0, FWP_VALUE0_0 as WfpWeightValue,
};
use windows_sys::Win32::System::Rpc::{UuidCreate, RPC_C_AUTHN_WINNT};

/// Ephemeral engine session for WFP. Resources owned by the session will be
/// dropped when the handle is closed, even on abrupt process termination.
/// The preflight does NOT create filters or modify network policy.
pub(super) struct DynamicWfpSession {
    handle: HANDLE,
    _not_send: PhantomData<*mut ()>,
}

impl DynamicWfpSession {
    pub(super) fn open() -> Result<Self> {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut handle: HANDLE = null_mut();
        // SAFETY: valid stack session, null server/authidentity, and writable
        // output pointer. WFP fills handle when the return code is success.
        let result =
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle) };
        if result != 0 {
            return Err(Error::Unsupported(format!(
                "cannot open Windows WFP dynamic session (0x{result:08X}); no rules created"
            )));
        }
        if handle.is_null() {
            return Err(Error::Unsupported(
                "WFP returned a null engine handle; no rules created".into(),
            ));
        }
        Ok(Self {
            handle,
            _not_send: PhantomData,
        })
    }

    /// Experimental policy compiler, NOT safe to call against OpenCode.
    ///
    /// An ALE_APP_ID policy impacts every instance of the executable,
    /// not just the process Ratriyx launches. It cannot protect descendants.
    /// The method is private and is never called by the public CLI or tests.
    ///
    /// Temporary policy:
    /// - IPv4: permit this app TCP to 127.0.0.1:proxy_port, deny all else.
    /// - IPv6: deny all outgoing connections from this app (IPv6 proxy is absent).
    /// - Underlying proxy/Tor must use a DIFFERENT executable identity.
    /// - DNS/service traffic originating in OTHER processes is not covered.
    #[allow(dead_code)]
    fn install_lab_policy_for_executable(&self, executable: &Path, proxy_port: u16) -> Result<()> {
        if proxy_port == 0 {
            return Err(Error::Config("WFP lab proxy port must not be zero".into()));
        }
        let absolute = executable.canonicalize().map_err(|err| {
            Error::Config(format!("WFP lab executable cannot be resolved: {err}"))
        })?;
        if !absolute.is_file() {
            return Err(Error::Config("WFP lab executable is not a file".into()));
        }
        let mut exe: Vec<u16> = absolute.as_os_str().encode_wide().collect();
        exe.push(0);
        let mut raw_blob = null_mut();
        // SAFETY: NUL-terminated native path; FwpmFreeMemory0 owns returned allocation.
        let code = unsafe { FwpmGetAppIdFromFileName0(exe.as_ptr(), &mut raw_blob) };
        wfp_status("get application identity", code)?;
        if raw_blob.is_null() {
            return Err(Error::Unsupported(
                "WFP application identity was null".into(),
            ));
        }
        let _owned_blob = WfpBlob(raw_blob);

        let mut key = GUID::from_u128(0);
        // SAFETY: GUID buffer writable. Local-only UUID result is also unique.
        let uuid_code = unsafe { UuidCreate(&mut key) };
        if uuid_code != 0 && uuid_code != 1824 {
            return Err(Error::Unsupported(format!(
                "WFP UUID error 0x{uuid_code:08X}"
            )));
        }

        let mut name: Vec<u16> = "Ratriyx isolated lab executable".encode_utf16().collect();
        name.push(0);
        let layer = FWPM_SUBLAYER0 {
            subLayerKey: key,
            displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                ..Default::default()
            },
            weight: 0x7fff,
            ..Default::default()
        };
        // SAFETY: session handle is valid; transaction is bound to this handle.
        wfp_status("begin lab transaction", unsafe {
            FwpmTransactionBegin0(self.handle, 0)
        })?;
        let result = (|| -> Result<()> {
            // SAFETY: valid transient WFP sublayer and session.
            wfp_status("add lab sublayer", unsafe {
                FwpmSubLayerAdd0(self.handle, &layer, null_mut())
            })?;

            let app = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: raw_blob },
                },
            };
            let address = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint32: 0x7f00_0001,
                    },
                },
            };
            let port = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: proxy_port },
                },
            };
            let protocol = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 6 }, // TCP
                },
            };
            // Within this sublayer the permitted proxy rule has higher weight.
            add_lab_filter(
                self.handle,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                key,
                &mut [app, address, port, protocol],
                FWP_ACTION_PERMIT,
                2,
            )?;
            add_lab_filter(
                self.handle,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                key,
                &mut [app],
                FWP_ACTION_BLOCK,
                1,
            )?;
            add_lab_filter(
                self.handle,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                key,
                &mut [app],
                FWP_ACTION_BLOCK,
                1,
            )?;
            // SAFETY: commit only the current WFP transaction.
            wfp_status("commit lab transaction", unsafe {
                FwpmTransactionCommit0(self.handle)
            })
        })();
        if result.is_err() {
            // SAFETY: abort only our transaction; ignored when commit already failed.
            unsafe { FwpmTransactionAbort0(self.handle) };
        }
        result
    }
}

impl Drop for DynamicWfpSession {
    fn drop(&mut self) {
        // SAFETY: handle came from successful FwpmEngineOpen0.
        unsafe { FwpmEngineClose0(self.handle) };
    }
}

#[allow(dead_code)]
fn wfp_status(label: &str, status: u32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Unsupported(format!(
            "Windows WFP {label} failed: 0x{status:08X}; no strict protection active"
        )))
    }
}

#[allow(dead_code)]
fn add_lab_filter(
    handle: HANDLE,
    layer: GUID,
    sublayer: GUID,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    action: u32,
    weight: u8,
) -> Result<()> {
    let filter = FWPM_FILTER0 {
        layerKey: layer,
        subLayerKey: sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: WfpWeightValue { uint8: weight },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0 {
            r#type: action,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: condition slices and all inner pointers remain alive throughout call.
    wfp_status("add lab filter", unsafe {
        FwpmFilterAdd0(handle, &filter, null_mut(), null_mut())
    })
}

struct WfpBlob(*mut FWP_BYTE_BLOB);
impl Drop for WfpBlob {
    fn drop(&mut self) {
        let mut pointer: *mut c_void = self.0.cast();
        // SAFETY: WFP allocated this pointer in FwpmGetAppIdFromFileName0.
        unsafe { FwpmFreeMemory0(&mut pointer) };
    }
}

/// Read-only availability probe; opening and closing a dynamic session
/// does not prove firewall privileges or application routing enforcement.
pub fn preflight() -> Result<&'static str> {
    let _handle = DynamicWfpSession::open()?;
    Ok("WFP engine reachable; no filters installed; strict enforcement remains unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_lab_rules_are_never_exposed_as_strict_enforcement() {
        // No session opened, no firewall mutation; type-level availability only.
        let _ = DynamicWfpSession::install_lab_policy_for_executable;
        assert!(crate::infrastructure::strict_guard::acquire("opencode").is_err());
    }
}
