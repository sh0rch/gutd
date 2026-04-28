//! Windows-only: WFP (Windows Filtering Platform) PERMIT-bypass for gutd.exe.
//!
//! Rationale: WireGuard for Windows (and other VPN clients) installs WFP
//! filters that block any non-tunnel traffic once the tunnel is up. A host
//! route to the obfuscator peer is *not* enough on its own, because WFP
//! runs at ALE layer and drops packets regardless of routing table. We
//! solve this WITHOUT touching the user's wg profile by adding our own
//! PERMIT filter scoped to `gutd.exe` via the `ALE_APP_ID` condition.
//!
//! Design:
//!   - Elevation check up-front: hard-exit if the process is not running
//!     as Administrator (WFP APIs require it).
//!   - Dynamic FWPM session (`FWPM_SESSION_FLAG_DYNAMIC`) — filters are
//!     auto-purged by the kernel when the process dies. No reboot-persistent
//!     garbage if gutd crashes.
//!   - Own sublayer with `weight = 0xFFFF`, so our PERMIT beats the wg
//!     sublayer's BLOCK. (WFP arbitration: highest sublayer weight wins,
//!     then highest filter weight inside the sublayer.)
//!   - Filters installed on four ALE layers:
//!       FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6       (outbound connect)
//!       FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4/V6 (bind)
//!   - Watchdog thread verifies filter presence every 15 s. If the engine
//!     handle is gone or the filter ID disappeared (wg reinstall, BFE
//!     restart, policy refresh) we rebuild from scratch with backoff.
//!     After MAX_FAILURES consecutive failures we exit so SCM restarts us.
//!
//! Privileges: requires Administrator + the BFE service to be running.

#![cfg(target_os = "windows")]
#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// ─── WFP constants and GUIDs (manual, since windows-sys 0.59 does not
//     re-export all of them reliably across feature sets) ───

const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x00000001;
const RPC_C_AUTHN_WINNT: u32 = 10;

const FWP_ACTION_PERMIT: u32 = 0x00001001;
const FWP_EMPTY: u32 = 0;
const FWP_BYTE_BLOB_TYPE: u32 = 1;

const FWP_MATCH_EQUAL: u32 = 0;

const FWPM_FILTER_FLAG_PERSISTENT: u32 = 0x00000002;

// Well-known layer GUIDs. Source: fwpmu.h / fwpmtypes.h in the Windows SDK.
// ALE_AUTH_CONNECT: outbound connection authorization (per-app).
const FWPM_LAYER_ALE_AUTH_CONNECT_V4: GUID = GUID {
    data1: 0xc38d5738,
    data2: 0x2f79,
    data3: 0x4439,
    data4: [0xb2, 0x9d, 0x3a, 0x1a, 0xa0, 0xc6, 0xf6, 0xc4],
};
const FWPM_LAYER_ALE_AUTH_CONNECT_V6: GUID = GUID {
    data1: 0x4a72393b,
    data2: 0x319f,
    data3: 0x44bc,
    data4: [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
};
// ALE_RESOURCE_ASSIGNMENT: bind authorization (needed for UDP sockets
// that bind to a physical uplink's source IP).
const FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4: GUID = GUID {
    data1: 0x1247d66d,
    data2: 0x0b60,
    data3: 0x4a15,
    data4: [0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c],
};
const FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6: GUID = GUID {
    data1: 0x55a650e1,
    data2: 0x5f0a,
    data3: 0x4eca,
    data4: [0xa6, 0x53, 0x88, 0xf5, 0x3b, 0x26, 0xaa, 0x8c],
};
// Condition: ALE_APP_ID = path to our executable (as NT device path).
const FWPM_CONDITION_ALE_APP_ID: GUID = GUID {
    data1: 0xd78e1e87,
    data2: 0x8644,
    data3: 0x4ea5,
    data4: [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71],
};

// Our private sublayer — a random v4 GUID generated once and hard-coded so
// we can look it up across restarts (in case a stale sublayer ever leaks).
const GUTD_SUBLAYER_KEY: GUID = GUID {
    data1: 0x4a8f3c2e,
    data2: 0x1b91,
    data3: 0x4e21,
    data4: [0xa7, 0x3d, 0x62, 0xf4, 0x9c, 0x05, 0x8b, 0x11],
};

// FWPM API — forward decls. windows-sys' `WindowsFilteringPlatform` feature
// gates these; feature name matches the module path we enabled in Cargo.toml.
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFilterGetById0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FWPM_ACTION0, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_SESSION0,
    FWPM_SUBLAYER0, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_VALUE0,
};

// ─── public API ─────────────────────────────────────────────────────────

/// Install a watchdog-backed WFP PERMIT-bypass for the current process.
///
/// On first successful install the returned `WfpBypass` owns the engine
/// session and keeps the watchdog alive. Dropping it tears everything down.
pub struct WfpBypass {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Drop for WfpBypass {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

/// Bail out with a friendly message if we are not running elevated.
///
/// Exits the process on failure — there is no graceful fallback: without
/// Admin we can neither add the host route nor the WFP filter, so running
/// on would just waste the user's time.
pub fn ensure_admin() {
    if is_elevated() {
        return;
    }
    eprintln!("gutd: ERROR — this build requires Administrator privileges on Windows.");
    eprintln!("gutd: Right-click the service / console and choose \"Run as administrator\".");
    eprintln!("gutd: (needed for host-route pinning and WFP bypass around WireGuard.)");
    std::process::exit(1);
}

/// Install the WFP bypass and keep it healthy in a background thread.
///
/// Returns `Err` if the initial install could not complete — caller decides
/// whether to abort startup (recommended when wg profile has AllowedIPs =
/// 0.0.0.0/0, otherwise gutd's UDP is guaranteed to be dropped by WFP).
pub fn install_for_self() -> Result<WfpBypass, String> {
    // First install synchronously so we can surface errors to startup.
    let state = install_once()?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_cl = stop.clone();
    let worker = thread::Builder::new()
        .name("gutd-wfp-watchdog".into())
        .spawn(move || watchdog_loop(state, stop_cl))
        .map_err(|e| format!("spawn watchdog: {e}"))?;

    Ok(WfpBypass {
        stop,
        worker: Some(worker),
    })
}

// ─── internals ──────────────────────────────────────────────────────────

const WATCHDOG_INTERVAL: Duration = Duration::from_secs(15);
const MAX_CONSECUTIVE_FAILURES: u32 = 20; // ~5 min of failed recovery

struct InstallState {
    /// Engine handle (owned). NOT Send across threads directly because the
    /// watchdog thread reinstalls on failure; we wrap in a Mutex inside
    /// `watchdog_loop` instead of holding it here.
    engine: HANDLE,
    filter_ids: Vec<u64>,
}

// Engine HANDLE is `isize` (pointer). Safety: we only touch it from the
// watchdog thread after ownership is moved into the closure.
unsafe impl Send for InstallState {}

fn watchdog_loop(initial: InstallState, stop: Arc<AtomicBool>) {
    let mut state = initial;
    let mut failures: u32 = 0;

    while !stop.load(Ordering::Relaxed) {
        thread::sleep(WATCHDOG_INTERVAL);
        if stop.load(Ordering::Relaxed) {
            break;
        }

        match verify(&state) {
            Ok(true) => {
                failures = 0;
            }
            Ok(false) | Err(_) => {
                // Teardown whatever is left and try again.
                teardown(&mut state);
                match install_once() {
                    Ok(new_state) => {
                        eprintln!("gutd: WFP filter re-installed after loss");
                        state = new_state;
                        failures = 0;
                    }
                    Err(e) => {
                        failures += 1;
                        eprintln!(
                            "gutd: WFP re-install failed ({}/{}): {}",
                            failures, MAX_CONSECUTIVE_FAILURES, e
                        );
                        if failures >= MAX_CONSECUTIVE_FAILURES {
                            eprintln!(
                                "gutd: WFP watchdog giving up; exiting so service manager \
                                 can restart the process."
                            );
                            // Exit with non-zero so SCM / systemd notices.
                            std::process::exit(2);
                        }
                    }
                }
            }
        }
    }

    // Normal shutdown path.
    teardown(&mut state);
}

fn verify(state: &InstallState) -> Result<bool, u32> {
    if state.engine.is_null() || state.engine == INVALID_HANDLE_VALUE {
        return Ok(false);
    }
    for &fid in &state.filter_ids {
        let mut out: *mut FWPM_FILTER0 = std::ptr::null_mut();
        let rc = unsafe { FwpmFilterGetById0(state.engine, fid, &mut out) };
        if !out.is_null() {
            unsafe { FwpmFreeMemory0(&mut (out as *mut _ as *mut _)) };
        }
        if rc != ERROR_SUCCESS {
            return Ok(false);
        }
    }
    Ok(true)
}

fn teardown(state: &mut InstallState) {
    if !state.engine.is_null() && state.engine != INVALID_HANDLE_VALUE {
        for &fid in &state.filter_ids {
            unsafe { FwpmFilterDeleteById0(state.engine, fid) };
        }
        unsafe { FwpmSubLayerDeleteByKey0(state.engine, &GUTD_SUBLAYER_KEY) };
        unsafe { FwpmEngineClose0(state.engine) };
    }
    state.engine = std::ptr::null_mut();
    state.filter_ids.clear();
}

fn install_once() -> Result<InstallState, String> {
    let exe_path_w = current_exe_path_w()?;
    let engine = open_engine()?;

    // Wrap in a guard: if anything below fails we must close the engine.
    let mut state = InstallState {
        engine,
        filter_ids: Vec::new(),
    };

    if let Err(e) = add_sublayer(engine) {
        teardown(&mut state);
        return Err(e);
    }

    // Resolve NT-path AppId blob from the Win32 exe path.
    let mut app_id_blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let rc = unsafe { FwpmGetAppIdFromFileName0(exe_path_w.as_ptr(), &mut app_id_blob) };
    if rc != ERROR_SUCCESS || app_id_blob.is_null() {
        teardown(&mut state);
        return Err(format!("FwpmGetAppIdFromFileName0 rc=0x{:08X}", rc));
    }

    let layers = [
        ("ALE_AUTH_CONNECT_V4", FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        ("ALE_AUTH_CONNECT_V6", FWPM_LAYER_ALE_AUTH_CONNECT_V6),
        (
            "ALE_RESOURCE_ASSIGNMENT_V4",
            FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        ),
        (
            "ALE_RESOURCE_ASSIGNMENT_V6",
            FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        ),
    ];

    for (name, layer_key) in layers.iter() {
        match add_permit_filter(engine, layer_key, app_id_blob, name) {
            Ok(id) => state.filter_ids.push(id),
            Err(e) => {
                unsafe { FwpmFreeMemory0(&mut (app_id_blob as *mut _ as *mut _)) };
                teardown(&mut state);
                return Err(format!("filter add on {}: {}", name, e));
            }
        }
    }

    unsafe { FwpmFreeMemory0(&mut (app_id_blob as *mut _ as *mut _)) };

    eprintln!(
        "gutd: WFP bypass installed for gutd.exe ({} filters across 4 ALE layers)",
        state.filter_ids.len()
    );
    Ok(state)
}

fn open_engine() -> Result<HANDLE, String> {
    let session: FWPM_SESSION0 = FWPM_SESSION0 {
        sessionKey: GUID {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        },
        displayData: FWPM_DISPLAY_DATA0 {
            name: std::ptr::null_mut(),
            description: std::ptr::null_mut(),
        },
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        txnWaitTimeoutInMSec: 0,
        processId: 0,
        sid: std::ptr::null_mut(),
        username: std::ptr::null_mut(),
        kernelMode: 0,
    };

    let mut engine: HANDLE = std::ptr::null_mut();
    let rc = unsafe {
        FwpmEngineOpen0(
            std::ptr::null(), // local machine
            RPC_C_AUTHN_WINNT,
            std::ptr::null_mut(),
            &session,
            &mut engine,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!(
            "FwpmEngineOpen0 rc=0x{:08X} (BFE service running? Admin?)",
            rc
        ));
    }
    Ok(engine)
}

fn add_sublayer(engine: HANDLE) -> Result<(), String> {
    let mut name_w: Vec<u16> = "gutd bypass"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut desc_w: Vec<u16> = "gutd WFP permit for self"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let sub = FWPM_SUBLAYER0 {
        subLayerKey: GUTD_SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name_w.as_mut_ptr(),
            description: desc_w.as_mut_ptr(),
        },
        flags: 0,
        providerKey: std::ptr::null_mut(),
        providerData: FWP_BYTE_BLOB {
            size: 0,
            data: std::ptr::null_mut(),
        },
        weight: 0xFFFF,
    };

    let rc = unsafe { FwpmSubLayerAdd0(engine, &sub, std::ptr::null_mut()) };
    // Ignore "already exists" — we reuse it.
    const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;
    if rc != ERROR_SUCCESS && rc != FWP_E_ALREADY_EXISTS {
        return Err(format!("FwpmSubLayerAdd0 rc=0x{:08X}", rc));
    }
    Ok(())
}

fn add_permit_filter(
    engine: HANDLE,
    layer: &GUID,
    app_id: *mut FWP_BYTE_BLOB,
    layer_name: &str,
) -> Result<u64, String> {
    let mut name_w: Vec<u16> = format!("gutd permit {}", layer_name)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL as i32,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE as i32,
            Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
        },
    };

    let action = FWPM_ACTION0 {
        r#type: FWP_ACTION_PERMIT as u32,
        Anonymous: unsafe { std::mem::zeroed() },
    };

    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.displayData.name = name_w.as_mut_ptr();
    filter.displayData.description = std::ptr::null_mut();
    filter.layerKey = *layer;
    filter.subLayerKey = GUTD_SUBLAYER_KEY;
    filter.weight = FWP_VALUE0 {
        r#type: FWP_EMPTY as i32,
        Anonymous: unsafe { std::mem::zeroed() },
    };
    filter.numFilterConditions = 1;
    filter.filterCondition = &mut cond;
    filter.action = action;
    // No FWPM_FILTER_FLAG_PERSISTENT — dynamic session cleans us up.
    filter.flags = 0;
    let _ = FWPM_FILTER_FLAG_PERSISTENT; // silence unused-const in some configs

    let mut fid: u64 = 0;
    let rc = unsafe { FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid) };
    if rc != ERROR_SUCCESS {
        return Err(format!("FwpmFilterAdd0 rc=0x{:08X}", rc));
    }
    Ok(fid)
}

// ─── helpers ───────────────────────────────────────────────────────────

fn current_exe_path_w() -> Result<Vec<u16>, String> {
    let mut buf = vec![0u16; 1024];
    loop {
        let n =
            unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return Err(format!("GetModuleFileNameW failed, err={}", unsafe {
                GetLastError()
            }));
        }
        if (n as usize) < buf.len() {
            buf.truncate(n as usize + 1); // keep trailing NUL
            return Ok(buf);
        }
        // Truncated; grow.
        if buf.len() >= 32 * 1024 {
            return Err("exe path longer than 32K wide chars".into());
        }
        buf.resize(buf.len() * 2, 0);
    }
}

#[allow(dead_code)]
fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    OsString::from_wide(&w[..end])
        .to_string_lossy()
        .into_owned()
}

fn is_elevated() -> bool {
    let proc_h = unsafe { GetCurrentProcess() };
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(proc_h, TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret_len: u32 = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
}
