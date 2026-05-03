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
//!   - Persistent FWPM session (NOT dynamic). Reason: dynamic sessions can
//!     only add filters to sublayers they created themselves; a persistent
//!     session can add filters to any sublayer, including WireGuard's.
//!     On clean exit `teardown()` deletes all added filters explicitly.
//!     On crash the filters linger but are harmless (they are PERMIT-only
//!     and bounded to this exe path). On the next start `add_sublayer()`
//!     does a delete-then-recreate of our fixed-GUID sublayer to clear up.
//!   - Own sublayer with `weight = 0xFFFF`.
//!   - Additional PERMIT filters injected into EVERY existing sublayer
//!     (including WireGuard's) with filter weight = u64::MAX, so our
//!     PERMIT outranks WireGuard's `blockAll` (weight = 0) within their
//!     own sublayer. This is the reliable path: WG's BLOCK has no
//!     CLEAR_ACTION_RIGHT, so a higher-weight PERMIT in the same sublayer
//!     terminates evaluation before the BLOCK is reached.
//!   - Filters installed on four ALE layers:
//!       FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6       (outbound connect)
//!       FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4/V6 (bind)
//!     Watchdog thread verifies filter presence every 5 s. If the engine
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

const RPC_C_AUTHN_WINNT: u32 = 10;

const FWP_ACTION_PERMIT: u32 = 0x00001002; // FWP_ACTION_FLAG_TERMINATING | 0x2
const FWP_EMPTY: u32 = 0;
const FWP_UINT64: u32 = 4; // FWP_DATA_TYPE::FWP_UINT64 — used for max filter weight
const FWP_BYTE_BLOB_TYPE: u32 = 12; // FWP_DATA_TYPE::FWP_BYTE_BLOB_TYPE

const FWP_MATCH_EQUAL: u32 = 0;

// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: if our PERMIT is the first terminating
// filter to fire in its sublayer, no lower-or-equal-weight sublayer can override.
const FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: u32 = 0x00000008;

// Well-known layer GUIDs. Source: fwpmu.h / fwpmtypes.h in the Windows SDK.
// ALE_AUTH_CONNECT: outbound connection authorization (per-app).
// ALE_AUTH_RECV_ACCEPT: inbound connection / packet-receive authorization.
// ALE_RESOURCE_ASSIGNMENT: bind authorization.
const FWPM_LAYER_ALE_AUTH_CONNECT_V4: GUID = GUID {
    data1: 0xc38d57d1,
    data2: 0x05a7,
    data3: 0x4c33,
    data4: [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
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
// ALE_AUTH_RECV_ACCEPT: WireGuard also blocks inbound on these layers.
const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: GUID = GUID {
    data1: 0xe1cd9fe7,
    data2: 0xf4b5,
    data3: 0x4273,
    data4: [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
};
const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: GUID = GUID {
    data1: 0xa3b42c97,
    data2: 0x9f04,
    data3: 0x4672,
    data4: [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
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
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmSubLayerCreateEnumHandle0,
    FwpmSubLayerDeleteByKey0, FwpmSubLayerDestroyEnumHandle0, FwpmSubLayerEnum0, FWPM_ACTION0,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_SESSION0, FWPM_SUBLAYER0,
    FWP_BYTE_BLOB, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_VALUE0, FWP_VALUE0_0,
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
    // Attempt initial install; if it fails (e.g. BFE not yet ready, WG not
    // up yet) start the watchdog anyway — it will keep retrying every
    // WATCHDOG_INTERVAL until it succeeds or MAX_CONSECUTIVE_FAILURES.
    let initial = match install_once() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "gutd: WFP bypass initial install failed: {} — watchdog will retry.\n\
                 gutd: (This is normal if WireGuard is not yet running.)",
                e
            );
            // Seed the watchdog with an empty/invalid state so it retries.
            InstallState {
                engine: INVALID_HANDLE_VALUE,
                filter_ids: Vec::new(),
            }
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_cl = stop.clone();
    let worker = thread::Builder::new()
        .name("gutd-wfp-watchdog".into())
        .spawn(move || watchdog_loop(initial, stop_cl))
        .map_err(|e| format!("spawn watchdog: {e}"))?;

    Ok(WfpBypass {
        stop,
        worker: Some(worker),
    })
}

// ─── internals ──────────────────────────────────────────────────────────

const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);
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

    // All six ALE layers that WireGuard blocks when the killswitch is active.
    // V6 layers may not exist when IPv6 is disabled; all are best-effort.
    let layers: &[(&str, GUID)] = &[
        ("ALE_AUTH_CONNECT_V4", FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        ("ALE_AUTH_CONNECT_V6", FWPM_LAYER_ALE_AUTH_CONNECT_V6),
        (
            "ALE_AUTH_RECV_ACCEPT_V4",
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        ),
        (
            "ALE_AUTH_RECV_ACCEPT_V6",
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ),
        (
            "ALE_RESOURCE_ASSIGNMENT_V4",
            FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        ),
        (
            "ALE_RESOURCE_ASSIGNMENT_V6",
            FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        ),
    ];

    // Step 1: add PERMIT to our own guaranteed sublayer (GUTD_SUBLAYER_KEY).
    for (name, layer_key) in layers.iter() {
        match add_permit_filter(engine, layer_key, app_id_blob, name, &GUTD_SUBLAYER_KEY) {
            Ok(id) => {
                state.filter_ids.push(id);
            }
            Err(e) => {
                eprintln!(
                    "gutd: WFP: skipping {} in own sublayer — {} (non-fatal)",
                    name, e
                );
            }
        }
    }

    // Step 2: also add PERMIT into every OTHER existing sublayer (e.g. WireGuard's)
    // with the maximum filter weight.  WireGuard uses sublayer weight=0xFFFF — the
    // same as ours — so the order in which equal-weight sublayers are evaluated is
    // implementation-defined and WG's BLOCK+CLEAR_ACTION_RIGHT fires first when WG
    // was installed earlier.  By planting our PERMIT *inside* WG's sublayer with
    // weight=u64::MAX we outrank their BLOCK within their own sublayer, so the
    // PERMIT wins before the BLOCK is ever considered.
    let extra_ids = add_permit_to_all_sublayers(engine, layers, app_id_blob);
    state.filter_ids.extend_from_slice(&extra_ids);

    unsafe { FwpmFreeMemory0(&mut (app_id_blob as *mut _ as *mut _)) };

    if state.filter_ids.is_empty() {
        teardown(&mut state);
        return Err("FwpmFilterAdd0 failed on all layers in all sublayers".to_string());
    }

    eprintln!(
        "gutd: WFP bypass installed for gutd.exe ({} filters across {} sublayer×layer pairs)",
        state.filter_ids.len(),
        state.filter_ids.len() / layers.len().max(1) + 1,
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
        flags: 0, // persistent session — can add filters to any sublayer
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
    // Delete any stale sublayer from a previous crash (cascades its filters).
    // Ignore errors — it simply doesn't exist on a clean first run.
    unsafe { FwpmSubLayerDeleteByKey0(engine, &GUTD_SUBLAYER_KEY) };

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
    if rc != ERROR_SUCCESS {
        return Err(format!("FwpmSubLayerAdd0 rc=0x{:08X}", rc));
    }
    Ok(())
}

/// Add a PERMIT filter to the specified sublayer.
/// `weight_override`: if Some(w), use FWP_UINT64 weight w (u64::MAX to outrank all);
///                    if None, let WFP auto-assign (FWP_EMPTY).
fn add_permit_filter(
    engine: HANDLE,
    layer: &GUID,
    app_id: *mut FWP_BYTE_BLOB,
    layer_name: &str,
    sublayer_key: &GUID,
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

    // Use auto-assigned weight for our own sublayer (only filter there).
    // For foreign sublayers we pass max weight via add_permit_to_all_sublayers.
    let weight = FWP_VALUE0 {
        r#type: FWP_EMPTY as i32,
        Anonymous: unsafe { std::mem::zeroed() },
    };

    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.displayData.name = name_w.as_mut_ptr();
    filter.displayData.description = std::ptr::null_mut();
    filter.layerKey = *layer;
    filter.subLayerKey = *sublayer_key;
    filter.weight = weight;
    filter.numFilterConditions = 1;
    filter.filterCondition = &mut cond;
    filter.action = action;
    // FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: our PERMIT is a "hard permit" — no
    // lower-or-equal-weight sublayer can override it once this fires.
    filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

    let mut fid: u64 = 0;
    let rc = unsafe { FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid) };
    if rc != ERROR_SUCCESS {
        return Err(format!("FwpmFilterAdd0 rc=0x{:08X}", rc));
    }
    Ok(fid)
}

/// Enumerate every WFP sublayer currently registered and plant a PERMIT filter
/// for gutd.exe in each one (except our own) with weight = u64::MAX.  This
/// guarantees that inside WireGuard's own sublayer (also weight=0xFFFF) our
/// PERMIT outranks their BLOCK by having the highest possible filter weight,
/// so WFP picks our PERMIT first within the sublayer.
fn add_permit_to_all_sublayers(
    engine: HANDLE,
    layers: &[(&str, GUID)],
    app_id: *mut FWP_BYTE_BLOB,
) -> Vec<u64> {
    let mut ids = Vec::new();

    let mut enum_handle: HANDLE = std::ptr::null_mut();
    let rc = unsafe { FwpmSubLayerCreateEnumHandle0(engine, std::ptr::null(), &mut enum_handle) };
    if rc != ERROR_SUCCESS {
        eprintln!(
            "gutd: WFP: FwpmSubLayerCreateEnumHandle0 rc=0x{:08X} (non-fatal)",
            rc
        );
        return ids;
    }

    const BATCH: u32 = 128;
    let mut entries: *mut *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
    let mut count: u32 = 0;
    let rc = unsafe { FwpmSubLayerEnum0(engine, enum_handle, BATCH, &mut entries, &mut count) };

    if rc == ERROR_SUCCESS && !entries.is_null() {
        // max_weight lives until after FwpmFilterAdd0 returns for every filter.
        let max_weight: u64 = u64::MAX;

        for i in 0..count as usize {
            let sl_ptr: *mut FWPM_SUBLAYER0 = unsafe { *entries.add(i) };
            if sl_ptr.is_null() {
                continue;
            }
            let key = unsafe { (*sl_ptr).subLayerKey };

            // Skip our own sublayer (already handled).
            if guid_eq(&key, &GUTD_SUBLAYER_KEY) {
                continue;
            }

            for (name, layer) in layers {
                let mut name_w: Vec<u16> = format!("gutd permit {} (foreign)", name)
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
                filter.subLayerKey = key;
                // FWP_UINT64 with value u64::MAX → outranks every other filter in
                // the sublayer (WG's BLOCK is typically FWP_UINT8 weight 0-15).
                filter.weight = FWP_VALUE0 {
                    r#type: FWP_UINT64 as i32,
                    Anonymous: FWP_VALUE0_0 {
                        uint64: &max_weight as *const u64 as *mut u64,
                    },
                };
                filter.numFilterConditions = 1;
                filter.filterCondition = &mut cond;
                filter.action = action;
                filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

                let mut fid: u64 = 0;
                let rc = unsafe { FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid) };
                if rc == ERROR_SUCCESS {
                    ids.push(fid);
                }
                // Silent: 0x8032000C / 0x8032002D = sublayers requiring a
                // matching providerKey we don't own. Expected and benign.
            }
        }

        unsafe { FwpmFreeMemory0(&mut (entries as *mut _ as *mut _)) };
    }

    unsafe { FwpmSubLayerDestroyEnumHandle0(engine, enum_handle) };
    ids
}

// ─── helpers ───────────────────────────────────────────────────────────

/// GUID field-by-field equality (GUID doesn't implement PartialEq).
#[inline]
fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

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
