/// Signal handling for config reload and graceful shutdown.
///
/// - Unix: SIGHUP → reload, SIGINT/SIGTERM handled in main.rs
/// - Windows: Ctrl+C / Ctrl+Break → exit (no reload signal)
use crate::Result;
use std::sync::atomic::{AtomicBool, Ordering};

static RELOAD_FLAG: AtomicBool = AtomicBool::new(false);
/// Shared exit flag — set by signal handlers on all platforms.
pub static EXIT_FLAG: AtomicBool = AtomicBool::new(false);

// ── Unix: SIGHUP ──────────────────────────────────────────────────

#[cfg(target_family = "unix")]
extern "C" fn sighup_handler(_: libc::c_int) {
    RELOAD_FLAG.store(true, Ordering::Relaxed);
}

#[cfg(target_family = "unix")]
pub fn setup_signal_handler() -> Result<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sighup_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&raw mut sa.sa_mask);

        if libc::sigaction(libc::SIGHUP, &raw const sa, std::ptr::null_mut()) < 0 {
            return Err("Failed to setup SIGHUP handler".into());
        }
    }

    Ok(())
}

// ── Windows: SetConsoleCtrlHandler ────────────────────────────────

#[cfg(target_family = "windows")]
pub fn setup_signal_handler() -> Result<()> {
    // On Windows there's no SIGHUP equivalent, so reload is not supported via signal.
    // Ctrl+C / Ctrl+Break will set EXIT_FLAG.

    unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
        // CTRL_C_EVENT = 0, CTRL_BREAK_EVENT = 1, CTRL_CLOSE_EVENT = 2
        if ctrl_type <= 2 {
            EXIT_FLAG.store(true, Ordering::Relaxed);
            1 // handled
        } else {
            0 // pass to next handler
        }
    }

    extern "system" {
        fn SetConsoleCtrlHandler(handler: unsafe extern "system" fn(u32) -> i32, add: i32) -> i32;
    }

    let ok = unsafe { SetConsoleCtrlHandler(ctrl_handler, 1) };
    if ok == 0 {
        return Err("Failed to setup console control handler".into());
    }
    Ok(())
}

pub fn should_reload() -> bool {
    RELOAD_FLAG.load(Ordering::Relaxed)
}

pub fn clear_reload_flag() {
    RELOAD_FLAG.store(false, Ordering::Relaxed);
}
