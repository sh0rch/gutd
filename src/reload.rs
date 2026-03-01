/// Signal handling for SIGHUP reload
use crate::Result;
use std::sync::atomic::{AtomicBool, Ordering};

static RELOAD_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn sighup_handler(_: libc::c_int) {
    RELOAD_FLAG.store(true, Ordering::Relaxed);
}

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

pub fn should_reload() -> bool {
    RELOAD_FLAG.load(Ordering::Relaxed)
}

pub fn clear_reload_flag() {
    RELOAD_FLAG.store(false, Ordering::Relaxed);
}
