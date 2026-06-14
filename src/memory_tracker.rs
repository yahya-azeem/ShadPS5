use log::{info, error, warn};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Clone, Copy)]
pub struct TrackedRange {
    pub start_addr: usize,
    pub len: usize,
    pub dirty_pages: *mut AtomicBool,
    pub num_pages: usize,
    pub active: bool,
}

unsafe impl Send for TrackedRange {}
unsafe impl Sync for TrackedRange {}

struct TrackerState {
    installed: bool,
    ranges: Vec<TrackedRange>,
}

static TRACKER_STATE: Mutex<TrackerState> = Mutex::new(TrackerState {
    installed: false,
    ranges: Vec::new(),
});

// Store the previous signal handler to cascade unsupported faults
static mut PREVIOUS_SIGSEGV: libc::sigaction = unsafe { std::mem::zeroed() };

/// Signal handler for SIGSEGV. Checks if fault address belongs to guest write-watch buffers.
unsafe extern "C" fn sigsegv_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    if info.is_null() {
        fallback_handler(sig, info, ucontext);
        return;
    }

    let fault_addr = (*info).si_addr() as usize;
    let page_start = fault_addr & !(4096 - 1);

    // Bypass lock to be async-signal-safe. We access TRACKER_STATE.ranges directly.
    // Rust Mutex is not safe in signal handler, so we query ranges through a static direct reference.
    // Note: since registration/unregistration are rare and happen under lock, reading the ranges is safe.
    let ranges_ptr = &raw const TRACKER_STATE_RAW_RANGES;
    let mut handled = false;

    if !ranges_ptr.is_null() {
        for range in &*ranges_ptr {
            if range.active && fault_addr >= range.start_addr && fault_addr < range.start_addr + range.len {
                let page_idx = (fault_addr - range.start_addr) / 4096;
                if page_idx < range.num_pages {
                    // Mark page as dirty
                    (*range.dirty_pages.add(page_idx)).store(true, Ordering::Relaxed);
                    
                    // Restore write permission so guest execution can continue
                    libc::mprotect(
                        page_start as *mut libc::c_void,
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                    handled = true;
                    break;
                }
            }
        }
    }

    if !handled {
        fallback_handler(sig, info, ucontext);
    }
}

unsafe fn fallback_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    let prev = &raw const PREVIOUS_SIGSEGV;
    if (*prev).sa_sigaction != 0 && (*prev).sa_sigaction != libc::SIG_DFL && (*prev).sa_sigaction != libc::SIG_IGN {
        let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
            std::mem::transmute((*prev).sa_sigaction);
        handler(sig, info, ucontext);
    } else {
        // Restore default handler and let it re-raise
        let mut dfl_act: libc::sigaction = std::mem::zeroed();
        dfl_act.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGSEGV, &dfl_act, std::ptr::null_mut());
    }
}

// Global raw copy of ranges for signal handler bypassing Mutex
static mut TRACKER_STATE_RAW_RANGES: Vec<TrackedRange> = Vec::new();

/// Installs the custom SIGSEGV handler using sigaction.
unsafe fn install_signal_handler() {
    let mut act: libc::sigaction = std::mem::zeroed();
    act.sa_sigaction = sigsegv_handler as usize;
    act.sa_flags = libc::SA_SIGINFO;
    libc::sigemptyset(&mut act.sa_mask);

    if libc::sigaction(libc::SIGSEGV, &act, &raw mut PREVIOUS_SIGSEGV) != 0 {
        error!("Failed to register custom SIGSEGV signal handler.");
    } else {
        info!("Successfully registered custom memory write-watch SIGSEGV handler.");
    }
}

/// Registers a guest memory range to be write-watched.
pub fn register_range(start_addr: u64, len: u64) {
    let start_addr = start_addr as usize;
    let len = len as usize;
    let num_pages = (len + 4095) / 4096;
    
    // Allocate dirty page flags
    let mut pages = Vec::with_capacity(num_pages);
    for _ in 0..num_pages {
        pages.push(AtomicBool::new(false));
    }
    let pages_slice = pages.into_boxed_slice();
    let dirty_pages = Box::into_raw(pages_slice) as *mut AtomicBool;

    let range = TrackedRange {
        start_addr,
        len,
        dirty_pages,
        num_pages,
        active: true,
    };

    unsafe {
        let mut tracker = TRACKER_STATE.lock().unwrap();
        if !tracker.installed {
            install_signal_handler();
            tracker.installed = true;
        }
        
        tracker.ranges.push(range);
        TRACKER_STATE_RAW_RANGES = tracker.ranges.clone();
        
        // Write protect the memory range so first write triggers page fault
        libc::mprotect(start_addr as *mut libc::c_void, len, libc::PROT_READ);
        info!(
            "Registered write-watch memory range: 0x{:X} - 0x{:X} ({} pages)",
            start_addr, start_addr + len, num_pages
        );
    }
}

/// Unregisters a previously registered guest memory range.
pub fn unregister_range(start_addr: u64) {
    let start_addr = start_addr as usize;
    unsafe {
        let mut tracker = TRACKER_STATE.lock().unwrap();
        if let Some(pos) = tracker.ranges.iter().position(|r| r.active && r.start_addr == start_addr) {
            let mut range = tracker.ranges.remove(pos);
            range.active = false;
            
            // Re-apply full permissions
            libc::mprotect(range.start_addr as *mut libc::c_void, range.len, libc::PROT_READ | libc::PROT_WRITE);
            
            // Deallocate dirty_pages Box
            let slice = Box::from_raw(std::slice::from_raw_parts_mut(range.dirty_pages, range.num_pages));
            drop(slice);
            
            TRACKER_STATE_RAW_RANGES = tracker.ranges.clone();
            info!("Unregistered write-watch memory range: 0x{:X}", start_addr);
        }
    }
}

/// Checks if a page in a range is dirty, runs a closure to synchronize, and re-protects the page.
pub fn sync_dirty_ranges<F>(mut sync_callback: F)
where
    F: FnMut(u64, u64, &[u8]),
{
    unsafe {
        let tracker = TRACKER_STATE.lock().unwrap();
        for range in &tracker.ranges {
            if !range.active {
                continue;
            }
            
            for idx in 0..range.num_pages {
                let page_dirty = (*range.dirty_pages.add(idx)).load(Ordering::Relaxed);
                if page_dirty {
                    let page_addr = range.start_addr + idx * 4096;
                    let page_data = std::slice::from_raw_parts(page_addr as *const u8, 4096);
                    
                    // Trigger sync callback
                    sync_callback(page_addr as u64, 4096, page_data);
                    
                    // Reset dirty status
                    (*range.dirty_pages.add(idx)).store(false, Ordering::Relaxed);
                    
                    // Re-apply read-only protection to catch subsequent modifications
                    libc::mprotect(page_addr as *mut libc::c_void, 4096, libc::PROT_READ);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_tracker_operations() {
        // Allocate page-aligned memory for test
        let mut page_buf = vec![0u8; 8192 + 4096];
        let raw_addr = page_buf.as_mut_ptr() as usize;
        let aligned_addr = (raw_addr + 4095) & !(4095);

        // Register the aligned memory range (4KB)
        register_range(aligned_addr as u64, 4096);

        // Verify initial state
        let ptr = aligned_addr as *mut u8;
        unsafe {
            // Read is allowed
            let val = *ptr;
            assert_eq!(val, 0);
            
            // Trigger a write page fault, which signals sigsegv, catches it, marks dirty, and resumes
            *ptr = 0xAA;
            assert_eq!(*ptr, 0xAA);
        }

        // Test dirty page synchronizer callback
        let mut sync_called = false;
        sync_dirty_ranges(|addr, len, data| {
            assert_eq!(addr, aligned_addr as u64);
            assert_eq!(len, 4096);
            assert_eq!(data[0], 0xAA);
            sync_called = true;
        });

        assert!(sync_called);

        // Unregister range
        unregister_range(aligned_addr as u64);
    }
}
