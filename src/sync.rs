use log::{info, error};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Condvar};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const EINVAL: i32 = 0x80020016u32 as i32;
const EBADF: i32 = 0x80020009u32 as i32;
const ETIMEDOUT: i32 = 0x80020056u32 as i32;

static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1000);

fn get_next_handle() -> u32 {
    NEXT_HANDLE.fetch_add(1, Ordering::SeqCst)
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SceKernelEvent {
    pub ident: u64,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: i64,
    pub udata: u64,
}

pub struct EqueueInternal {
    pub handle: u32,
    pub name: String,
    pub state: Mutex<EqueueState>,
    pub cond: Condvar,
}

pub struct EqueueState {
    pub registered: HashMap<(u64, i16), SceKernelEvent>,
    pub triggered: Vec<SceKernelEvent>,
    pub active_timers: HashMap<i32, Arc<std::sync::atomic::AtomicBool>>,
}

static KQUEUES: std::sync::OnceLock<Mutex<HashMap<u32, Arc<EqueueInternal>>>> = std::sync::OnceLock::new();
static EVENT_FLAGS: std::sync::OnceLock<Mutex<HashMap<u32, Arc<EventFlagInternal>>>> = std::sync::OnceLock::new();

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelCreateEqueue(
    eq_ptr: *mut u32,
    name_ptr: *const std::os::raw::c_char,
) -> i32 {
    if eq_ptr.is_null() {
        return EINVAL; // EINVAL
    }
    let name = if name_ptr.is_null() {
        "unnamed_eq".to_string()
    } else {
        std::ffi::CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
    };
    
    let handle = get_next_handle();
    let eq = Arc::new(EqueueInternal {
        handle,
        name: name.clone(),
        state: Mutex::new(EqueueState {
            registered: HashMap::new(),
            triggered: Vec::new(),
            active_timers: HashMap::new(),
        }),
        cond: Condvar::new(),
    });
    
    KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap().insert(handle, eq);
    *eq_ptr = handle;
    info!("sceKernelCreateEqueue: name = '{}', handle = {}", name, handle);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelDeleteEqueue(handle: u32) -> i32 {
    info!("sceKernelDeleteEqueue: handle = {}", handle);
    let eq = {
        let mut guard = KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.remove(&handle)
    };
    
    if let Some(eq) = eq {
        let mut state = eq.state.lock().unwrap();
        for (_, cancel_flag) in state.active_timers.drain() {
            cancel_flag.store(true, Ordering::SeqCst);
        }
        0
    } else {
        EBADF // EBADF
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelWaitEqueue(
    handle: u32,
    ev_ptr: u64,
    num: i32,
    out_ptr: *mut i32,
    timeout_ptr: *const u64,
) -> i32 {
    let eq = {
        let guard = KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    
    let eq = match eq {
        Some(q) => q,
        None => return EBADF,
    };
    
    if ev_ptr == 0 || out_ptr.is_null() || num < 1 {
        return EINVAL;
    }
    
    let host_ev_ptr = match crate::kernel::translate_guest_addr(ev_ptr) {
        Some(addr) => addr as *mut SceKernelEvent,
        None => ev_ptr as *mut SceKernelEvent,
    };
    
    let timeout = if timeout_ptr.is_null() {
        None
    } else {
        Some(*timeout_ptr)
    };
    
    let mut state = eq.state.lock().unwrap();
    
    let got_events = if state.triggered.is_empty() {
        if let Some(us) = timeout {
            if us == 0 {
                0
            } else {
                let duration = Duration::from_micros(us);
                let (new_state, result) = eq.cond.wait_timeout(state, duration).unwrap();
                state = new_state;
                if result.timed_out() {
                    *out_ptr = 0;
                    return ETIMEDOUT; // ETIMEDOUT
                }
                state.triggered.len().min(num as usize)
            }
        } else {
            while state.triggered.is_empty() {
                state = eq.cond.wait(state).unwrap();
            }
            state.triggered.len().min(num as usize)
        }
    } else {
        state.triggered.len().min(num as usize)
    };
    
    if got_events > 0 {
        let drained: Vec<SceKernelEvent> = state.triggered.drain(0..got_events).collect();
        for (i, ev) in drained.into_iter().enumerate() {
            *host_ev_ptr.add(i) = ev;
        }
        *out_ptr = got_events as i32;
        0
    } else {
        *out_ptr = 0;
        if timeout.is_some() {
            ETIMEDOUT
        } else {
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelAddUserEvent(handle: u32, id: i32) -> i32 {
    info!("sceKernelAddUserEvent: handle = {}, id = {}", handle, id);
    let eq = {
        let guard = KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let eq = match eq {
        Some(q) => q,
        None => return EBADF,
    };
    
    let mut state = eq.state.lock().unwrap();
    let ev = SceKernelEvent {
        ident: id as u64,
        filter: -11,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: 0,
    };
    state.registered.insert((id as u64, -11), ev);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelAddUserEventEdge(handle: u32, id: i32) -> i32 {
    info!("sceKernelAddUserEventEdge: handle = {}, id = {}", handle, id);
    let eq = {
        let guard = KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let eq = match eq {
        Some(q) => q,
        None => return EBADF,
    };
    
    let mut state = eq.state.lock().unwrap();
    let ev = SceKernelEvent {
        ident: id as u64,
        filter: -11,
        flags: 0x0020, // EV_CLEAR
        fflags: 0,
        data: 0,
        udata: 0,
    };
    state.registered.insert((id as u64, -11), ev);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelDeleteUserEvent(handle: u32, id: i32) -> i32 {
    info!("sceKernelDeleteUserEvent: handle = {}, id = {}", handle, id);
    let eq = {
        let guard = KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let eq = match eq {
        Some(q) => q,
        None => return EBADF,
    };
    
    let mut state = eq.state.lock().unwrap();
    state.registered.remove(&(id as u64, -11));
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelTriggerUserEvent(
    handle: u32,
    id: i32,
    udata: *mut std::ffi::c_void,
) -> i32 {
    info!("sceKernelTriggerUserEvent: handle = {}, id = {}, udata = {:?}", handle, id, udata);
    let eq = {
        let guard = KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let eq = match eq {
        Some(q) => q,
        None => return EBADF,
    };
    
    let mut state = eq.state.lock().unwrap();
    let triggered_ev = if let Some(&registered_ev) = state.registered.get(&(id as u64, -11)) {
        let mut ev = registered_ev;
        ev.udata = udata as u64;
        ev
    } else {
        SceKernelEvent {
            ident: id as u64,
            filter: -11,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: udata as u64,
        }
    };
    state.triggered.push(triggered_ev);
    eq.cond.notify_all();
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelAddTimerEvent(
    handle: u32,
    id: i32,
    usec: u64,
    udata: *mut std::ffi::c_void,
) -> i32 {
    info!("sceKernelAddTimerEvent: handle = {}, id = {}, usec = {}, udata = {:?}", handle, id, usec, udata);
    let eq = {
        let guard = KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let eq = match eq {
        Some(q) => q,
        None => return EBADF,
    };
    
    let mut state = eq.state.lock().unwrap();
    if let Some(cancel_flag) = state.active_timers.remove(&id) {
        cancel_flag.store(true, Ordering::SeqCst);
    }
    
    let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    state.active_timers.insert(id, cancel_flag.clone());
    
    let eq_clone = eq.clone();
    let udata_val = udata as u64;
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_micros(usec));
            if cancel_flag.load(Ordering::SeqCst) {
                break;
            }
            
            let mut q_state = eq_clone.state.lock().unwrap();
            if cancel_flag.load(Ordering::SeqCst) {
                break;
            }
            
            let ev = SceKernelEvent {
                ident: id as u64,
                filter: -7, // EVFILT_TIMER
                flags: 0,
                fflags: 0,
                data: 0,
                udata: udata_val,
            };
            q_state.triggered.push(ev);
            eq_clone.cond.notify_all();
        }
    });
    
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelDeleteTimerEvent(handle: u32, id: i32) -> i32 {
    info!("sceKernelDeleteTimerEvent: handle = {}, id = {}", handle, id);
    let eq = {
        let guard = KQUEUES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let eq = match eq {
        Some(q) => q,
        None => return EBADF,
    };
    
    let mut state = eq.state.lock().unwrap();
    if let Some(cancel_flag) = state.active_timers.remove(&id) {
        cancel_flag.store(true, Ordering::SeqCst);
        0
    } else {
        ETIMEDOUT
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelGetEventUserData(ev: *const SceKernelEvent) -> *mut std::ffi::c_void {
    if ev.is_null() {
        std::ptr::null_mut()
    } else {
        (*ev).udata as *mut std::ffi::c_void
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelGetEventId(ev: *const SceKernelEvent) -> u64 {
    if ev.is_null() {
        0
    } else {
        (*ev).ident
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelGetEventFilter(ev: *const SceKernelEvent) -> i32 {
    if ev.is_null() {
        0
    } else {
        (*ev).filter as i32
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelGetEventData(ev: *const SceKernelEvent) -> u64 {
    if ev.is_null() {
        0
    } else {
        (*ev).data as u64
    }
}

// =========================================================================
// Event Flags Implementation
// =========================================================================

pub struct EventFlagInternal {
    pub handle: u32,
    pub name: String,
    pub attr: u32,
    pub state: Mutex<EventFlagState>,
    pub cond: Condvar,
}

pub struct EventFlagState {
    pub pattern: u64,
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelCreateEventFlag(
    ef_ptr: *mut u32,
    name_ptr: *const std::os::raw::c_char,
    attr: u32,
    init_pattern: u64,
    _opt: *const std::ffi::c_void,
) -> i32 {
    if ef_ptr.is_null() {
        return EINVAL;
    }
    let name = if name_ptr.is_null() {
        "unnamed_ef".to_string()
    } else {
        std::ffi::CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
    };
    
    let handle = get_next_handle();
    let ef = Arc::new(EventFlagInternal {
        handle,
        name: name.clone(),
        attr,
        state: Mutex::new(EventFlagState { pattern: init_pattern }),
        cond: Condvar::new(),
    });
    
    EVENT_FLAGS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap().insert(handle, ef);
    *ef_ptr = handle;
    info!("sceKernelCreateEventFlag: name = '{}', attr = 0x{:X}, init = 0x{:X}, handle = {}", name, attr, init_pattern, handle);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelDeleteEventFlag(handle: u32) -> i32 {
    info!("sceKernelDeleteEventFlag: handle = {}", handle);
    let mut guard = EVENT_FLAGS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    if guard.remove(&handle).is_some() {
        0
    } else {
        EBADF
    }
}

fn check_event_flag_match(pattern: u64, bit_pattern: u64, wait_mode: u32) -> bool {
    let is_and = (wait_mode & 0x01) != 0;
    let is_or = (wait_mode & 0x02) != 0;
    
    if is_and {
        (pattern & bit_pattern) == bit_pattern
    } else if is_or {
        (pattern & bit_pattern) != 0
    } else {
        (pattern & bit_pattern) != 0
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelWaitEventFlag(
    handle: u32,
    bit_pattern: u64,
    wait_mode: u32,
    result_pat_ptr: *mut u64,
    timeout_ptr: *const u64,
) -> i32 {
    let ef = {
        let guard = EVENT_FLAGS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let ef = match ef {
        Some(f) => f,
        None => return EBADF,
    };
    
    let timeout = if timeout_ptr.is_null() {
        None
    } else {
        Some(*timeout_ptr)
    };
    
    let mut state = ef.state.lock().unwrap();
    
    if check_event_flag_match(state.pattern, bit_pattern, wait_mode) {
        if !result_pat_ptr.is_null() {
            *result_pat_ptr = state.pattern;
        }
        
        if (wait_mode & 0x10) != 0 {
            state.pattern = 0;
        } else if (wait_mode & 0x20) != 0 {
            state.pattern &= !bit_pattern;
        }
        return 0;
    }
    
    if let Some(us) = timeout {
        if us == 0 {
            return ETIMEDOUT;
        }
        let duration = Duration::from_micros(us);
        let (new_state, result) = ef.cond.wait_timeout_while(state, duration, |s| {
            !check_event_flag_match(s.pattern, bit_pattern, wait_mode)
        }).unwrap();
        state = new_state;
        
        if result.timed_out() {
            return ETIMEDOUT;
        }
    } else {
        while !check_event_flag_match(state.pattern, bit_pattern, wait_mode) {
            state = ef.cond.wait(state).unwrap();
        }
    }
    
    if !result_pat_ptr.is_null() {
        *result_pat_ptr = state.pattern;
    }
    
    if (wait_mode & 0x10) != 0 {
        state.pattern = 0;
    } else if (wait_mode & 0x20) != 0 {
        state.pattern &= !bit_pattern;
    }
    
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelPollEventFlag(
    handle: u32,
    bit_pattern: u64,
    wait_mode: u32,
    result_pat_ptr: *mut u64,
) -> i32 {
    let ef = {
        let guard = EVENT_FLAGS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let ef = match ef {
        Some(f) => f,
        None => return EBADF,
    };
    
    let mut state = ef.state.lock().unwrap();
    if check_event_flag_match(state.pattern, bit_pattern, wait_mode) {
        if !result_pat_ptr.is_null() {
            *result_pat_ptr = state.pattern;
        }
        if (wait_mode & 0x10) != 0 {
            state.pattern = 0;
        } else if (wait_mode & 0x20) != 0 {
            state.pattern &= !bit_pattern;
        }
        0
    } else {
        ETIMEDOUT
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelSetEventFlag(handle: u32, bit_pattern: u64) -> i32 {
    let ef = {
        let guard = EVENT_FLAGS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let ef = match ef {
        Some(f) => f,
        None => return EBADF,
    };
    
    {
        let mut state = ef.state.lock().unwrap();
        state.pattern |= bit_pattern;
    }
    ef.cond.notify_all();
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelClearEventFlag(handle: u32, bit_pattern: u64) -> i32 {
    let ef = {
        let guard = EVENT_FLAGS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        guard.get(&handle).cloned()
    };
    let ef = match ef {
        Some(f) => f,
        None => return EBADF,
    };
    
    {
        let mut state = ef.state.lock().unwrap();
        state.pattern &= !bit_pattern;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equeue_operations() {
        let mut eq = 0u32;
        let name = std::ffi::CString::new("test_queue").unwrap();
        assert_eq!(unsafe { sceKernelCreateEqueue(&mut eq, name.as_ptr()) }, 0);
        assert!(eq >= 1000);

        // Add user event
        assert_eq!(unsafe { sceKernelAddUserEvent(eq, 10) }, 0);

        // Spawn thread to trigger user event
        let eq_val = eq;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            unsafe {
                sceKernelTriggerUserEvent(eq_val, 10, 0x12345 as *mut std::ffi::c_void);
            }
        });

        // Wait on event queue
        let mut events = [SceKernelEvent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: 0,
        }; 4];
        let mut out_count = 0;
        let timeout = 1000000u64; // 1 second in microseconds
        
        let wait_res = unsafe {
            sceKernelWaitEqueue(
                eq,
                &mut events as *mut SceKernelEvent as u64,
                4,
                &mut out_count,
                &timeout,
            )
        };

        assert_eq!(wait_res, 0);
        assert_eq!(out_count, 1);
        assert_eq!(events[0].ident, 10);
        assert_eq!(events[0].filter, -11); // EVFILT_USER
        assert_eq!(events[0].udata, 0x12345);

        assert_eq!(unsafe { sceKernelDeleteEqueue(eq) }, 0);
    }

    #[test]
    fn test_event_flags() {
        let mut ef = 0u32;
        let name = std::ffi::CString::new("test_flag").unwrap();
        // attr 0x20 (multi), init 0x01
        assert_eq!(unsafe { sceKernelCreateEventFlag(&mut ef, name.as_ptr(), 0x20, 0x01, std::ptr::null()) }, 0);

        // Spawn thread to set event flag
        let ef_val = ef;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            unsafe {
                sceKernelSetEventFlag(ef_val, 0x02);
            }
        });

        // Wait for pattern (AND wait mode = 0x01: wait for 0x01 | 0x02 = 0x03)
        let mut result_pat = 0u64;
        let timeout = 1000000u64;
        let wait_res = unsafe {
            sceKernelWaitEventFlag(ef, 0x03, 0x01, &mut result_pat, &timeout)
        };

        assert_eq!(wait_res, 0);
        assert_eq!(result_pat, 0x03);

        assert_eq!(unsafe { sceKernelDeleteEventFlag(ef) }, 0);
    }
}
