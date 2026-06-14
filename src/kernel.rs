use log::{info, error, warn, debug};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

// Platform-specific imports
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

#[cfg(target_os = "linux")]
use std::ptr;

// Global thread-safe wait queue for futex synchronization
static WAIT_QUEUE: std::sync::OnceLock<Mutex<HashMap<u64, Vec<std::thread::Thread>>>> = std::sync::OnceLock::new();

// Registry to track spawned host threads so we can join them in pthread_join
static THREAD_REGISTRY: std::sync::OnceLock<Mutex<HashMap<u64, std::thread::JoinHandle<()>>>> = std::sync::OnceLock::new();

// Registry to track recursive lock counts for HLE mutexes
static MUTEX_RECURSIONS: std::sync::OnceLock<Mutex<HashMap<u64, u32>>> = std::sync::OnceLock::new();

#[derive(Debug, Clone, Copy)]
pub struct GuestMemoryMapping {
    pub guest_addr: u64,
    pub host_ptr: u64,
    pub size: usize,
}

pub static GUEST_MEMORY_MAP: std::sync::OnceLock<Mutex<HashMap<u64, GuestMemoryMapping>>> = std::sync::OnceLock::new();

pub fn register_guest_memory(guest_addr: u64, host_ptr: u64, size: usize) {
    let map_lock = GUEST_MEMORY_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map_lock.lock().unwrap();
    map.insert(guest_addr, GuestMemoryMapping {
        guest_addr,
        host_ptr,
        size,
    });
    debug!("Registered HLE Guest Memory Mapping: Guest 0x{:X} -> Host 0x{:X} (Size: {} bytes)", guest_addr, host_ptr, size);
}

pub fn translate_guest_addr(guest_addr: u64) -> Option<u64> {
    let map_lock = GUEST_MEMORY_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let map = map_lock.lock().unwrap();
    for mapping in map.values() {
        if guest_addr >= mapping.guest_addr && guest_addr < mapping.guest_addr + mapping.size as u64 {
            let offset = guest_addr - mapping.guest_addr;
            return Some(mapping.host_ptr + offset);
        }
    }
    None
}

// Thread-local storage to track the active thread's simulated TID
thread_local! {
    pub static CURRENT_TID: std::cell::Cell<i32> = std::cell::Cell::new(1000); // Main thread defaults to 1000
}

static NEXT_TID: AtomicI32 = AtomicI32::new(2000);

/// FreeBSD struct thr_param definition
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThrParam {
    pub start_func: u64,     // void (*start_func)(void *)
    pub arg: u64,            // void *arg
    pub stack_base: u64,     // char *stack_base
    pub stack_size: usize,   // size_t stack_size
    pub tls_base: u64,       // char *tls_base
    pub tls_size: usize,     // size_t tls_size
    pub child_tid: u64,      // long *child_tid
    pub parent_tid: u64,     // long *parent_tid
    pub flags: i32,          // int flags
    pub rtp: u64,            // void *rtp
}

/// The PS5 standard page size is 16KB (16384 bytes)
pub const SCE_KERNEL_PAGE_SIZE: usize = 16384;

/// Total simulated direct memory pool size (16 GB GDDR6)
pub const SCE_KERNEL_MAIN_DMEM_SIZE: usize = 16 * 1024 * 1024 * 1024;

static GUEST_VM_BUMP: AtomicU64 = AtomicU64::new(0x700000000000);

#[cfg(target_os = "linux")]
#[repr(C)]
struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct sock_fprog {
    len: u16,
    filter: *const sock_filter,
}

#[cfg(target_os = "linux")]
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
#[cfg(target_os = "linux")]
const PR_SET_SECCOMP: libc::c_int = 22;
#[cfg(target_os = "linux")]
const SECCOMP_MODE_FILTER: libc::c_int = 2;

#[cfg(target_os = "linux")]
const BPF_LD: u16 = 0x00;
#[cfg(target_os = "linux")]
const BPF_W: u16 = 0x00;
#[cfg(target_os = "linux")]
const BPF_ABS: u16 = 0x20;
#[cfg(target_os = "linux")]
const BPF_JMP: u16 = 0x05;
#[cfg(target_os = "linux")]
const BPF_K: u16 = 0x00;
#[cfg(target_os = "linux")]
const BPF_RET: u16 = 0x06;

#[cfg(target_os = "linux")]
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
#[cfg(target_os = "linux")]
const SECCOMP_RET_TRAP: u32 = 0x00030000;

#[cfg(target_os = "linux")]
unsafe extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    if info.is_null() || ucontext.is_null() {
        return;
    }
    let ucontext = ucontext as *mut libc::ucontext_t;
    let mcontext = &mut (*ucontext).uc_mcontext;
    
    let rax = mcontext.gregs[libc::REG_RAX as usize] as u32;
    let rdi = mcontext.gregs[libc::REG_RDI as usize] as u64;
    let rsi = mcontext.gregs[libc::REG_RSI as usize] as u64;
    let rdx = mcontext.gregs[libc::REG_RDX as usize] as u64;
    let rcx = mcontext.gregs[libc::REG_RCX as usize] as u64;
    let r8 = mcontext.gregs[libc::REG_R8 as usize] as u64;
    let r9 = mcontext.gregs[libc::REG_R9 as usize] as u64;
    
    let rip = mcontext.gregs[libc::REG_RIP as usize] as u64;
    
    log::debug!("seccomp trapped syscall {} from RIP 0x{:X}", rax, rip);
    
    let args = [rdi, rsi, rdx, rcx, r8, r9];
    let res = dispatch_syscall(rax, &args);
    
    match res {
        SyscallResult::Success(val) => {
            mcontext.gregs[libc::REG_RAX as usize] = val as i64;
            mcontext.gregs[libc::REG_EFL as usize] &= !1;
        }
        SyscallResult::Error(err) => {
            mcontext.gregs[libc::REG_RAX as usize] = err as i64;
            mcontext.gregs[libc::REG_EFL as usize] |= 1;
        }
    }
}

#[cfg(target_os = "linux")]
pub fn initialize_syscall_interceptor() {
    info!("Setting up seccomp-bpf system call interceptor...");
    
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigsys_handler as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut()) != 0 {
            error!("Failed to register SIGSYS handler!");
            return;
        }
    }
    
    unsafe {
        if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            error!("Failed to set PR_SET_NO_NEW_PRIVS!");
            return;
        }
    }
    
    let filter = [
        sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 12,
        },
        sock_filter {
            code: BPF_JMP | 0x30 | BPF_K, // BPF_JGE
            jt: 0,
            jf: 2,
            k: 0x7000,
        },
        sock_filter {
            code: BPF_JMP | 0x20 | BPF_K, // BPF_JGT
            jt: 1,
            jf: 0,
            k: 0x70FF,
        },
        sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_TRAP,
        },
        sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    
    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    
    unsafe {
        if libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const _ as usize, 0, 0) != 0 {
            error!("Failed to load seccomp BPF filter!");
        } else {
            info!("Seccomp BPF filter loaded successfully!");
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn initialize_syscall_interceptor() {
    warn!("Syscall interceptor is only supported on Linux.");
}

/// Initialize the guest OS kernel virtualization subsystem
pub fn initialize_kernel() {
    info!("Prospero Kernel Virtualization Layer Initialized.");
    info!("Direct Memory Pool Size: {} GB", SCE_KERNEL_MAIN_DMEM_SIZE / (1024 * 1024 * 1024));
    info!("Page size constraint: 16KB ({} bytes)", SCE_KERNEL_PAGE_SIZE);
    initialize_syscall_interceptor();
}

/// Represents the status of a guest system call execution
#[derive(Debug)]
pub enum SyscallResult {
    Success(u64),
    Error(i32),
}

/// Intercepts and executes a guest system call by its numerical ID.
///
/// System calls on Prospero are based on FreeBSD 11 numbering conventions.
pub fn dispatch_syscall(syscall_num: u32, args: &[u64]) -> SyscallResult {
    match syscall_num {
        // sys_write (write to file descriptor) - FreeBSD ID: 4
        4 => {
            let fd = args[0];
            let buf_ptr = args[1] as *const u8;
            let count = args[2] as usize;
            
            if fd == 1 || fd == 2 {
                let slice = unsafe { std::slice::from_raw_parts(buf_ptr, count) };
                if let Ok(text) = std::str::from_utf8(slice) {
                    info!("[Guest Output] {}", text.trim_end());
                }
                SyscallResult::Success(count as u64)
            } else {
                warn!("Syscall (write): Unknown file descriptor: {}", fd);
                SyscallResult::Success(0)
            }
        }

        // sys_munmap (unmap memory) - FreeBSD ID: 73
        73 => {
            let addr = args[0];
            let len = args[1] as usize;
            info!("Syscall (munmap): Addr: 0x{:X}, Len: {} bytes", addr, len);
            
            deallocate_guest_memory(addr, len);
            SyscallResult::Success(0)
        }

        // sys_getpid - FreeBSD ID: 20
        20 => {
            let pid = std::process::id() as u64;
            info!("Syscall (getpid): Returning PID: {}", pid);
            SyscallResult::Success(pid)
        }

        // sys_getuid - FreeBSD ID: 24
        24 => {
            info!("Syscall (getuid): Returning UID: 0");
            SyscallResult::Success(0)
        }

        // sys_ioctl - FreeBSD ID: 54
        54 => {
            let fd = args[0];
            let request = args[1];
            info!("Syscall (ioctl): FD: {}, Request: 0x{:X}", fd, request);
            SyscallResult::Success(0)
        }

        // sys_clock_gettime - FreeBSD ID: 232
        232 => {
            let clock_id = args[0];
            info!("Syscall (clock_gettime): Clock ID: {}", clock_id);
            SyscallResult::Success(0)
        }

        // sys_nanosleep - FreeBSD ID: 240
        240 => {
            let rqtp = args[0] as *const u64;
            if !rqtp.is_null() {
                unsafe {
                    let seconds = *rqtp;
                    let nanoseconds = *rqtp.add(1);
                    info!("Syscall (nanosleep): {}s, {}ns", seconds, nanoseconds);
                    std::thread::sleep(std::time::Duration::new(seconds, nanoseconds as u32));
                }
            }
            SyscallResult::Success(0)
        }

        // sys__umtx_op - FreeBSD ID: 454
        454 => {
            let obj = args[0];
            let op = args[1];
            let val = args[2];
            debug!("Syscall (_umtx_op): Obj: 0x{:X}, Op: {}, Val: {}", obj, op, val);
            
            match op {
                1 => { // UMTX_OP_WAIT
                    let current_tid = CURRENT_TID.with(|cell| cell.get());
                    let ptr = obj as *const i32;
                    let current_val = unsafe { *ptr };
                    if current_val == val as i32 {
                        let current_thread = std::thread::current();
                        {
                            let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
                            let mut queue = queue_mutex.lock().unwrap();
                            queue.entry(obj).or_default().push(current_thread);
                        }
                        debug!("  --> UMTX_OP_WAIT: Thread {} parking waiting on address 0x{:X}...", current_tid, obj);
                        std::thread::park();
                        debug!("  --> UMTX_OP_WAIT: Thread {} resumed.", current_tid);
                    } else {
                        debug!("  --> UMTX_OP_WAIT: Value mismatch at 0x{:X} (current={}, expected={}). Return immediate.", obj, current_val, val);
                    }
                    SyscallResult::Success(0)
                }
                2 => { // UMTX_OP_WAKE
                    let current_tid = CURRENT_TID.with(|cell| cell.get());
                    let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
                    let mut queue = queue_mutex.lock().unwrap();
                    let mut waked = 0;
                    if let Some(threads) = queue.get_mut(&obj) {
                        let wake_count = val as usize;
                        let to_wake: Vec<std::thread::Thread> = threads.drain(0..wake_count.min(threads.len())).collect();
                        waked = to_wake.len();
                        for t in to_wake {
                            debug!("  --> UMTX_OP_WAKE: Thread {} waking up thread {:?}", current_tid, t.id());
                            t.unpark();
                        }
                    }
                    SyscallResult::Success(waked as u64)
                }
                15 => { // UMTX_OP_MUTEX_LOCK
                    let m_owner_ptr = obj as *mut i32;
                    let current_tid = CURRENT_TID.with(|cell| cell.get());
                    
                    loop {
                        let prev_val = unsafe {
                            let atomic_ptr = m_owner_ptr as *const std::sync::atomic::AtomicI32;
                            (*atomic_ptr).compare_exchange(
                                0,
                                current_tid,
                                Ordering::SeqCst,
                                Ordering::SeqCst
                            )
                        };
                        
                        match prev_val {
                            Ok(_) => {
                                debug!("  --> UMTX_OP_MUTEX_LOCK: Thread {} successfully acquired mutex 0x{:X}", current_tid, obj);
                                break;
                            }
                            Err(owner) => {
                                if owner == current_tid {
                                    debug!("  --> UMTX_OP_MUTEX_LOCK: Thread {} already owns mutex 0x{:X} (recursive)", current_tid, obj);
                                    break;
                                }
                                
                                let current_thread = std::thread::current();
                                {
                                    let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
                                    let mut queue = queue_mutex.lock().unwrap();
                                    queue.entry(obj).or_default().push(current_thread);
                                }
                                debug!("  --> UMTX_OP_MUTEX_LOCK: Thread {} waiting on mutex 0x{:X} owned by {}", current_tid, obj, owner);
                                std::thread::park();
                            }
                        }
                    }
                    SyscallResult::Success(0)
                }
                16 => { // UMTX_OP_MUTEX_UNLOCK
                    let m_owner_ptr = obj as *mut i32;
                    let current_tid = CURRENT_TID.with(|cell| cell.get());
                    
                    let prev_val = unsafe {
                        let atomic_ptr = m_owner_ptr as *const std::sync::atomic::AtomicI32;
                        (*atomic_ptr).compare_exchange(
                            current_tid,
                            0,
                            Ordering::SeqCst,
                            Ordering::SeqCst
                        )
                    };
                    
                    match prev_val {
                        Ok(_) => {
                            debug!("  --> UMTX_OP_MUTEX_UNLOCK: Thread {} released mutex 0x{:X}", current_tid, obj);
                            let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
                            let mut queue = queue_mutex.lock().unwrap();
                            if let Some(threads) = queue.get_mut(&obj) {
                                if !threads.is_empty() {
                                    let t = threads.remove(0);
                                    debug!("  --> UMTX_OP_MUTEX_UNLOCK: Waking thread {:?}", t.id());
                                    t.unpark();
                                }
                            }
                        }
                        Err(actual_owner) => {
                            warn!("  --> UMTX_OP_MUTEX_UNLOCK: Thread {} failed to unlock mutex 0x{:X} (actual owner is {})", current_tid, obj, actual_owner);
                        }
                    }
                    SyscallResult::Success(0)
                }
                _ => {
                    warn!("  --> Unhandled umtx operation: {}", op);
                    SyscallResult::Success(0)
                }
            }
        }

        // sys_thr_new - FreeBSD ID: 455
        455 => {
            let param_ptr = args[0] as *const ThrParam;
            if param_ptr.is_null() {
                return SyscallResult::Error(22); // EINVAL
            }
            let param = unsafe { *param_ptr };
            let new_tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
            info!("Syscall (thr_new): Spawning new guest thread ID {} with entry 0x{:X}...", new_tid, param.start_func);
            
            if param.parent_tid != 0 {
                unsafe {
                    *(param.parent_tid as *mut i32) = new_tid;
                }
            }
            if param.child_tid != 0 {
                unsafe {
                    *(param.child_tid as *mut i32) = new_tid;
                }
            }
            
            let entry_fn: unsafe extern "sysv64" fn(u64) -> i32 = unsafe { std::mem::transmute(param.start_func) };
            let thread_arg = param.arg;
            
            std::thread::spawn(move || {
                CURRENT_TID.with(|cell| cell.set(new_tid));
                info!("  [Host Guest Thread {}] Executing entry point function...", new_tid);
                unsafe {
                    entry_fn(thread_arg);
                }
                info!("  [Host Guest Thread {}] Terminated execution.", new_tid);
            });
            
            SyscallResult::Success(0)
        }

        // sys_mmap - FreeBSD ID: 477
        477 => {
            let addr = args[0];
            let len = args[1] as usize;
            let prot = args[2] as i32;
            let flags = args[3] as i32;
            info!("Syscall (mmap): Addr: 0x{:X}, Len: {} bytes, Prot: {}, Flags: {}", addr, len, prot, flags);
            
            match allocate_guest_memory(addr, len) {
                Ok(ptr) => SyscallResult::Success(ptr as u64),
                Err(e) => {
                    error!("mmap allocation failed: {}", e);
                    SyscallResult::Error(12) // ENOMEM
                }
            }
        }

        // sys_exit - FreeBSD ID: 1
        1 => {
            let status = args[0] as i32;
            let current_tid = CURRENT_TID.with(|cell| cell.get());
            info!("Syscall (sys_exit): Guest thread {} requested exit with status = {}. Parking thread indefinitely to keep emulator alive.", current_tid, status);
            loop {
                std::thread::park();
            }
        }

        // sys_thr_exit - FreeBSD ID: 431
        431 => {
            let state = args[0] as *mut i64;
            let current_tid = CURRENT_TID.with(|cell| cell.get());
            info!("Syscall (sys_thr_exit): Guest thread {} exiting.", current_tid);
            if !state.is_null() {
                unsafe {
                    *state = 0;
                }
            }
            #[cfg(unix)]
            unsafe {
                libc::pthread_exit(std::ptr::null_mut());
            }
            #[cfg(not(unix))]
            loop {
                std::thread::park();
            }
        }

        // sys_thr_set_name - FreeBSD ID: 464
        464 => {
            let tid = args[0] as i64;
            let name_ptr = args[1] as *const std::os::raw::c_char;
            let current_tid = CURRENT_TID.with(|cell| cell.get());
            if !name_ptr.is_null() {
                let c_str = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
                if let Ok(name) = c_str.to_str() {
                    info!("Syscall (sys_thr_set_name): Thread {} (target tid={}) name set to: {}", current_tid, tid, name);
                    #[cfg(target_os = "linux")]
                    unsafe {
                        let mut name_truncated = name.to_string();
                        name_truncated.truncate(15);
                        let c_name = std::ffi::CString::new(name_truncated).unwrap();
                        libc::pthread_setname_np(libc::pthread_self(), c_name.as_ptr());
                    }
                }
            }
            SyscallResult::Success(0)
        }

        _ => {
            warn!("Unhandled guest system call intercepted. ID: {}", syscall_num);
            SyscallResult::Error(78)
        }
    }
}

/// Allocates virtual memory on the host system, enforcing 16KB page alignment constraints.
pub fn allocate_guest_memory(hint_addr: u64, size: usize) -> Result<*mut u8, &'static str> {
    // Round size up to the nearest multiple of SCE_KERNEL_PAGE_SIZE (16KB)
    let aligned_size = (size + SCE_KERNEL_PAGE_SIZE - 1) & !(SCE_KERNEL_PAGE_SIZE - 1);
    if aligned_size != size {
        debug!("Memory size 0x{:X} aligned up to page boundary: 0x{:X}", size, aligned_size);
    }

    #[cfg(target_os = "windows")]
    {
        let desired_addr = if hint_addr >= 0x700000000000 && hint_addr < 0x70FF00000000 {
            hint_addr as *const std::ffi::c_void
        } else {
            let size_to_bump = (aligned_size + 0xFFFFF) & !0xFFFFF; // 1MB align
            let bump = GUEST_VM_BUMP.fetch_add(size_to_bump as u64, Ordering::SeqCst);
            bump as *const std::ffi::c_void
        };
        let mut ptr = unsafe {
            VirtualAlloc(
                desired_addr,
                aligned_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        // Fallback: If allocation fails with the bump address, try another bump
        if ptr.is_null() {
            let size_to_bump = (aligned_size + 0xFFFFF) & !0xFFFFF;
            let bump = GUEST_VM_BUMP.fetch_add(size_to_bump as u64, Ordering::SeqCst);
            ptr = unsafe {
                VirtualAlloc(
                    bump as *const std::ffi::c_void,
                    aligned_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
        }
        if ptr.is_null() {
            Err("VirtualAlloc failed to allocate memory page.")
        } else {
            debug!("Windows VirtualAlloc mapped 16KB aligned memory block at: {:p} (size: {} bytes)", ptr, aligned_size);
            Ok(ptr as *mut u8)
        }
    }

    #[cfg(target_os = "linux")]
    {
        unsafe {
            let desired_addr = if hint_addr >= 0x700000000000 && hint_addr < 0x70FF00000000 {
                hint_addr as *mut libc::c_void
            } else {
                let size_to_bump = (aligned_size + 0xFFFFF) & !0xFFFFF; // 1MB align
                let bump = GUEST_VM_BUMP.fetch_add(size_to_bump as u64, Ordering::SeqCst);
                bump as *mut libc::c_void
            };
            let mut ptr = libc::mmap(
                desired_addr,
                aligned_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            // Fallback: If mmap fails with the bump address, try another bump
            if ptr == libc::MAP_FAILED {
                let size_to_bump = (aligned_size + 0xFFFFF) & !0xFFFFF;
                let bump = GUEST_VM_BUMP.fetch_add(size_to_bump as u64, Ordering::SeqCst);
                ptr = libc::mmap(
                    bump as *mut libc::c_void,
                    aligned_size,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
            }
            if ptr == libc::MAP_FAILED {
                Err("Linux mmap failed to allocate memory page.")
            } else {
                debug!("Linux mmap mapped 16KB aligned memory block at: {:p} (size: {} bytes)", ptr, aligned_size);
                Ok(ptr as *mut u8)
            }
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err("Unsupported host operating system for direct guest virtual memory mapping.")
    }
}

/// Frees virtual memory allocated on the host system.
pub fn deallocate_guest_memory(addr: u64, size: usize) {
    let aligned_size = (size + SCE_KERNEL_PAGE_SIZE - 1) & !(SCE_KERNEL_PAGE_SIZE - 1);

    #[cfg(target_os = "windows")]
    {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualFree(
                addr as *mut std::ffi::c_void,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
    }

    #[cfg(target_os = "linux")]
    {
        unsafe {
            libc::munmap(addr as *mut libc::c_void, aligned_size);
        }
    }
}

// =========================================================================
// =========================================================================

#[no_mangle]
pub extern "sysv64" fn sceKernelGetDirectMemorySize() -> usize {
    info!("API Intercepted: sceKernelGetDirectMemorySize");
    SCE_KERNEL_MAIN_DMEM_SIZE
}

#[no_mangle]
pub extern "sysv64" fn sceKernelAllocateDirectMemory(
    _search_start: u64,
    _search_end: u64,
    len: usize,
    alignment: usize,
    memory_type: i32,
    phys_addr_out: *mut u64,
) -> i32 {
    info!(
        "API Intercepted: sceKernelAllocateDirectMemory | Length: {} bytes | Alignment: {} | MemoryType: {}",
        len, alignment, memory_type
    );
    
    // Allocate host page memory block to represent this direct memory
    match allocate_guest_memory(0, len) {
        Ok(ptr) => {
            unsafe {
                *phys_addr_out = ptr as u64;
            }
            0 // SCE_OK
        }
        Err(_) => 0x8002000Cu32 as i32, // Simulated error code (ENOMEM)
    }
}

#[no_mangle]
pub extern "sysv64" fn sceKernelMapDirectMemory(
    addr_in_out: *mut *mut u8,
    len: usize,
    prot: i32,
    flags: i32,
    direct_memory_start: u64,
    _alignment: usize,
) -> i32 {
    info!(
        "API Intercepted: sceKernelMapDirectMemory | DirectMemoryStart: 0x{:X} | Length: {} bytes | Prot: {} | Flags: {}",
        direct_memory_start, len, prot, flags
    );
    
    // In HLE emulator, mapping direct memory binds it to host virtual pages
    // We reuse the already allocated direct memory pointer as the mapped address
    unsafe {
        *addr_in_out = direct_memory_start as *mut u8;
    }
    
    register_guest_memory(direct_memory_start, direct_memory_start, len);
    
    // Register range in write-watch memory tracker to intercept updates
    crate::memory_tracker::register_range(direct_memory_start, len as u64);
    
    0
}

static ALLOCATIONS: std::sync::OnceLock<Mutex<HashMap<u64, usize>>> = std::sync::OnceLock::new();

pub fn is_valid_guest_ptr(ptr: u64, size: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    translate_guest_addr(ptr).is_some() && translate_guest_addr(ptr + size as u64 - 1).is_some()
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }
    if size > 0x1000000000 {
        error!("HLE malloc: allocation failed because size is suspiciously large: {} (0x{:X})", size, size);
        for offset in (-64..64).step_by(8) {
            let addr = (0x7000006cc1d0 as i64 + offset) as u64;
            if let Some(sym) = crate::loader::lookup_got_symbol(addr) {
                error!("  GOT[0x{:X}] = {}", addr, sym);
            }
        }
    }
    match allocate_guest_memory(0, size) {
        Ok(ptr) => {
            let addr = ptr as u64;
            let allocs_lock = ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()));
            let mut allocs = allocs_lock.lock().unwrap();
            allocs.insert(addr, size);
            register_guest_memory(addr, addr, size);
            debug!("HLE malloc: allocated size {} at pointer {:p}", size, ptr);
            ptr
        }
        Err(e) => {
            error!("HLE malloc: allocation failed for size {}: {}", size, e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let addr = ptr as u64;
    let allocs_lock = ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut allocs = allocs_lock.lock().unwrap();
    if let Some(size) = allocs.remove(&addr) {
        deallocate_guest_memory(addr, size);
        debug!("HLE free: deallocated pointer {:p} of size {}", ptr, size);
    } else {
        warn!("HLE free: attempted to free unknown pointer {:p}", ptr);
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_malloc_usable_size(ptr: *mut u8) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let addr = ptr as u64;
    let allocs_lock = ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()));
    let allocs = allocs_lock.lock().unwrap();
    allocs.get(&addr).copied().unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_calloc(num: usize, size: usize) -> *mut u8 {
    let total = num * size;
    let ptr = hle_malloc(total);
    if !ptr.is_null() {
        std::ptr::write_bytes(ptr, 0, total);
    }
    ptr
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
    if ptr.is_null() {
        return hle_malloc(new_size);
    }
    if new_size == 0 {
        hle_free(ptr);
        return std::ptr::null_mut();
    }
    
    let addr = ptr as u64;
    let old_size = {
        let allocs_lock = ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()));
        let allocs = allocs_lock.lock().unwrap();
        allocs.get(&addr).copied()
    };
    
    if let Some(size) = old_size {
        if size >= new_size {
            let allocs_lock = ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()));
            let mut allocs = allocs_lock.lock().unwrap();
            allocs.insert(addr, new_size);
            return ptr;
        }
        let new_ptr = hle_malloc(new_size);
        if !new_ptr.is_null() {
            std::ptr::copy_nonoverlapping(ptr, new_ptr, size);
            hle_free(ptr);
        }
        new_ptr
    } else {
        warn!("HLE realloc: attempted to reallocate unknown pointer {:p}", ptr);
        hle_malloc(new_size)
    }
}


// =========================================================================
// HLE POSIX Thread & Mutex Implementations
// =========================================================================

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_create(
    thread_out: *mut u64,
    _attr: *const u64,
    start_routine: u64,
    arg: u64,
) -> i32 {
    let new_tid = NEXT_TID.fetch_add(1, Ordering::SeqCst) as u64;
    info!("HLE pthread_create: Spawning thread {} with entry 0x{:X}...", new_tid, start_routine);
    
    if !thread_out.is_null() {
        *thread_out = new_tid;
    }
    
    let entry_fn: unsafe extern "sysv64" fn(u64) -> *mut std::ffi::c_void = std::mem::transmute(start_routine);
    
    let handle = std::thread::spawn(move || {
        CURRENT_TID.with(|cell| cell.set(new_tid as i32));
        
        let mut host_fs: u64 = 0;
        unsafe {
            std::arch::asm!("mov {}, fs:[0]", out(reg) host_fs);
        }
        
        let static_tls_size = crate::loader::STATIC_TLS_SIZE.load(Ordering::SeqCst);
        let tcb_size = 256;
        let total_size = static_tls_size + tcb_size;
        let layout = std::alloc::Layout::from_size_align(total_size, 64).unwrap();
        let guest_tls_mem = unsafe { std::alloc::alloc_zeroed(layout) };
        let guest_tcb_addr = guest_tls_mem as u64 + static_tls_size as u64;
        
        unsafe {
            *(guest_tcb_addr as *mut u64) = guest_tcb_addr;
            *((guest_tcb_addr + 0x40) as *mut u64) = host_fs;
            *((guest_tcb_addr + 0x48) as *mut u64) = guest_tcb_addr;
        }
        
        crate::hle_symbols::GUEST_FS.with(|fs| fs.set(guest_tcb_addr));
        
        unsafe {
            libc::syscall(libc::SYS_arch_prctl, 0x1002, guest_tcb_addr); // ARCH_SET_FS
        }
        
        info!("  [Host Thread {}] Executing pthread entry point with guest FS...", new_tid);
        unsafe {
            entry_fn(arg);
        }
        
        unsafe {
            libc::syscall(libc::SYS_arch_prctl, 0x1002, host_fs); // Restore host FS
        }
        
        info!("  [Host Thread {}] Terminated pthread execution.", new_tid);
    });
    
    let registry_mutex = THREAD_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    registry_mutex.lock().unwrap().insert(new_tid, handle);
    
    0 // Success
}

#[no_mangle]
pub extern "sysv64" fn hle_pthread_join(thread: u64, _retval: *mut *mut std::ffi::c_void) -> i32 {
    info!("HLE pthread_join: Joining thread {}...", thread);
    let registry_mutex = THREAD_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let handle_opt = {
        let mut registry = registry_mutex.lock().unwrap();
        registry.remove(&thread)
    };
    if let Some(handle) = handle_opt {
        if let Err(e) = handle.join() {
            error!("HLE pthread_join: Failed to join thread {}: {:?}", thread, e);
            return 22; // EINVAL
        }
        info!("HLE pthread_join: Thread {} successfully joined.", thread);
    } else {
        warn!("HLE pthread_join: Thread {} not found in registry (might have been joined or detached already).", thread);
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_mutex_init(
    mutex_ptr: *mut i32,
    _attr: *const u64,
) -> i32 {
    if !mutex_ptr.is_null() {
        *mutex_ptr = 0; // Initialize to unlocked
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_mutex_destroy(mutex_ptr: *mut i32) -> i32 {
    if !mutex_ptr.is_null() {
        let obj = mutex_ptr as u64;
        let recursions_lock = MUTEX_RECURSIONS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut recursions = recursions_lock.lock().unwrap();
        recursions.remove(&obj);
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_mutex_lock(mutex_ptr: *mut i32) -> i32 {
    if mutex_ptr.is_null() {
        return 22; // EINVAL
    }
    
    let current_tid = CURRENT_TID.with(|cell| cell.get());
    let obj = mutex_ptr as u64;
    
    loop {
        let atomic_ptr = mutex_ptr as *const std::sync::atomic::AtomicI32;
        let prev_val = (*atomic_ptr).compare_exchange(
            0,
            current_tid,
            Ordering::SeqCst,
            Ordering::SeqCst
        );
        
        match prev_val {
            Ok(_) => {
                debug!("hle_pthread_mutex_lock: Thread {} acquired mutex {:p}", current_tid, mutex_ptr);
                break;
            }
            Err(owner) => {
                if owner == current_tid {
                    debug!("hle_pthread_mutex_lock: Thread {} already owns mutex {:p} (recursive)", current_tid, mutex_ptr);
                    let recursions_lock = MUTEX_RECURSIONS.get_or_init(|| Mutex::new(HashMap::new()));
                    let mut recursions = recursions_lock.lock().unwrap();
                    let count = recursions.entry(obj).or_insert(0);
                    *count += 1;
                    break;
                }
                let current_thread = std::thread::current();
                {
                    let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
                    let mut queue = queue_mutex.lock().unwrap();
                    queue.entry(obj).or_default().push(current_thread);
                }
                debug!("hle_pthread_mutex_lock: Thread {} waiting on mutex {:p} owned by {}", current_tid, mutex_ptr, owner);
                std::thread::park();
            }
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_mutex_unlock(mutex_ptr: *mut i32) -> i32 {
    if mutex_ptr.is_null() {
        return 22; // EINVAL
    }
    
    let current_tid = CURRENT_TID.with(|cell| cell.get());
    let obj = mutex_ptr as u64;
    
    // Check if it's a recursive lock held by current thread
    let recursions_lock = MUTEX_RECURSIONS.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let mut recursions = recursions_lock.lock().unwrap();
        if let Some(count) = recursions.get_mut(&obj) {
            if *count > 0 {
                *count -= 1;
                debug!("hle_pthread_mutex_unlock: Thread {} decreased recursive lock count to {} on mutex {:p}", current_tid, *count, mutex_ptr);
                return 0;
            }
        }
    }
    
    let atomic_ptr = mutex_ptr as *const std::sync::atomic::AtomicI32;
    let prev_val = (*atomic_ptr).compare_exchange(
        current_tid,
        0,
        Ordering::SeqCst,
        Ordering::SeqCst
    );
    
    match prev_val {
        Ok(_) => {
            debug!("hle_pthread_mutex_unlock: Thread {} released mutex {:p}", current_tid, mutex_ptr);
            
            // Clean up the entry from recursions map if any
            {
                let mut recursions = recursions_lock.lock().unwrap();
                recursions.remove(&obj);
            }
            
            let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
            let mut queue = queue_mutex.lock().unwrap();
            if let Some(threads) = queue.get_mut(&obj) {
                if !threads.is_empty() {
                    let t = threads.remove(0);
                    debug!("hle_pthread_mutex_unlock: Waking thread {:?}", t.id());
                    t.unpark();
                }
            }
            0
        }
        Err(actual_owner) => {
            warn!("hle_pthread_mutex_unlock: Thread {} failed to unlock mutex {:p} (actual owner is {})", current_tid, mutex_ptr, actual_owner);
            22 // EINVAL
        }
    }
}

#[no_mangle]
pub extern "sysv64" fn hle_pthread_self() -> u64 {
    CURRENT_TID.with(|cell| cell.get()) as u64
}

// =========================================================================
// =========================================================================

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadCreate(
    thread_out: *mut u64,
    attr: *const u64,
    start_routine: u64,
    arg: u64,
    name: *const std::ffi::c_char,
) -> i32 {
    let name_str = if name.is_null() {
        "unnamed_guest_thread".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    info!("API Thread Intercepted: scePthreadCreate | Name: '{}' | Entry: 0x{:X}", name_str, start_routine);
    hle_pthread_create(thread_out, attr, start_routine, arg)
}

#[no_mangle]
pub extern "sysv64" fn scePthreadJoin(thread: u64, retval: *mut *mut std::ffi::c_void) -> i32 {
    info!("API Thread Intercepted: scePthreadJoin | Thread ID: {}", thread);
    hle_pthread_join(thread, retval)
}

#[no_mangle]
pub extern "sysv64" fn scePthreadSelf() -> u64 {
    hle_pthread_self()
}

#[no_mangle]
pub extern "sysv64" fn scePthreadExit(retval: *mut std::ffi::c_void) {
    info!("API Thread Intercepted: scePthreadExit");
    // In HLE, thread exits by returning, mock exit behavior
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadMutexInit(
    mutex_ptr: *mut i32,
    attr: *const u64,
    name: *const std::ffi::c_char,
) -> i32 {
    let name_str = if name.is_null() {
        "unnamed_mutex".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    info!("API Mutex Intercepted: scePthreadMutexInit | Name: '{}'", name_str);
    hle_pthread_mutex_init(mutex_ptr, attr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadMutexLock(mutex_ptr: *mut i32) -> i32 {
    debug!("API Mutex Intercepted: scePthreadMutexLock | Mutex: {:p}", mutex_ptr);
    hle_pthread_mutex_lock(mutex_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadMutexUnlock(mutex_ptr: *mut i32) -> i32 {
    debug!("API Mutex Intercepted: scePthreadMutexUnlock | Mutex: {:p}", mutex_ptr);
    hle_pthread_mutex_unlock(mutex_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadMutexDestroy(mutex_ptr: *mut i32) -> i32 {
    info!("API Mutex Intercepted: scePthreadMutexDestroy | Mutex: {:p}", mutex_ptr);
    hle_pthread_mutex_destroy(mutex_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadCondInit(
    cond_ptr: *mut i32,
    _attr: *const u64,
    name: *const std::ffi::c_char,
) -> i32 {
    let name_str = if name.is_null() {
        "unnamed_condvar".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    info!("API CondVar Intercepted: scePthreadCondInit | Name: '{}'", name_str);
    if !cond_ptr.is_null() {
        *cond_ptr = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadCondDestroy(cond_ptr: *mut i32) -> i32 {
    info!("API CondVar Intercepted: scePthreadCondDestroy | CondVar: {:p}", cond_ptr);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadCondWait(cond_ptr: *mut i32, mutex_ptr: *mut i32) -> i32 {
    if cond_ptr.is_null() || mutex_ptr.is_null() {
        return 22; // EINVAL
    }
    let current_tid = CURRENT_TID.with(|cell| cell.get());
    let cond_obj = cond_ptr as u64;

    debug!("API CondVar Intercepted: scePthreadCondWait | CondVar: {:p} | Mutex: {:p} (Thread {})", cond_ptr, mutex_ptr, current_tid);

    // 1. Release the mutex before waiting
    hle_pthread_mutex_unlock(mutex_ptr);

    // 2. Park the thread on the condvar address
    let current_thread = std::thread::current();
    {
        let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut queue = queue_mutex.lock().unwrap();
        queue.entry(cond_obj).or_default().push(current_thread);
    }
    std::thread::park();
    debug!("scePthreadCondWait: Thread {} awoke from condvar {:p}, re-acquiring mutex {:p}...", current_tid, cond_ptr, mutex_ptr);

    // 3. Re-acquire the mutex after waking up
    hle_pthread_mutex_lock(mutex_ptr);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadCondSignal(cond_ptr: *mut i32) -> i32 {
    if cond_ptr.is_null() {
        return 22; // EINVAL
    }
    let cond_obj = cond_ptr as u64;
    debug!("API CondVar Intercepted: scePthreadCondSignal | CondVar: {:p}", cond_ptr);
    let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut queue = queue_mutex.lock().unwrap();
    if let Some(threads) = queue.get_mut(&cond_obj) {
        if !threads.is_empty() {
            let t = threads.remove(0);
            debug!("scePthreadCondSignal: Waking up thread {:?}", t.id());
            t.unpark();
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadCondBroadcast(cond_ptr: *mut i32) -> i32 {
    if cond_ptr.is_null() {
        return 22; // EINVAL
    }
    let cond_obj = cond_ptr as u64;
    debug!("API CondVar Intercepted: scePthreadCondBroadcast | CondVar: {:p}", cond_ptr);
    let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut queue = queue_mutex.lock().unwrap();
    if let Some(threads) = queue.get_mut(&cond_obj) {
        let to_wake: Vec<std::thread::Thread> = threads.drain(..).collect();
        debug!("scePthreadCondBroadcast: Waking up all {} threads waiting on condvar {:p}...", to_wake.len(), cond_ptr);
        for t in to_wake {
            t.unpark();
        }
    }
    0
}

struct HleSemaphore {
    value: i32,
    waiters: Vec<std::thread::Thread>,
}

static SEMAPHORES: std::sync::OnceLock<Mutex<HashMap<u64, HleSemaphore>>> = std::sync::OnceLock::new();

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadSemInit(
    sem_ptr: *mut i32,
    value: i32,
    name: *const std::ffi::c_char,
) -> i32 {
    let name_str = if name.is_null() {
        "unnamed_sem".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    info!("API Semaphore Intercepted: scePthreadSemInit | Name: '{}' | Value: {}", name_str, value);
    if !sem_ptr.is_null() {
        *sem_ptr = value;
        let sems_mutex = SEMAPHORES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut sems = sems_mutex.lock().unwrap();
        sems.insert(sem_ptr as u64, HleSemaphore {
            value,
            waiters: Vec::new(),
        });
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadSemDestroy(sem_ptr: *mut i32) -> i32 {
    info!("API Semaphore Intercepted: scePthreadSemDestroy | Semaphore: {:p}", sem_ptr);
    if !sem_ptr.is_null() {
        let sems_mutex = SEMAPHORES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut sems = sems_mutex.lock().unwrap();
        sems.remove(&(sem_ptr as u64));
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadSemWait(sem_ptr: *mut i32) -> i32 {
    if sem_ptr.is_null() {
        return 22; // EINVAL
    }
    let current_tid = CURRENT_TID.with(|cell| cell.get());
    let sem_obj = sem_ptr as u64;

    loop {
        let sems_mutex = SEMAPHORES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut sems = sems_mutex.lock().unwrap();
        let sem = sems.entry(sem_obj).or_insert(HleSemaphore {
            value: 0,
            waiters: Vec::new(),
        });
        if sem.value > 0 {
            sem.value -= 1;
            *sem_ptr = sem.value;
            debug!("scePthreadSemWait: Thread {} acquired semaphore {:p} (value remaining: {})", current_tid, sem_ptr, sem.value);
            return 0;
        }
        let current_thread = std::thread::current();
        sem.waiters.push(current_thread);
        
        debug!("scePthreadSemWait: Thread {} waiting on semaphore {:p}...", current_tid, sem_ptr);
        drop(sems);
        std::thread::park();
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn scePthreadSemPost(sem_ptr: *mut i32) -> i32 {
    if sem_ptr.is_null() {
        return 22; // EINVAL
    }
    let sem_obj = sem_ptr as u64;
    debug!("API Semaphore Intercepted: scePthreadSemPost | Semaphore: {:p}", sem_ptr);
    let sems_mutex = SEMAPHORES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut sems = sems_mutex.lock().unwrap();
    let sem = sems.entry(sem_obj).or_insert(HleSemaphore {
        value: 0,
        waiters: Vec::new(),
    });
    sem.value += 1;
    *sem_ptr = sem.value;
    if !sem.waiters.is_empty() {
        let t = sem.waiters.remove(0);
        debug!("scePthreadSemPost: Waking thread {:?}", t.id());
        t.unpark();
    }
    0
}

static DOORBELL_PAGES: std::sync::OnceLock<Mutex<Vec<u64>>> = std::sync::OnceLock::new();

pub fn register_doorbell_page(addr: u64) {
    let pages = DOORBELL_PAGES.get_or_init(|| Mutex::new(Vec::new()));
    pages.lock().unwrap().push(addr);
    info!("Registered HLE Doorbell Page: 0x{:X}", addr);
}

pub fn write_guest_doorbell(addr: u64, value: u32) {
    let host_ptr = match translate_guest_addr(addr) {
        Some(ptr) => ptr as *mut u32,
        None => addr as *mut u32,
    };
    if !host_ptr.is_null() {
        unsafe {
            std::ptr::write_volatile(host_ptr, value);
        }
    }
    crate::gpu_queue::trigger_doorbell(addr, value);
}

// =========================================================================
// JIT Shared Memory IPC Implementation
// =========================================================================

const ENOMEM: i32 = 0x8002000Cu32 as i32;
const EINVAL: i32 = 0x80020016u32 as i32;
const EBADF: i32 = 0x80020009u32 as i32;

#[derive(Debug, Clone)]
pub struct JitSharedMemoryInfo {
    pub name: String,
    pub len: u64,
    pub max_prot: i32,
    pub host_ptr: u64,
    pub guest_addr: u64,
}

static JIT_SHARED_MEM: std::sync::OnceLock<Mutex<HashMap<i32, JitSharedMemoryInfo>>> = std::sync::OnceLock::new();
static NEXT_JIT_FD: AtomicI32 = AtomicI32::new(500);

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelJitCreateSharedMemory(
    name: u64,
    len: u64,
    max_prot: i32,
    fd_out: u64,
) -> i32 {
    let name_str = if name == 0 {
        "unnamed_jit".to_string()
    } else {
        let host_name_ptr = match translate_guest_addr(name) {
            Some(addr) => addr as *const std::os::raw::c_char,
            None => name as *const std::os::raw::c_char,
        };
        std::ffi::CStr::from_ptr(host_name_ptr).to_string_lossy().into_owned()
    };

    info!(
        "sceKernelJitCreateSharedMemory: name = '{}', len = {} bytes, maxProt = 0x{:X}",
        name_str, len, max_prot
    );

    let host_ptr = match allocate_guest_memory(0, len as usize) {
        Ok(ptr) => ptr as u64,
        Err(e) => {
            error!("sceKernelJitCreateSharedMemory: mmap allocation failed: {}", e);
            return ENOMEM;
        }
    };

    let host_fd_out = match translate_guest_addr(fd_out) {
        Some(addr) => addr as *mut i32,
        None => fd_out as *mut i32,
    };
    if host_fd_out.is_null() {
        deallocate_guest_memory(host_ptr, len as usize);
        return EINVAL;
    }

    let fd = NEXT_JIT_FD.fetch_add(1, Ordering::SeqCst);
    let info = JitSharedMemoryInfo {
        name: name_str,
        len,
        max_prot,
        host_ptr,
        guest_addr: 0,
    };

    let map = JIT_SHARED_MEM.get_or_init(|| Mutex::new(HashMap::new()));
    map.lock().unwrap().insert(fd, info);

    *host_fd_out = fd;
    info!("sceKernelJitCreateSharedMemory: Created JIT memory fd = {}", fd);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelJitCreateAliasOfSharedMemory(
    fd: i32,
    max_prot: i32,
    fd_out: u64,
) -> i32 {
    info!(
        "sceKernelJitCreateAliasOfSharedMemory: parent_fd = {}, maxProt = 0x{:X}",
        fd, max_prot
    );

    let map = JIT_SHARED_MEM.get_or_init(|| Mutex::new(HashMap::new()));
    let parent_info = {
        let guard = map.lock().unwrap();
        match guard.get(&fd) {
            Some(info) => info.clone(),
            None => return EBADF,
        }
    };

    let host_fd_out = match translate_guest_addr(fd_out) {
        Some(addr) => addr as *mut i32,
        None => fd_out as *mut i32,
    };
    if host_fd_out.is_null() {
        return EINVAL;
    }

    let alias_fd = NEXT_JIT_FD.fetch_add(1, Ordering::SeqCst);
    let info = JitSharedMemoryInfo {
        name: format!("{}_alias", parent_info.name),
        len: parent_info.len,
        max_prot,
        host_ptr: parent_info.host_ptr,
        guest_addr: parent_info.guest_addr,
    };

    map.lock().unwrap().insert(alias_fd, info);
    *host_fd_out = alias_fd;
    info!("sceKernelJitCreateAliasOfSharedMemory: Created JIT alias fd = {}", alias_fd);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelJitMapSharedMemory(
    fd: i32,
    prot: i32,
    start_out: u64,
) -> i32 {
    info!("sceKernelJitMapSharedMemory: fd = {}, prot = 0x{:X}", fd, prot);

    let host_start_out = match translate_guest_addr(start_out) {
        Some(addr) => addr as *mut u64,
        None => start_out as *mut u64,
    };
    if host_start_out.is_null() {
        return EINVAL;
    }

    let map = JIT_SHARED_MEM.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap();
    if let Some(info) = guard.get_mut(&fd) {
        register_guest_memory(info.host_ptr, info.host_ptr, info.len as usize);
        info.guest_addr = info.host_ptr;
        
        *host_start_out = info.host_ptr;
        info!("sceKernelJitMapSharedMemory: Mapped JIT fd = {} to guest addr 0x{:X}", fd, info.guest_addr);
        0
    } else {
        EBADF
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelJitGetSharedMemoryInfo(
    fd: i32,
    name: u64,
    name_buffer_size: i32,
    start_out: u64,
    len_out: u64,
    max_prot_out: u64,
) -> i32 {
    info!("sceKernelJitGetSharedMemoryInfo: fd = {}", fd);

    let map = JIT_SHARED_MEM.get_or_init(|| Mutex::new(HashMap::new()));
    let guard = map.lock().unwrap();
    if let Some(info) = guard.get(&fd) {
        if name != 0 && name_buffer_size > 0 {
            let host_name = match translate_guest_addr(name) {
                Some(addr) => addr as *mut u8,
                None => name as *mut u8,
            };
            if !host_name.is_null() {
                let name_bytes = info.name.as_bytes();
                let copy_len = name_bytes.len().min((name_buffer_size - 1) as usize);
                std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), host_name, copy_len);
                *host_name.add(copy_len) = 0; // Null terminator
            }
        }

        if start_out != 0 {
            let host_start_out = match translate_guest_addr(start_out) {
                Some(addr) => addr as *mut u64,
                None => start_out as *mut u64,
            };
            if !host_start_out.is_null() {
                *host_start_out = info.guest_addr;
            }
        }

        if len_out != 0 {
            let host_len_out = match translate_guest_addr(len_out) {
                Some(addr) => addr as *mut u64,
                None => len_out as *mut u64,
            };
            if !host_len_out.is_null() {
                *host_len_out = info.len;
            }
        }

        if max_prot_out != 0 {
            let host_max_prot_out = match translate_guest_addr(max_prot_out) {
                Some(addr) => addr as *mut i32,
                None => max_prot_out as *mut i32,
            };
            if !host_max_prot_out.is_null() {
                *host_max_prot_out = info.max_prot;
            }
        }

        0
    } else {
        EBADF
    }
}

// =========================================================================
// =========================================================================

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DinkumXtime {
    pub sec: i64,
    pub nsec: i64,
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Mtx_init(mutex_ptr: *mut i32, _type: i32) -> i32 {
    info!("Dinkumware: _Mtx_init | Mutex: {:p}", mutex_ptr);
    if !mutex_ptr.is_null() {
        *mutex_ptr = 0;
    }
    0 // _Thrd_success
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Mtx_init_with_name(
    mutex_ptr: *mut i32,
    _type: i32,
    name: *const std::ffi::c_char,
) -> i32 {
    let name_str = if name.is_null() {
        "unnamed_mtx".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    info!("Dinkumware: _Mtx_init_with_name | Mutex: {:p} | Name: '{}'", mutex_ptr, name_str);
    if !mutex_ptr.is_null() {
        *mutex_ptr = 0;
    }
    0 // _Thrd_success
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Mtx_destroy(mutex_ptr: *mut i32) {
    info!("Dinkumware: _Mtx_destroy | Mutex: {:p}", mutex_ptr);
    hle_pthread_mutex_destroy(mutex_ptr);
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Mtx_lock(mutex_ptr: *mut i32) -> i32 {
    info!("Dinkumware: _Mtx_lock | Mutex: {:p}", mutex_ptr);
    hle_pthread_mutex_lock(mutex_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Mtx_unlock(mutex_ptr: *mut i32) -> i32 {
    info!("Dinkumware: _Mtx_unlock | Mutex: {:p}", mutex_ptr);
    hle_pthread_mutex_unlock(mutex_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Mtx_timedlock(mutex_ptr: *mut i32, _xt_ptr: *const DinkumXtime) -> i32 {
    info!("Dinkumware: _Mtx_timedlock | Mutex: {:p}", mutex_ptr);
    hle_pthread_mutex_lock(mutex_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Mtx_trylock(mutex_ptr: *mut i32) -> i32 {
    info!("Dinkumware: _Mtx_trylock | Mutex: {:p}", mutex_ptr);
    if mutex_ptr.is_null() {
        return 4; // _Thrd_error
    }
    let current_tid = CURRENT_TID.with(|cell| cell.get());
    let obj = mutex_ptr as u64;
    let atomic_ptr = mutex_ptr as *const std::sync::atomic::AtomicI32;
    let prev_val = (*atomic_ptr).compare_exchange(
        0,
        current_tid,
        Ordering::SeqCst,
        Ordering::SeqCst
    );
    match prev_val {
        Ok(_) => {
            info!("hle_Mtx_trylock: Thread {} acquired mutex {:p}", current_tid, mutex_ptr);
            0 // _Thrd_success
        }
        Err(owner) => {
            if owner == current_tid {
                info!("hle_Mtx_trylock: Thread {} already owns mutex {:p} (recursive)", current_tid, mutex_ptr);
                let recursions_lock = MUTEX_RECURSIONS.get_or_init(|| Mutex::new(HashMap::new()));
                let mut recursions = recursions_lock.lock().unwrap();
                let count = recursions.entry(obj).or_insert(0);
                *count += 1;
                0 // _Thrd_success
            } else {
                3 // _Thrd_busy
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Cnd_init(cond_ptr: *mut i32) -> i32 {
    info!("Dinkumware: _Cnd_init | CondVar: {:p}", cond_ptr);
    if !cond_ptr.is_null() {
        *cond_ptr = 0;
    }
    0 // _Thrd_success
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Cnd_init_with_name(
    cond_ptr: *mut i32,
    name: *const std::ffi::c_char,
) -> i32 {
    let name_str = if name.is_null() {
        "unnamed_cnd".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    info!("Dinkumware: _Cnd_init_with_name | CondVar: {:p} | Name: '{}'", cond_ptr, name_str);
    if !cond_ptr.is_null() {
        *cond_ptr = 0;
    }
    0 // _Thrd_success
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Cnd_destroy(cond_ptr: *mut i32) {
    info!("Dinkumware: _Cnd_destroy | CondVar: {:p}", cond_ptr);
    if !cond_ptr.is_null() {
        let cond_obj = cond_ptr as u64;
        let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut queue = queue_mutex.lock().unwrap();
        queue.remove(&cond_obj);
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Cnd_signal(cond_ptr: *mut i32) -> i32 {
    info!("Dinkumware: _Cnd_signal | CondVar: {:p}", cond_ptr);
    scePthreadCondSignal(cond_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Cnd_broadcast(cond_ptr: *mut i32) -> i32 {
    info!("Dinkumware: _Cnd_broadcast | CondVar: {:p}", cond_ptr);
    scePthreadCondBroadcast(cond_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Cnd_wait(cond_ptr: *mut i32, mutex_ptr: *mut i32) -> i32 {
    info!("Dinkumware: _Cnd_wait | CondVar: {:p} | Mutex: {:p}", cond_ptr, mutex_ptr);
    scePthreadCondWait(cond_ptr, mutex_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Cnd_timedwait(
    cond_ptr: *mut i32,
    mutex_ptr: *mut i32,
    xt_ptr: *const DinkumXtime,
) -> i32 {
    if cond_ptr.is_null() || mutex_ptr.is_null() {
        return 4; // _Thrd_error
    }
    info!("Dinkumware: _Cnd_timedwait | CondVar: {:p} | Mutex: {:p} | Xtime: {:p}", cond_ptr, mutex_ptr, xt_ptr);
    
    // Release the mutex before waiting
    hle_pthread_mutex_unlock(mutex_ptr);
    
    let cond_obj = cond_ptr as u64;
    let current_thread = std::thread::current();
    {
        let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut queue = queue_mutex.lock().unwrap();
        queue.entry(cond_obj).or_default().push(current_thread);
    }
    
    let mut timed_out = false;
    if !xt_ptr.is_null() {
        let xt = &*xt_ptr;
        // Calculate timeout duration
        let now = std::time::SystemTime::now();
        let epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let target_sec = xt.sec as u64;
        let target_nsec = xt.nsec as u32;
        
        let target_duration = std::time::Duration::new(target_sec, target_nsec);
        if target_duration > epoch {
            let delay = target_duration - epoch;
            std::thread::park_timeout(delay);
            
            // Check if we are still in the wait queue. If we are, it means we timed out.
            let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
            let mut queue = queue_mutex.lock().unwrap();
            if let Some(threads) = queue.get_mut(&cond_obj) {
                let current_tid = std::thread::current().id();
                if let Some(pos) = threads.iter().position(|t| t.id() == current_tid) {
                    threads.remove(pos);
                    timed_out = true;
                }
            }
        } else {
            // Already expired
            let queue_mutex = WAIT_QUEUE.get_or_init(|| Mutex::new(HashMap::new()));
            let mut queue = queue_mutex.lock().unwrap();
            if let Some(threads) = queue.get_mut(&cond_obj) {
                let current_tid = std::thread::current().id();
                if let Some(pos) = threads.iter().position(|t| t.id() == current_tid) {
                    threads.remove(pos);
                }
            }
            timed_out = true;
        }
    } else {
        std::thread::park();
    }
    
    // Re-acquire the mutex
    hle_pthread_mutex_lock(mutex_ptr);
    
    if timed_out {
        2 // _Thrd_timedout
    } else {
        0 // _Thrd_success
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_memory_ipc() {
        let name = std::ffi::CString::new("my_shared_memory").unwrap();
        let mut fd = 0i32;
        let res = unsafe {
            sceKernelJitCreateSharedMemory(
                name.as_ptr() as u64,
                4096,
                0x7, // PROT_READ | PROT_WRITE | PROT_EXEC
                &mut fd as *mut i32 as u64,
            )
        };
        assert_eq!(res, 0);
        assert!(fd >= 500);

        // Alias creation
        let mut alias_fd = 0i32;
        let res_alias = unsafe {
            sceKernelJitCreateAliasOfSharedMemory(
                fd,
                0x3, // PROT_READ | PROT_WRITE
                &mut alias_fd as *mut i32 as u64,
            )
        };
        assert_eq!(res_alias, 0);
        assert!(alias_fd >= 500);
        assert_ne!(fd, alias_fd);

        // Mapping original
        let mut addr = 0u64;
        let res_map = unsafe {
            sceKernelJitMapSharedMemory(fd, 0x3, &mut addr as *mut u64 as u64)
        };
        assert_eq!(res_map, 0);
        assert_ne!(addr, 0);

        // Verify we can write to it
        let ptr = addr as *mut u32;
        unsafe {
            *ptr = 0xDEADBEEF;
        }

        // Mapping alias
        let mut alias_addr = 0u64;
        let res_alias_map = unsafe {
            sceKernelJitMapSharedMemory(alias_fd, 0x3, &mut alias_addr as *mut u64 as u64)
        };
        assert_eq!(res_alias_map, 0);
        assert_eq!(alias_addr, addr);

        unsafe {
            assert_eq!(*ptr, 0xDEADBEEF);
            assert_eq!(*(alias_addr as *mut u32), 0xDEADBEEF);
        }

        // Get info
        let mut info_name = [0u8; 32];
        let mut start = 0u64;
        let mut len = 0u64;
        let mut max_prot = 0i32;
        let res_info = unsafe {
            sceKernelJitGetSharedMemoryInfo(
                fd,
                info_name.as_mut_ptr() as u64,
                32,
                &mut start as *mut u64 as u64,
                &mut len as *mut u64 as u64,
                &mut max_prot as *mut i32 as u64,
            )
        };
        assert_eq!(res_info, 0);
        let name_str = std::ffi::CStr::from_bytes_until_nul(&info_name)
            .unwrap()
            .to_string_lossy();
        assert!(name_str.starts_with("my_shared_memory"));
        assert_eq!(start, addr);
        assert_eq!(len, 4096);
        assert_eq!(max_prot, 0x7);
    }
}


