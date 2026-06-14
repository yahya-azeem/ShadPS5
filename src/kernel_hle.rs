use log::{info, error, warn, debug};
use std::collections::HashMap;
use std::sync::Mutex;
use std::fs::File;
use std::path::PathBuf;

// Global thread-safe registry to map guest virtual file descriptors to host file handles.
static ACTIVE_FILES: Mutex<Option<HashMap<i32, File>>> = Mutex::new(None);
static mut FILE_COUNTER: i32 = 100;

pub fn initialize_fs() {
    let mut files = ACTIVE_FILES.lock().unwrap();
    if files.is_none() {
        *files = Some(HashMap::new());
    }
}

/// Translates guest path virtual structures (e.g. `/app0/`, `/hostapp/`) to sandbox paths.
pub fn translate_guest_path(guest_path: &str) -> PathBuf {
    // Sandbox root base folder
    let sandbox_base = std::path::Path::new("game_root");
    
    // Normalize path formatting to bypass host specific differences
    let clean_path = guest_path
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string();
        
    let final_path = sandbox_base.join(clean_path);
    
    // Ensure the localized folder container directory hierarchy exists
    if let Some(parent) = final_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    
    final_path
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelOpen(path_ptr: u64, flags: i32, mode: u64) -> i32 {
    initialize_fs();
    if path_ptr == 0 {
        return -1; // EINVAL
    }
    let cstr = std::ffi::CStr::from_ptr(path_ptr as *const std::os::raw::c_char);
    let path_str = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let host_path = translate_guest_path(path_str);
    info!("sceKernelOpen: guest path '{}' -> host path '{:?}'", path_str, host_path);
    
    // Translate FreeBSD open flag bits to Rust standard options
    let mut options = std::fs::OpenOptions::new();
    let read = (flags & 3) == 0 || (flags & 3) == 2;
    let write = (flags & 3) == 1 || (flags & 3) == 2;
    options.read(read);
    options.write(write);
    
    if (flags & 0x0200) != 0 { // O_CREAT
        options.create(true);
    }
    if (flags & 0x0400) != 0 { // O_TRUNC
        options.truncate(true);
    }
    if (flags & 0x0008) != 0 { // O_APPEND
        options.append(true);
    }
    
    if write && (flags & 0x0200) == 0 {
        options.create(false);
    }
    
    match options.open(&host_path) {
        Ok(file) => {
            let mut files_guard = ACTIVE_FILES.lock().unwrap();
            let files = files_guard.as_mut().unwrap();
            let fd = FILE_COUNTER;
            FILE_COUNTER += 1;
            files.insert(fd, file);
            info!("sceKernelOpen: opened file successfully. Descriptor fd={}", fd);
            fd
        }
        Err(e) => {
            let raw_error = e.raw_os_error().unwrap_or(2); // Default to ENOENT
            let error_code = 0x80020000 | (raw_error as u32);
            error!("sceKernelOpen: failed to open host file '{:?}': {} (error code: 0x{:X})", host_path, e, error_code);
            error_code as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelRead(fd: i32, buf_ptr: u64, nbytes: u64) -> u64 {
    initialize_fs();
    let mut files_guard = ACTIVE_FILES.lock().unwrap();
    let files = files_guard.as_mut().unwrap();
    if let Some(file) = files.get_mut(&fd) {
        let host_buf = if let Some(addr) = crate::kernel::translate_guest_addr(buf_ptr) {
            addr as *mut u8
        } else {
            buf_ptr as *mut u8
        };
        
        let slice = std::slice::from_raw_parts_mut(host_buf, nbytes as usize);
        match std::io::Read::read(file, slice) {
            Ok(bytes_read) => {
                debug!("sceKernelRead: read {} bytes from fd {}", bytes_read, fd);
                bytes_read as u64
            }
            Err(e) => {
                error!("sceKernelRead: failed to read from fd {}: {}", fd, e);
                u64::MAX
            }
        }
    } else {
        warn!("sceKernelRead: fd {} not found in HLE registry", fd);
        u64::MAX
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelWrite(fd: i32, buf_ptr: u64, nbytes: u64) -> u64 {
    initialize_fs();
    if fd == 1 || fd == 2 {
        let host_buf = if let Some(addr) = crate::kernel::translate_guest_addr(buf_ptr) {
            addr as *const u8
        } else {
            buf_ptr as *const u8
        };
        let slice = std::slice::from_raw_parts(host_buf, nbytes as usize);
        if let Ok(text) = std::str::from_utf8(slice) {
            info!("[Guest Output] {}", text.trim_end());
        }
        return nbytes;
    }
    
    let mut files_guard = ACTIVE_FILES.lock().unwrap();
    let files = files_guard.as_mut().unwrap();
    if let Some(file) = files.get_mut(&fd) {
        let host_buf = if let Some(addr) = crate::kernel::translate_guest_addr(buf_ptr) {
            addr as *const u8
        } else {
            buf_ptr as *const u8
        };
        
        let slice = std::slice::from_raw_parts(host_buf, nbytes as usize);
        match std::io::Write::write(file, slice) {
            Ok(bytes_written) => {
                debug!("sceKernelWrite: wrote {} bytes to fd {}", bytes_written, fd);
                bytes_written as u64
            }
            Err(e) => {
                error!("sceKernelWrite: failed to write to fd {}: {}", fd, e);
                u64::MAX
            }
        }
    } else {
        warn!("sceKernelWrite: fd {} not found in HLE registry", fd);
        u64::MAX
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelLseek(fd: i32, offset: u64, whence: i32) -> u64 {
    initialize_fs();
    let mut files_guard = ACTIVE_FILES.lock().unwrap();
    let files = files_guard.as_mut().unwrap();
    if let Some(file) = files.get_mut(&fd) {
        use std::io::Seek;
        let pos = match whence {
            0 => std::io::SeekFrom::Start(offset),
            1 => std::io::SeekFrom::Current(offset as i64),
            2 => std::io::SeekFrom::End(offset as i64),
            _ => {
                error!("sceKernelLseek: invalid whence value {} for fd {}", whence, fd);
                return u64::MAX;
            }
        };
        match file.seek(pos) {
            Ok(new_pos) => {
                debug!("sceKernelLseek: seeked fd {} to offset {}", fd, new_pos);
                new_pos
            }
            Err(e) => {
                error!("sceKernelLseek: seek failed for fd {}: {}", fd, e);
                u64::MAX
            }
        }
    } else {
        warn!("sceKernelLseek: fd {} not found in HLE registry", fd);
        u64::MAX
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelClose(fd: i32) -> i32 {
    initialize_fs();
    let mut files_guard = ACTIVE_FILES.lock().unwrap();
    let files = files_guard.as_mut().unwrap();
    if files.remove(&fd).is_some() {
        info!("sceKernelClose: closed descriptor fd={}", fd);
        0
    } else {
        warn!("sceKernelClose: fd {} not found in HLE registry", fd);
        0x80020009u32 as i32
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelLoadStartModule(
    path_ptr: u64,
    argc: u32,
    argv: u64,
    flags: u32,
    _opt: u64,
    res_out: *mut i32,
) -> i32 {
    if path_ptr == 0 {
        return -1; // EINVAL
    }
    let cstr = std::ffi::CStr::from_ptr(path_ptr as *const std::os::raw::c_char);
    let path_str = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let host_path = translate_guest_path(path_str);
    info!("sceKernelLoadStartModule: loading module from '{}' (host: '{:?}')", path_str, host_path);
    
    match crate::loader::load_sprx_module(&host_path) {
        Ok(mod_id) => {
            let entrypoint = {
                let modules = crate::loader::get_loaded_modules();
                modules.get(&mod_id).map(|m| m.entrypoint).unwrap_or(0)
            };
            
            if entrypoint != 0 {
                info!("sceKernelLoadStartModule: spawning thread to execute entrypoint 0x{:X}", entrypoint);
                let entry_fn: unsafe extern "sysv64" fn(u32, u64) -> i32 = std::mem::transmute(entrypoint);
                std::thread::spawn(move || {
                    let res = entry_fn(argc, argv);
                    info!("Module ID {} entrypoint returned {}", mod_id, res);
                });
            }
            
            if !res_out.is_null() {
                *res_out = 0;
            }
            mod_id as i32
        }
        Err(e) => {
            error!("sceKernelLoadStartModule error: {:?}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelStopUnloadModule(
    mod_id: i32,
    _argc: u32,
    _argv: u64,
    _flags: u32,
    _opt: u64,
    res_out: *mut i32,
) -> i32 {
    info!("sceKernelStopUnloadModule: stopping and unloading module ID {}", mod_id);
    crate::loader::unload_sprx_module(mod_id as u32);
    if !res_out.is_null() {
        *res_out = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelCreateGpuQueue(
    queue_type: u32,
    ring_base: u64,
    ring_size: u32,
    rptr_addr: u64,
    wptr_addr: u64,
    doorbell_addr: u64,
    queue_id_out: *mut u32,
) -> i32 {
    info!(
        "API Intercepted: sceKernelCreateGpuQueue | Type: {} | RingBase: 0x{:X} | Size: {} bytes | RptrAddr: 0x{:X} | WptrAddr: 0x{:X} | Doorbell: 0x{:X}",
        queue_type, ring_base, ring_size, rptr_addr, wptr_addr, doorbell_addr
    );

    // Register guest memory segments so they are mapped and tracked on the host
    crate::kernel::register_guest_memory(ring_base, ring_base, ring_size as usize);
    crate::kernel::register_guest_memory(rptr_addr, rptr_addr, 4);
    crate::kernel::register_guest_memory(wptr_addr, wptr_addr, 4);
    crate::kernel::register_guest_memory(doorbell_addr, doorbell_addr, 4);
    crate::kernel::register_doorbell_page(doorbell_addr);

    let q_type = if queue_type == 0 {
        crate::gpu_queue::GpuQueueType::Graphics
    } else {
        crate::gpu_queue::GpuQueueType::Compute
    };

    // Register ring buffer in CP and spawn background runner thread
    let ring = crate::gpu_queue::GpuRingBuffer {
        ring_base,
        ring_size,
        rptr_addr,
        wptr_addr,
        doorbell_addr,
        queue_type: q_type,
    };

    let cp = crate::gpu_queue::CommandProcessor::new(ring);

    if !queue_id_out.is_null() {
        *queue_id_out = cp.queue_id;
    }

    0 // SCE_OK
}

#[no_mangle]
pub extern "sysv64" fn sceKernelMapGpuRing(queue_id: u32) -> i32 {
    info!("API Intercepted: sceKernelMapGpuRing | Queue ID: {}", queue_id);
    0 // SCE_OK
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelReserveVirtualRange(
    addr: *mut *mut u8,
    len: usize,
    flags: i32,
    alignment: usize,
) -> i32 {
    info!(
        "sceKernelReserveVirtualRange: addr={:?}, len={}, flags={}, alignment={}",
        addr, len, flags, alignment
    );
    if addr.is_null() {
        return 0x80020016u32 as i32; // EINVAL
    }
    let hint = *addr as u64;
    match crate::kernel::allocate_guest_memory(hint, len) {
        Ok(ptr) => {
            *addr = ptr;
            0 // SCE_OK
        }
        Err(_) => 0x8002000Cu32 as i32, // ENOMEM
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelMapNamedDirectMemory(
    addr: *mut *mut u8,
    len: usize,
    prot: i32,
    flags: i32,
    direct_memory_start: u64,
    alignment: usize,
    name: *const std::os::raw::c_char,
) -> i32 {
    let name_str = if name.is_null() {
        "anon".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    info!(
        "sceKernelMapNamedDirectMemory: name='{}', addr={:?}, len={}, prot={}, flags={}, direct_memory_start=0x{:X}, alignment={}",
        name_str, addr, len, prot, flags, direct_memory_start, alignment
    );
    if addr.is_null() {
        return 0x80020016u32 as i32; // EINVAL
    }
    
    *addr = direct_memory_start as *mut u8;
    
    crate::kernel::register_guest_memory(direct_memory_start, direct_memory_start, len);
    
    // Register range in write-watch memory tracker to intercept GPU resources updates
    crate::memory_tracker::register_range(direct_memory_start, len as u64);
    
    0 // SCE_OK
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceKernelFstat(fd: i32, sb_ptr: u64) -> i32 {
    initialize_fs();
    if sb_ptr == 0 {
        return -1; // EINVAL
    }
    
    let host_sb = if let Some(addr) = crate::kernel::translate_guest_addr(sb_ptr) {
        addr as *mut u8
    } else {
        sb_ptr as *mut u8
    };

    // Zero out the guest stat buffer to avoid garbage values (such as host return addresses)
    std::ptr::write_bytes(host_sb, 0, 120);

    let mut files_guard = ACTIVE_FILES.lock().unwrap();
    let files = files_guard.as_mut().unwrap();
    if let Some(file) = files.get(&fd) {
        if let Ok(metadata) = file.metadata() {
            let size = metadata.len();
            debug!("sceKernelFstat: fd {} size is {} bytes", fd, size);
            // st_size is at offset 72 of the guest stat struct
            std::ptr::write(host_sb.add(72) as *mut u64, size);
            0 // success
        } else {
            error!("sceKernelFstat: failed to get metadata for fd {}", fd);
            -1
        }
    } else {
        warn!("sceKernelFstat: fd {} not found in HLE registry", fd);
        -1
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::write;

    #[test]
    fn test_hle_fs_sandbox() {
        // Test guest path translation
        let translated = translate_guest_path("/app0/eboot.bin");
        assert_eq!(translated, std::path::Path::new("game_root/app0/eboot.bin"));

        // Setup test file
        let test_dir = std::path::Path::new("game_root/app0");
        let _ = std::fs::create_dir_all(test_dir);
        let file_path = test_dir.join("test_file.txt");
        let _ = write(&file_path, b"Hello PS5 Sandbox!");

        // Open via HLE
        let path_cstr = std::ffi::CString::new("/app0/test_file.txt").unwrap();
        let fd = unsafe { sceKernelOpen(path_cstr.as_ptr() as u64, 0, 0) };
        assert!(fd >= 100);

        // Fstat via HLE
        let mut stat_buf = [0u8; 120];
        let fstat_res = unsafe { sceKernelFstat(fd, stat_buf.as_mut_ptr() as u64) };
        assert_eq!(fstat_res, 0);
        let size_from_stat = u64::from_ne_bytes(stat_buf[72..80].try_into().unwrap());
        assert_eq!(size_from_stat, 18);

        // Read via HLE
        let mut read_buf = [0u8; 18];
        let bytes_read = unsafe { sceKernelRead(fd, read_buf.as_mut_ptr() as u64, 18) };
        assert_eq!(bytes_read, 18);
        assert_eq!(&read_buf, b"Hello PS5 Sandbox!");

        // Close via HLE
        let close_res = unsafe { sceKernelClose(fd) };
        assert_eq!(close_res, 0);

        // Cleanup
        let _ = std::fs::remove_file(file_path);
    }
}
