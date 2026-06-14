use log::info;
use std::sync::Mutex;
use std::time::{Instant, Duration};

static VIDEO_OUT_STATE: Mutex<VideoOutState> = Mutex::new(VideoOutState {
    initialized: false,
    flip_count: 0,
    current_buffer: 0,
    last_flip_arg: -1,
    start_time: None,
});

struct VideoOutState {
    initialized: bool,
    flip_count: u64,
    current_buffer: i32,
    last_flip_arg: i64,
    start_time: Option<Instant>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SceVideoOutBuffers {
    pub data: *const std::ffi::c_void,
    pub metadata: *const std::ffi::c_void,
    pub reserved: [*const std::ffi::c_void; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SceVideoOutBufferAttribute2 {
    pub reserved0: i32,
    pub tiling_mode: i32,
    pub aspect_ratio: i32,
    pub width: u32,
    pub height: u32,
    pub pitch_in_pixel: u32,
    pub option: u64,
    pub pixel_format: u64,
    pub dcc_cb_register_clear_color: u64,
    pub dcc_control: u32,
    pub pad0: u32,
    pub reserved1: [u64; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SceVideoOutFlipStatus {
    pub count: u64,
    pub process_time: u64,
    pub reserved0: u64,
    pub flip_arg: i64,
    pub reserved1: u64,
    pub process_time_counter: u64,
    pub gc_queue_num: i32,
    pub flip_pending_num: i32,
    pub current_buffer: i32,
    pub reserved2: u32,
    pub submit_process_time_counter: u64,
    pub reserved3: [u64; 7],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SceVideoOutVblankStatus {
    pub count: u64,
    pub process_time: u64,
    pub reserved: u64,
    pub process_time_counter: u64,
    pub flags: u8,
    pub phase: u8,
    pub pad1: [u8; 6],
}

// HLE API implementations

#[no_mangle]
pub extern "sysv64" fn sceVideoOutOpen(
    user_id: i32,
    video_out_type: i32,
    index: i32,
    param: *const std::ffi::c_void,
) -> i32 {
    info!(
        "API VideoOut Intercepted: sceVideoOutOpen | UserID: {} | Type: {} | Index: {} | Param: {:?}",
        user_id, video_out_type, index, param
    );
    let mut state = VIDEO_OUT_STATE.lock().unwrap();
    state.initialized = true;
    state.start_time = Some(Instant::now());
    1 // Return handle = 1
}

#[no_mangle]
pub extern "sysv64" fn sceVideoOutClose(handle: i32) -> i32 {
    info!("API VideoOut Intercepted: sceVideoOutClose | Handle: {}", handle);
    let mut state = VIDEO_OUT_STATE.lock().unwrap();
    state.initialized = false;
    0 // Success
}

#[no_mangle]
pub extern "sysv64" fn sceVideoOutRegisterBuffers2(
    handle: i32,
    set_index: i32,
    buffer_index_start: i32,
    buffers: *const SceVideoOutBuffers,
    buffer_num: i32,
    attribute: *const SceVideoOutBufferAttribute2,
    category: i32,
    option: *mut std::ffi::c_void,
) -> i32 {
    info!(
        "API VideoOut Intercepted: sceVideoOutRegisterBuffers2 | Handle: {} | SetIndex: {} | Start: {} | Num: {} | Cat: {} | Option: {:?}",
        handle, set_index, buffer_index_start, buffer_num, category, option
    );
    if !attribute.is_null() {
        let attr = unsafe { *attribute };
        info!("  -> Attribute size: {}x{}, format: 0x{:X}", attr.width, attr.height, attr.pixel_format);
    }
    0
}

#[no_mangle]
pub extern "sysv64" fn sceVideoOutSubmitFlip(
    handle: i32,
    buffer_index: i32,
    flip_mode: u32,
    flip_arg: i64,
) -> i32 {
    info!(
        "API VideoOut Intercepted: sceVideoOutSubmitFlip | Handle: {} | BufferIndex: {} | FlipMode: {} | FlipArg: {}",
        handle, buffer_index, flip_mode, flip_arg
    );
    let mut state = VIDEO_OUT_STATE.lock().unwrap();
    state.flip_count += 1;
    state.current_buffer = buffer_index;
    state.last_flip_arg = flip_arg;
    0
}

#[no_mangle]
pub extern "sysv64" fn sceVideoOutGetFlipStatus(
    handle: i32,
    status: *mut SceVideoOutFlipStatus,
) -> i32 {
    if status.is_null() {
        return -1;
    }
    let state = VIDEO_OUT_STATE.lock().unwrap();
    let elapsed_micros = state.start_time
        .map(|t| t.elapsed().as_micros() as u64)
        .unwrap_or(0);
        
    unsafe {
        (*status).count = state.flip_count;
        (*status).process_time = elapsed_micros;
        (*status).reserved0 = 0;
        (*status).flip_arg = state.last_flip_arg;
        (*status).reserved1 = 0;
        (*status).process_time_counter = elapsed_micros;
        (*status).gc_queue_num = 0;
        (*status).flip_pending_num = 0;
        (*status).current_buffer = state.current_buffer;
        (*status).reserved2 = 0;
        (*status).submit_process_time_counter = elapsed_micros;
        (*status).reserved3 = [0; 7];
    }
    0
}

#[no_mangle]
pub extern "sysv64" fn sceVideoOutGetVblankStatus(
    handle: i32,
    status: *mut SceVideoOutVblankStatus,
) -> i32 {
    if status.is_null() {
        return -1;
    }
    let state = VIDEO_OUT_STATE.lock().unwrap();
    let elapsed = state.start_time.map(|t| t.elapsed()).unwrap_or(Duration::from_secs(0));
    let elapsed_micros = elapsed.as_micros() as u64;
    let vblank_count = (elapsed.as_secs_f64() * 60.0) as u64;
    
    unsafe {
        (*status).count = vblank_count;
        (*status).process_time = elapsed_micros;
        (*status).reserved = 0;
        (*status).process_time_counter = elapsed_micros;
        (*status).flags = 0;
        (*status).phase = 0;
        (*status).pad1 = [0; 6];
    }
    0
}

#[no_mangle]
pub extern "sysv64" fn sceVideoOutIsFlipPending(handle: i32) -> i32 {
    0 // No flip pending (0 = false)
}

#[no_mangle]
pub extern "sysv64" fn sceVideoOutWaitVblank(handle: i32) -> i32 {
    // Throttle execution to ~60 FPS
    std::thread::sleep(Duration::from_millis(16));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_video_out_hle() {
        let handle = sceVideoOutOpen(0x100, 0, 0, std::ptr::null());
        assert_eq!(handle, 1);

        let attr = SceVideoOutBufferAttribute2 {
            reserved0: 0,
            tiling_mode: 1,
            aspect_ratio: 0,
            width: 1920,
            height: 1080,
            pitch_in_pixel: 0,
            option: 0,
            pixel_format: 0x8000000000000000,
            dcc_cb_register_clear_color: 0,
            dcc_control: 0,
            pad0: 0,
            reserved1: [0; 3],
        };

        assert_eq!(
            sceVideoOutRegisterBuffers2(
                handle,
                0,
                0,
                std::ptr::null(),
                2,
                &attr,
                0,
                std::ptr::null_mut()
            ),
            0
        );

        assert_eq!(sceVideoOutSubmitFlip(handle, 1, 1, 999), 0);

        let mut flip_status = SceVideoOutFlipStatus {
            count: 0,
            process_time: 0,
            reserved0: 0,
            flip_arg: 0,
            reserved1: 0,
            process_time_counter: 0,
            gc_queue_num: 0,
            flip_pending_num: 0,
            current_buffer: 0,
            reserved2: 0,
            submit_process_time_counter: 0,
            reserved3: [0; 7],
        };

        assert_eq!(sceVideoOutGetFlipStatus(handle, &mut flip_status), 0);
        assert_eq!(flip_status.count, 1);
        assert_eq!(flip_status.current_buffer, 1);
        assert_eq!(flip_status.flip_arg, 999);

        assert_eq!(sceVideoOutIsFlipPending(handle), 0);
        assert_eq!(sceVideoOutWaitVblank(handle), 0);

        assert_eq!(sceVideoOutClose(handle), 0);
    }
}
