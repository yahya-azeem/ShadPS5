use log::{info, error};
use std::sync::Mutex;

// Global thread-safe state for pad inputs
static PAD_STATE: Mutex<ScePadData> = Mutex::new(ScePadData {
    buttons: 0,
    lx: 127, // Center sticks (0-255)
    ly: 127,
    rx: 127,
    ry: 127,
    reserved: [0; 16],
});

/// Represents the controller state structure exported in pad.h
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScePadData {
    pub buttons: u32,
    pub lx: u8,
    pub ly: u8,
    pub rx: u8,
    pub ry: u8,
    pub reserved: [u8; 16],
}

// PS5 Gamepad Button bitmasks (mapped from pad.h)
pub const SCE_PAD_BUTTON_L3: u32        = 0x00000002;
pub const SCE_PAD_BUTTON_R3: u32        = 0x00000004;
pub const SCE_PAD_BUTTON_OPTIONS: u32   = 0x00000008;
pub const SCE_PAD_BUTTON_START: u32     = 0x00000008; // Alias for OPTIONS
pub const SCE_PAD_BUTTON_UP: u32        = 0x00000010;
pub const SCE_PAD_BUTTON_RIGHT: u32     = 0x00000020;
pub const SCE_PAD_BUTTON_DOWN: u32      = 0x00000040;
pub const SCE_PAD_BUTTON_LEFT: u32      = 0x00000080;
pub const SCE_PAD_BUTTON_L2: u32        = 0x00000100;
pub const SCE_PAD_BUTTON_R2: u32        = 0x00000200;
pub const SCE_PAD_BUTTON_L1: u32        = 0x00000400;
pub const SCE_PAD_BUTTON_R1: u32        = 0x00000800;
pub const SCE_PAD_BUTTON_TRIANGLE: u32  = 0x00001000;
pub const SCE_PAD_BUTTON_CIRCLE: u32    = 0x00002000;
pub const SCE_PAD_BUTTON_CROSS: u32     = 0x00004000;
pub const SCE_PAD_BUTTON_SQUARE: u32    = 0x00008000;
pub const SCE_PAD_BUTTON_TOUCH_PAD: u32 = 0x00100000;

/// Updates the global input state. Called from the SDL2 event loop in main.rs.
pub fn update_global_pad_state(buttons_mask: u32, lx: u8, ly: u8, rx: u8, ry: u8) {
    let mut state = PAD_STATE.lock().unwrap();
    state.buttons = buttons_mask;
    state.lx = lx;
    state.ly = ly;
    state.rx = rx;
    state.ry = ry;
}

// =========================================================================
// =========================================================================

#[no_mangle]
pub extern "sysv64" fn scePadInit() -> i32 {
    info!("API Input Intercepted: scePadInit");
    0 // SCE_OK
}

#[no_mangle]
pub extern "sysv64" fn scePadOpen(
    user_id: i32,
    port_type: i32,
    index: i32,
    _param: *const std::ffi::c_void,
) -> i32 {
    info!(
        "API Input Intercepted: scePadOpen | UserID: {} | PortType: {} | Index: {}",
        user_id, port_type, index
    );
    100 // Return simulated pad handle
}

#[no_mangle]
pub extern "sysv64" fn scePadClose(handle: i32) -> i32 {
    info!("API Input Intercepted: scePadClose | Handle: {}", handle);
    0
}

/// Populates the guest's ScePadData structure with our current keyboard/controller state.
#[no_mangle]
pub unsafe extern "sysv64" fn scePadReadState(handle: i32, data_out: *mut ScePadData) -> i32 {
    if data_out.is_null() {
        return -1;
    }
    
    // Copy thread-safe global pad state to target pointer
    let state = PAD_STATE.lock().unwrap();
    *data_out = *state;
    
    // 0 = Success (Active state)
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hle_pad_operations() {
        assert_eq!(scePadInit(), 0);
        let handle = scePadOpen(2000, 0, 0, std::ptr::null());
        assert_eq!(handle, 100);

        let mut data = ScePadData {
            buttons: 0,
            lx: 0,
            ly: 0,
            rx: 0,
            ry: 0,
            reserved: [0; 16],
        };

        update_global_pad_state(SCE_PAD_BUTTON_CROSS | SCE_PAD_BUTTON_UP, 45, 90, 135, 180);

        unsafe {
            assert_eq!(scePadReadState(handle, &mut data as *mut ScePadData), 0);
        }

        assert_eq!(data.buttons, SCE_PAD_BUTTON_CROSS | SCE_PAD_BUTTON_UP);
        assert_eq!(data.lx, 45);
        assert_eq!(data.ly, 90);
        assert_eq!(data.rx, 135);
        assert_eq!(data.ry, 180);

        assert_eq!(scePadClose(handle), 0);
    }
}
