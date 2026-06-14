use log::info;
use std::sync::atomic::{AtomicU32, Ordering};

const SCE_COMMON_DIALOG_STATUS_NONE: u32 = 0;
const SCE_COMMON_DIALOG_STATUS_INITIALIZED: u32 = 1;
const SCE_COMMON_DIALOG_STATUS_RUNNING: u32 = 2;
const SCE_COMMON_DIALOG_STATUS_FINISHED: u32 = 3;

static DIALOG_STATUS: AtomicU32 = AtomicU32::new(SCE_COMMON_DIALOG_STATUS_NONE);
static DIALOG_MODE: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SceMsgDialogResult {
    pub mode: i32,
    pub result: i32,
    pub button_id: i32,
    pub reserved: [u8; 32],
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceCommonDialogInitialize() -> i32 {
    info!("sceCommonDialogInitialize");
    DIALOG_STATUS.store(SCE_COMMON_DIALOG_STATUS_INITIALIZED, Ordering::SeqCst);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceCommonDialogIsUsed() -> bool {
    info!("sceCommonDialogIsUsed");
    false
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogInitialize() -> i32 {
    info!("sceMsgDialogInitialize");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceMsgDialogParamInitialize(param_ptr: u64) {
    info!("sceMsgDialogParamInitialize: param_ptr = 0x{:X}", param_ptr);
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogOpen(param_ptr: u64) -> i32 {
    info!("sceMsgDialogOpen: param_ptr = 0x{:X}", param_ptr);
    
    if param_ptr != 0 {
        let addr = crate::kernel::translate_guest_addr(param_ptr).unwrap_or(param_ptr);
        let mode = *((addr as *const u8).add(56) as *const i32);
        DIALOG_MODE.store(mode as u32, Ordering::SeqCst);
        info!("[MsgDialog] Mode = {}", mode);
        
        if mode == 1 { // SCE_MSG_DIALOG_MODE_USER_MSG
            let user_msg_param_ptr = *((addr as *const u8).add(64) as *const u64);
            info!("[MsgDialog] userMsgParam = 0x{:X}", user_msg_param_ptr);
            if user_msg_param_ptr != 0 {
                let msg_param_addr = crate::kernel::translate_guest_addr(user_msg_param_ptr).unwrap_or(user_msg_param_ptr);
                let button_type = *(msg_param_addr as *const i32);
                let msg_ptr = *((msg_param_addr as *const u8).add(8) as *const u64);
                info!("[MsgDialog] ButtonType = {}, MsgPtr = 0x{:X}", button_type, msg_ptr);
                if msg_ptr != 0 {
                    let msg_addr = crate::kernel::translate_guest_addr(msg_ptr).unwrap_or(msg_ptr);
                    let msg_cstr = std::ffi::CStr::from_ptr(msg_addr as *const std::os::raw::c_char);
                    info!("[MsgDialog Message] {}", msg_cstr.to_string_lossy());
                }
            }
        } else if mode == 3 { // SCE_MSG_DIALOG_MODE_SYSTEM_MSG
            let sys_msg_param_ptr = *((addr as *const u8).add(80) as *const u64);
            info!("[MsgDialog] sysMsgParam = 0x{:X}", sys_msg_param_ptr);
            if sys_msg_param_ptr != 0 {
                let sys_param_addr = crate::kernel::translate_guest_addr(sys_msg_param_ptr).unwrap_or(sys_msg_param_ptr);
                let sys_msg_type = *(sys_param_addr as *const i32);
                info!("[MsgDialog System Message Type] {}", sys_msg_type);
            }
        } else if mode == 2 { // PROGRESS_BAR
            let prog_bar_param_ptr = *((addr as *const u8).add(72) as *const u64);
            info!("[MsgDialog] progBarParam = 0x{:X}", prog_bar_param_ptr);
            if prog_bar_param_ptr != 0 {
                let prog_param_addr = crate::kernel::translate_guest_addr(prog_bar_param_ptr).unwrap_or(prog_bar_param_ptr);
                let bar_type = *(prog_param_addr as *const i32);
                let msg_ptr = *((prog_param_addr as *const u8).add(8) as *const u64);
                info!("[MsgDialog Progress Bar Type] {}, MsgPtr = 0x{:X}", bar_type, msg_ptr);
                if msg_ptr != 0 {
                    let msg_addr = crate::kernel::translate_guest_addr(msg_ptr).unwrap_or(msg_ptr);
                    let msg_cstr = std::ffi::CStr::from_ptr(msg_addr as *const std::os::raw::c_char);
                    info!("[MsgDialog Message] {}", msg_cstr.to_string_lossy());
                }
            }
        }
    }
    
    DIALOG_STATUS.store(SCE_COMMON_DIALOG_STATUS_FINISHED, Ordering::SeqCst);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogUpdateStatus() -> u32 {
    let status = DIALOG_STATUS.load(Ordering::SeqCst);
    info!("sceMsgDialogUpdateStatus: status = {}", status);
    status
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogGetStatus() -> u32 {
    let status = DIALOG_STATUS.load(Ordering::SeqCst);
    info!("sceMsgDialogGetStatus: status = {}", status);
    status
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogGetResult(result_ptr: u64) -> i32 {
    info!("sceMsgDialogGetResult: result_ptr = 0x{:X}", result_ptr);
    if result_ptr == 0 {
        return -1;
    }
    
    let result_host_ptr = match crate::kernel::translate_guest_addr(result_ptr) {
        Some(addr) => addr as *mut SceMsgDialogResult,
        None => result_ptr as *mut SceMsgDialogResult,
    };
    
    let result_ref = &mut *result_host_ptr;
    result_ref.mode = DIALOG_MODE.load(Ordering::SeqCst) as i32;
    result_ref.result = 0; // SCE_OK
    result_ref.button_id = 1; // SCE_MSG_DIALOG_BUTTON_ID_OK
    result_ref.reserved = [0u8; 32];
    
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogTerminate() -> i32 {
    info!("sceMsgDialogTerminate");
    DIALOG_STATUS.store(SCE_COMMON_DIALOG_STATUS_NONE, Ordering::SeqCst);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogClose() -> i32 {
    info!("sceMsgDialogClose");
    DIALOG_STATUS.store(SCE_COMMON_DIALOG_STATUS_NONE, Ordering::SeqCst);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogProgressBarInc(target: u64, delta: u32) -> i32 {
    info!("sceMsgDialogProgressBarInc: target = 0x{:X}, delta = {}", target, delta);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogProgressBarSetValue(target: u64, rate: u32) -> i32 {
    info!("sceMsgDialogProgressBarSetValue: target = 0x{:X}, rate = {}", target, rate);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceMsgDialogProgressBarSetMsg(target: u64, bar_msg: u64) -> i32 {
    info!("sceMsgDialogProgressBarSetMsg: target = 0x{:X}, bar_msg = 0x{:X}", target, bar_msg);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_dialog_hle() {
        assert_eq!(unsafe { sceCommonDialogInitialize() }, 0);
        assert!(!unsafe { sceCommonDialogIsUsed() });
        assert_eq!(unsafe { sceMsgDialogInitialize() }, 0);
        
        // Open
        assert_eq!(unsafe { sceMsgDialogOpen(0) }, 0);
        assert_eq!(unsafe { sceMsgDialogGetStatus() }, SCE_COMMON_DIALOG_STATUS_FINISHED);
        
        let mut result = SceMsgDialogResult {
            mode: 0,
            result: -1,
            button_id: -1,
            reserved: [0u8; 32],
        };
        assert_eq!(unsafe { sceMsgDialogGetResult(&mut result as *mut SceMsgDialogResult as u64) }, 0);
        assert_eq!(result.result, 0);
        assert_eq!(result.button_id, 1);
        
        assert_eq!(unsafe { sceMsgDialogClose() }, 0);
        assert_eq!(unsafe { sceMsgDialogGetStatus() }, SCE_COMMON_DIALOG_STATUS_NONE);
        assert_eq!(unsafe { sceMsgDialogTerminate() }, 0);
    }
}
