use log::info;

/// HLE implementation of sceNpGetOnlineId
#[no_mangle]
pub unsafe extern "sysv64" fn sceNpGetOnlineId(user_id: i32, online_id_out: u64) -> i32 {
    info!("sceNpGetOnlineId: user_id = {}", user_id);
    let host_out = match crate::kernel::translate_guest_addr(online_id_out) {
        Some(addr) => addr as *mut u8,
        None => online_id_out as *mut u8,
    };
    if host_out.is_null() {
        return 0x80550004u32 as i32; // SCE_NP_ERROR_INVALID_PARAMETER
    }
    let id_str = b"ProsperoUser\0";
    std::ptr::copy_nonoverlapping(id_str.as_ptr(), host_out, id_str.len());
    0
}

/// HLE implementation of sceNpGetAccountIdA
#[no_mangle]
pub unsafe extern "sysv64" fn sceNpGetAccountIdA(user_id: i32, account_id_out: u64) -> i32 {
    info!("sceNpGetAccountIdA: user_id = {}", user_id);
    let host_out = match crate::kernel::translate_guest_addr(account_id_out) {
        Some(addr) => addr as *mut u64,
        None => account_id_out as *mut u64,
    };
    if host_out.is_null() {
        return 0x80550004u32 as i32;
    }
    *host_out = 0x1234567890ABCDEF;
    0
}

/// HLE implementation of sceNpGetUserIdByAccountId
#[no_mangle]
pub unsafe extern "sysv64" fn sceNpGetUserIdByAccountId(account_id: u64, user_id_out: u64) -> i32 {
    info!("sceNpGetUserIdByAccountId: account_id = 0x{:X}", account_id);
    let host_out = match crate::kernel::translate_guest_addr(user_id_out) {
        Some(addr) => addr as *mut i32,
        None => user_id_out as *mut i32,
    };
    if host_out.is_null() {
        return 0x80550004u32 as i32;
    }
    *host_out = 0x100; // Default local user ID 0x100
    0
}

/// HLE implementation of sceNpGetState
#[no_mangle]
pub unsafe extern "sysv64" fn sceNpGetState(user_id: i32, state_out: u64) -> i32 {
    info!("sceNpGetState: user_id = {}", user_id);
    let host_out = match crate::kernel::translate_guest_addr(state_out) {
        Some(addr) => addr as *mut i32,
        None => state_out as *mut i32,
    };
    if host_out.is_null() {
        return 0x80550004u32 as i32;
    }
    *host_out = 1; // 1 = initialized offline/ready state
    0
}

/// HLE implementation of sceNpRegisterStateCallbackA
#[no_mangle]
pub unsafe extern "sysv64" fn sceNpRegisterStateCallbackA(callback: u64, arg: u64) -> i32 {
    info!("sceNpRegisterStateCallbackA: callback = 0x{:X}, arg = 0x{:X}", callback, arg);
    0
}

/// HLE implementation of sceNpUnregisterStateCallbackA
#[no_mangle]
pub unsafe extern "sysv64" fn sceNpUnregisterStateCallbackA(callback: u64) -> i32 {
    info!("sceNpUnregisterStateCallbackA: callback = 0x{:X}", callback);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_profile() {
        let mut online_id = [0u8; 16];
        let res = unsafe {
            sceNpGetOnlineId(0x100, online_id.as_mut_ptr() as u64)
        };
        assert_eq!(res, 0);
        let name = std::ffi::CStr::from_bytes_until_nul(&online_id)
            .unwrap()
            .to_string_lossy();
        assert_eq!(name, "ProsperoUser");

        let mut account_id = 0u64;
        let res_acc = unsafe {
            sceNpGetAccountIdA(0x100, &mut account_id as *mut u64 as u64)
        };
        assert_eq!(res_acc, 0);
        assert_eq!(account_id, 0x1234567890ABCDEF);

        let mut state = 0i32;
        let res_state = unsafe {
            sceNpGetState(0x100, &mut state as *mut i32 as u64)
        };
        assert_eq!(res_state, 0);
        assert_eq!(state, 1);

        let mut user_id = 0i32;
        let res_uid = unsafe {
            sceNpGetUserIdByAccountId(0x1234567890ABCDEF, &mut user_id as *mut i32 as u64)
        };
        assert_eq!(res_uid, 0);
        assert_eq!(user_id, 0x100);
    }
}
