use log::info;

// Default dummy login user ID
pub const DEFAULT_USER_ID: i32 = 0x100;

#[no_mangle]
pub extern "sysv64" fn sceUserServiceInitialize(
    _param: *const std::ffi::c_void,
) -> i32 {
    info!("API UserService Intercepted: sceUserServiceInitialize");
    0 // Success (SCE_OK)
}

#[no_mangle]
pub extern "sysv64" fn sceUserServiceGetLoginUserIdList(
    user_id_list_out: *mut i32,
) -> i32 {
    info!("API UserService Intercepted: sceUserServiceGetLoginUserIdList");
    if user_id_list_out.is_null() {
        return -1;
    }
    
    unsafe {
        // Provide the default user ID and a sentinel or just the active one.
        *user_id_list_out = DEFAULT_USER_ID;
        // The list can be terminated or sized depending on API, but filling the first element is standard.
        // Let's populate the next ones with invalid/empty user IDs if needed (e.g. -1).
        let next_ptr = user_id_list_out.offset(1);
        *next_ptr = -1;
    }
    0 // Success
}

#[no_mangle]
pub extern "sysv64" fn sceUserServiceGetUserName(
    user_id: i32,
    name_out: *mut u8,
    size: usize,
) -> i32 {
    info!(
        "API UserService Intercepted: sceUserServiceGetUserName | UserID: 0x{:X} | Output Size: {}",
        user_id, size
    );
    if name_out.is_null() || size < 20 {
        return -1;
    }
    
    let username = b"PlayStation Player\0";
    unsafe {
        std::ptr::copy_nonoverlapping(username.as_ptr(), name_out, username.len().min(size));
    }
    0 // Success
}

#[no_mangle]
pub extern "sysv64" fn sceUserServiceTerminate() -> i32 {
    info!("API UserService Intercepted: sceUserServiceTerminate");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_service_hle() {
        assert_eq!(sceUserServiceInitialize(std::ptr::null()), 0);
        
        let mut user_list = [0i32; 4];
        assert_eq!(sceUserServiceGetLoginUserIdList(user_list.as_mut_ptr()), 0);
        assert_eq!(user_list[0], DEFAULT_USER_ID);
        assert_eq!(user_list[1], -1);

        let mut name_buf = [0u8; 32];
        assert_eq!(sceUserServiceGetUserName(DEFAULT_USER_ID, name_buf.as_mut_ptr(), 32), 0);
        
        let name_str = std::ffi::CStr::from_bytes_until_nul(&name_buf)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(name_str, "PlayStation Player");

        assert_eq!(sceUserServiceTerminate(), 0);
    }
}
