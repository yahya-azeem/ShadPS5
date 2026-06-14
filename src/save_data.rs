use log::{info, error};
use std::sync::atomic::{AtomicU32, Ordering};

static MOUNT_COUNT: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SceSaveDataDirName {
    pub data: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SceSaveDataMountPoint {
    pub data: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SceSaveDataMount3 {
    pub userId: i32,
    pub padding: i32,
    pub dirName: u64, // Guest virtual pointer to SceSaveDataDirName
    pub blocks: u64,
    pub systemBlocks: u64,
    pub mountMode: u32,
    pub padding2: i32,
    pub resource: i32,
    pub reserved: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SceSaveDataMountResult {
    pub mountPoint: SceSaveDataMountPoint,
    pub requiredBlocks: u64,
    pub unused: u32,
    pub mountStatus: u32,
    pub reserved: [u8; 28],
    pub alignment: i32,
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataInitialize3(init_param: u64) -> i32 {
    info!("sceSaveDataInitialize3: init_param = 0x{:X}", init_param);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataTerminate() -> i32 {
    info!("sceSaveDataTerminate");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataCreateTransactionResource(size: u32) -> i32 {
    info!("sceSaveDataCreateTransactionResource: size = {}", size);
    1 // Return a dummy resource ID
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataDeleteTransactionResource(resource: i32) -> i32 {
    info!("sceSaveDataDeleteTransactionResource: resource = {}", resource);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataMount3(mount_ptr: u64, result_ptr: u64) -> i32 {
    info!("sceSaveDataMount3: mount_ptr = 0x{:X}, result_ptr = 0x{:X}", mount_ptr, result_ptr);
    if mount_ptr == 0 || result_ptr == 0 {
        return -1;
    }

    let mount_host_ptr = match crate::kernel::translate_guest_addr(mount_ptr) {
        Some(addr) => addr as *const SceSaveDataMount3,
        None => mount_ptr as *const SceSaveDataMount3,
    };
    let result_host_ptr = match crate::kernel::translate_guest_addr(result_ptr) {
        Some(addr) => addr as *mut SceSaveDataMountResult,
        None => result_ptr as *mut SceSaveDataMountResult,
    };

    let mount_ref = &*mount_host_ptr;
    let result_ref = &mut *result_host_ptr;

    let dir_name = if mount_ref.dirName != 0 {
        match crate::kernel::translate_guest_addr(mount_ref.dirName) {
            Some(addr) => {
                let name_struct = &*(addr as *const SceSaveDataDirName);
                std::ffi::CStr::from_bytes_until_nul(&name_struct.data)
                    .map(|c| c.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "default".to_string())
            }
            None => "default".to_string(),
        }
    } else {
        "default".to_string()
    };

    let mount_idx = MOUNT_COUNT.fetch_add(1, Ordering::SeqCst);
    let mount_name = format!("/savedata{}", mount_idx);
    info!(
        "sceSaveDataMount3: user_id = 0x{:X}, dir_name = '{}', mount_name = '{}'",
        mount_ref.userId, dir_name, mount_name
    );

    // Create the host directory under game_root
    let host_dir = std::path::Path::new("game_root").join(mount_name.trim_start_matches('/'));
    if let Err(e) = std::fs::create_dir_all(&host_dir) {
        error!("sceSaveDataMount3: failed to create host directory {:?}: {}", host_dir, e);
    } else {
        info!("sceSaveDataMount3: created host directory {:?}", host_dir);
    }

    // Populate MountResult
    let mut mp_bytes = [0u8; 16];
    let name_bytes = mount_name.as_bytes();
    let len = name_bytes.len().min(15);
    mp_bytes[..len].copy_from_slice(&name_bytes[..len]);
    result_ref.mountPoint.data = mp_bytes;
    result_ref.requiredBlocks = 0;
    result_ref.unused = 0;
    result_ref.mountStatus = 0; // OK
    result_ref.reserved = [0u8; 28];
    result_ref.alignment = 0;

    0 // SCE_OK
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataUmount2(mode: u32, mount_point_ptr: u64) -> i32 {
    let mount_point = if mount_point_ptr != 0 {
        match crate::kernel::translate_guest_addr(mount_point_ptr) {
            Some(addr) => {
                let mp_struct = &*(addr as *const SceSaveDataMountPoint);
                std::ffi::CStr::from_bytes_until_nul(&mp_struct.data)
                    .map(|c| c.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "unknown".to_string())
            }
            None => "unknown".to_string(),
        }
    } else {
        "unknown".to_string()
    };
    info!("sceSaveDataUmount2: mode = {}, mount_point = '{}'", mode, mount_point);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataGetMountInfo(mount_point_ptr: u64, info_ptr: u64) -> i32 {
    info!("sceSaveDataGetMountInfo: mount_point_ptr = 0x{:X}, info_ptr = 0x{:X}", mount_point_ptr, info_ptr);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataPrepare(mount_point_ptr: u64, param_ptr: u64) -> i32 {
    info!("sceSaveDataPrepare: mount_point_ptr = 0x{:X}, param_ptr = 0x{:X}", mount_point_ptr, param_ptr);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceSaveDataCommit(param_ptr: u64) -> i32 {
    info!("sceSaveDataCommit: param_ptr = 0x{:X}", param_ptr);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_data_mounting() {
        // Setup mock structures
        let mut mount = SceSaveDataMount3 {
            userId: 0x100,
            padding: 0,
            dirName: 0,
            blocks: 10,
            systemBlocks: 0,
            mountMode: 0,
            padding2: 0,
            resource: 0,
            reserved: [0u8; 32],
        };
        
        let mut dir_name = SceSaveDataDirName { data: [0u8; 32] };
        let name_str = b"myslot0\0";
        dir_name.data[..name_str.len()].copy_from_slice(name_str);
        mount.dirName = &dir_name as *const SceSaveDataDirName as u64;

        let mut result = SceSaveDataMountResult {
            mountPoint: SceSaveDataMountPoint { data: [0u8; 16] },
            requiredBlocks: 99,
            unused: 99,
            mountStatus: 99,
            reserved: [0u8; 28],
            alignment: 0,
        };

        let res = unsafe {
            sceSaveDataMount3(
                &mount as *const SceSaveDataMount3 as u64,
                &mut result as *mut SceSaveDataMountResult as u64,
            )
        };

        assert_eq!(res, 0);
        
        let mp_str = std::ffi::CStr::from_bytes_until_nul(&result.mountPoint.data)
            .unwrap()
            .to_str()
            .unwrap();
        
        assert!(mp_str.starts_with("/savedata"));
        assert_eq!(result.mountStatus, 0);

        // Check if directory was created
        let path = std::path::Path::new("game_root").join(mp_str.trim_start_matches('/'));
        assert!(path.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(path);
    }
}
