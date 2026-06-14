// High-Level Emulation stubs for sceAmpr (Agile Memory & Process Redirect) and other unresolved symbols.

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmSubmitCommandBuffer(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmSubmitCommandBuffer called (a1=0x{:X}, a2=0x{:X}, a3=0x{:X})", a1, a2, a3);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeReadFileGatherScatter(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeReadFileGatherScatter called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAprCommandBufferConstructor(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAprCommandBufferConstructor called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferSetMarkerWithColor(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferSetMarkerWithColor called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferReset(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferReset called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferWriteAddressFromTimeCounterOnCompletion(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferWriteAddressFromTimeCounterOnCompletion called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmMeasureAmmCommandSizeMapDirect(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmMeasureAmmCommandSizeMapDirect called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferGetSize(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferGetSize called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferWaitOnAddress_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferWaitOnAddress_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferWaitOnCounter_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferWaitOnCounter_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferWriteAddress_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferWriteAddress_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferWriteAddressFromTimeCounter_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferWriteAddressFromTimeCounter_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferWriteAddressFromCounter_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferWriteAddressFromCounter_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferWriteCounter_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferWriteCounter_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmCommandBufferModifyMtypeProtect(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmCommandBufferModifyMtypeProtect called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferGetType(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferGetType called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmCommandBufferUnmap(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmCommandBufferUnmap called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmMeasureAmmCommandSizeMultiMapWithGpuMaskId(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmMeasureAmmCommandSizeMultiMapWithGpuMaskId called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAprCommandBufferResetGatherScatterState(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAprCommandBufferResetGatherScatterState called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWaitOnAddress(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWaitOnAddress called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWaitOnCounter(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWaitOnCounter called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmCommandBufferDestructor(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmCommandBufferDestructor called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferPopMarker(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferPopMarker called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeResetGatherScatterState(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeResetGatherScatterState called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferConstructor(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferConstructor called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferNopWithData(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferNopWithData called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizePushMarkerWithColor(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizePushMarkerWithColor called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAprCommandBufferMapBegin(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAprCommandBufferMapBegin called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAprCommandBufferMapDirectBegin(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAprCommandBufferMapDirectBegin called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAprCommandBufferMapEnd(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAprCommandBufferMapEnd called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWaitOnAddress_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWaitOnAddress_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWaitOnCounter_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWaitOnCounter_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWriteAddress_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWriteAddress_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWriteAddressFromTimeCounter_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWriteAddressFromTimeCounter_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWriteAddressFromCounter_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWriteAddressFromCounter_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWriteAddressFromCounterPair_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWriteAddressFromCounterPair_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeWriteKernelEventQueue_04_00(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeWriteKernelEventQueue_04_00 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmCommandBufferModifyProtect(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmCommandBufferModifyProtect called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferGetCurrentOffset(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferGetCurrentOffset called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmCommandBufferMultiMap(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmCommandBufferMultiMap called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmCommandBufferMap(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmCommandBufferMap called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeNop(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeNop called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeMapBegin(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeMapBegin called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeMapDirectBegin(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeMapDirectBegin called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeMapEnd(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeMapEnd called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmCommandBufferRemapWithGpuMaskId(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmCommandBufferRemapWithGpuMaskId called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprAmmMeasureAmmCommandSizeRemap(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprAmmMeasureAmmCommandSizeRemap called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprMeasureCommandSizeReadFile(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprMeasureCommandSizeReadFile called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferPushMarker(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferPushMarker called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sceAmprCommandBufferSetBuffer(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE: sceAmprCommandBufferSetBuffer called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_ICaGtkEIXTk(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: ICaGtkEIXTk called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_WHIOMbb_iIU(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: WHIOMbb+iIU called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_chJWZcNSzjk(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: chJWZcNSzjk called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_plus_iAOE3jCnkk(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: +iAOE3jCnkk called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_fPSCdQxgpSw(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: fPSCdQxgpSw called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_eAy8eGNsCuU(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: eAy8eGNsCuU called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_y5K5tPktiL8(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: y5K5tPktiL8 called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_EJBA4dbmvfg(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: EJBA4dbmvfg called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_7Wa3aeJgeVU(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: 7Wa3aeJgeVU called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_rP5xLdOf26k(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: rP5xLdOf26k called");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_d4NZIlguzv0(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    log::debug!("HLE Unknown: d4NZIlguzv0 called");
    0
}


pub fn lookup_ampr_hle_address(name: &str) -> Option<u64> {
    match name {
        "sceAmprAmmSubmitCommandBuffer" | "8aI7R7WaOlc" => Some(hle_sceAmprAmmSubmitCommandBuffer as u64),
        "sceAmprMeasureCommandSizeReadFileGatherScatter" | "GuchCTefuZw" => Some(hle_sceAmprMeasureCommandSizeReadFileGatherScatter as u64),
        "sceAmprAprCommandBufferConstructor" | "baQO9ez2gL4" | "a8uLzYY--tM" | "a8uLzYY__tM" | "a8uLzYY++tM" => Some(hle_sceAmprAprCommandBufferConstructor as u64),
        "sceAmprCommandBufferSetMarkerWithColor" | "ULvXMDz56po" => Some(hle_sceAmprCommandBufferSetMarkerWithColor as u64),
        "sceAmprCommandBufferReset" | "VEDMaQmJZng" => Some(hle_sceAmprCommandBufferReset as u64),
        "sceAmprCommandBufferWriteAddressFromTimeCounterOnCompletion" | "tZDDEo2tE5k" => Some(hle_sceAmprCommandBufferWriteAddressFromTimeCounterOnCompletion as u64),
        "sceAmprAmmMeasureAmmCommandSizeMapDirect" | "gzndltBEzWc" => Some(hle_sceAmprAmmMeasureAmmCommandSizeMapDirect as u64),
        "sceAmprCommandBufferGetSize" | "GnxKOHEawhk" => Some(hle_sceAmprCommandBufferGetSize as u64),
        "sceAmprCommandBufferWaitOnAddress_04_00" | "DLfoNxTFNVk" => Some(hle_sceAmprCommandBufferWaitOnAddress_04_00 as u64),
        "sceAmprCommandBufferWaitOnCounter_04_00" | "cQb8Zr8Q0Y0" => Some(hle_sceAmprCommandBufferWaitOnCounter_04_00 as u64),
        "sceAmprCommandBufferWriteAddress_04_00" | "j0+3uJMxYJY" => Some(hle_sceAmprCommandBufferWriteAddress_04_00 as u64),
        "sceAmprCommandBufferWriteAddressFromTimeCounter_04_00" | "bt3LHR9xjK4" => Some(hle_sceAmprCommandBufferWriteAddressFromTimeCounter_04_00 as u64),
        "sceAmprCommandBufferWriteAddressFromCounter_04_00" | "t4ExS+SwLjs" => Some(hle_sceAmprCommandBufferWriteAddressFromCounter_04_00 as u64),
        "sceAmprCommandBufferWriteCounter_04_00" | "jK+yuYCI7MA" => Some(hle_sceAmprCommandBufferWriteCounter_04_00 as u64),
        "sceAmprAmmCommandBufferModifyMtypeProtect" | "GmOguNIsuKk" => Some(hle_sceAmprAmmCommandBufferModifyMtypeProtect as u64),
        "sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId" | "tNn5WBkta60" => Some(hle_sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId as u64),
        "sceAmprCommandBufferGetType" | "pFQ9UHpO52s" => Some(hle_sceAmprCommandBufferGetType as u64),
        "sceAmprAmmCommandBufferUnmap" | "4UkZbYKVF7c" => Some(hle_sceAmprAmmCommandBufferUnmap as u64),
        "sceAmprAmmMeasureAmmCommandSizeMultiMapWithGpuMaskId" | "sWbST0oQKsc" => Some(hle_sceAmprAmmMeasureAmmCommandSizeMultiMapWithGpuMaskId as u64),
        "sceAmprAprCommandBufferResetGatherScatterState" | "4quckD2y7Pg" => Some(hle_sceAmprAprCommandBufferResetGatherScatterState as u64),
        "sceAmprMeasureCommandSizeWaitOnAddress" | "f12ObAMEi9A" => Some(hle_sceAmprMeasureCommandSizeWaitOnAddress as u64),
        "sceAmprMeasureCommandSizeWaitOnCounter" | "dXPaz65HNmk" => Some(hle_sceAmprMeasureCommandSizeWaitOnCounter as u64),
        "sceAmprAmmCommandBufferDestructor" | "pvUFDOHilnE" => Some(hle_sceAmprAmmCommandBufferDestructor as u64),
        "sceAmprCommandBufferPopMarker" | "mv0O8Zg0woU" => Some(hle_sceAmprCommandBufferPopMarker as u64),
        "sceAmprMeasureCommandSizeResetGatherScatterState" | "Qs1xtplKo0U" => Some(hle_sceAmprMeasureCommandSizeResetGatherScatterState as u64),
        "sceAmprCommandBufferConstructor" | "mZSbNJVJpV8" => Some(hle_sceAmprCommandBufferConstructor as u64),
        "sceAmprCommandBufferNopWithData" | "BVmR1H8l+XI" => Some(hle_sceAmprCommandBufferNopWithData as u64),
        "sceAmprMeasureCommandSizePushMarkerWithColor" | "YPxkUDhgoNI" => Some(hle_sceAmprMeasureCommandSizePushMarkerWithColor as u64),
        "sceAmprAprCommandBufferMapBegin" | "Eul7AGEpjLo" => Some(hle_sceAmprAprCommandBufferMapBegin as u64),
        "sceAmprAprCommandBufferMapDirectBegin" | "bFEs0Gs6D2A" => Some(hle_sceAmprAprCommandBufferMapDirectBegin as u64),
        "sceAmprAprCommandBufferMapEnd" | "X169CE6G3Y4" => Some(hle_sceAmprAprCommandBufferMapEnd as u64),
        "sceAmprMeasureCommandSizeWaitOnAddress_04_00" | "0BMj1hgG+kE" => Some(hle_sceAmprMeasureCommandSizeWaitOnAddress_04_00 as u64),
        "sceAmprMeasureCommandSizeWaitOnCounter_04_00" | "ClnsFLLLcss" => Some(hle_sceAmprMeasureCommandSizeWaitOnCounter_04_00 as u64),
        "sceAmprMeasureCommandSizeWriteAddress_04_00" | "4fgtGfXDrFc" => Some(hle_sceAmprMeasureCommandSizeWriteAddress_04_00 as u64),
        "sceAmprMeasureCommandSizeWriteAddressFromTimeCounter_04_00" | "gAtc79UTt5E" => Some(hle_sceAmprMeasureCommandSizeWriteAddressFromTimeCounter_04_00 as u64),
        "sceAmprMeasureCommandSizeWriteAddressFromCounter_04_00" | "JYd9g9L+TmE" => Some(hle_sceAmprMeasureCommandSizeWriteAddressFromCounter_04_00 as u64),
        "sceAmprMeasureCommandSizeWriteAddressFromCounterPair_04_00" | "2Hw8gjMdwSY" => Some(hle_sceAmprMeasureCommandSizeWriteAddressFromCounterPair_04_00 as u64),
        "sceAmprMeasureCommandSizeWriteKernelEventQueue_04_00" | "sSAUCCU1dv4" => Some(hle_sceAmprMeasureCommandSizeWriteKernelEventQueue_04_00 as u64),
        "sceAmprAmmCommandBufferModifyProtect" | "Xp85BP3+BBI" => Some(hle_sceAmprAmmCommandBufferModifyProtect as u64),
        "sceAmprCommandBufferGetCurrentOffset" | "qesF88X4DRg" => Some(hle_sceAmprCommandBufferGetCurrentOffset as u64),
        "sceAmprAmmCommandBufferMultiMap" | "7nXGDGMXSqo" => Some(hle_sceAmprAmmCommandBufferMultiMap as u64),
        "sceAmprAmmCommandBufferMap" | "DXmgc5op8Yw" => Some(hle_sceAmprAmmCommandBufferMap as u64),
        "sceAmprMeasureCommandSizeNop" | "rddQYXM0CjM" => Some(hle_sceAmprMeasureCommandSizeNop as u64),
        "sceAmprMeasureCommandSizeMapBegin" | "kdFImtTD0hc" => Some(hle_sceAmprMeasureCommandSizeMapBegin as u64),
        "sceAmprMeasureCommandSizeMapDirectBegin" | "qvbdJc7bG+s" => Some(hle_sceAmprMeasureCommandSizeMapDirectBegin as u64),
        "sceAmprMeasureCommandSizeMapEnd" | "iwTNhyaemnw" => Some(hle_sceAmprMeasureCommandSizeMapEnd as u64),
        "sceAmprAmmCommandBufferRemapWithGpuMaskId" | "tmfr97+ED5I" => Some(hle_sceAmprAmmCommandBufferRemapWithGpuMaskId as u64),
        "sceAmprAmmMeasureAmmCommandSizeRemap" | "3OfeY4pzDV0" => Some(hle_sceAmprAmmMeasureAmmCommandSizeRemap as u64),
        "sceAmprMeasureCommandSizeReadFile" | "0RdLmAh7WVo" => Some(hle_sceAmprMeasureCommandSizeReadFile as u64),
        "sceAmprCommandBufferPushMarker" | "pbnNnahE8vk" => Some(hle_sceAmprCommandBufferPushMarker as u64),
        "sceAmprCommandBufferSetBuffer" | "N-FSPA4S3nI" | "N_FSPA4S3nI" | "N+FSPA4S3nI" => Some(hle_sceAmprCommandBufferSetBuffer as u64),

        // Unresolved ones
        "ICaGtkEIXTk" => Some(hle_ICaGtkEIXTk as u64),
        "WHIOMbb+iIU" | "WHIOMbb_iIU" | "WHIOMbb-iIU" => Some(hle_WHIOMbb_iIU as u64),
        "chJWZcNSzjk" => Some(hle_chJWZcNSzjk as u64),
        "+iAOE3jCnkk" | "plus_iAOE3jCnkk" => Some(hle_plus_iAOE3jCnkk as u64),
        "fPSCdQxgpSw" => Some(hle_fPSCdQxgpSw as u64),
        "eAy8eGNsCuU" => Some(hle_eAy8eGNsCuU as u64),
        "y5K5tPktiL8" => Some(hle_y5K5tPktiL8 as u64),
        "EJBA4dbmvfg" => Some(hle_EJBA4dbmvfg as u64),
        "7Wa3aeJgeVU" => Some(hle_7Wa3aeJgeVU as u64),
        "rP5xLdOf26k" => Some(hle_rP5xLdOf26k as u64),
        "d4NZIlguzv0" => Some(hle_d4NZIlguzv0 as u64),

        _ => None,
    }
}
