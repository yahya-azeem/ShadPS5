// Handwritten HLE Symbols and Resolution Module for Prospero OS APIs.

use log::{info, warn, debug, error};

// Static dummy memory space to resolve C++ variables, vtables, typeinfo, locales
pub static DUMMY_VAR_SPACE: [u64; 1024] = [0; 1024];

// Static NaN value mapped for _Nan double-precision symbols
pub static DUMMY_NAN_VAL: f64 = f64::NAN;

extern "C" {
    static stdin: *mut libc::FILE;
    static stdout: *mut libc::FILE;
    static stderr: *mut libc::FILE;
}

static STACK_CHK_GUARD: u64 = 0x5E5C3D2A1B0F;

pub fn lookup_hle_address(name: &str) -> Option<u64> {
    let base_name = name.split('#').next().unwrap_or(name);
    match base_name {
        // Kernel Memory allocation hooks
        "malloc" => Some(crate::kernel::hle_malloc as u64),
        "free" => Some(crate::kernel::hle_free as u64),
        "calloc" => Some(crate::kernel::hle_calloc as u64),
        "realloc" => Some(crate::kernel::hle_realloc as u64),
        "malloc_stats" => Some(hle_malloc_stats as u64),

        // Libc Mspace allocation intercepts
        "sceLibcMspaceCreate" => Some(hle_sceLibcMspaceCreate as u64),
        "sceLibcMspaceDestroy" => Some(hle_sceLibcMspaceDestroy as u64),
        "sceLibcMspaceMalloc" => Some(hle_sceLibcMspaceMalloc as u64),
        "sceLibcMspaceFree" => Some(hle_sceLibcMspaceFree as u64),
        "sceLibcMspaceCalloc" => Some(hle_sceLibcMspaceCalloc as u64),
        "sceLibcMspaceAlignedAlloc" => Some(hle_sceLibcMspaceAlignedAlloc as u64),
        "sceLibcMspaceMemalign" => Some(hle_sceLibcMspaceMemalign as u64),
        "sceLibcMspaceRealloc" => Some(hle_sceLibcMspaceRealloc as u64),
        "sceLibcMspaceReallocalign" => Some(hle_sceLibcMspaceReallocalign as u64),
        "sceLibcMspacePosixMemalign" => Some(hle_sceLibcMspacePosixMemalign as u64),
        "sceLibcMspaceMallocUsableSize" => Some(hle_sceLibcMspaceMallocUsableSize as u64),
        "sceLibcMspaceIsHeapEmpty" => Some(hle_sceLibcMspaceIsHeapEmpty as u64),

        // Dinkumware Threading Hooks (Mapped to kernel.rs implementations)
        "_Mtx_init" => Some(crate::kernel::hle_Mtx_init as u64),
        "_Mtx_init_with_name" => Some(crate::kernel::hle_Mtx_init_with_name as u64),
        "_Mtx_destroy" => Some(crate::kernel::hle_Mtx_destroy as u64),
        "_Mtx_lock" => Some(crate::kernel::hle_Mtx_lock as u64),
        "_Mtx_unlock" => Some(crate::kernel::hle_Mtx_unlock as u64),
        "_Mtx_timedlock" => Some(crate::kernel::hle_Mtx_timedlock as u64),
        "_Mtx_trylock" => Some(crate::kernel::hle_Mtx_trylock as u64),
        "_Cnd_init" => Some(crate::kernel::hle_Cnd_init as u64),
        "_Cnd_init_with_name" => Some(crate::kernel::hle_Cnd_init_with_name as u64),
        "_Cnd_destroy" => Some(crate::kernel::hle_Cnd_destroy as u64),
        "_Cnd_signal" => Some(crate::kernel::hle_Cnd_signal as u64),
        "_Cnd_broadcast" => Some(crate::kernel::hle_Cnd_broadcast as u64),
        "_Cnd_wait" => Some(crate::kernel::hle_Cnd_wait as u64),
        "_Cnd_timedwait" => Some(crate::kernel::hle_Cnd_timedwait as u64),

        // POSIX / C runtime mappings
        "sceKernelGetDirectMemorySize" => Some(crate::kernel::sceKernelGetDirectMemorySize as u64),
        "sceKernelAllocateDirectMemory" => Some(crate::kernel::sceKernelAllocateDirectMemory as u64),
        "sceKernelMapDirectMemory" => Some(crate::kernel::sceKernelMapDirectMemory as u64),
        "sceKernelReserveVirtualRange" => Some(crate::kernel_hle::sceKernelReserveVirtualRange as u64),
        "sceKernelMapNamedDirectMemory" => Some(crate::kernel_hle::sceKernelMapNamedDirectMemory as u64),
        "sceKernelCreateGpuQueue" => Some(crate::kernel_hle::sceKernelCreateGpuQueue as u64),
        "sceKernelMapGpuRing" => Some(crate::kernel_hle::sceKernelMapGpuRing as u64),
        "sceKernelOpen" => Some(crate::kernel_hle::sceKernelOpen as u64),
        "sceKernelRead" => Some(crate::kernel_hle::sceKernelRead as u64),
        "sceKernelWrite" => Some(crate::kernel_hle::sceKernelWrite as u64),
        "sceKernelLseek" => Some(crate::kernel_hle::sceKernelLseek as u64),
        "sceKernelClose" => Some(crate::kernel_hle::sceKernelClose as u64),
        "sceKernelFstat" => Some(crate::kernel_hle::sceKernelFstat as u64),
        "sceKernelLoadStartModule" => Some(crate::kernel_hle::sceKernelLoadStartModule as u64),
        "sceKernelStopUnloadModule" => Some(crate::kernel_hle::sceKernelStopUnloadModule as u64),

        "scePthreadCreate" => Some(crate::kernel::scePthreadCreate as u64),
        "scePthreadJoin" => Some(crate::kernel::scePthreadJoin as u64),
        "scePthreadSelf" => Some(crate::kernel::scePthreadSelf as u64),
        "scePthreadExit" => Some(crate::kernel::scePthreadExit as u64),
        "scePthreadMutexInit" => Some(crate::kernel::scePthreadMutexInit as u64),
        "scePthreadMutexLock" => Some(crate::kernel::scePthreadMutexLock as u64),
        "scePthreadMutexUnlock" => Some(crate::kernel::scePthreadMutexUnlock as u64),
        "scePthreadMutexDestroy" => Some(crate::kernel::scePthreadMutexDestroy as u64),
        "scePthreadCondInit" => Some(crate::kernel::scePthreadCondInit as u64),
        "scePthreadCondDestroy" => Some(crate::kernel::scePthreadCondDestroy as u64),
        "scePthreadCondSignal" => Some(crate::kernel::scePthreadCondSignal as u64),
        "scePthreadCondBroadcast" => Some(crate::kernel::scePthreadCondBroadcast as u64),
        "scePthreadCondWait" => Some(crate::kernel::scePthreadCondWait as u64),

        "sceNetInit" => Some(crate::network::sceNetInit as u64),
        "sceNetSocket" => Some(crate::network::sceNetSocket as u64),
        "sceNetConnect" => Some(crate::network::sceNetConnect as u64),
        "sceNetSend" => Some(crate::network::sceNetSend as u64),
        "sceNetRecv" => Some(crate::network::sceNetRecv as u64),
        "sceNetSocketClose" => Some(crate::network::sceNetSocketClose as u64),
        "sceNetClose" => Some(crate::network::sceNetClose as u64),
        "sceNetPoolCreate" => Some(crate::network::sceNetPoolCreate as u64),
        "sceNetPoolDestroy" => Some(crate::network::sceNetPoolDestroy as u64),
        
        "sceAudioOutInit" => Some(crate::audio::sceAudioOutInit as u64),
        "sceAudioOutOpen" => Some(crate::audio::sceAudioOutOpen as u64),
        "sceAudioOutClose" => Some(crate::audio::sceAudioOutClose as u64),
        "sceAudioOutOutput" => Some(crate::audio::sceAudioOutOutput as u64),
        "sceAudioOutSetVolume" => Some(crate::audio::sceAudioOutSetVolume as u64),
        "sceAudio3dInitialize" => Some(crate::audio::sceAudio3dInitialize as u64),
        
        "scePadInit" => Some(crate::input::scePadInit as u64),
        "scePadOpen" => Some(crate::input::scePadOpen as u64),
        "scePadClose" => Some(crate::input::scePadClose as u64),
        "scePadReadState" => Some(crate::input::scePadReadState as u64),
        
        "sceUserServiceInitialize" => Some(crate::user_service::sceUserServiceInitialize as u64),
        "sceUserServiceGetLoginUserIdList" => Some(crate::user_service::sceUserServiceGetLoginUserIdList as u64),
        "sceUserServiceGetUserName" => Some(crate::user_service::sceUserServiceGetUserName as u64),
        "sceUserServiceTerminate" => Some(crate::user_service::sceUserServiceTerminate as u64),
        
        "sceAgcSubmitGraphics" => Some(crate::graphics::sceAgcSubmitGraphics as u64),
        "sceAgcSubmitAsyncCompute" => Some(crate::graphics::sceAgcSubmitAsyncCompute as u64),
        
        "sceSaveDataInitialize3" => Some(crate::save_data::sceSaveDataInitialize3 as u64),
        "sceSaveDataTerminate" => Some(crate::save_data::sceSaveDataTerminate as u64),
        "sceSaveDataCreateTransactionResource" => Some(crate::save_data::sceSaveDataCreateTransactionResource as u64),
        "sceSaveDataDeleteTransactionResource" => Some(crate::save_data::sceSaveDataDeleteTransactionResource as u64),
        "sceSaveDataMount3" => Some(crate::save_data::sceSaveDataMount3 as u64),
        "sceSaveDataUmount2" => Some(crate::save_data::sceSaveDataUmount2 as u64),
        "sceSaveDataGetMountInfo" => Some(crate::save_data::sceSaveDataGetMountInfo as u64),
        "sceSaveDataPrepare" => Some(crate::save_data::sceSaveDataPrepare as u64),
        "sceSaveDataCommit" => Some(crate::save_data::sceSaveDataCommit as u64),
        
        "sceCommonDialogInitialize" => Some(crate::common_dialog::sceCommonDialogInitialize as u64),
        "sceCommonDialogIsUsed" => Some(crate::common_dialog::sceCommonDialogIsUsed as u64),
        "sceMsgDialogInitialize" => Some(crate::common_dialog::sceMsgDialogInitialize as u64),
        "sceMsgDialogOpen" => Some(crate::common_dialog::sceMsgDialogOpen as u64),
        "sceMsgDialogUpdateStatus" => Some(crate::common_dialog::sceMsgDialogUpdateStatus as u64),
        "sceMsgDialogGetStatus" => Some(crate::common_dialog::sceMsgDialogGetStatus as u64),
        "sceMsgDialogGetResult" => Some(crate::common_dialog::sceMsgDialogGetResult as u64),
        "sceMsgDialogTerminate" => Some(crate::common_dialog::sceMsgDialogTerminate as u64),
        "sceMsgDialogClose" => Some(crate::common_dialog::sceMsgDialogClose as u64),
        "sceMsgDialogProgressBarInc" => Some(crate::common_dialog::sceMsgDialogProgressBarInc as u64),
        "sceMsgDialogProgressBarSetValue" => Some(crate::common_dialog::sceMsgDialogProgressBarSetValue as u64),
        "sceMsgDialogProgressBarSetMsg" => Some(crate::common_dialog::sceMsgDialogProgressBarSetMsg as u64),
        "sceVideoOutOpen" => Some(crate::video_out::sceVideoOutOpen as u64),
        "sceVideoOutClose" => Some(crate::video_out::sceVideoOutClose as u64),
        "sceVideoOutRegisterBuffers2" => Some(crate::video_out::sceVideoOutRegisterBuffers2 as u64),
        "sceVideoOutSubmitFlip" => Some(crate::video_out::sceVideoOutSubmitFlip as u64),
        "sceVideoOutGetFlipStatus" => Some(crate::video_out::sceVideoOutGetFlipStatus as u64),
        "sceVideoOutGetVblankStatus" => Some(crate::video_out::sceVideoOutGetVblankStatus as u64),
        "sceVideoOutIsFlipPending" => Some(crate::video_out::sceVideoOutIsFlipPending as u64),
        "sceVideoOutWaitVblank" => Some(crate::video_out::sceVideoOutWaitVblank as u64),

        "memcpy" => Some(hle_memcpy as u64),
        "memset" => Some(hle_memset as u64),
        "memmove" => Some(hle_memmove as u64),
        "__stack_chk_fail" => Some(hle_stack_chk_fail as u64),
        "printf" => Some(hle_printf as u64),
        "exit" => Some(hle_exit as u64),
        "usleep" => Some(hle_usleep as u64),
        
        // Math functions (double precision)
        "sin" => Some(hle_sin as u64),
        "cos" => Some(hle_cos as u64),
        "exp" => Some(hle_exp as u64),
        "log" => Some(hle_log as u64),
        "pow" => Some(hle_pow as u64),
        "modf" => Some(hle_modf as u64),
        "ldexp" => Some(hle_ldexp as u64),
        "exp2" => Some(hle_exp2 as u64),
        
        // Math functions (single precision)
        "sinf" => Some(hle_sinf as u64),
        "cosf" => Some(hle_cosf as u64),
        "expf" => Some(hle_expf as u64),
        "logf" => Some(hle_logf as u64),
        "fmodf" => Some(hle_fmodf as u64),
        "log10f" => Some(hle_log10f as u64),
        "sincos" => Some(hle_sincos as u64),
        "sincosf" => Some(hle_sincosf as u64),
        
        // Compiler builtins
        "powisf2" => Some(hle_powisf2 as u64),
        "__udivti3" => Some(hle_udivti3 as u64),
        "__Atomic_load_2" => Some(hle_Atomic_load_2 as u64),
        "__divsf3" => Some(hle_divsf3 as u64),
        "__mulsf3" => Some(hle_mulsf3 as u64),
        "__umodsi3" => Some(hle_umodsi3 as u64),
        "__floatundixf" => Some(hle_floatundixf as u64),
        
        // Dinkumware float classifications
        "_FDtest" => Some(hle_FDtest as u64),
        "_Dtest" => Some(hle_Dtest as u64),
        "_LDtest" => Some(hle_LDtest as u64),
        "_Getpctype" | "sUP1hBaouOw" => Some(hle_Getpctype as u64),
        "_Getptolower" | "1uJgoVq3bQU" => Some(hle_Getptolower as u64),
        "_Getptoupper" | "rcQCUr0EaRU" => Some(hle_Getptoupper as u64),
        
        // C string / utility functions
        "vfprintf" => Some(hle_vfprintf as u64),
        "strcspn" => Some(hle_strcspn as u64),
        "ctime" => Some(hle_ctime as u64),
        "strnlen" => Some(hle_strnlen as u64),
        "strchr" => Some(hle_strchr as u64),
        "mbstowcs" => Some(hle_mbstowcs as u64),
        "_Nan" => Some(&DUMMY_NAN_VAL as *const f64 as u64),
        "fopen" | "xeYO4u7uyJ0" => Some(hle_fopen as u64),
        "fclose" | "uodLYyUip20" => Some(hle_fclose as u64),
        "fread" | "lbB+UlZqVG0" => Some(hle_fread as u64),
        "fwrite" | "MpxhMh8QFro" => Some(hle_fwrite as u64),
        "ftell" | "Qazy8LmXTvw" => Some(hle_ftell as u64),
        "memchr" | "8u8lPzUEq+U" => Some(hle_memchr as u64),
        "bcmp" | "5TjaJwkLWxE" => Some(hle_bcmp as u64),
        "sprintf" | "tcVi5SivF7Q" => Some(hle_sprintf as u64),
        "vsprintf" | "jbz9I9vkqkk" => Some(hle_vsprintf as u64),
        "snprintf" | "eLdDw6l0-bU" => Some(hle_snprintf as u64),
        "vsnprintf" | "Q2V+iqvjgC0" => Some(hle_vsnprintf as u64),
        "strstr" | "viiwFMaNamA" => Some(hle_strstr as u64),
        "__isnan" | "GfxAp9Xyiqs" => Some(hle_isnan as u64),
        "__isnanf" | "lA94ZgT+vMM" => Some(hle_isnanf as u64),
        "__isfinite" | "dhK16CKwhQg" => Some(hle_isfinite as u64),
        "__isfinitef" | "Q8pvJimUWis" => Some(hle_isfinitef as u64),
        
        // C++ Exception / Unwind / Alloc critical stubs
        "__cxa_allocate_exception" | "cfAXurvfl5o" => Some(hle_cxa_allocate_exception as u64),
        "__cxa_free_exception" | "nOIEswYD4Ig" => Some(hle_cxa_free_exception as u64),
        "__cxa_throw" | "vkuuLfhnSZI" => Some(hle_cxa_throw as u64),
        "__cxa_rethrow" | "ZL9FV4mJXxo" => Some(hle_cxa_rethrow as u64),
        "__cxa_end_catch" | "lX+4FNUklF0" => Some(hle_cxa_end_catch as u64),
        "__cxa_uncaught_exception" => Some(hle_uncaught_exception as u64),
        "_ZSt9terminatev" => Some(hle_terminate as u64),
        "_Unwind_Resume" => Some(hle_Unwind_Resume as u64),
        "_Unwind_Resume_or_Rethrow" => Some(hle_Unwind_Resume as u64),
        "_ZNSt15system_categoryEv" => Some(hle_noop as u64),
        "_ZNSt14threadhardware_concurrencyEv" | "_ZNSt6thread20hardware_concurrencyEv" => Some(hle_hardware_concurrency as u64),
        "_ZNSt12bad_allocateEv" => Some(hle_Xbad_alloc as u64),
        "_ZSt20__throw_bad_function_callv" => Some(hle_Xbad_function_call as u64),
        "_ZNSt12length_errorC1EPKc" | "_ZNSt12length_errorC2EPKc" => Some(hle_Xlength_error as u64),
        "_ZNSt12out_of_rangeC1EPKc" | "_ZNSt12out_of_rangeC2EPKc" => Some(hle_Xout_of_range as u64),
        "_ZNSt16invalid_argumentC1EPKc" | "_ZNSt16invalid_argumentC2EPKc" => Some(hle_Xinvalid_argument as u64),
        "_ZSt11_Throw_C_errori" => Some(hle_Throw_C_error as u64),
        "_ZSt13_Throw_Cpp_errori" => Some(hle_Throw_Cpp_error as u64),
        "_ZSt15get_new_handlerv" => Some(hle_get_new_handler as u64),
        
        "rand" | "random_device" => Some(hle_Random_device as u64),
        "strcat" => Some(hle_strcat as u64),
        "strrchr" => Some(hle_strrchr as u64),
        "strspn" => Some(hle_strspn as u64),
        "strncasecmp" => Some(hle_strncasecmp as u64),
        "strcasecmp" => Some(hle_strcasecmp as u64),
        "strlen" => Some(hle_strlen as u64),
        "strcmp" => Some(hle_strcmp as u64),
        "strncmp" => Some(hle_strncmp as u64),
        "strcpy" => Some(hle_strcpy as u64),
        "strncpy" => Some(hle_strncpy as u64),
        "memcmp" => Some(hle_memcmp as u64),
        "strtol" => Some(hle_strtol as u64),
        "strtoull" => Some(hle_strtoull as u64),
        "strtok" => Some(hle_strtok as u64),
        "sscanf" => Some(hle_sscanf as u64),
        "puts" => Some(hle_puts as u64),
        "qsort" => Some(hle_qsort as u64),
        "memalign" => Some(hle_memalign as u64),
        "localeconv" => Some(hle_localeconv as u64),
        "tanf" => Some(hle_tanf as u64),
        "powf" => Some(hle_powf as u64),
        "ldexpf" => Some(hle_ldexpf as u64),
        "modff" => Some(hle_modff as u64),
        "log2f" => Some(hle_log2f as u64),
        "isfinite" => Some(hle_isfinite as u64),
        "isfinitef" => Some(hle_isfinitef as u64),
        "isfinitel" => Some(hle_isfinitel as u64),
        "isnan" => Some(hle_isnan as u64),
        "isnanf" => Some(hle_isnanf as u64),
        
        // setjmp/longjmp
        "setjmp" => Some(hle_setjmp as u64),
        "longjmp" => Some(hle_longjmp as u64),
        "quick_exit" => Some(hle_quick_exit as u64),
        
        // Dinkumware threading
        "_Thrd_join" => Some(hle_Thrd_join as u64),
        "_Thrd_detach" => Some(hle_Thrd_detach as u64),
        "_Thrd_yield" => Some(hle_Thrd_yield as u64),
        "_Thrd_id" => Some(hle_Thrd_id as u64),
        "_Thrd_current" => Some(hle_Thrd_current as u64),
        "_Thrd_equal" => Some(hle_Thrd_equal as u64),
        "_Locksyslock" => Some(hle_Locksyslock as u64),
        "_Unlocksyslock" => Some(hle_Unlocksyslock as u64),
        "_Towctrans" => Some(hle_Towctrans as u64),
        
        // POSIX threading/scheduler/srand/fgetwc
        "pthread_yield" => Some(hle_pthread_yield as u64),
        "srand" => Some(hle_srand as u64),
        "time" | "wLlFkwG9UcQ" => Some(hle_time as u64),
        "localtime" | "efhK-YSUYYQ" => Some(hle_localtime as u64),
        "asctime" | "jT3xiGpA3B4" => Some(hle_asctime as u64),
        "fgetwc" => Some(hle_fgetwc as u64),
        "sched_getparam" => Some(hle_sched_getparam as u64),
        "pthread_exit" => Some(crate::kernel::scePthreadExit as u64),
        "pthread_mutex_timedlock" => Some(hle_pthread_mutex_timedlock as u64),
        
        // POSIX Read-Write Locks
        "pthread_rwlock_init" | "ytQULN-nhL4" | "6ULAa0fq4jA" => Some(hle_pthread_rwlock_init as u64),
        "pthread_rwlock_destroy" | "1471ajPzxh0" | "BB+kb08Tl9A" => Some(hle_pthread_rwlock_destroy as u64),
        "pthread_rwlock_rdlock" | "iGjsr1WAtI0" | "Ox9i0c7L5w0" => Some(hle_pthread_rwlock_rdlock as u64),
        "pthread_rwlock_timedrdlock" | "lb8lnYo-o7k" | "iPtZRWICjrM" => Some(hle_pthread_rwlock_timedrdlock as u64),
        "pthread_rwlock_wrlock" | "sIlRvQqsN2Y" | "mqdNorrB+gI" => Some(hle_pthread_rwlock_wrlock as u64),
        "pthread_rwlock_timedwrlock" | "9zklzAl9CGM" | "adh--6nIqTk" => Some(hle_pthread_rwlock_timedwrlock as u64),
        "pthread_rwlock_tryrdlock" | "SFxTMOfuCkE" | "XD3mDeybCnk" => Some(hle_pthread_rwlock_tryrdlock as u64),
        "pthread_rwlock_trywrlock" | "XhWHn6P5R7U" | "bIHoZCTomsI" => Some(hle_pthread_rwlock_trywrlock as u64),
        "pthread_rwlock_unlock" | "EgmLo6EWgso" | "+L98PIbGttk" => Some(hle_pthread_rwlock_unlock as u64),
        "pthread_rwlockattr_init" | "xFebsA4YsFI" | "yOfGg-I1ZII" => Some(hle_pthread_rwlockattr_init as u64),
        "pthread_rwlockattr_destroy" | "qsdmgXjqSgk" | "i2ifZ3fS2fo" => Some(hle_pthread_rwlockattr_destroy as u64),
        "pthread_rwlockattr_getpshared" | "VqEMuCv-qHY" | "LcOZBHGqbFk" => Some(hle_pthread_rwlockattr_getpshared as u64),
        "pthread_rwlockattr_setpshared" | "OuKg+kRDD7U" | "-ZvQH18j10c" => Some(hle_pthread_rwlockattr_setpshared as u64),
        "pthread_rwlockattr_gettype_np" | "l+bG5fsYkhg" | "Kyls1ChFyrc" => Some(hle_pthread_rwlockattr_gettype_np as u64),
        "pthread_rwlockattr_settype_np" | "8NuOHiTr1Vw" | "h-OifiouBd8" => Some(hle_pthread_rwlockattr_settype_np as u64),
        
        // Network stubs
        "socket" => Some(hle_socket as u64),
        "sendto" => Some(hle_sendto as u64),
        "send" => Some(hle_send as u64),
        "recvfrom" => Some(hle_recvfrom as u64),
        "setsockopt" => Some(hle_setsockopt as u64),
        "inet_ntop" => Some(hle_inet_ntop as u64),
        "inet_pton" => Some(hle_inet_pton as u64),
        
        // Additional CRT / POSIX stubs
        "freopen" | "gkWgn0p1AfU" => Some(hle_freopen as u64),
        "freopen_s" | "NdvAi34vV3g" => Some(hle_freopen_s as u64),
        "__error" => Some(crate::loader::hle_error as u64),
        "__tls_get_addr" => Some(crate::loader::hle_tls_get_addr as u64),
        "__stack_chk_guard" => Some(&STACK_CHK_GUARD as *const u64 as u64),
        "_Stdin" | "__stdinp" => Some(unsafe { stdin } as u64),
        "_Stdout" | "__stdoutp" => Some(unsafe { stdout } as u64),
        "_Stderr" | "__stderrp" => Some(unsafe { stderr } as u64),
        "_init_env" => Some(hle_noop as u64),
        "feof" => Some(hle_feof as u64),
        "fflush" => Some(hle_fflush as u64),
        "wcstoul" => Some(hle_wcstoul as u64),
        "bsearch" => Some(hle_bsearch as u64),
        "lgamma_r" => Some(hle_lgamma_r as u64),
        "fmod" => Some(hle_fmod as u64),
        "_Exit" => Some(hle_Exit as u64),
        "atexit" => Some(hle_atexit as u64),
        "catchReturnFromMain" => Some(hle_catchReturnFromMain as u64),
        "__cxa_atexit" => Some(hle_cxa_atexit as u64),
        "__cxa_begin_catch" => Some(hle_cxa_begin_catch as u64),
        "__cxa_guard_acquire" => Some(hle_cxa_guard_acquire as u64),
        "__cxa_guard_abort" => Some(hle_cxa_guard_abort as u64),
        "__cxa_guard_release" => Some(hle_cxa_guard_release as u64),
        "_Znwm" => Some(hle_new as u64),
        "_Znam" => Some(hle_new_array as u64),
        "_ZdlPv" | "_ZdaPv" | "_ZdlPvm" | "_ZdaPvm" => Some(hle_delete as u64),
        "rintf" => Some(hle_rintf as u64),
        "tan" => Some(hle_tan as u64),
        "c16rtomb" => Some(hle_c16rtomb as u64),
        "_Xtime_get_ticks" => Some(hle_Xtime_get_ticks as u64),
        "nexttowardl" => Some(hle_nexttowardl as u64),

        "__signbit" => Some(hle_signbit as u64),
        "__isfinitel" => Some(hle_isfinitel as u64),
        "fseek" => Some(hle_fseek as u64),
        "rewind" => Some(hle_rewind as u64),
        "strtod" => Some(hle_strtod as u64),
        "_Stoul" => Some(hle_Stoul as u64),
        "_Atomic_compare_exchange_weak_4" => Some(hle_Atomic_compare_exchange_weak_4 as u64),
        "_Atomic_fetch_add_4" => Some(hle_Atomic_fetch_add_4 as u64),
        "_Atomic_fetch_sub_4" => Some(hle_Atomic_fetch_sub_4 as u64),
        "_Atomic_load_4" => Some(hle_Atomic_load_4 as u64),
        "atan2f" => Some(hle_atan2f as u64),
        "__dynamic_cast" => Some(hle_noop as u64),
        "atof" => Some(hle_atof as u64),
        "fgets" => Some(hle_fgets as u64),
        "difftime" => Some(hle_difftime as u64),
        "atan" => Some(hle_atan as u64),
        "close" => Some(hle_close as u64),
        "bind" => Some(hle_bind as u64),
        "fprintf" => Some(hle_fprintf as u64),
        "fputc" => Some(hle_fputc as u64),
        "sprintf_s" => Some(hle_sprintf_s as u64),
        "acosf" => Some(hle_acosf as u64),
        "fputs" => Some(hle_fputs as u64),
        "abort" => Some(hle_abort as u64),
        "sceKernelUsleep" => Some(hle_sceKernelUsleep as u64),
        "_sceFiberInitializeImpl" => Some(hle_sceFiberInitializeImpl as u64),
        "aligned_alloc" => Some(hle_aligned_alloc as u64),
        "_Mtx_init_with_default_name_override" => Some(hle_Mtx_init_with_default_name_override as u64),
        "__powisf2" => Some(hle_powisf2 as u64),
        "__gxx_personality_v0" => Some(hle_noop as u64),
        "__cxa_pure_virtual" => Some(hle_cxa_pure_virtual as u64),
        "Need_sceLibc" => Some(&DUMMY_VAR_SPACE as *const _ as u64),
        "exp2f" => Some(hle_exp2f as u64),
        "ferror" => Some(hle_ferror as u64),
        
        _ if base_name.starts_with("sceAgc") || 
             base_name.starts_with("sceAmpr") || 
             base_name.starts_with("sceFiber") || 
             base_name.starts_with("sceNgs2") ||
             base_name.starts_with("sceKernelApr") ||
             base_name.starts_with("sceJson") ||
             base_name.starts_with("_Z") ||
             (base_name.len() == 11 && base_name.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_')) => {
            if base_name.starts_with("_ZTV") || base_name.starts_with("_ZTI") || base_name.starts_with("_ZTS") || base_name.starts_with("_ZGV") || base_name.starts_with("_ZNSt14numeric_limits") || base_name.ends_with("trapsE") {
                Some(&DUMMY_VAR_SPACE as *const _ as u64)
            } else {
                Some(hle_noop as u64)
            }
        }
        _ => None,
    }
}

extern "sysv64" fn hle_noop() -> i32 {
    0
}

unsafe extern "sysv64" fn hle_feof(stream: *mut std::ffi::c_void) -> i32 {
    if stream.is_null() {
        return 0;
    }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        0
    } else {
        extern "C" {
            fn feof(stream: *mut std::ffi::c_void) -> i32;
        }
        feof(stream)
    }
}

unsafe extern "sysv64" fn hle_fflush(stream: *mut std::ffi::c_void) -> i32 {
    if stream.is_null() {
        return 0;
    }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        0
    } else {
        extern "C" {
            fn fflush(stream: *mut std::ffi::c_void) -> i32;
        }
        fflush(stream)
    }
}

unsafe extern "sysv64" fn hle_wcstoul(nptr: *const u32, endptr: *mut *mut u32, base: i32) -> u64 {
    extern "C" {
        fn wcstoul(nptr: *const u32, endptr: *mut *mut u32, base: i32) -> u64;
    }
    wcstoul(nptr, endptr, base)
}

unsafe extern "sysv64" fn hle_bsearch(
    key: *const std::ffi::c_void,
    base: *const std::ffi::c_void,
    nmemb: usize,
    size: usize,
    compar: u64,
) -> *mut std::ffi::c_void {
    if key.is_null() || base.is_null() || compar == 0 {
        return std::ptr::null_mut();
    }
    let compare_fn: unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> i32 = 
        std::mem::transmute(compar);
    libc::bsearch(key, base, nmemb, size, Some(compare_fn))
}

unsafe extern "sysv64" fn hle_lgamma_r(x: f64, signgamp: *mut i32) -> f64 {
    extern "C" {
        fn lgamma_r(x: f64, signgamp: *mut i32) -> f64;
    }
    lgamma_r(x, signgamp)
}

extern "sysv64" fn hle_fmod(x: f64, y: f64) -> f64 { x % y }

extern "sysv64" fn hle_Exit(status: i32) {
    info!("Guest called _Exit({})", status);
    std::process::exit(status);
}

unsafe extern "sysv64" fn hle_atexit(func: u64) -> i32 {
    info!("atexit handler registered: 0x{:X}", func);
    0
}

unsafe extern "sysv64" fn hle_catchReturnFromMain(status: i32) {
    info!("catchReturnFromMain called with status: {}", status);
    std::process::exit(status);
}

unsafe extern "sysv64" fn hle_cxa_atexit(func: u64, arg: u64, dso_handle: u64) -> i32 {
    info!("__cxa_atexit handler registered: func=0x{:X}, arg=0x{:X}, dso=0x{:X}", func, arg, dso_handle);
    0
}

unsafe extern "sysv64" fn hle_cxa_begin_catch(exception_obj: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    info!("__cxa_begin_catch called for exception: {:p}", exception_obj);
    exception_obj
}

unsafe extern "sysv64" fn hle_cxa_guard_acquire(guard_object: *mut i64) -> i32 {
    if guard_object.is_null() {
        return 0;
    }
    let val = *guard_object;
    let initialized = (val & 0xFF) != 0;
    if initialized {
        0
    } else {
        1
    }
}

unsafe extern "sysv64" fn hle_cxa_guard_release(guard_object: *mut i64) {
    if !guard_object.is_null() {
        *guard_object = 1;
    }
}

unsafe extern "sysv64" fn hle_cxa_guard_abort(guard_object: *mut i64) {
    if !guard_object.is_null() {
        *guard_object = 0;
    }
}

unsafe extern "sysv64" fn hle_delete(ptr: *mut std::ffi::c_void) {
    crate::kernel::hle_free(ptr as *mut u8);
}

unsafe extern "sysv64" fn hle_new_array(size: usize) -> *mut std::ffi::c_void {
    crate::kernel::hle_malloc(size) as *mut std::ffi::c_void
}

unsafe extern "sysv64" fn hle_new(size: usize) -> *mut std::ffi::c_void {
    crate::kernel::hle_malloc(size) as *mut std::ffi::c_void
}

unsafe extern "sysv64" fn hle_strcasecmp(s1: *const std::ffi::c_char, s2: *const std::ffi::c_char) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    libc::strcasecmp(s1, s2)
}

unsafe extern "sysv64" fn hle_strlen(s: *const std::ffi::c_char) -> usize {
    if s.is_null() { return 0; }
    libc::strlen(s)
}

unsafe extern "sysv64" fn hle_strcmp(s1: *const std::ffi::c_char, s2: *const std::ffi::c_char) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    libc::strcmp(s1, s2)
}

unsafe extern "sysv64" fn hle_strncmp(s1: *const std::ffi::c_char, s2: *const std::ffi::c_char, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    libc::strncmp(s1, s2, n)
}

unsafe extern "sysv64" fn hle_strcpy(dst: *mut std::ffi::c_char, src: *const std::ffi::c_char) -> *mut std::ffi::c_char {
    if dst.is_null() || src.is_null() { return dst; }
    libc::strcpy(dst, src)
}

unsafe extern "sysv64" fn hle_strncpy(dst: *mut std::ffi::c_char, src: *const std::ffi::c_char, n: usize) -> *mut std::ffi::c_char {
    if dst.is_null() || src.is_null() { return dst; }
    libc::strncpy(dst, src, n)
}

unsafe extern "sysv64" fn hle_memcmp(s1: *const std::ffi::c_void, s2: *const std::ffi::c_void, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    libc::memcmp(s1, s2, n)
}

extern "sysv64" fn hle_rintf(x: f32) -> f32 { x.round() }

extern "sysv64" fn hle_tan(x: f64) -> f64 { x.tan() }

unsafe extern "sysv64" fn hle_c16rtomb(pmb: *mut u8, c16: u16, _ps: *mut std::ffi::c_void) -> usize {
    if pmb.is_null() {
        return 1;
    }
    if c16 < 0x80 {
        *pmb = c16 as u8;
        1
    } else if c16 < 0x800 {
        *pmb = (0xC0 | (c16 >> 6)) as u8;
        *pmb.add(1) = (0x80 | (c16 & 0x3F)) as u8;
        2
    } else {
        *pmb = (0xE0 | (c16 >> 12)) as u8;
        *pmb.add(1) = (0x80 | ((c16 >> 6) & 0x3F)) as u8;
        *pmb.add(2) = (0x80 | (c16 & 0x3F)) as u8;
        3
    }
}

extern "sysv64" fn hle_Xtime_get_ticks() -> i64 {
    hle_get_process_time() as i64
}

extern "sysv64" fn hle_nexttowardl(x: f64, _y: f64) -> f64 { x }

unsafe extern "sysv64" fn hle_sceAgcDriverSubmitDcb(
    arg0: u64,
    dcb_gpu_addr: u64,
    dcb_size_in_dwords: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
) -> i32 {
    info!(
        "API Driver Intercepted: sceAgcDriverSubmitDcb | Context: 0x{:X} | PacketAddress: 0x{:X} | Size: {} DWORDs",
        arg0, dcb_gpu_addr, dcb_size_in_dwords
    );
    crate::graphics::decode_pm4_command_buffer(dcb_gpu_addr, dcb_size_in_dwords as u32);
    0
}

unsafe extern "sysv64" fn hle_memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    std::ptr::copy_nonoverlapping(src, dest, n);
    dest
}

unsafe extern "sysv64" fn hle_memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    std::ptr::write_bytes(dest, c as u8, n);
    dest
}

unsafe extern "sysv64" fn hle_memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    std::ptr::copy(src, dest, n);
    dest
}

extern "sysv64" fn hle_stack_chk_fail() {
    error!("Stack corruption detected in guest (stack_chk_fail)!");
    std::process::exit(1);
}

static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

extern "sysv64" fn hle_get_process_time() -> u64 {
    let start = START_TIME.get_or_init(std::time::Instant::now);
    start.elapsed().as_micros() as u64
}

fn format_c_string(format: &str, args: &[u64]) -> String {
    let mut result = String::new();
    let mut chars = format.chars().peekable();
    let mut arg_idx = 0;

    while let Some(c) = chars.next() {
        if c == '%' {
            if let Some(&next_c) = chars.peek() {
                if next_c == '%' {
                    result.push('%');
                    chars.next();
                    continue;
                }
            }

            let mut flags = String::new();
            while let Some(&next_c) = chars.peek() {
                if next_c == '-' || next_c == '+' || next_c == ' ' || next_c == '#' || next_c == '0' {
                    flags.push(next_c);
                    chars.next();
                } else {
                    break;
                }
            }

            let mut width = None;
            let mut width_val = 0;
            let mut has_width = false;
            while let Some(&next_c) = chars.peek() {
                if next_c.is_ascii_digit() {
                    width_val = width_val * 10 + (next_c as u8 - b'0') as usize;
                    has_width = true;
                    chars.next();
                } else {
                    break;
                }
            }
            if has_width {
                width = Some(width_val);
            }

            let mut precision = None;
            if let Some(&next_c) = chars.peek() {
                if next_c == '.' {
                    chars.next();
                    let mut prec_val = 0;
                    let mut has_prec = false;
                    while let Some(&next_c) = chars.peek() {
                        if next_c.is_ascii_digit() {
                            prec_val = prec_val * 10 + (next_c as u8 - b'0') as usize;
                            has_prec = true;
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if has_prec {
                        precision = Some(prec_val);
                    }
                }
            }

            let mut long_spec = false;
            let mut size_t_spec = false;
            while let Some(&next_c) = chars.peek() {
                if next_c == 'l' {
                    long_spec = true;
                    chars.next();
                } else if next_c == 'z' {
                    size_t_spec = true;
                    chars.next();
                } else if next_c == 'h' {
                    chars.next();
                } else {
                    break;
                }
            }

            if let Some(spec_char) = chars.next() {
                if arg_idx < args.len() {
                    let val = args[arg_idx];
                    arg_idx += 1;
                    let formatted = match spec_char {
                        'd' | 'i' => {
                            let num = if long_spec || size_t_spec { val as i64 } else { val as i32 as i64 };
                            if let Some(w) = width {
                                if flags.contains('0') {
                                    format!("{:0width$}", num, width = w)
                                } else {
                                    format!("{:width$}", num, width = w)
                                }
                            } else {
                                num.to_string()
                            }
                        }
                        'u' => {
                            let num = if long_spec || size_t_spec { val as u64 } else { val as u32 as u64 };
                            if let Some(w) = width {
                                if flags.contains('0') {
                                    format!("{:0width$}", num, width = w)
                                } else {
                                    format!("{:width$}", num, width = w)
                                }
                            } else {
                                num.to_string()
                            }
                        }
                        'x' => {
                            let num = if long_spec || size_t_spec { val as u64 } else { val as u32 as u64 };
                            if let Some(w) = width {
                                if flags.contains('0') {
                                    format!("{:0width$x}", num, width = w)
                                } else {
                                    format!("{:width$x}", num, width = w)
                                }
                            } else {
                                format!("{:x}", num)
                            }
                        }
                        'X' => {
                            let num = if long_spec || size_t_spec { val as u64 } else { val as u32 as u64 };
                            if let Some(w) = width {
                                if flags.contains('0') {
                                    format!("{:0width$X}", num, width = w)
                                } else {
                                    format!("{:width$X}", num, width = w)
                                }
                            } else {
                                format!("{:X}", num)
                            }
                        }
                        'p' => {
                            format!("0x{:x}", val)
                        }
                        's' => {
                            if val == 0 {
                                "(null)".to_string()
                            } else {
                                unsafe {
                                    let cstr = std::ffi::CStr::from_ptr(val as *const std::os::raw::c_char);
                                    if let Ok(s) = cstr.to_str() {
                                        s.to_string()
                                    } else {
                                        "(invalid string)".to_string()
                                    }
                                }
                            }
                        }
                        'c' => {
                            if let Some(ch) = std::char::from_u32(val as u32) {
                                ch.to_string()
                            } else {
                                "?".to_string()
                            }
                        }
                        _ => {
                            let mut raw = "%".to_string();
                            raw.push_str(&flags);
                            if let Some(w) = width {
                                raw.push_str(&w.to_string());
                            }
                            if let Some(p) = precision {
                                raw.push_str(&format!(".{}", p));
                            }
                            if long_spec { raw.push('l'); }
                            if size_t_spec { raw.push('z'); }
                            raw.push(spec_char);
                            raw
                        }
                    };
                    result.push_str(&formatted);
                } else {
                    result.push_str("<missing arg>");
                }
            } else {
                result.push('%');
            }
        } else {
            result.push(c);
        }
    }
    result
}

unsafe extern "sysv64" fn hle_printf(
    format: *const std::os::raw::c_char,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> std::os::raw::c_int {
    if !format.is_null() {
        let cstr = std::ffi::CStr::from_ptr(format);
        if let Ok(str_slice) = cstr.to_str() {
            let formatted = format_c_string(str_slice, &[arg1, arg2, arg3, arg4, arg5]);
            info!("[Guest Printf] {}", formatted.trim_end());
            return formatted.len() as std::os::raw::c_int;
        }
    }
    0
}

extern "sysv64" fn hle_exit(code: i32) {
    info!("Guest exited via exit({})", code);
    std::process::exit(code);
}

unsafe extern "sysv64" fn hle_usleep(usec: u32) -> i32 {
    std::thread::sleep(std::time::Duration::from_micros(usec as u64));
    0
}

// Math functions (double precision):
extern "sysv64" fn hle_sin(x: f64) -> f64 { x.sin() }
extern "sysv64" fn hle_cos(x: f64) -> f64 { x.cos() }
extern "sysv64" fn hle_exp(x: f64) -> f64 { x.exp() }
extern "sysv64" fn hle_log(x: f64) -> f64 { x.ln() }
extern "sysv64" fn hle_pow(x: f64, y: f64) -> f64 { x.powf(y) }
extern "sysv64" fn hle_modf(x: f64, iptr: *mut f64) -> f64 {
    let integer_part = x.trunc();
    if !iptr.is_null() {
        unsafe { *iptr = integer_part; }
    }
    x - integer_part
}
extern "sysv64" fn hle_ldexp(x: f64, exp: i32) -> f64 {
    x * 2.0_f64.powi(exp)
}
extern "sysv64" fn hle_exp2(x: f64) -> f64 { x.exp2() }

// Math functions (single precision):
extern "sysv64" fn hle_sinf(x: f32) -> f32 { x.sin() }
extern "sysv64" fn hle_cosf(x: f32) -> f32 { x.cos() }
extern "sysv64" fn hle_expf(x: f32) -> f32 { x.exp() }
extern "sysv64" fn hle_logf(x: f32) -> f32 { x.ln() }
extern "sysv64" fn hle_fmodf(x: f32, y: f32) -> f32 { x % y }
extern "sysv64" fn hle_log10f(x: f32) -> f32 { x.log10() }

// sincos functions (both double and float):
unsafe extern "sysv64" fn hle_sincos(x: f64, sin_out: *mut f64, cos_out: *mut f64) {
    if !sin_out.is_null() { *sin_out = x.sin(); }
    if !cos_out.is_null() { *cos_out = x.cos(); }
}

unsafe extern "sysv64" fn hle_sincosf(x: f32, sin_out: *mut f32, cos_out: *mut f32) {
    if !sin_out.is_null() { *sin_out = x.sin(); }
    if !cos_out.is_null() { *cos_out = x.cos(); }
}

// Compiler builtins:
extern "sysv64" fn hle_powisf2(base: f32, exp: i32) -> f32 {
    base.powi(exp)
}

extern "sysv64" fn hle_udivti3(a_lo: u64, a_hi: u64, b_lo: u64, b_hi: u64) -> u128 {
    let a = (a_hi as u128) << 64 | a_lo as u128;
    let b = (b_hi as u128) << 64 | b_lo as u128;
    if b == 0 { return 0; }
    a / b
}

unsafe extern "sysv64" fn hle_Atomic_load_2(src: *const u16, _memorder: i32) -> u16 {
    if src.is_null() { return 0; }
    std::ptr::read_volatile(src)
}

// C string/utility functions:
unsafe extern "sysv64" fn hle_vfprintf(
    stream: *mut std::ffi::c_void,
    format: *const libc::c_char,
    ap: *mut std::ffi::c_void,
) -> i32 {
    if stream.is_null() || format.is_null() {
        return -1;
    }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        let mut buf = [0u8; 4096];
        extern "C" {
            fn vsnprintf(s: *mut libc::c_char, n: usize, format: *const libc::c_char, ap: *mut libc::c_void) -> libc::c_int;
        }
        let written = vsnprintf(buf.as_mut_ptr() as *mut libc::c_char, buf.len(), format, ap);
        if written > 0 {
            let text = String::from_utf8_lossy(&buf[..written as usize]);
            info!("[Guest stdio] {}", text.trim_end());
        }
        written
    } else {
        extern "C" {
            fn vfprintf(stream: *mut libc::FILE, format: *const libc::c_char, ap: *mut libc::c_void) -> libc::c_int;
        }
        vfprintf(stream as *mut libc::FILE, format, ap as *mut libc::c_void)
    }
}

unsafe extern "sysv64" fn hle_strcspn(s: *const u8, reject: *const u8) -> usize {
    if s.is_null() || reject.is_null() {
        return 0;
    }
    libc::strcspn(s as *const libc::c_char, reject as *const libc::c_char)
}

unsafe extern "sysv64" fn hle_ctime(timer: *const i64) -> *mut u8 {
    if timer.is_null() {
        return std::ptr::null_mut();
    }
    extern "C" {
        fn ctime(timer: *const libc::time_t) -> *mut libc::c_char;
    }
    ctime(timer as *const libc::time_t) as *mut u8
}

unsafe extern "sysv64" fn hle_strnlen(s: *const u8, maxlen: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    libc::strnlen(s as *const libc::c_char, maxlen)
}

// C++ runtime critical stubs:
extern "sysv64" fn hle_uncaught_exception() -> bool {
    false
}

extern "sysv64" fn hle_terminate() {
    error!("Guest called std::terminate()!");
    std::process::exit(1);
}

extern "sysv64" fn hle_Unwind_Resume(_exception_object: u64) {
    error!("Guest called _Unwind_Resume!");
    std::process::exit(1);
}

extern "sysv64" fn hle_hardware_concurrency() -> u32 {
    std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(4)
}

extern "sysv64" fn hle_Xbad_alloc() {
    error!("Guest called _Xbad_alloc!");
    std::process::exit(1);
}

extern "sysv64" fn hle_Xlength_error(_what: *const u8) {
    error!("Guest called _Xlength_error!");
    std::process::exit(1);
}

extern "sysv64" fn hle_Xout_of_range(_what: *const u8) {
    error!("Guest called _Xout_of_range!");
    std::process::exit(1);
}

extern "sysv64" fn hle_Throw_C_error(_code: i32) {
    error!("Guest called _Throw_C_error!");
}

extern "sysv64" fn hle_Throw_Cpp_error(_code: i32) {
    error!("Guest called _Throw_Cpp_error!");
}

extern "sysv64" fn hle_get_new_handler() -> u64 {
    0  // return null handler
}

extern "sysv64" fn hle_Xbad_function_call() {
    error!("Guest called _Xbad_function_call!");
    std::process::exit(1);
}

extern "sysv64" fn hle_Xinvalid_argument(_what: *const u8) {
    error!("Guest called _Xinvalid_argument!");
    std::process::exit(1);
}

unsafe extern "sysv64" fn hle_Random_device() -> u32 {
    libc::rand() as u32
}

unsafe extern "sysv64" fn hle_strcat(dest: *mut u8, src: *const u8) -> *mut u8 {
    if dest.is_null() || src.is_null() { return dest; }
    libc::strcat(dest as *mut libc::c_char, src as *const libc::c_char) as *mut u8
}

unsafe extern "sysv64" fn hle_strrchr(s: *const u8, c: i32) -> *mut u8 {
    if s.is_null() { return std::ptr::null_mut(); }
    libc::strrchr(s as *const libc::c_char, c) as *mut u8
}

unsafe extern "sysv64" fn hle_strspn(s: *const u8, accept: *const u8) -> usize {
    if s.is_null() || accept.is_null() { return 0; }
    libc::strspn(s as *const libc::c_char, accept as *const libc::c_char)
}

unsafe extern "sysv64" fn hle_strncasecmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() { return 0; }
    libc::strncasecmp(s1 as *const libc::c_char, s2 as *const libc::c_char, n)
}

unsafe extern "sysv64" fn hle_strtol(nptr: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
    if nptr.is_null() { return 0; }
    libc::strtol(nptr as *const libc::c_char, endptr as *mut *mut libc::c_char, base)
}

unsafe extern "sysv64" fn hle_strtoull(nptr: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
    if nptr.is_null() { return 0; }
    libc::strtoull(nptr as *const libc::c_char, endptr as *mut *mut libc::c_char, base)
}

unsafe extern "sysv64" fn hle_strtok(s: *mut u8, delim: *const u8) -> *mut u8 {
    libc::strtok(s as *mut libc::c_char, delim as *const libc::c_char) as *mut u8
}

unsafe extern "sysv64" fn hle_sscanf(
    s: *const u8,
    format: *const u8,
    arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64,
) -> i32 {
    extern "C" {
        fn sscanf(s: *const libc::c_char, format: *const libc::c_char, ...) -> i32;
    }
    if s.is_null() || format.is_null() { return -1; }
    sscanf(s as *const libc::c_char, format as *const libc::c_char, arg1, arg2, arg3, arg4, arg5, arg6)
}

unsafe extern "sysv64" fn hle_puts(s: *const u8) -> i32 {
    if s.is_null() { return -1; }
    libc::puts(s as *const libc::c_char)
}

unsafe extern "sysv64" fn hle_qsort(base: *mut u8, nmemb: usize, size: usize, compar: u64) {
    if base.is_null() || compar == 0 { return; }
    let compare_fn: unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> i32 = 
        std::mem::transmute(compar);
    libc::qsort(base as *mut std::ffi::c_void, nmemb, size, Some(compare_fn));
}

unsafe extern "sysv64" fn hle_memalign(alignment: usize, size: usize) -> *mut u8 {
    let mut ptr = std::ptr::null_mut();
    let align = if alignment < std::mem::size_of::<usize>() { std::mem::size_of::<usize>() } else { alignment };
    if size == 0 { return std::ptr::null_mut(); }
    let ret = libc::posix_memalign(&mut ptr, align, size);
    if ret == 0 { ptr as *mut u8 } else { std::ptr::null_mut() }
}

unsafe extern "sysv64" fn hle_localeconv() -> *mut std::ffi::c_void {
    libc::localeconv() as *mut std::ffi::c_void
}

extern "sysv64" fn hle_tanf(x: f32) -> f32 { x.tan() }
extern "sysv64" fn hle_powf(x: f32, y: f32) -> f32 { x.powf(y) }
extern "sysv64" fn hle_ldexpf(x: f32, exp: i32) -> f32 {
    x * 2.0_f32.powi(exp)
}
extern "sysv64" fn hle_modff(x: f32, iptr: *mut f32) -> f32 {
    let integer_part = x.trunc();
    if !iptr.is_null() {
        unsafe { *iptr = integer_part; }
    }
    x - integer_part
}
extern "sysv64" fn hle_log2f(x: f32) -> f32 { x.log2() }

extern "sysv64" fn hle_isfinite(x: f64) -> i32 { if x.is_finite() { 1 } else { 0 } }
extern "sysv64" fn hle_isfinitef(x: f32) -> i32 { if x.is_finite() { 1 } else { 0 } }
extern "sysv64" fn hle_isfinitel(x: f64) -> i32 { if x.is_finite() { 1 } else { 0 } }
extern "sysv64" fn hle_isnan(x: f64) -> i32 { if x.is_nan() { 1 } else { 0 } }
extern "sysv64" fn hle_isnanf(x: f32) -> i32 { if x.is_nan() { 1 } else { 0 } }

unsafe extern "sysv64" fn hle_setjmp(env: *mut u8) -> i32 {
    if !env.is_null() {
        std::ptr::write_bytes(env, 0, 200);
    }
    0
}

extern "sysv64" fn hle_longjmp(_env: *mut u8, _val: i32) {
    error!("Guest called longjmp - not fully supported!");
}

extern "sysv64" fn hle_quick_exit(status: i32) {
    info!("Guest called quick_exit({})", status);
    std::process::exit(status);
}

unsafe extern "sysv64" fn hle_Thrd_join(thr: u64, res: *mut i32) -> i32 {
    debug!("HLE: _Thrd_join (thr=0x{:X})", thr);
    if !res.is_null() { *res = 0; }
    0
}

extern "sysv64" fn hle_Thrd_detach(_thr: u64) -> i32 {
    debug!("HLE: _Thrd_detach");
    0
}

extern "sysv64" fn hle_Thrd_yield() {
    std::thread::yield_now();
}

extern "sysv64" fn hle_Thrd_id() -> u64 {
    debug!("HLE: _Thrd_id");
    crate::kernel::hle_pthread_self()
}

extern "sysv64" fn hle_Thrd_current() -> u64 {
    debug!("HLE: _Thrd_current");
    crate::kernel::hle_pthread_self()
}

extern "sysv64" fn hle_Thrd_equal(t1: u64, t2: u64) -> i32 {
    debug!("HLE: _Thrd_equal(t1=0x{:X}, t2=0x{:X})", t1, t2);
    if t1 == t2 { 1 } else { 0 }
}

unsafe extern "sysv64" fn hle_Locksyslock(lock_category: i32) {
    debug!("HLE: _Locksyslock({})", lock_category);
}

unsafe extern "sysv64" fn hle_Unlocksyslock(lock_category: i32) {
    debug!("HLE: _Unlocksyslock({})", lock_category);
}

unsafe extern "sysv64" fn hle_Towctrans(_c: u32, _desc: u64) -> u32 {
    0
}

unsafe extern "sysv64" fn hle_socket(domain: i32, type_: i32, protocol: i32) -> i32 {
    debug!("HLE: socket(domain={}, type={}, protocol={})", domain, type_, protocol);
    -1
}

unsafe extern "sysv64" fn hle_sendto(fd: i32, _buf: *const u8, len: usize, _flags: i32, _addr: *const u8, _addrlen: u32) -> i64 {
    debug!("HLE: sendto(fd={}, len={})", fd, len);
    -1
}

unsafe extern "sysv64" fn hle_recvfrom(fd: i32, _buf: *mut u8, len: usize, _flags: i32, _addr: *mut u8, _addrlen: *mut u32) -> i64 {
    debug!("HLE: recvfrom(fd={}, len={})", fd, len);
    -1
}

unsafe extern "sysv64" fn hle_setsockopt(fd: i32, level: i32, optname: i32, _optval: *const u8, _optlen: u32) -> i32 {
    debug!("HLE: setsockopt(fd={}, level={}, opt={})", fd, level, optname);
    0
}

unsafe extern "sysv64" fn hle_inet_ntop(af: i32, _src: *const u8, dst: *mut u8, size: u32) -> *const u8 {
    debug!("HLE: inet_ntop(af={})", af);
    if !dst.is_null() && size > 0 {
        *dst = 0;
    }
    dst
}

unsafe extern "sysv64" fn hle_inet_pton(af: i32, _src: *const u8, _dst: *mut u8) -> i32 {
    debug!("HLE: inet_pton(af={})", af);
    0
}

unsafe extern "sysv64" fn hle_pthread_yield() {
    std::thread::yield_now();
}

unsafe extern "sysv64" fn hle_srand(seed: u32) {
    libc::srand(seed);
}

unsafe extern "sysv64" fn hle_time(tloc: *mut i64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if !tloc.is_null() {
        let host_tloc = if let Some(addr) = crate::kernel::translate_guest_addr(tloc as u64) {
            addr as *mut i64
        } else {
            tloc
        };
        *host_tloc = now;
    }
    now
}

unsafe extern "sysv64" fn hle_localtime(timep: *const i64) -> *mut libc::tm {
    if timep.is_null() {
        return std::ptr::null_mut();
    }
    let host_timep = if let Some(addr) = crate::kernel::translate_guest_addr(timep as u64) {
        addr as *const i64
    } else {
        timep
    };
    libc::localtime(host_timep)
}

unsafe extern "sysv64" fn hle_asctime(tm: *const libc::tm) -> *mut libc::c_char {
    if tm.is_null() {
        return std::ptr::null_mut();
    }
    let host_tm = if let Some(addr) = crate::kernel::translate_guest_addr(tm as u64) {
        addr as *const libc::tm
    } else {
        tm
    };
    extern "C" {
        fn asctime(tm: *const libc::tm) -> *mut libc::c_char;
    }
    asctime(host_tm)
}

unsafe extern "sysv64" fn hle_fgetwc(stream: *mut std::ffi::c_void) -> i32 {
    if stream.is_null() { return -1; }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        -1 // WEOF
    } else {
        extern "C" {
            fn fgetwc(stream: *mut libc::FILE) -> libc::c_int;
        }
        fgetwc(stream as *mut libc::FILE) as i32
    }
}

// =========================================================================
// Newly Added HLE functions for Game Boot
// =========================================================================

#[no_mangle]
pub unsafe extern "sysv64" fn hle_send(fd: i32, buf: *const u8, len: usize, flags: i32) -> i64 {
    debug!("HLE: send(fd={}, len={}, flags={})", fd, len, flags);
    if !buf.is_null() && len > 0 {
        if !crate::kernel::is_valid_guest_ptr(buf as u64, len) {
            warn!("hle_send: Invalid buffer pointer {:p}", buf);
            return -1;
        }
        libc::send(fd, buf as *const libc::c_void, len, flags) as i64
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sched_getparam(pid: i32, param: *mut u8) -> i32 {
    debug!("HLE: sched_getparam(pid={}, param={:p})", pid, param);
    if !param.is_null() {
        std::ptr::write_bytes(param, 0, 16);
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_mutex_timedlock(mutex: *mut u64, abstime: *const u8) -> i32 {
    debug!("HLE: pthread_mutex_timedlock(mutex={:p}, abstime={:p})", mutex, abstime);
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_strchr(s: *const u8, c: i32) -> *mut u8 {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut ptr = s;
    let target = (c & 0xff) as u8;
    while *ptr != 0 {
        if *ptr == target {
            return ptr as *mut u8;
        }
        ptr = ptr.add(1);
    }
    if target == 0 {
        return ptr as *mut u8;
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_malloc_stats() -> i32 {
    debug!("HLE: malloc_stats()");
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_mbstowcs(pwcs: *mut u32, s: *const u8, n: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut count = 0;
    let mut src = s;
    let mut dst = pwcs;
    while *src != 0 && (pwcs.is_null() || count < n) {
        if !pwcs.is_null() {
            *dst = *src as u32;
            dst = dst.add(1);
        }
        src = src.add(1);
        count += 1;
    }
    if !pwcs.is_null() && count < n {
        *dst = 0;
    }
    count
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_divsf3(a: f32, b: f32) -> f32 {
    a / b
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_mulsf3(a: f32, b: f32) -> f32 {
    a * b
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_umodsi3(a: u32, b: u32) -> u32 {
    if b == 0 { 0 } else { a % b }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_floatundixf(val: u64) -> f64 {
    val as f64
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_FDtest(_px: *mut f32) -> i32 { 5 }

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Dtest(_px: *mut f64) -> i32 { 5 }

#[no_mangle]
pub unsafe extern "sysv64" fn hle_LDtest(_px: *mut u8) -> i32 { 5 }

// =========================================================================
// POSIX Read-Write Locks (rwlock) HLE Implementation
// =========================================================================

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_init(rwlock_ptr: *mut i32, _attr: *const u64) -> i32 {
    info!("HLE POSIX: pthread_rwlock_init | rwlock: {:p}", rwlock_ptr);
    if !rwlock_ptr.is_null() {
        *rwlock_ptr = 0; // Initialize as unlocked
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_destroy(rwlock_ptr: *mut i32) -> i32 {
    info!("HLE POSIX: pthread_rwlock_destroy | rwlock: {:p}", rwlock_ptr);
    if !rwlock_ptr.is_null() {
        crate::kernel::hle_pthread_mutex_destroy(rwlock_ptr);
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_rdlock(rwlock_ptr: *mut i32) -> i32 {
    info!("HLE POSIX: pthread_rwlock_rdlock | rwlock: {:p}", rwlock_ptr);
    crate::kernel::hle_pthread_mutex_lock(rwlock_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_timedrdlock(rwlock_ptr: *mut i32, _abstime: *const u64) -> i32 {
    info!("HLE POSIX: pthread_rwlock_timedrdlock | rwlock: {:p}", rwlock_ptr);
    crate::kernel::hle_pthread_mutex_lock(rwlock_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_wrlock(rwlock_ptr: *mut i32) -> i32 {
    info!("HLE POSIX: pthread_rwlock_wrlock | rwlock: {:p}", rwlock_ptr);
    crate::kernel::hle_pthread_mutex_lock(rwlock_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_timedwrlock(rwlock_ptr: *mut i32, _abstime: *const u64) -> i32 {
    info!("HLE POSIX: pthread_rwlock_timedwrlock | rwlock: {:p}", rwlock_ptr);
    crate::kernel::hle_pthread_mutex_lock(rwlock_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_tryrdlock(rwlock_ptr: *mut i32) -> i32 {
    info!("HLE POSIX: pthread_rwlock_tryrdlock | rwlock: {:p}", rwlock_ptr);
    let res = crate::kernel::hle_Mtx_trylock(rwlock_ptr);
    if res == 0 {
        0
    } else {
        16 // EBUSY
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_trywrlock(rwlock_ptr: *mut i32) -> i32 {
    info!("HLE POSIX: pthread_rwlock_trywrlock | rwlock: {:p}", rwlock_ptr);
    let res = crate::kernel::hle_Mtx_trylock(rwlock_ptr);
    if res == 0 {
        0
    } else {
        16 // EBUSY
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlock_unlock(rwlock_ptr: *mut i32) -> i32 {
    info!("HLE POSIX: pthread_rwlock_unlock | rwlock: {:p}", rwlock_ptr);
    crate::kernel::hle_pthread_mutex_unlock(rwlock_ptr)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlockattr_init(attr_ptr: *mut *mut u8) -> i32 {
    info!("HLE POSIX: pthread_rwlockattr_init | attr: {:p}", attr_ptr);
    if !attr_ptr.is_null() {
        *attr_ptr = crate::kernel::hle_malloc(8);
        if (*attr_ptr).is_null() {
            return 12; // ENOMEM
        }
        let data = *attr_ptr as *mut u64;
        *data = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlockattr_destroy(attr_ptr: *mut *mut u8) -> i32 {
    info!("HLE POSIX: pthread_rwlockattr_destroy | attr: {:p}", attr_ptr);
    if !attr_ptr.is_null() && !(*attr_ptr).is_null() {
        crate::kernel::hle_free(*attr_ptr);
        *attr_ptr = std::ptr::null_mut();
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlockattr_getpshared(attr_ptr: *mut *mut u8, pshared: *mut i32) -> i32 {
    info!("HLE POSIX: pthread_rwlockattr_getpshared | attr: {:p}", attr_ptr);
    if !pshared.is_null() {
        *pshared = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlockattr_setpshared(_attr_ptr: *mut *mut u8, pshared: i32) -> i32 {
    info!("HLE POSIX: pthread_rwlockattr_setpshared | pshared: {}", pshared);
    if pshared != 0 {
        return 22; // EINVAL
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlockattr_gettype_np(attr_ptr: *mut *mut u8, type_ptr: *mut i32) -> i32 {
    info!("HLE POSIX: pthread_rwlockattr_gettype_np | attr: {:p}", attr_ptr);
    if !type_ptr.is_null() {
        *type_ptr = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_pthread_rwlockattr_settype_np(_attr_ptr: *mut *mut u8, _type_val: i32) -> i32 {
    info!("HLE POSIX: pthread_rwlockattr_settype_np | type: {}", _type_val);
    0
}

// =========================================================================
// Dinkumware Locale & Ctype tables
// =========================================================================

static CTYPE_TABLE: [i16; 384] = {
    let mut table = [0i16; 384];
    let mut i = 0usize;
    while i < 256 {
        let c = i as u8;
        let mut flags = 0i16;
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' || c == b'\x0b' || c == b'\x0c' {
            flags |= 0x04; // _SP
        }
        if c >= b'0' && c <= b'9' {
            flags |= 0x20; // _DI
            flags |= 0x01; // _XD
        }
        if c >= b'a' && c <= b'z' {
            flags |= 0x10; // _LO
            if c <= b'f' {
                flags |= 0x01; // _XD
            }
        }
        if c >= b'A' && c <= b'Z' {
            flags |= 0x02; // _UP
            if c <= b'F' {
                flags |= 0x01; // _XD
            }
        }
        if (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126) {
            flags |= 0x08; // _PU
        }
        if c < 32 || c == 127 {
            flags |= 0x40; // _CN
        }
        table[128 + i] = flags;
        i += 1;
    }
    table
};

static TOLOWER_TABLE: [i16; 384] = {
    let mut table = [0i16; 384];
    let mut i = 0usize;
    while i < 384 {
        let c = (i as isize - 128) as i16;
        if c >= 65 && c <= 90 { // 'A'-'Z'
            table[i] = c + 32;
        } else {
            table[i] = c;
        }
        i += 1;
    }
    table
};

static TOUPPER_TABLE: [i16; 384] = {
    let mut table = [0i16; 384];
    let mut i = 0usize;
    while i < 384 {
        let c = (i as isize - 128) as i16;
        if c >= 97 && c <= 122 { // 'a'-'z'
            table[i] = c - 32;
        } else {
            table[i] = c;
        }
        i += 1;
    }
    table
};

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Getpctype() -> *const i16 {
    CTYPE_TABLE.as_ptr().add(128)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Getptolower() -> *const i16 {
    TOLOWER_TABLE.as_ptr().add(128)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_Getptoupper() -> *const i16 {
    TOUPPER_TABLE.as_ptr().add(128)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_freopen(
    filename: *const std::os::raw::c_char,
    mode: *const std::os::raw::c_char,
    _stream: *mut libc::FILE,
) -> *mut libc::FILE {
    if filename.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }
    let filename_cstr = std::ffi::CStr::from_ptr(filename);
    let mode_cstr = std::ffi::CStr::from_ptr(mode);
    let filename_str = filename_cstr.to_string_lossy();
    let host_path = crate::kernel_hle::translate_guest_path(&filename_str);
    let host_path_str = host_path.to_string_lossy();
    let host_path_cstr = std::ffi::CString::new(host_path_str.as_ref()).unwrap();
    
    info!(
        "HLE POSIX: freopen | guest_filename: {:?} | host_filename: {:?} | mode: {:?}",
        filename_str, host_path_str, mode_cstr
    );
    
    let new_stream = libc::fopen(host_path_cstr.as_ptr(), mode);
    if new_stream.is_null() {
        error!("HLE POSIX: freopen failed to open target file {:?}", host_path);
        std::ptr::null_mut()
    } else {
        info!("HLE POSIX: freopen opened target file successfully -> stream: {:p}", new_stream);
        new_stream
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_freopen_s(
    newstreamptr: *mut *mut libc::FILE,
    filename: *const std::os::raw::c_char,
    mode: *const std::os::raw::c_char,
    _stream: *mut libc::FILE,
) -> i32 {
    if newstreamptr.is_null() || filename.is_null() || mode.is_null() {
        return 22; // EINVAL
    }
    let filename_cstr = std::ffi::CStr::from_ptr(filename);
    let mode_cstr = std::ffi::CStr::from_ptr(mode);
    let filename_str = filename_cstr.to_string_lossy();
    let host_path = crate::kernel_hle::translate_guest_path(&filename_str);
    let host_path_str = host_path.to_string_lossy();
    let host_path_cstr = std::ffi::CString::new(host_path_str.as_ref()).unwrap();

    info!(
        "HLE POSIX: freopen_s | guest_filename: {:?} | host_filename: {:?} | mode: {:?}",
        filename_str, host_path_str, mode_cstr
    );

    let new_stream = libc::fopen(host_path_cstr.as_ptr(), mode);
    if new_stream.is_null() {
        error!("HLE POSIX: freopen_s failed to open target file {:?}", host_path);
        22 // EINVAL on failure
    } else {
        info!("HLE POSIX: freopen_s opened target file successfully -> stream: {:p}", new_stream);
        *newstreamptr = new_stream;
        0
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_fopen(
    filename: *const std::os::raw::c_char,
    mode: *const std::os::raw::c_char,
) -> *mut libc::FILE {
    if filename.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }
    let filename_cstr = std::ffi::CStr::from_ptr(filename);
    let mode_cstr = std::ffi::CStr::from_ptr(mode);
    let filename_str = filename_cstr.to_string_lossy();
    let host_path = crate::kernel_hle::translate_guest_path(&filename_str);
    let host_path_str = host_path.to_string_lossy();
    let host_path_cstr = std::ffi::CString::new(host_path_str.as_ref()).unwrap();
    
    info!(
        "HLE POSIX: fopen | guest_filename: {:?} | host_filename: {:?} | mode: {:?}",
        filename_str, host_path_str, mode_cstr
    );
    
    libc::fopen(host_path_cstr.as_ptr(), mode)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_fclose(stream: *mut libc::FILE) -> i32 {
    info!("HLE POSIX: fclose | stream: {:p}", stream);
    if stream.is_null() {
        return -1;
    }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        0
    } else {
        libc::fclose(stream)
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_fread(
    ptr: u64,
    size: usize,
    nmemb: usize,
    stream: *mut libc::FILE,
) -> usize {
    if stream.is_null() || ptr == 0 {
        return 0;
    }
    let host_ptr = if let Some(addr) = crate::kernel::translate_guest_addr(ptr) {
        addr as *mut u8
    } else {
        ptr as *mut u8
    };
    
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        0
    } else {
        let res = libc::fread(host_ptr as *mut libc::c_void, size, nmemb, stream);
        debug!("HLE POSIX: fread | read {} elements of size {} from stream {:p}", res, size, stream);
        res
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_fwrite(
    ptr: u64,
    size: usize,
    nmemb: usize,
    stream: *mut libc::FILE,
) -> usize {
    if stream.is_null() || ptr == 0 {
        return 0;
    }
    let host_ptr = if let Some(addr) = crate::kernel::translate_guest_addr(ptr) {
        addr as *const u8
    } else {
        ptr as *const u8
    };
    
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        let total_bytes = size * nmemb;
        let slice = std::slice::from_raw_parts(host_ptr, total_bytes);
        if let Ok(text) = std::str::from_utf8(slice) {
            info!("[Guest stdio] {}", text.trim_end());
        } else {
            info!("[Guest stdio] (binary data of length {})", total_bytes);
        }
        nmemb
    } else {
        let res = libc::fwrite(host_ptr as *const libc::c_void, size, nmemb, stream);
        debug!("HLE POSIX: fwrite | wrote {} elements of size {} to stream {:p}", res, size, stream);
        res
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_ftell(stream: *mut libc::FILE) -> i64 {
    if stream.is_null() {
        return -1;
    }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        0
    } else {
        libc::ftell(stream)
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_memchr(s: u64, c: i32, n: usize) -> u64 {
    if s == 0 {
        return 0;
    }
    let host_s = if let Some(addr) = crate::kernel::translate_guest_addr(s) {
        addr as *const u8
    } else {
        s as *const u8
    };
    let res = libc::memchr(host_s as *const libc::c_void, c, n);
    if res.is_null() {
        0
    } else {
        let offset = (res as u64) - (host_s as u64);
        s + offset
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_bcmp(s1: u64, s2: u64, n: usize) -> i32 {
    let host_s1 = if let Some(addr) = crate::kernel::translate_guest_addr(s1) {
        addr as *const u8
    } else {
        s1 as *const u8
    };
    let host_s2 = if let Some(addr) = crate::kernel::translate_guest_addr(s2) {
        addr as *const u8
    } else {
        s2 as *const u8
    };
    libc::memcmp(host_s1 as *const libc::c_void, host_s2 as *const libc::c_void, n)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_strstr(haystack: u64, needle: u64) -> u64 {
    if haystack == 0 || needle == 0 {
        return 0;
    }
    let host_haystack = if let Some(addr) = crate::kernel::translate_guest_addr(haystack) {
        addr as *const std::os::raw::c_char
    } else {
        haystack as *const std::os::raw::c_char
    };
    let host_needle = if let Some(addr) = crate::kernel::translate_guest_addr(needle) {
        addr as *const std::os::raw::c_char
    } else {
        needle as *const std::os::raw::c_char
    };
    let res = libc::strstr(host_haystack, host_needle);
    if res.is_null() {
        0
    } else {
        let offset = (res as u64) - (host_haystack as u64);
        haystack + offset
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_sprintf(
    str_ptr: u64,
    format: *const std::os::raw::c_char,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> std::os::raw::c_int {
    if str_ptr == 0 || format.is_null() {
        return 0;
    }
    let host_str = if let Some(addr) = crate::kernel::translate_guest_addr(str_ptr) {
        addr as *mut u8
    } else {
        str_ptr as *mut u8
    };
    let cstr = std::ffi::CStr::from_ptr(format);
    if let Ok(str_slice) = cstr.to_str() {
        let formatted = format_c_string(str_slice, &[arg1, arg2, arg3, arg4, arg5]);
        let bytes = formatted.as_bytes();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), host_str, bytes.len());
        *host_str.add(bytes.len()) = 0; // null terminator
        return bytes.len() as std::os::raw::c_int;
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_vsprintf(
    str_ptr: u64,
    format: *const std::os::raw::c_char,
    ap: *mut u8, // Pointer to va_list
) -> std::os::raw::c_int {
    if str_ptr == 0 || format.is_null() || ap.is_null() {
        return 0;
    }
    let host_str = if let Some(addr) = crate::kernel::translate_guest_addr(str_ptr) {
        addr as *mut u8
    } else {
        str_ptr as *mut u8
    };
    
    let gp_offset = *(ap as *const u32) as usize;
    let overflow_arg_area = *(ap.add(8) as *const *mut u64);
    let reg_save_area = *(ap.add(16) as *const *mut u8);
    
    let mut args = Vec::new();
    let mut curr_gp = gp_offset;
    for _ in 0..8 {
        if curr_gp < 48 {
            let val = *(reg_save_area.add(curr_gp) as *const u64);
            args.push(val);
            curr_gp += 8;
        } else {
            let idx = (curr_gp - 48) / 8;
            if !overflow_arg_area.is_null() {
                let val = *overflow_arg_area.add(idx);
                args.push(val);
            } else {
                args.push(0);
            }
            curr_gp += 8;
        }
    }

    let cstr = std::ffi::CStr::from_ptr(format);
    if let Ok(str_slice) = cstr.to_str() {
        let formatted = format_c_string(str_slice, &args);
        let bytes = formatted.as_bytes();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), host_str, bytes.len());
        *host_str.add(bytes.len()) = 0; // null terminator
        return bytes.len() as std::os::raw::c_int;
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_snprintf(
    str_ptr: u64,
    size: usize,
    format: *const std::os::raw::c_char,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> std::os::raw::c_int {
    if str_ptr == 0 || format.is_null() {
        return 0;
    }
    let host_str = if let Some(addr) = crate::kernel::translate_guest_addr(str_ptr) {
        addr as *mut u8
    } else {
        str_ptr as *mut u8
    };
    if size == 0 {
        return 0;
    }
    let cstr = std::ffi::CStr::from_ptr(format);
    if let Ok(str_slice) = cstr.to_str() {
        let formatted = format_c_string(str_slice, &[arg1, arg2, arg3, arg4, arg5]);
        let bytes = formatted.as_bytes();
        let copy_len = std::cmp::min(bytes.len(), size - 1);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), host_str, copy_len);
        *host_str.add(copy_len) = 0; // null terminator
        return bytes.len() as std::os::raw::c_int;
    }
    0
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_vsnprintf(
    str_ptr: u64,
    size: usize,
    format: *const std::os::raw::c_char,
    ap: *mut u8,
) -> std::os::raw::c_int {
    if str_ptr == 0 || format.is_null() || ap.is_null() {
        return 0;
    }
    let host_str = if let Some(addr) = crate::kernel::translate_guest_addr(str_ptr) {
        addr as *mut u8
    } else {
        str_ptr as *mut u8
    };
    if size == 0 {
        return 0;
    }
    
    let gp_offset = *(ap as *const u32) as usize;
    let overflow_arg_area = *(ap.add(8) as *const *mut u64);
    let reg_save_area = *(ap.add(16) as *const *mut u8);
    
    let mut args = Vec::new();
    let mut curr_gp = gp_offset;
    for _ in 0..8 {
        if curr_gp < 48 {
            let val = *(reg_save_area.add(curr_gp) as *const u64);
            args.push(val);
            curr_gp += 8;
        } else {
            let idx = (curr_gp - 48) / 8;
            let val = *overflow_arg_area.add(idx);
            args.push(val);
            curr_gp += 8;
        }
    }
    
    let cstr = std::ffi::CStr::from_ptr(format);
    if let Ok(str_slice) = cstr.to_str() {
        let formatted = format_c_string(str_slice, &args);
        let bytes = formatted.as_bytes();
        let copy_len = std::cmp::min(bytes.len(), size - 1);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), host_str, copy_len);
        *host_str.add(copy_len) = 0; // null terminator
        return bytes.len() as std::os::raw::c_int;
    }
    0
}



#[no_mangle]
pub unsafe extern "sysv64" fn hle_cxa_allocate_exception(size: usize) -> *mut u8 {
    info!("HLE C++: __cxa_allocate_exception | size: {}", size);
    crate::kernel::hle_malloc(size)
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_cxa_free_exception(ptr: *mut u8) {
    info!("HLE C++: __cxa_free_exception | ptr: {:p}", ptr);
    crate::kernel::hle_free(ptr);
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_cxa_throw(ptr: *mut u8, tinfo: u64, dest: u64) {
    error!("FATAL: Guest threw a C++ exception! ptr: {:p} | tinfo: 0x{:X} | dest: 0x{:X}", ptr, tinfo, dest);
    std::process::exit(1);
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_cxa_rethrow() {
    error!("FATAL: Guest re-threw a C++ exception!");
    std::process::exit(1);
}

#[no_mangle]
pub unsafe extern "sysv64" fn hle_cxa_end_catch() {
    info!("HLE C++: __cxa_end_catch called");
}

// =========================================================================
// Newly Added HLE Symbol Implementations for Commercial Game Boot
// =========================================================================

extern "sysv64" fn hle_signbit(x: f64) -> i32 {
    if x.is_sign_negative() { 1 } else { 0 }
}


unsafe extern "sysv64" fn hle_strtod(
    nptr: *const libc::c_char,
    endptr: *mut *mut libc::c_char,
) -> f64 {
    if nptr.is_null() { return 0.0; }
    libc::strtod(nptr, endptr)
}

unsafe extern "sysv64" fn hle_Stoul(
    str: *const libc::c_char,
    endptr: *mut *mut libc::c_char,
    base: i32,
) -> libc::c_ulong {
    if str.is_null() { return 0; }
    libc::strtoul(str, endptr, base)
}

unsafe extern "sysv64" fn hle_Atomic_compare_exchange_weak_4(
    obj: *mut u32,
    expected: *mut u32,
    desired: u32,
    _succ: i32,
    _fail: i32,
) -> i32 {
    if obj.is_null() || expected.is_null() { return 0; }
    let exp = *expected;
    let obj_ref = &*(obj as *const std::sync::atomic::AtomicU32);
    match obj_ref.compare_exchange(exp, desired, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst) {
        Ok(_) => 1,
        Err(actual) => {
            *expected = actual;
            0
        }
    }
}

unsafe extern "sysv64" fn hle_Atomic_fetch_add_4(obj: *mut u32, val: u32, _order: i32) -> u32 {
    if obj.is_null() { return 0; }
    let obj_ref = &*(obj as *const std::sync::atomic::AtomicU32);
    obj_ref.fetch_add(val, std::sync::atomic::Ordering::SeqCst)
}

unsafe extern "sysv64" fn hle_Atomic_fetch_sub_4(obj: *mut u32, val: u32, _order: i32) -> u32 {
    if obj.is_null() { return 0; }
    let obj_ref = &*(obj as *const std::sync::atomic::AtomicU32);
    obj_ref.fetch_sub(val, std::sync::atomic::Ordering::SeqCst)
}

unsafe extern "sysv64" fn hle_Atomic_load_4(src: *const u32, _memorder: i32) -> u32 {
    if src.is_null() { return 0; }
    let src_ref = &*(src as *const std::sync::atomic::AtomicU32);
    src_ref.load(std::sync::atomic::Ordering::SeqCst)
}

unsafe extern "sysv64" fn hle_Mtx_init_with_default_name_override(mtx: *mut *mut std::ffi::c_void, type_: i32) -> i32 {
    crate::kernel::hle_Mtx_init(mtx as *mut i32, type_)
}

extern "sysv64" fn hle_atan2f(y: f32, x: f32) -> f32 {
    y.atan2(x)
}

unsafe extern "sysv64" fn hle_atof(str: *const libc::c_char) -> f64 {
    if str.is_null() { return 0.0; }
    libc::atof(str)
}

unsafe extern "sysv64" fn hle_fgets(str: *mut libc::c_char, size: i32, stream: *mut std::ffi::c_void) -> *mut libc::c_char {
    if str.is_null() || stream.is_null() || size <= 0 { return std::ptr::null_mut(); }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        std::ptr::null_mut()
    } else {
        extern "C" {
            fn fgets(str: *mut libc::c_char, size: libc::c_int, stream: *mut std::ffi::c_void) -> *mut libc::c_char;
        }
        fgets(str, size, stream)
    }
}

extern "sysv64" fn hle_difftime(time1: i64, time0: i64) -> f64 {
    (time1 - time0) as f64
}

extern "sysv64" fn hle_atan(x: f64) -> f64 {
    x.atan()
}

unsafe extern "sysv64" fn hle_close(fd: i32) -> i32 {
    if fd >= 500 {
        crate::network::sceNetSocketClose(fd)
    } else if fd >= 100 {
        crate::kernel_hle::sceKernelClose(fd)
    } else {
        libc::close(fd)
    }
}

unsafe extern "sysv64" fn hle_bind(fd: i32, addr: *const std::ffi::c_void, addrlen: u32) -> i32 {
    info!("hle_bind called for fd={}, addrlen={}", fd, addrlen);
    if fd >= 500 {
        0 // Virtual socket bind success mockup
    } else {
        extern "C" {
            fn bind(sockfd: libc::c_int, addr: *const std::ffi::c_void, addrlen: libc::socklen_t) -> libc::c_int;
        }
        bind(fd, addr, addrlen)
    }
}

unsafe extern "sysv64" fn hle_sprintf_s(
    s: *mut libc::c_char,
    n: usize,
    format: *const libc::c_char,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> i32 {
    if s.is_null() || format.is_null() || n == 0 { return -1; }
    extern "C" {
        fn snprintf(s: *mut libc::c_char, n: usize, format: *const libc::c_char, ...) -> libc::c_int;
    }
    snprintf(s, n, format, arg1, arg2, arg3)
}

extern "sysv64" fn hle_acosf(x: f32) -> f32 {
    x.acos()
}

unsafe extern "sysv64" fn hle_sceKernelUsleep(usec: u32) -> i32 {
    std::thread::sleep(std::time::Duration::from_micros(usec as u64));
    0
}

unsafe extern "sysv64" fn hle_sceFiberInitializeImpl(
    _a: u64, _b: u64, _c: u64, _d: u64, _e: u64, _f: u64
) -> i32 {
    info!("sceFiberInitializeImpl stub called");
    0
}

unsafe extern "sysv64" fn hle_aligned_alloc(alignment: usize, size: usize) -> *mut u8 {
    info!("hle_aligned_alloc called: alignment={}, size={}", alignment, size);
    crate::kernel::hle_malloc(size)
}

unsafe extern "sysv64" fn hle_sceLibcMspaceCreate(
    _name: *const libc::c_char,
    _base: *mut std::ffi::c_void,
    _capacity: usize,
    _flag: u32,
) -> *mut std::ffi::c_void {
    let msp = Box::into_raw(Box::new(0u64)) as *mut std::ffi::c_void;
    info!("sceLibcMspaceCreate called -> returning dummy msp: {:?}", msp);
    msp
}

unsafe extern "sysv64" fn hle_sceLibcMspaceDestroy(msp: *mut std::ffi::c_void) -> i32 {
    info!("sceLibcMspaceDestroy called for msp: {:?}", msp);
    if !msp.is_null() {
        let _ = Box::from_raw(msp as *mut u64);
    }
    0
}

unsafe extern "sysv64" fn hle_sceLibcMspaceMalloc(_msp: *mut std::ffi::c_void, size: usize) -> *mut std::ffi::c_void {
    let ptr = crate::kernel::hle_malloc(size) as *mut std::ffi::c_void;
    debug!("sceLibcMspaceMalloc(size={}) -> {:?}", size, ptr);
    ptr
}

unsafe extern "sysv64" fn hle_sceLibcMspaceFree(_msp: *mut std::ffi::c_void, ptr: *mut std::ffi::c_void) -> i32 {
    debug!("sceLibcMspaceFree(ptr={:?})", ptr);
    crate::kernel::hle_free(ptr as *mut u8);
    0
}

unsafe extern "sysv64" fn hle_sceLibcMspaceCalloc(
    _msp: *mut std::ffi::c_void,
    nelem: usize,
    size: usize,
) -> *mut std::ffi::c_void {
    let ptr = crate::kernel::hle_calloc(nelem, size) as *mut std::ffi::c_void;
    debug!("sceLibcMspaceCalloc(nelem={}, size={}) -> {:?}", nelem, size, ptr);
    ptr
}

unsafe extern "sysv64" fn hle_sceLibcMspaceAlignedAlloc(
    _msp: *mut std::ffi::c_void,
    alignment: usize,
    size: usize,
) -> *mut std::ffi::c_void {
    let ptr = hle_aligned_alloc(alignment, size) as *mut std::ffi::c_void;
    debug!("sceLibcMspaceAlignedAlloc(alignment={}, size={}) -> {:?}", alignment, size, ptr);
    ptr
}

unsafe extern "sysv64" fn hle_sceLibcMspaceMemalign(
    _msp: *mut std::ffi::c_void,
    boundary: usize,
    size: usize,
) -> *mut std::ffi::c_void {
    let ptr = hle_aligned_alloc(boundary, size) as *mut std::ffi::c_void;
    debug!("sceLibcMspaceMemalign(boundary={}, size={}) -> {:?}", boundary, size, ptr);
    ptr
}

unsafe extern "sysv64" fn hle_sceLibcMspaceRealloc(
    _msp: *mut std::ffi::c_void,
    ptr: *mut std::ffi::c_void,
    size: usize,
) -> *mut std::ffi::c_void {
    let new_ptr = crate::kernel::hle_realloc(ptr as *mut u8, size) as *mut std::ffi::c_void;
    debug!("sceLibcMspaceRealloc(ptr={:?}, size={}) -> {:?}", ptr, size, new_ptr);
    new_ptr
}

unsafe extern "sysv64" fn hle_sceLibcMspaceReallocalign(
    _msp: *mut std::ffi::c_void,
    ptr: *mut std::ffi::c_void,
    alignment: usize,
    size: usize,
) -> *mut std::ffi::c_void {
    let new_ptr = crate::kernel::hle_realloc(ptr as *mut u8, size) as *mut std::ffi::c_void;
    debug!("sceLibcMspaceReallocalign(ptr={:?}, alignment={}, size={}) -> {:?}", ptr, alignment, size, new_ptr);
    new_ptr
}

unsafe extern "sysv64" fn hle_sceLibcMspacePosixMemalign(
    _msp: *mut std::ffi::c_void,
    ptr_out: u64,
    alignment: usize,
    size: usize,
) -> i32 {
    let host_ptr = match crate::kernel::translate_guest_addr(ptr_out) {
        Some(addr) => addr as *mut *mut std::ffi::c_void,
        None => ptr_out as *mut *mut std::ffi::c_void,
    };
    if host_ptr.is_null() {
        return 22; // EINVAL
    }
    let allocated = hle_aligned_alloc(alignment, size) as *mut std::ffi::c_void;
    *host_ptr = allocated;
    debug!("sceLibcMspacePosixMemalign(alignment={}, size={}) -> wrote {:?}", alignment, size, allocated);
    0
}

unsafe extern "sysv64" fn hle_sceLibcMspaceMallocUsableSize(ptr: *mut std::ffi::c_void) -> usize {
    let size = crate::kernel::hle_malloc_usable_size(ptr as *mut u8);
    debug!("sceLibcMspaceMallocUsableSize(ptr={:?}) -> {}", ptr, size);
    size
}

unsafe extern "sysv64" fn hle_sceLibcMspaceIsHeapEmpty(_msp: *mut std::ffi::c_void) -> i32 {
    0
}

extern "sysv64" fn hle_cxa_pure_virtual() {
    error!("FATAL: Guest called pure virtual function!");
    std::process::exit(1);
}

extern "sysv64" fn hle_exp2f(x: f32) -> f32 {
    x.exp2()
}

unsafe extern "sysv64" fn hle_ferror(stream: *mut std::ffi::c_void) -> i32 {
    if stream.is_null() { return 0; }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        0
    } else {
        extern "C" {
            fn ferror(stream: *mut std::ffi::c_void) -> libc::c_int;
        }
        ferror(stream)
    }
}

unsafe extern "sysv64" fn hle_fprintf(
    stream: *mut std::ffi::c_void,
    format: *const libc::c_char,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> i32 {
    if stream.is_null() || format.is_null() { return -1; }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        let mut buf = [0u8; 1024];
        extern "C" {
            fn snprintf(s: *mut libc::c_char, n: usize, format: *const libc::c_char, ...) -> libc::c_int;
        }
        let written = snprintf(buf.as_mut_ptr() as *mut libc::c_char, buf.len(), format, arg1, arg2, arg3, arg4);
        if written > 0 {
            let text = String::from_utf8_lossy(&buf[..written as usize]);
            info!("[Guest stdio] {}", text.trim_end());
        }
        written
    } else {
        extern "C" {
            fn fprintf(stream: *mut std::ffi::c_void, format: *const libc::c_char, ...) -> libc::c_int;
        }
        fprintf(stream, format, arg1, arg2, arg3, arg4)
    }
}

unsafe extern "sysv64" fn hle_fputc(c: i32, stream: *mut std::ffi::c_void) -> i32 {
    if stream.is_null() { return -1; }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        let ch = c as u8 as char;
        print!("{}", ch);
        c
    } else {
        extern "C" {
            fn fputc(c: libc::c_int, stream: *mut std::ffi::c_void) -> libc::c_int;
        }
        fputc(c, stream)
    }
}

unsafe extern "sysv64" fn hle_fputs(s: *const libc::c_char, stream: *mut std::ffi::c_void) -> i32 {
    if s.is_null() || stream.is_null() { return -1; }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        let cstr = std::ffi::CStr::from_ptr(s);
        let text = cstr.to_string_lossy();
        info!("[Guest stdio] {}", text.trim_end());
        0
    } else {
        extern "C" {
            fn fputs(s: *const libc::c_char, stream: *mut std::ffi::c_void) -> libc::c_int;
        }
        fputs(s, stream)
    }
}

unsafe extern "sysv64" fn hle_fseek(stream: *mut std::ffi::c_void, offset: i64, whence: i32) -> i32 {
    if stream.is_null() { return -1; }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        0
    } else {
        extern "C" {
            fn fseek(stream: *mut std::ffi::c_void, offset: libc::c_long, whence: libc::c_int) -> libc::c_int;
        }
        fseek(stream, offset, whence)
    }
}

unsafe extern "sysv64" fn hle_rewind(stream: *mut std::ffi::c_void) {
    if stream.is_null() { return; }
    if crate::kernel::translate_guest_addr(stream as u64).is_some() {
        // NOP
    } else {
        extern "C" {
            fn rewind(stream: *mut std::ffi::c_void);
        }
        rewind(stream);
    }
}

std::arch::global_asm!(
    ".global hle_abort",
    "hle_abort:",
    "jmp abort"
);

extern "sysv64" {
    pub fn hle_abort();
}

thread_local! {
    pub static GUEST_FS: std::cell::Cell<u64> = std::cell::Cell::new(0);
}

#[no_mangle]
pub extern "sysv64" fn get_current_guest_fs() -> u64 {
    GUEST_FS.with(|fs| fs.get())
}

#[no_mangle]
pub extern "sysv64" fn debug_hle_transition(host_fs: u64, syscall_res: i64) {
    info!("DEBUG TRANSITION: host_fs=0x{:X}, syscall_res={}", host_fs, syscall_res);
}

#[no_mangle]
pub extern "sysv64" fn debug_hle_return(guest_fs: u64, syscall_res: i64) {
    info!("DEBUG RETURN: guest_fs=0x{:X}, syscall_res={}", guest_fs, syscall_res);
}

std::arch::global_asm!(
    ".global common_hle_wrapper",
    ".type common_hle_wrapper, @function",
    "common_hle_wrapper:",
    "    # Save GPR argument/volatile registers",
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push r8",
    "    push r9",
    "    push r11",
    "",
    "    # Save SSE/volatile registers",
    "    sub rsp, 144",
    "    movdqu [rsp], xmm0",
    "    movdqu [rsp + 16], xmm1",
    "    movdqu [rsp + 32], xmm2",
    "    movdqu [rsp + 48], xmm3",
    "    movdqu [rsp + 64], xmm4",
    "    movdqu [rsp + 80], xmm5",
    "    movdqu [rsp + 96], xmm6",
    "    movdqu [rsp + 112], xmm7",
    "",
    "    # Read host FS base from guest TCB (offset 0x40)",
    "    mov rsi, fs:[0x40]",
    "",
    "    # Swap to host FS base",
    "    mov rax, 158",
    "    mov rdi, 0x1002",
    "    syscall",
    "",
    "    # Call debug_hle_transition(host_fs, syscall_res)",
    "    mov rdi, rsi",
    "    mov rsi, rax",
    "    sub rsp, 8",
    "    call debug_hle_transition",
    "    add rsp, 8",
    "",
    "    # Restore SSE registers",
    "    movdqu xmm0, [rsp]",
    "    movdqu xmm1, [rsp + 16]",
    "    movdqu xmm2, [rsp + 32]",
    "    movdqu xmm3, [rsp + 48]",
    "    movdqu xmm4, [rsp + 64]",
    "    movdqu xmm5, [rsp + 80]",
    "    movdqu xmm6, [rsp + 96]",
    "    movdqu xmm7, [rsp + 112]",
    "    add rsp, 144",
    "",
    "    # Pop GPR argument registers",
    "    pop r11",
    "    pop r9",
    "    pop r8",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rax",
    "",
    "    # Call target HLE function",
    "    call r11",
    "",
    "    # Save return value registers",
    "    push rax",
    "    push rdx",
    "    sub rsp, 16",
    "    movdqu [rsp], xmm0",
    "",
    "    # Call get_current_guest_fs()",
    "    sub rsp, 8",
    "    call get_current_guest_fs",
    "    add rsp, 8",
    "",
    "    # Swap back to guest FS base",
    "    mov rsi, rax",
    "    mov rax, 158",
    "    mov rdi, 0x1002",
    "    syscall",
    "",
    "    # Call debug_hle_return(guest_fs, syscall_res)",
    "    mov rdi, rsi",
    "    mov rsi, rax",
    "    sub rsp, 8",
    "    call debug_hle_return",
    "    add rsp, 8",
    "",
    "    # Restore return registers",
    "    movdqu xmm0, [rsp]",
    "    add rsp, 16",
    "    pop rdx",
    "    pop rax",
    "",
    "    # ret",
    "    ret"
);

extern "sysv64" {
    pub fn common_hle_wrapper();
}
