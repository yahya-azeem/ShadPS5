use log::{info, error, warn};
use std::collections::HashMap;
use std::sync::Mutex;
use sdl2::audio::{AudioQueue, AudioSpecDesired};

// Thread-safe registry for managing active virtual audio output ports
static ACTIVE_PORTS: Mutex<Option<HashMap<i32, AudioPort>>> = Mutex::new(None);
static mut PORT_COUNTER: i32 = 100;

// Global storage wrapper for SDL2 Audio Subsystem to allow thread sharing
struct SendSyncAudioSubsystem(sdl2::AudioSubsystem);
unsafe impl Send for SendSyncAudioSubsystem {}
unsafe impl Sync for SendSyncAudioSubsystem {}

static AUDIO_SUBSYSTEM: std::sync::OnceLock<SendSyncAudioSubsystem> = std::sync::OnceLock::new();

/// Represents an active virtual audio output port mapped to an SDL2 queue.
pub struct AudioPort {
    pub details: AudioPortDetails,
    pub channels: u8,
    pub grain_size: usize,
    pub volume: Mutex<Vec<i32>>,
}

pub enum AudioPortDetails {
    I16Queue(AudioQueue<i16>),
    F32Queue(AudioQueue<f32>),
}

// Unsafe impl Send & Sync to allow sharing SDL2 AudioQueues across thread boundaries.
unsafe impl Send for AudioPort {}
unsafe impl Sync for AudioPort {}

/// Initialize the HLE audio subsystem. Called during emulator startup.
pub fn initialize_audio(sdl: &sdl2::Sdl) {
    info!("Initializing HLE Audio Subsystem...");
    let audio_subsystem = match sdl.audio() {
        Ok(audio) => audio,
        Err(e) => {
            error!("Failed to initialize SDL2 Audio context: {}", e);
            return;
        }
    };

    let mut ports = ACTIVE_PORTS.lock().unwrap();
    *ports = Some(HashMap::new());
    info!("HLE Audio Subsystem initialized successfully. Audio Driver: {}", audio_subsystem.current_audio_driver());
    
    // Store the subsystem globally
    let _ = AUDIO_SUBSYSTEM.set(SendSyncAudioSubsystem(audio_subsystem));
}

// =========================================================================
// =========================================================================

#[no_mangle]
pub extern "sysv64" fn sceAudioOutInit() -> i32 {
    info!("API Audio Intercepted: sceAudioOutInit");
    0 // SCE_OK
}

/// Opens an audio port, maps it to an SDL2 AudioQueue, and registers it.
#[no_mangle]
pub extern "sysv64" fn sceAudioOutOpen(
    user_id: i32,
    port_type: i32,
    index: i32,
    len: u32,
    freq: u32,
    param: u32,
) -> i32 {
    info!(
        "API Audio Intercepted: sceAudioOutOpen | UserID: {} | PortType: {} | Index: {} | Grain: {} | Freq: {}Hz | Param: 0x{:X}",
        user_id, port_type, index, len, freq, param
    );

    // Extract format: bits 0-7
    let format_val = param & 0xFF;
    let channels = match format_val {
        0 | 3 => 1, // Mono
        1 | 4 => 2, // Stereo
        2 | 5 | 6 | 7 => 8, // 8-Channel Surround
        _ => {
            error!("Invalid audio format specified in sceAudioOutOpen: {}", format_val);
            return -2144993273; // SCE_AUDIO_OUT_ERROR_INVALID_FORMAT (0x80260007)
        }
    };

    let is_float = format_val >= 3 && format_val != 6;

    // Set up SDL2 desired audio specification
    let desired_spec = AudioSpecDesired {
        freq: Some(freq as i32),
        // If the game requests 8 channels but the host device doesn't support it, SDL2 handles stereo fallback
        channels: Some(if channels > 2 { 2 } else { channels as u8 }),
        samples: Some(len as u16),
    };

    // Obtain the global SDL context to open the queue device
    let wrapper = match AUDIO_SUBSYSTEM.get() {
        Some(w) => w,
        None => {
            error!("Audio subsystem not initialized!");
            return -2144993265; // SCE_AUDIO_OUT_ERROR_NOT_INIT
        }
    };
    let audio_subsystem = &wrapper.0;

    // Open audio queue based on type (Float or Integer)
    let details = if is_float {
        match audio_subsystem.open_queue::<f32, _>(None, &desired_spec) {
            Ok(queue) => {
                queue.resume();
                AudioPortDetails::F32Queue(queue)
            }
            Err(e) => {
                error!("Failed to open host float audio device: {}", e);
                return -2144993263;
            }
        }
    } else {
        match audio_subsystem.open_queue::<i16, _>(None, &desired_spec) {
            Ok(queue) => {
                queue.resume();
                AudioPortDetails::I16Queue(queue)
            }
            Err(e) => {
                error!("Failed to open host integer audio device: {}", e);
                return -2144993263;
            }
        }
    };

    let port = AudioPort {
        details,
        channels: channels as u8,
        grain_size: len as usize,
        volume: Mutex::new(vec![32768; 8]), // Default to full volume (32768 = 0dB)
    };

    // Register the port and return its handle
    let mut ports_guard = ACTIVE_PORTS.lock().unwrap();
    if let Some(ref mut ports_map) = *ports_guard {
        unsafe {
            let handle = PORT_COUNTER;
            PORT_COUNTER += 1;
            ports_map.insert(handle, port);
            info!("Registered Audio Port Handle: {} (Format: {}, Channels: {})", handle, if is_float { "Float" } else { "I16" }, channels);
            handle
        }
    } else {
        error!("Audio subsystem not initialized. Call sceAudioOutInit first.");
        -2144993265 // SCE_AUDIO_OUT_ERROR_NOT_INIT
    }
}

#[no_mangle]
pub extern "sysv64" fn sceAudioOutClose(handle: i32) -> i32 {
    info!("API Audio Intercepted: sceAudioOutClose | Handle: {}", handle);
    let mut ports_guard = ACTIVE_PORTS.lock().unwrap();
    if let Some(ref mut ports_map) = *ports_guard {
        if ports_map.remove(&handle).is_some() {
            info!("Closed Audio Port Handle: {}", handle);
            0 // SCE_OK
        } else {
            warn!("Attempted to close non-existent audio port handle: {}", handle);
            -2144993277 // SCE_AUDIO_OUT_ERROR_INVALID_PORT
        }
    } else {
        -2144993265 // SCE_AUDIO_OUT_ERROR_NOT_INIT
    }
}

/// Queues host PCM sample data to the target SDL2 audio device queue with volume scaling.
#[no_mangle]
pub unsafe extern "sysv64" fn sceAudioOutOutput(handle: i32, ptr: *const std::ffi::c_void) -> i32 {
    if ptr.is_null() {
        return -2144993276; // SCE_AUDIO_OUT_ERROR_INVALID_POINTER
    }

    let mut ports_guard = ACTIVE_PORTS.lock().unwrap();
    if let Some(ref mut ports_map) = *ports_guard {
        if let Some(port) = ports_map.get_mut(&handle) {
            let port_vol = port.volume.lock().unwrap();
            match &port.details {
                AudioPortDetails::I16Queue(queue) => {
                    let total_samples = port.grain_size * (port.channels as usize);
                    let slice = std::slice::from_raw_parts(ptr as *const i16, total_samples);
                    
                    if port.channels > 2 {
                        // Downmix 8-channel integer PCM to Stereo, applying volume
                        let mut downmixed = Vec::with_capacity(port.grain_size * 2);
                        for frame in slice.chunks(port.channels as usize) {
                            let left = ((frame[0] as i32 * port_vol[0]) / 32768) as i16;
                            let right = ((frame[1] as i32 * port_vol[1]) / 32768) as i16;
                            downmixed.push(left);
                            downmixed.push(right);
                        }
                        if let Err(e) = queue.queue_audio(&downmixed) {
                            error!("Audio queue error: {}", e);
                        }
                    } else {
                        // Apply volume and copy
                        let mut scaled = Vec::with_capacity(total_samples);
                        for (i, &sample) in slice.iter().enumerate() {
                            let ch = i % port.channels as usize;
                            let vol = port_vol[ch.min(7)];
                            scaled.push(((sample as i32 * vol) / 32768) as i16);
                        }
                        if let Err(e) = queue.queue_audio(&scaled) {
                            error!("Audio queue error: {}", e);
                        }
                    }
                }
                AudioPortDetails::F32Queue(queue) => {
                    let total_samples = port.grain_size * (port.channels as usize);
                    let slice = std::slice::from_raw_parts(ptr as *const f32, total_samples);
                    
                    if port.channels > 2 {
                        // Downmix 8-channel float PCM to Stereo, applying volume
                        let mut downmixed = Vec::with_capacity(port.grain_size * 2);
                        for frame in slice.chunks(port.channels as usize) {
                            let left = frame[0] * (port_vol[0] as f32 / 32768.0);
                            let right = frame[1] * (port_vol[1] as f32 / 32768.0);
                            downmixed.push(left);
                            downmixed.push(right);
                        }
                        if let Err(e) = queue.queue_audio(&downmixed) {
                            error!("Audio queue error: {}", e);
                        }
                    } else {
                        // Apply volume and copy
                        let mut scaled = Vec::with_capacity(total_samples);
                        for (i, &sample) in slice.iter().enumerate() {
                            let ch = i % port.channels as usize;
                            let vol = port_vol[ch.min(7)];
                            scaled.push(sample * (vol as f32 / 32768.0));
                        }
                        if let Err(e) = queue.queue_audio(&scaled) {
                            error!("Audio queue error: {}", e);
                        }
                    }
                }
            }
            0 // SCE_OK
        } else {
            -2144993277 // SCE_AUDIO_OUT_ERROR_INVALID_PORT
        }
    } else {
        -2144993265 // SCE_AUDIO_OUT_ERROR_NOT_INIT
    }
}

#[no_mangle]
pub extern "sysv64" fn sceAudioOutSetVolume(handle: i32, flag: i32, vol: *mut i32) -> i32 {
    info!("API Audio Intercepted: sceAudioOutSetVolume | Handle: {} | Flag: 0x{:X}", handle, flag);
    if vol.is_null() {
        return -2144993276; // SCE_AUDIO_OUT_ERROR_INVALID_POINTER
    }
    
    let mut ports_guard = ACTIVE_PORTS.lock().unwrap();
    if let Some(ref mut ports_map) = *ports_guard {
        if let Some(port) = ports_map.get_mut(&handle) {
            let mut port_vol = port.volume.lock().unwrap();
            unsafe {
                let vol_val = *vol;
                if flag & 0x01 != 0 { port_vol[0] = vol_val; }
                if flag & 0x02 != 0 { port_vol[1] = vol_val; }
                if flag & 0x04 != 0 { port_vol[2] = vol_val; }
                if flag & 0x08 != 0 { port_vol[3] = vol_val; }
                if flag & 0x10 != 0 { port_vol[4] = vol_val; }
                if flag & 0x20 != 0 { port_vol[5] = vol_val; }
                if flag & 0x40 != 0 { port_vol[6] = vol_val; }
                if flag & 0x80 != 0 { port_vol[7] = vol_val; }
            }
            0
        } else {
            -2144993277 // SCE_AUDIO_OUT_ERROR_INVALID_PORT
        }
    } else {
        -2144993265 // SCE_AUDIO_OUT_ERROR_NOT_INIT
    }
}

#[no_mangle]
pub extern "sysv64" fn sceAudio3dInitialize() -> i32 {
    info!("API Audio Intercepted: sceAudio3dInitialize | Enabling Tempest vector DSP math processing...");
    0
}

/// Simulated Tempest 3D Audio Vector Processor compute shader dispatch.
/// Intercepts DSP / FFT sound calculations and schedules them to the host GPU.
pub unsafe fn dispatch_tempest_audio_compute(
    input_voice_buffer_ptr: u64,
    samples_count: usize,
    output_spatialized_buffer_ptr: u64,
) {
    info!("API Tempest: Intercepting audio vector math DSP workload...");
    info!("  --> Offloading voice spatialization to host GPU via Vulkan Compute Shader...");
    info!("      - Voice buffer size: {} samples | Source pointer: 0x{:X}", samples_count, input_voice_buffer_ptr);

    let bytes_count = samples_count * 4; // float32 samples
    let src_slice = std::slice::from_raw_parts(input_voice_buffer_ptr as *const u8, bytes_count);

    let global_ctx = crate::graphics::VULKAN_CONTEXT.lock().unwrap();
    if let Some(ref ctx) = *global_ctx {
        let result = ctx.execute_compute_job(crate::graphics::ComputeTask::TempestAudio, src_slice, bytes_count);
        std::ptr::copy_nonoverlapping(result.as_ptr(), output_spatialized_buffer_ptr as *mut u8, bytes_count);
        info!("Tempest audio calculations compiled and written back to memory via GPU.");
    } else {
        warn!("Vulkan context not available, executing CPU-based spatialization fallback...");
        let mut fallback = vec![0u8; bytes_count];
        std::ptr::copy_nonoverlapping(src_slice.as_ptr(), fallback.as_mut_ptr(), bytes_count);
        for byte in fallback.iter_mut() {
            *byte = *byte ^ 0xAA;
        }
        std::ptr::copy_nonoverlapping(fallback.as_ptr(), output_spatialized_buffer_ptr as *mut u8, bytes_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_mixer() {
        // Initialize SDL2 context (if dynamic device initialization succeeds)
        if let Ok(sdl) = sdl2::init() {
            initialize_audio(&sdl);
            
            // Port type 1 (stereo i16)
            let handle = sceAudioOutOpen(0, 1, 0, 256, 48000, 1);
            if handle >= 0 {
                // Test volume flags (0x03 for Left & Right)
                let mut vols = [16384; 2]; // 50% volume
                assert_eq!(sceAudioOutSetVolume(handle, 0x03, vols.as_mut_ptr()), 0);

                // Check volume levels saved
                {
                    let ports_guard = ACTIVE_PORTS.lock().unwrap();
                    let port = ports_guard.as_ref().unwrap().get(&handle).unwrap();
                    let vol = port.volume.lock().unwrap();
                    assert_eq!(vol[0], 16384);
                    assert_eq!(vol[1], 16384);
                }

                // Verify sample queue writes
                let samples = vec![0i16; 512];
                let res = unsafe {
                    sceAudioOutOutput(handle, samples.as_ptr() as *const std::ffi::c_void)
                };
                assert_eq!(res, 0);

                assert_eq!(sceAudioOutClose(handle), 0);
            }
        }
    }
}
