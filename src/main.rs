#![allow(unused_variables, unused_imports, unused_mut, unused_assignments, dead_code, non_snake_case, function_casts_as_integer)]

use log::{error, info, warn};
use std::env;
use std::path::Path;

mod audio;
mod decompression;
mod gpu_queue;
mod graphics;
mod hle_autogen;
mod hle_symbols;
mod input;
mod kernel;
mod kernel_hle;
mod loader;
mod network;
mod shader_translation;
mod user_service;
mod video_out;
mod memory_tracker;
mod save_data;
mod common_dialog;
mod sync;
mod network_profile;
pub mod ampr;

fn main() {
    // Initialize the environment logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Initializing ShadPS5 High-Level Emulator Base...");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let elf_path = if args.len() > 1 {
        Some(args[1].clone())
    } else {
        warn!("No input ELF or SELF file path provided. Running in idle state.");
        None
    };

    // Initialize SDL2
    info!("Initializing SDL2 Subsystem...");
    let sdl_context = match sdl2::init() {
        Ok(context) => context,
        Err(e) => {
            error!("Failed to initialize SDL2: {}", e);
            return;
        }
    };

    // Disable SDL2 window events to prevent panic on Wayland/X11 extension window event types (e.g. 0x206/0x207)
    // which are unmapped by the Rust sdl2 crate version.
    unsafe {
        extern "C" {
            fn SDL_EventState(type_: u32, state: i32) -> u8;
        }
        SDL_EventState(0x200, 0); // 0x200 is SDL_WINDOWEVENT, 0 is SDL_DISABLE
    }

    // Initialize HLE Audio Subsystem mapping
    audio::initialize_audio(&sdl_context);

    // Initialize HLE Network Subsystem mapping
    network::initialize_network();

    // Initialize SDL2 GameController subsystem
    let controller_subsystem = match sdl_context.game_controller() {
        Ok(gc) => {
            info!("SDL2 GameController subsystem initialized.");
            Some(gc)
        }
        Err(e) => {
            warn!("Failed to initialize SDL2 GameController subsystem: {}. Gamepad support disabled.", e);
            None
        }
    };

    let mut active_controllers = std::collections::HashMap::new();
    if let Some(ref gc_subsystem) = controller_subsystem {
        if let Ok(num_joysticks) = gc_subsystem.num_joysticks() {
            for i in 0..num_joysticks {
                if gc_subsystem.is_game_controller(i) {
                    match gc_subsystem.open(i) {
                        Ok(controller) => {
                            info!("Found gamepad at startup: {}", controller.name());
                            active_controllers.insert(i, controller);
                        }
                        Err(e) => {
                            error!("Failed to open gamepad at startup {}: {}", i, e);
                        }
                    }
                }
            }
        }
    }

    let video_subsystem = match sdl_context.video() {
        Ok(video) => video,
        Err(e) => {
            error!("Failed to initialize SDL2 Video subsystem: {}", e);
            return;
        }
    };

    // Create SDL2 Window
    info!("Creating SDL2 Application Window...");
    let window = match video_subsystem
        .window("ShadPS5 Emulator - Base Codebase", 1280, 720)
        .position_centered()
        .resizable()
        .vulkan()
        .build()
    {
        Ok(win) => win,
        Err(e) => {
            error!("Failed to create application window: {}", e);
            return;
        }
    };

    // Initialize Vulkan Context
    info!("Initializing Vulkan API context...");
    let has_vulkan = match graphics::VulkanContext::new(&window) {
        Ok(ctx) => {
            info!("Vulkan initialized successfully! Device: {}", ctx.device_name());
            let mut global_ctx = graphics::VULKAN_CONTEXT.lock().unwrap();
            *global_ctx = Some(ctx);
            graphics::init_compiler_thread();
            true
        }
        Err(e) => {
            error!("Vulkan initialization failed: {}. Continuing with graphics disabled.", e);
            false
        }
    };

    // Load Guest ELF if provided
    if let Some(ref path_str) = elf_path {
        let path = Path::new(path_str);
        info!("Attempting to load Prospero executable: {:?}", path);
        match loader::load_executable(path) {
            Ok(executable) => {
                info!("Executable successfully parsed and mapped into memory.");
                info!("Entrypoint: 0x{:X}", executable.entrypoint);
                
                // Spin up thread simulation and system call interceptor
                info!("Booting Prospero OS Kernel Virtualization Layer...");
                kernel::initialize_kernel();
                
                unsafe {
                    let strlen_got_ptr = 0x7000006cc210 as *const u64;
                    info!("DEBUG BEFORE GUEST RUN: *0x7000006cc210 = 0x{:X}", *strlen_got_ptr);
                    info!("DEBUG BEFORE GUEST RUN: unresolved_trampoline = 0x{:X}", loader::hle_unresolved_import_trampoline as u64);
                    if let Some(addr) = crate::hle_symbols::lookup_hle_address("strlen") {
                        info!("DEBUG BEFORE GUEST RUN: hle_strlen address = 0x{:X}", addr);
                    }
                }

                info!("Transitioning to guest execution entrypoint (Concurrent Thread): 0x{:X}", executable.entrypoint);
                let entrypoint_fn: unsafe extern "sysv64" fn(*const u64) -> i32 = unsafe { std::mem::transmute(executable.entrypoint) };
                
                std::thread::spawn(move || {
                    let mut host_fs: u64 = 0;
                    unsafe {
                        std::arch::asm!("mov {}, fs:[0]", out(reg) host_fs);
                    }
                    
                    let static_tls_size = loader::STATIC_TLS_SIZE.load(std::sync::atomic::Ordering::SeqCst);
                    let tcb_size = 256;
                    let total_size = static_tls_size + tcb_size;
                    let layout = std::alloc::Layout::from_size_align(total_size, 64).unwrap();
                    let guest_tls_mem = unsafe { std::alloc::alloc_zeroed(layout) };
                    let guest_tcb_addr = guest_tls_mem as u64 + static_tls_size as u64;
                    
                    unsafe {
                        *(guest_tcb_addr as *mut u64) = guest_tcb_addr;
                        *((guest_tcb_addr + 0x40) as *mut u64) = host_fs;
                        *((guest_tcb_addr + 0x48) as *mut u64) = guest_tcb_addr;
                    }
                    
                    crate::hle_symbols::GUEST_FS.with(|fs| fs.set(guest_tcb_addr));
                    
                    unsafe {
                        libc::syscall(libc::SYS_arch_prctl, 0x1002, guest_tcb_addr); // ARCH_SET_FS
                    }
                    
                    unsafe {
                        let program_name = b"ps5_app.elf\0";
                        let argv: [*const u8; 2] = [program_name.as_ptr(), std::ptr::null()];
                        let args: [u64; 3] = [
                            1, // argc
                            argv.as_ptr() as u64,
                            0, // null terminator
                        ];
                        let result = entrypoint_fn(args.as_ptr());
                        info!("Guest executable returned code: {}", result);
                    }
                    
                    unsafe {
                        libc::syscall(libc::SYS_arch_prctl, 0x1002, host_fs); // Restore host FS
                    }
                });
            }
            Err(e) => {
                error!("Failed to load executable: {:?}", e);
            }
        }
    }

    // Main Event Loop
    info!("Entering emulator event loop...");
    let mut event_pump = sdl_context.event_pump().unwrap();
    
    let mut key_space = false;
    let mut key_return = false;
    let mut key_a = false;
    let mut key_left = false;
    let mut key_d = false;
    let mut key_right = false;
    let mut key_w = false;
    let mut key_up = false;
    let mut key_s = false;
    let mut key_down = false;

    'running: loop {
        for event in event_pump.poll_iter() {
            match event {
                sdl2::event::Event::Quit { .. } => break 'running,
                sdl2::event::Event::KeyDown { keycode: Some(kc), .. } => {
                    if kc == sdl2::keyboard::Keycode::Escape {
                        break 'running;
                    }
                    match kc {
                        sdl2::keyboard::Keycode::Space => key_space = true,
                        sdl2::keyboard::Keycode::Return => key_return = true,
                        sdl2::keyboard::Keycode::A => key_a = true,
                        sdl2::keyboard::Keycode::Left => key_left = true,
                        sdl2::keyboard::Keycode::D => key_d = true,
                        sdl2::keyboard::Keycode::Right => key_right = true,
                        sdl2::keyboard::Keycode::W => key_w = true,
                        sdl2::keyboard::Keycode::Up => key_up = true,
                        sdl2::keyboard::Keycode::S => key_s = true,
                        sdl2::keyboard::Keycode::Down => key_down = true,
                        _ => {}
                    }
                }
                sdl2::event::Event::KeyUp { keycode: Some(kc), .. } => {
                    match kc {
                        sdl2::keyboard::Keycode::Space => key_space = false,
                        sdl2::keyboard::Keycode::Return => key_return = false,
                        sdl2::keyboard::Keycode::A => key_a = false,
                        sdl2::keyboard::Keycode::Left => key_left = false,
                        sdl2::keyboard::Keycode::D => key_d = false,
                        sdl2::keyboard::Keycode::Right => key_right = false,
                        sdl2::keyboard::Keycode::W => key_w = false,
                        sdl2::keyboard::Keycode::Up => key_up = false,
                        sdl2::keyboard::Keycode::S => key_s = false,
                        sdl2::keyboard::Keycode::Down => key_down = false,
                        _ => {}
                    }
                }
                sdl2::event::Event::ControllerDeviceAdded { which, .. } => {
                    if let Some(ref gc_subsystem) = controller_subsystem {
                        match gc_subsystem.open(which) {
                            Ok(controller) => {
                                info!("Gamepad connected: {}", controller.name());
                                active_controllers.insert(which, controller);
                            }
                            Err(e) => {
                                error!("Failed to open gamepad {}: {}", which, e);
                            }
                        }
                    }
                }
                sdl2::event::Event::ControllerDeviceRemoved { which, .. } => {
                    if let Some(controller) = active_controllers.remove(&which) {
                        info!("Gamepad disconnected: {}", controller.name());
                    }
                }
                _ => {}
            }
        }

        let mut buttons = 0;
        let mut lx = 127;
        let mut ly = 127;
        let mut rx = 127;
        let mut ry = 127;

        // 1. Read first active gamepad (DualSense/Standard mapping)
        if let Some(controller) = active_controllers.values().next() {
            if controller.button(sdl2::controller::Button::A) {
                buttons |= input::SCE_PAD_BUTTON_CROSS;
            }
            if controller.button(sdl2::controller::Button::B) {
                buttons |= input::SCE_PAD_BUTTON_CIRCLE;
            }
            if controller.button(sdl2::controller::Button::X) {
                buttons |= input::SCE_PAD_BUTTON_SQUARE;
            }
            if controller.button(sdl2::controller::Button::Y) {
                buttons |= input::SCE_PAD_BUTTON_TRIANGLE;
            }
            if controller.button(sdl2::controller::Button::DPadUp) {
                buttons |= input::SCE_PAD_BUTTON_UP;
            }
            if controller.button(sdl2::controller::Button::DPadDown) {
                buttons |= input::SCE_PAD_BUTTON_DOWN;
            }
            if controller.button(sdl2::controller::Button::DPadLeft) {
                buttons |= input::SCE_PAD_BUTTON_LEFT;
            }
            if controller.button(sdl2::controller::Button::DPadRight) {
                buttons |= input::SCE_PAD_BUTTON_RIGHT;
            }
            if controller.button(sdl2::controller::Button::LeftShoulder) {
                buttons |= input::SCE_PAD_BUTTON_L1;
            }
            if controller.button(sdl2::controller::Button::RightShoulder) {
                buttons |= input::SCE_PAD_BUTTON_R1;
            }
            if controller.button(sdl2::controller::Button::Back) {
                buttons |= input::SCE_PAD_BUTTON_OPTIONS;
            }
            if controller.button(sdl2::controller::Button::Start) {
                buttons |= input::SCE_PAD_BUTTON_OPTIONS;
            }
            if controller.button(sdl2::controller::Button::LeftStick) {
                buttons |= input::SCE_PAD_BUTTON_L3;
            }
            if controller.button(sdl2::controller::Button::RightStick) {
                buttons |= input::SCE_PAD_BUTTON_R3;
            }

            // Triggers
            if controller.axis(sdl2::controller::Axis::TriggerLeft) > 3276 {
                buttons |= input::SCE_PAD_BUTTON_L2;
            }
            if controller.axis(sdl2::controller::Axis::TriggerRight) > 3276 {
                buttons |= input::SCE_PAD_BUTTON_R2;
            }

            // Analog sticks
            let val_lx = controller.axis(sdl2::controller::Axis::LeftX);
            let val_ly = controller.axis(sdl2::controller::Axis::LeftY);
            let val_rx = controller.axis(sdl2::controller::Axis::RightX);
            let val_ry = controller.axis(sdl2::controller::Axis::RightY);

            // Scale from i16 to u8 (0-255)
            lx = (((val_lx as i32 + 32768) * 255) / 65535) as u8;
            ly = (((val_ly as i32 + 32768) * 255) / 65535) as u8;
            rx = (((val_rx as i32 + 32768) * 255) / 65535) as u8;
            ry = (((val_ry as i32 + 32768) * 255) / 65535) as u8;
        }

        // 2. Poll Keyboard and merge button presses
        if key_space {
            buttons |= input::SCE_PAD_BUTTON_CROSS;
        }
        if key_return {
            buttons |= input::SCE_PAD_BUTTON_START;
        }
        if key_a || key_left {
            lx = 0;
        }
        if key_d || key_right {
            lx = 255;
        }
        if key_w || key_up {
            ly = 0;
        }
        if key_s || key_down {
            ly = 255;
        }

        input::update_global_pad_state(buttons, lx, ly, rx, ry);

        // Run graphics updates
        if has_vulkan {
            let global_ctx = graphics::VULKAN_CONTEXT.lock().unwrap();
            if let Some(ref ctx) = *global_ctx {
                if let Err(e) = ctx.render_frame() {
                    error!("Render error: {}", e);
                }
            }
        }

        // Limit frame rate (approx. 60 FPS)
        std::thread::sleep(std::time::Duration::from_millis(16));
    }

    info!("ShadPS5 emulator shutting down safely. Goodbye.");
}
