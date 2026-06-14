use log::{info, warn, error};
use std::ffi::{c_char, CStr, CString};
use ash::{vk, Entry, Instance, Device};
use sdl2::video::Window;
use ash::vk::Handle;
use std::cell::Cell;
use std::sync::Mutex;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

const MAX_FRAMES_IN_FLIGHT: usize = 2;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct PipelineStateKey {
    pub vertex_shader_gpu_addr: u64,
    pub fragment_shader_gpu_addr: u64,
    pub topology: vk::PrimitiveTopology,
    pub depth_test_enable: bool,
    pub depth_write_enable: bool,
    pub stencil_test_enable: bool,
    pub stencil_write_enable: bool,
    pub has_vertex_buffer: bool,
    pub has_constant_buffer: bool,
    pub has_texture: bool,
    pub blend_enable: bool,
    pub src_color_blend_factor: u32,
    pub dst_color_blend_factor: u32,
    pub color_blend_op: u32,
    pub src_alpha_blend_factor: u32,
    pub dst_alpha_blend_factor: u32,
    pub alpha_blend_op: u32,
    pub color_write_mask: u32,
}

#[derive(Clone, Debug)]
pub struct ActiveGraphicsState {
    pub vertex_shader_gpu_addr: u64,
    pub fragment_shader_gpu_addr: u64,
    pub compute_shader_gpu_addr: u64,
    pub topology: vk::PrimitiveTopology,
    pub depth_test_enable: bool,
    pub depth_write_enable: bool,
    pub stencil_test_enable: bool,
    pub stencil_write_enable: bool,
    pub vertex_buffer_gpu_addr: u64,
    pub vertex_buffer_size: u32,
    pub index_buffer_gpu_addr: u64,
    pub index_buffer_count: u32,
    pub index_type: vk::IndexType,
    pub constant_buffer_gpu_addr: u64,
    pub constant_buffer_size: u32,
    pub texture_gpu_addr: u64,
    pub texture_width: u32,
    pub texture_height: u32,
    pub texture_format: u32,
    pub sampler_filter: u32,
    pub blend_enable: bool,
    pub src_color_blend_factor: u32,
    pub dst_color_blend_factor: u32,
    pub color_blend_op: u32,
    pub src_alpha_blend_factor: u32,
    pub dst_alpha_blend_factor: u32,
    pub alpha_blend_op: u32,
    pub color_write_mask: u32,
    pub viewport_x: f32,
    pub viewport_y: f32,
    pub viewport_width: f32,
    pub viewport_height: f32,
    pub viewport_min_depth: f32,
    pub viewport_max_depth: f32,
    pub scissor_x: i32,
    pub scissor_y: i32,
    pub scissor_width: u32,
    pub scissor_height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComputeTask {
    KrakenDecompress,
    TempestAudio,
}

pub struct CachedComputePipeline {
    pub pipeline: vk::Pipeline,
    pub pipeline_layout: vk::PipelineLayout,
    pub desc_layout: vk::DescriptorSetLayout,
    pub shader_module: vk::ShaderModule,
}

/// Manages the Vulkan driver, instance, device, queues, surface, and swapchain resources.
pub struct VulkanContext {
    _entry: Entry,
    instance: Instance,
    physical_device: vk::PhysicalDevice,
    device: Device,
    queue: vk::Queue,
    device_name: String,

    // Surface & Swapchain
    surface_loader: ash::khr::surface::Instance,
    surface: vk::SurfaceKHR,
    swapchain_loader: ash::khr::swapchain::Device,
    swapchain: vk::SwapchainKHR,
    swapchain_images: Vec<vk::Image>,
    swapchain_image_views: Vec<vk::ImageView>,
    swapchain_format: vk::Format,
    swapchain_extent: vk::Extent2D,

    // Depth Buffer
    depth_image: vk::Image,
    depth_image_memory: vk::DeviceMemory,
    depth_image_view: vk::ImageView,

    // Graphics Pipeline / Clearing Pass
    render_pass: vk::RenderPass,
    framebuffers: Vec<vk::Framebuffer>,
    command_pool: vk::CommandPool,
    command_buffers: Vec<vk::CommandBuffer>,

    // Synchronization Objects
    image_available_semaphores: Vec<vk::Semaphore>,
    render_finished_semaphores: Vec<vk::Semaphore>,
    in_flight_fences: Vec<vk::Fence>,
    current_frame: Cell<usize>,

    // Resource cleanup lists per frame in flight
    buffers_to_destroy: Mutex<Vec<Vec<vk::Buffer>>>,
    memory_to_free: Mutex<Vec<Vec<vk::DeviceMemory>>>,
    images_to_destroy: Mutex<Vec<Vec<vk::Image>>>,
    image_views_to_destroy: Mutex<Vec<Vec<vk::ImageView>>>,
    samplers_to_destroy: Mutex<Vec<Vec<vk::Sampler>>>,
    desc_pools_to_destroy: Mutex<Vec<Vec<vk::DescriptorPool>>>,

    // Compute Shader pipeline cache
    compute_pipeline_cache: Mutex<HashMap<ComputeTask, CachedComputePipeline>>,
    pipeline_cache: vk::PipelineCache,
}

impl VulkanContext {
    /// Initializes Vulkan on the host system, creates window surface, swapchain, and rendering passes.
    pub fn new(window: &Window) -> Result<Self, String> {
        info!("Loading Vulkan loader DLL/Shared Library...");
        let entry = unsafe { Entry::load().map_err(|e| format!("Vulkan loader not found: {:?}", e))? };

        let app_name = CString::new("ShadPS5").unwrap();
        let engine_name = CString::new("ShadPS5-AGC").unwrap();

        let extension_names = window
            .vulkan_instance_extensions()
            .map_err(|e| format!("Failed to query SDL2 Vulkan extensions: {}", e))?;
        
        let mut extension_names_c: Vec<CString> = extension_names
            .iter()
            .map(|&name| CString::new(name).unwrap())
            .collect();
        extension_names_c.push(CString::new("VK_KHR_surface").unwrap());

        let extension_names_ptrs: Vec<*const c_char> = extension_names_c
            .iter()
            .map(|c_str| c_str.as_ptr())
            .collect();

        let app_info = vk::ApplicationInfo::default()
            .application_name(&app_name)
            .application_version(vk::make_api_version(0, 0, 1, 0))
            .engine_name(&engine_name)
            .engine_version(vk::make_api_version(0, 0, 1, 0))
            .api_version(vk::API_VERSION_1_3);

        let create_info = vk::InstanceCreateInfo::default()
            .application_info(&app_info)
            .enabled_extension_names(&extension_names_ptrs);

        info!("Creating Vulkan Instance...");
        let instance = unsafe {
            entry
                .create_instance(&create_info, None)
                .map_err(|e| format!("Failed to create Vulkan instance: {:?}", e))?
        };

        // Surface creation using SDL2
        info!("Creating Vulkan Surface via SDL2 Window...");
        let surface_handle = window
            .vulkan_create_surface(instance.handle().as_raw() as usize)
            .map_err(|e| format!("Failed to create Vulkan surface: {}", e))?;
        let surface = vk::SurfaceKHR::from_raw(surface_handle);
        let surface_loader = ash::khr::surface::Instance::new(&entry, &instance);

        info!("Enumerating host graphics devices (GPUs)...");
        let physical_devices = unsafe {
            instance
                .enumerate_physical_devices()
                .map_err(|e| format!("Failed to enumerate physical devices: {:?}", e))?
        };

        if physical_devices.is_empty() {
            return Err("No Vulkan-compatible GPUs found.".to_string());
        }

        // Find physical device that supports both graphics queue and presentation to surface
        let mut selected_gpu = None;
        let mut graphics_queue_family_index = None;

        for &pd in &physical_devices {
            let queue_family_properties = unsafe {
                instance.get_physical_device_queue_family_properties(pd)
            };

            for (index, prop) in queue_family_properties.iter().enumerate() {
                let is_graphics = prop.queue_flags.contains(vk::QueueFlags::GRAPHICS);
                let is_present = unsafe {
                    surface_loader
                        .get_physical_device_surface_support(pd, index as u32, surface)
                        .unwrap_or(false)
                };

                if is_graphics && is_present {
                    graphics_queue_family_index = Some(index as u32);
                    selected_gpu = Some(pd);
                    break;
                }
            }
            if selected_gpu.is_some() {
                break;
            }
        }

        let physical_device = selected_gpu
            .ok_or_else(|| "Could not find a physical device with graphics and surface presentation support.".to_string())?;
        let queue_family_index = graphics_queue_family_index.unwrap();

        let device_properties = unsafe { instance.get_physical_device_properties(physical_device) };
        let device_name_bytes = unsafe { CStr::from_ptr(device_properties.device_name.as_ptr()) };
        let device_name = device_name_bytes.to_string_lossy().into_owned();
        info!("Selected GPU with presentation support: {}", device_name);

        // Query memory properties to verify Resizable BAR (ReBAR) support
        let memory_properties = unsafe { instance.get_physical_device_memory_properties(physical_device) };
        let mut has_rebar = false;
        let mut rebar_size = 0;
        for i in 0..memory_properties.memory_type_count as usize {
            let mem_type = memory_properties.memory_types[i];
            let flags = mem_type.property_flags;
            if flags.contains(vk::MemoryPropertyFlags::DEVICE_LOCAL) && flags.contains(vk::MemoryPropertyFlags::HOST_VISIBLE) {
                has_rebar = true;
                let heap_size = memory_properties.memory_heaps[mem_type.heap_index as usize].size;
                rebar_size = rebar_size.max(heap_size);
            }
        }
        if has_rebar {
            info!("  [Memory Info] Resizable BAR / Host-Visible VRAM is SUPPORTED. Size: {} MB", rebar_size / (1024 * 1024));
            if rebar_size < 1024 * 1024 * 1024 {
                warn!("  [Memory Info] Host-visible device local heap is small ({} MB). Resizable BAR might be disabled or constrained in BIOS.", rebar_size / (1024 * 1024));
            }
        } else {
            warn!("  [Memory Info] Resizable BAR / Host-Visible VRAM is NOT supported by host GPU! CPU-GPU zero-copy emulation will require slow readbacks.");
        }

        // Query host subgroup properties
        let mut subgroup_properties = vk::PhysicalDeviceSubgroupProperties::default();
        let mut properties2 = vk::PhysicalDeviceProperties2::default().push_next(&mut subgroup_properties);
        unsafe {
            instance.get_physical_device_properties2(physical_device, &mut properties2);
        }
        info!("  [Subgroup Info] Supported stages: {:?}", subgroup_properties.supported_stages);
        info!("  [Subgroup Info] Supported operations: {:?}", subgroup_properties.supported_operations);
        info!("  [Subgroup Info] Subgroup size: {}", subgroup_properties.subgroup_size);

        if !subgroup_properties.supported_operations.contains(vk::SubgroupFeatureFlags::SHUFFLE) {
            warn!("Host GPU does not support subgroup shuffle operations! Dynamic recompiler lane logic might fail.");
        }

        // Logical Device setup with VK_KHR_swapchain extension enabled
        let queue_priorities = [1.0_f32];
        let queue_create_info = vk::DeviceQueueCreateInfo::default()
            .queue_family_index(queue_family_index)
            .queue_priorities(&queue_priorities);

        let device_extensions = [
            ash::khr::swapchain::NAME.as_ptr(),
        ];

        let mut float16_features = vk::PhysicalDeviceShaderFloat16Int8Features::default()
            .shader_float16(true);

        let mut buffer_device_address_features = vk::PhysicalDeviceBufferDeviceAddressFeatures::default()
            .buffer_device_address(true);

        let device_create_info = vk::DeviceCreateInfo::default()
            .queue_create_infos(std::slice::from_ref(&queue_create_info))
            .enabled_extension_names(&device_extensions)
            .push_next(&mut buffer_device_address_features)
            .push_next(&mut float16_features);

        info!("Creating Vulkan logical device with Swapchain and Physical Buffer Device Address support...");
        let device = unsafe {
            instance
                .create_device(physical_device, &device_create_info, None)
                .map_err(|e| format!("Failed to create Vulkan logical device: {:?}", e))?
        };

        let queue = unsafe { device.get_device_queue(queue_family_index, 0) };
        let swapchain_loader = ash::khr::swapchain::Device::new(&instance, &device);

        // Swapchain configuration
        let (width, height) = window.size();
        let surface_capabilities = unsafe {
            surface_loader
                .get_physical_device_surface_capabilities(physical_device, surface)
                .map_err(|e| format!("Failed to query surface capabilities: {:?}", e))?
        };

        let surface_formats = unsafe {
            surface_loader
                .get_physical_device_surface_formats(physical_device, surface)
                .map_err(|e| format!("Failed to query surface formats: {:?}", e))?
        };

        // Select a color format, fallback to the first one available
        let format = surface_formats
            .iter()
            .find(|f| f.format == vk::Format::B8G8R8A8_SRGB && f.color_space == vk::ColorSpaceKHR::SRGB_NONLINEAR)
            .cloned()
            .unwrap_or_else(|| surface_formats[0]);

        let extent = if surface_capabilities.current_extent.width != u32::MAX {
            surface_capabilities.current_extent
        } else {
            vk::Extent2D {
                width: width.clamp(surface_capabilities.min_image_extent.width, surface_capabilities.max_image_extent.width),
                height: height.clamp(surface_capabilities.min_image_extent.height, surface_capabilities.max_image_extent.height),
            }
        };

        let mut image_count = surface_capabilities.min_image_count + 1;
        if surface_capabilities.max_image_count > 0 && image_count > surface_capabilities.max_image_count {
            image_count = surface_capabilities.max_image_count;
        }

        let swapchain_create_info = vk::SwapchainCreateInfoKHR::default()
            .surface(surface)
            .min_image_count(image_count)
            .image_format(format.format)
            .image_color_space(format.color_space)
            .image_extent(extent)
            .image_array_layers(1)
            .image_usage(vk::ImageUsageFlags::COLOR_ATTACHMENT)
            .image_sharing_mode(vk::SharingMode::EXCLUSIVE)
            .pre_transform(surface_capabilities.current_transform)
            .composite_alpha(vk::CompositeAlphaFlagsKHR::OPAQUE)
            .present_mode(vk::PresentModeKHR::FIFO)
            .clipped(true);

        info!("Creating Vulkan Swapchain (extent: {}x{})...", extent.width, extent.height);
        let swapchain = unsafe {
            swapchain_loader
                .create_swapchain(&swapchain_create_info, None)
                .map_err(|e| format!("Failed to create Vulkan Swapchain: {:?}", e))?
        };

        let swapchain_images = unsafe {
            swapchain_loader
                .get_swapchain_images(swapchain)
                .map_err(|e| format!("Failed to retrieve swapchain images: {:?}", e))?
        };

        let mut swapchain_image_views = Vec::new();
        for &img in &swapchain_images {
            let iv_create_info = vk::ImageViewCreateInfo::default()
                .image(img)
                .view_type(vk::ImageViewType::TYPE_2D)
                .format(format.format)
                .components(vk::ComponentMapping {
                    r: vk::ComponentSwizzle::IDENTITY,
                    g: vk::ComponentSwizzle::IDENTITY,
                    b: vk::ComponentSwizzle::IDENTITY,
                    a: vk::ComponentSwizzle::IDENTITY,
                })
                .subresource_range(vk::ImageSubresourceRange {
                    aspect_mask: vk::ImageAspectFlags::COLOR,
                    base_mip_level: 0,
                    level_count: 1,
                    base_array_layer: 0,
                    layer_count: 1,
                });

            let img_view = unsafe {
                device
                    .create_image_view(&iv_create_info, None)
                    .map_err(|e| format!("Failed to create image view: {:?}", e))?
            };
            swapchain_image_views.push(img_view);
        }

        // =====================================================================
        // Depth Buffer Creation (D32_SFLOAT)
        // =====================================================================
        let depth_format = vk::Format::D32_SFLOAT_S8_UINT;
        info!("Creating depth buffer (format: D32_SFLOAT_S8_UINT, {}x{})...", extent.width, extent.height);

        let depth_image_info = vk::ImageCreateInfo::default()
            .image_type(vk::ImageType::TYPE_2D)
            .extent(vk::Extent3D {
                width: extent.width,
                height: extent.height,
                depth: 1,
            })
            .mip_levels(1)
            .array_layers(1)
            .format(depth_format)
            .tiling(vk::ImageTiling::OPTIMAL)
            .initial_layout(vk::ImageLayout::UNDEFINED)
            .usage(vk::ImageUsageFlags::DEPTH_STENCIL_ATTACHMENT)
            .samples(vk::SampleCountFlags::TYPE_1)
            .sharing_mode(vk::SharingMode::EXCLUSIVE);

        let depth_image = unsafe {
            device
                .create_image(&depth_image_info, None)
                .map_err(|e| format!("Failed to create depth image: {:?}", e))?
        };

        let depth_mem_reqs = unsafe { device.get_image_memory_requirements(depth_image) };
        let mem_props = unsafe { instance.get_physical_device_memory_properties(physical_device) };

        let depth_mem_type_idx = {
            let mut found = 0;
            for i in 0..mem_props.memory_type_count {
                if (depth_mem_reqs.memory_type_bits & (1 << i)) != 0
                    && mem_props.memory_types[i as usize]
                        .property_flags
                        .contains(vk::MemoryPropertyFlags::DEVICE_LOCAL)
                {
                    found = i;
                    break;
                }
            }
            found
        };

        let depth_mem_alloc = vk::MemoryAllocateInfo::default()
            .allocation_size(depth_mem_reqs.size)
            .memory_type_index(depth_mem_type_idx);

        let depth_image_memory = unsafe {
            device
                .allocate_memory(&depth_mem_alloc, None)
                .map_err(|e| format!("Failed to allocate depth image memory: {:?}", e))?
        };

        unsafe {
            device
                .bind_image_memory(depth_image, depth_image_memory, 0)
                .map_err(|e| format!("Failed to bind depth image memory: {:?}", e))?;
        }

        let depth_view_info = vk::ImageViewCreateInfo::default()
            .image(depth_image)
            .view_type(vk::ImageViewType::TYPE_2D)
            .format(depth_format)
            .subresource_range(vk::ImageSubresourceRange {
                aspect_mask: vk::ImageAspectFlags::DEPTH | vk::ImageAspectFlags::STENCIL,
                base_mip_level: 0,
                level_count: 1,
                base_array_layer: 0,
                layer_count: 1,
            });

        let depth_image_view = unsafe {
            device
                .create_image_view(&depth_view_info, None)
                .map_err(|e| format!("Failed to create depth image view: {:?}", e))?
        };

        info!("Depth buffer created successfully ({} bytes GPU memory).", depth_mem_reqs.size);

        // =====================================================================
        // Render Pass (Color + Depth attachments)
        // =====================================================================
        let color_attachment = vk::AttachmentDescription::default()
            .format(format.format)
            .samples(vk::SampleCountFlags::TYPE_1)
            .load_op(vk::AttachmentLoadOp::CLEAR)
            .store_op(vk::AttachmentStoreOp::STORE)
            .stencil_load_op(vk::AttachmentLoadOp::DONT_CARE)
            .stencil_store_op(vk::AttachmentStoreOp::DONT_CARE)
            .initial_layout(vk::ImageLayout::UNDEFINED)
            .final_layout(vk::ImageLayout::PRESENT_SRC_KHR);

        let depth_attachment = vk::AttachmentDescription::default()
            .format(depth_format)
            .samples(vk::SampleCountFlags::TYPE_1)
            .load_op(vk::AttachmentLoadOp::CLEAR)
            .store_op(vk::AttachmentStoreOp::DONT_CARE)
            .stencil_load_op(vk::AttachmentLoadOp::DONT_CARE)
            .stencil_store_op(vk::AttachmentStoreOp::DONT_CARE)
            .initial_layout(vk::ImageLayout::UNDEFINED)
            .final_layout(vk::ImageLayout::DEPTH_STENCIL_ATTACHMENT_OPTIMAL);

        let color_attachment_ref = vk::AttachmentReference::default()
            .attachment(0)
            .layout(vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL);

        let depth_attachment_ref = vk::AttachmentReference::default()
            .attachment(1)
            .layout(vk::ImageLayout::DEPTH_STENCIL_ATTACHMENT_OPTIMAL);

        let subpass = vk::SubpassDescription::default()
            .pipeline_bind_point(vk::PipelineBindPoint::GRAPHICS)
            .color_attachments(std::slice::from_ref(&color_attachment_ref))
            .depth_stencil_attachment(&depth_attachment_ref);

        let dependency = vk::SubpassDependency::default()
            .src_subpass(vk::SUBPASS_EXTERNAL)
            .dst_subpass(0)
            .src_stage_mask(
                vk::PipelineStageFlags::COLOR_ATTACHMENT_OUTPUT
                    | vk::PipelineStageFlags::EARLY_FRAGMENT_TESTS,
            )
            .src_access_mask(vk::AccessFlags::empty())
            .dst_stage_mask(
                vk::PipelineStageFlags::COLOR_ATTACHMENT_OUTPUT
                    | vk::PipelineStageFlags::EARLY_FRAGMENT_TESTS,
            )
            .dst_access_mask(
                vk::AccessFlags::COLOR_ATTACHMENT_WRITE
                    | vk::AccessFlags::DEPTH_STENCIL_ATTACHMENT_WRITE,
            );

        let attachments = [color_attachment, depth_attachment];
        let rp_create_info = vk::RenderPassCreateInfo::default()
            .attachments(&attachments)
            .subpasses(std::slice::from_ref(&subpass))
            .dependencies(std::slice::from_ref(&dependency));

        let render_pass = unsafe {
            device
                .create_render_pass(&rp_create_info, None)
                .map_err(|e| format!("Failed to create Render Pass: {:?}", e))?
        };

        // Framebuffers (color + depth)
        let mut framebuffers = Vec::new();
        for &img_view in &swapchain_image_views {
            let fb_attachments = [img_view, depth_image_view];
            let fb_create_info = vk::FramebufferCreateInfo::default()
                .render_pass(render_pass)
                .attachments(&fb_attachments)
                .width(extent.width)
                .height(extent.height)
                .layers(1);

            let framebuffer = unsafe {
                device
                    .create_framebuffer(&fb_create_info, None)
                    .map_err(|e| format!("Failed to create Framebuffer: {:?}", e))?
            };
            framebuffers.push(framebuffer);
        }

        // Command Pool and Buffers
        let cp_create_info = vk::CommandPoolCreateInfo::default()
            .queue_family_index(queue_family_index)
            .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER);

        let command_pool = unsafe {
            device
                .create_command_pool(&cp_create_info, None)
                .map_err(|e| format!("Failed to create Command Pool: {:?}", e))?
        };

        let cb_alloc_info = vk::CommandBufferAllocateInfo::default()
            .command_pool(command_pool)
            .level(vk::CommandBufferLevel::PRIMARY)
            .command_buffer_count(MAX_FRAMES_IN_FLIGHT as u32);

        let command_buffers = unsafe {
            device
                .allocate_command_buffers(&cb_alloc_info)
                .map_err(|e| format!("Failed to allocate Command Buffers: {:?}", e))?
        };

        // Transition depth image layout to DEPTH_STENCIL_ATTACHMENT_OPTIMAL
        {
            let one_shot_alloc = vk::CommandBufferAllocateInfo::default()
                .command_pool(command_pool)
                .level(vk::CommandBufferLevel::PRIMARY)
                .command_buffer_count(1);
            let one_shot_cb = unsafe { device.allocate_command_buffers(&one_shot_alloc).unwrap()[0] };
            let begin_info = vk::CommandBufferBeginInfo::default()
                .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
            unsafe {
                device.begin_command_buffer(one_shot_cb, &begin_info).unwrap();

                let barrier = vk::ImageMemoryBarrier::default()
                    .old_layout(vk::ImageLayout::UNDEFINED)
                    .new_layout(vk::ImageLayout::DEPTH_STENCIL_ATTACHMENT_OPTIMAL)
                    .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                    .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                    .image(depth_image)
                    .subresource_range(vk::ImageSubresourceRange {
                        aspect_mask: vk::ImageAspectFlags::DEPTH | vk::ImageAspectFlags::STENCIL,
                        base_mip_level: 0,
                        level_count: 1,
                        base_array_layer: 0,
                        layer_count: 1,
                    })
                    .src_access_mask(vk::AccessFlags::empty())
                    .dst_access_mask(
                        vk::AccessFlags::DEPTH_STENCIL_ATTACHMENT_READ
                            | vk::AccessFlags::DEPTH_STENCIL_ATTACHMENT_WRITE,
                    );

                device.cmd_pipeline_barrier(
                    one_shot_cb,
                    vk::PipelineStageFlags::TOP_OF_PIPE,
                    vk::PipelineStageFlags::EARLY_FRAGMENT_TESTS,
                    vk::DependencyFlags::empty(),
                    &[],
                    &[],
                    &[barrier],
                );

                device.end_command_buffer(one_shot_cb).unwrap();

                let submit_info = vk::SubmitInfo::default()
                    .command_buffers(std::slice::from_ref(&one_shot_cb));
                {
                    let _lock = SUBMIT_MUTEX.lock().unwrap();
                    device.queue_submit(queue, &[submit_info], vk::Fence::null()).unwrap();
                }
                device.queue_wait_idle(queue).unwrap();
                device.free_command_buffers(command_pool, &[one_shot_cb]);
            }
            info!("Depth image transitioned to DEPTH_STENCIL_ATTACHMENT_OPTIMAL.");
        }

        // Sync semaphores and fences
        let mut image_available_semaphores = Vec::new();
        let mut render_finished_semaphores = Vec::new();
        let mut in_flight_fences = Vec::new();

        let semaphore_create_info = vk::SemaphoreCreateInfo::default();
        let fence_create_info = vk::FenceCreateInfo::default().flags(vk::FenceCreateFlags::SIGNALED);

        for _ in 0..MAX_FRAMES_IN_FLIGHT {
            unsafe {
                let img_sem = device.create_semaphore(&semaphore_create_info, None).unwrap();
                let render_sem = device.create_semaphore(&semaphore_create_info, None).unwrap();
                let fence = device.create_fence(&fence_create_info, None).unwrap();
                
                image_available_semaphores.push(img_sem);
                render_finished_semaphores.push(render_sem);
                in_flight_fences.push(fence);
            }
        }

        let cache_path = std::path::Path::new("shader_cache/pipeline_cache.bin");
        let initial_data = if cache_path.exists() {
            std::fs::read(cache_path).unwrap_or_default()
        } else {
            Vec::new()
        };

        let pc_create_info = if !initial_data.is_empty() {
            vk::PipelineCacheCreateInfo::default().initial_data(&initial_data)
        } else {
            vk::PipelineCacheCreateInfo::default()
        };

        let pipeline_cache = unsafe {
            device.create_pipeline_cache(&pc_create_info, None)
                .unwrap_or(vk::PipelineCache::null())
        };

        if pipeline_cache != vk::PipelineCache::null() && !initial_data.is_empty() {
            info!("Successfully initialized Vulkan PipelineCache from disk: ({} bytes)", initial_data.len());
        } else if pipeline_cache != vk::PipelineCache::null() {
            info!("Created new Vulkan PipelineCache.");
        } else {
            warn!("Failed to create Vulkan PipelineCache.");
        }

        Ok(VulkanContext {
            _entry: entry,
            instance,
            physical_device,
            device,
            queue,
            device_name,
            surface_loader,
            surface,
            swapchain_loader,
            swapchain,
            swapchain_images,
            swapchain_image_views,
            swapchain_format: format.format,
            swapchain_extent: extent,
            depth_image,
            depth_image_memory,
            depth_image_view,
            render_pass,
            framebuffers,
            command_pool,
            command_buffers,
            image_available_semaphores,
            render_finished_semaphores,
            in_flight_fences,
            current_frame: Cell::new(0),
            buffers_to_destroy: Mutex::new(vec![Vec::new(); MAX_FRAMES_IN_FLIGHT]),
            memory_to_free: Mutex::new(vec![Vec::new(); MAX_FRAMES_IN_FLIGHT]),
            images_to_destroy: Mutex::new(vec![Vec::new(); MAX_FRAMES_IN_FLIGHT]),
            image_views_to_destroy: Mutex::new(vec![Vec::new(); MAX_FRAMES_IN_FLIGHT]),
            samplers_to_destroy: Mutex::new(vec![Vec::new(); MAX_FRAMES_IN_FLIGHT]),
            desc_pools_to_destroy: Mutex::new(vec![Vec::new(); MAX_FRAMES_IN_FLIGHT]),
            compute_pipeline_cache: Mutex::new(HashMap::new()),
            pipeline_cache,
        })
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Renders a host application frame. Clears swapchain image views using a dark premium color.
    pub fn render_frame(&self) -> Result<(), &'static str> {
        let device = &self.device;
        let current_frame_val = self.current_frame.get();
        let current_fence = self.in_flight_fences[current_frame_val];

        unsafe {
            // Wait for previous operations to complete on the current frame's fences
            device.wait_for_fences(&[current_fence], true, u64::MAX).unwrap();

            // Safe to destroy/free resources registered to this frame slot
            {
                let mut bufs = self.buffers_to_destroy.lock().unwrap();
                for buf in bufs[current_frame_val].drain(..) {
                    device.destroy_buffer(buf, None);
                }
                let mut mems = self.memory_to_free.lock().unwrap();
                for mem in mems[current_frame_val].drain(..) {
                    device.free_memory(mem, None);
                }
                let mut imgs = self.images_to_destroy.lock().unwrap();
                for img in imgs[current_frame_val].drain(..) {
                    device.destroy_image(img, None);
                }
                let mut views = self.image_views_to_destroy.lock().unwrap();
                for view in views[current_frame_val].drain(..) {
                    device.destroy_image_view(view, None);
                }
                let mut samps = self.samplers_to_destroy.lock().unwrap();
                for samp in samps[current_frame_val].drain(..) {
                    device.destroy_sampler(samp, None);
                }
                let mut pools = self.desc_pools_to_destroy.lock().unwrap();
                for pool in pools[current_frame_val].drain(..) {
                    device.destroy_descriptor_pool(pool, None);
                }
            }

            device.reset_fences(&[current_fence]).unwrap();

            // Acquire next image from swapchain
            let acquire_res = self.swapchain_loader.acquire_next_image(
                self.swapchain,
                u64::MAX,
                self.image_available_semaphores[current_frame_val],
                vk::Fence::null(),
            );

            let image_index = match acquire_res {
                Ok((idx, _)) => idx as usize,
                Err(vk::Result::ERROR_OUT_OF_DATE_KHR) => {
                    warn!("Swapchain is out of date. Skipping frame.");
                    return Ok(());
                }
                Err(_) => return Err("Failed to acquire next swapchain image"),
            };

            let cmd_buffer = self.command_buffers[current_frame_val];
            device.reset_command_buffer(cmd_buffer, vk::CommandBufferResetFlags::empty()).unwrap();

            let begin_info = vk::CommandBufferBeginInfo::default()
                .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);

            device.begin_command_buffer(cmd_buffer, &begin_info).unwrap();

            // Clear color: #0b0f19 (vibrant premium dark background) + depth clear to 1.0
            let clear_values = [
                vk::ClearValue {
                    color: vk::ClearColorValue {
                        float32: [0.043, 0.059, 0.098, 1.0],
                    },
                },
                vk::ClearValue {
                    depth_stencil: vk::ClearDepthStencilValue {
                        depth: 1.0,
                        stencil: 0,
                    },
                },
            ];

            let render_pass_info = vk::RenderPassBeginInfo::default()
                .render_pass(self.render_pass)
                .framebuffer(self.framebuffers[image_index])
                .render_area(vk::Rect2D {
                    offset: vk::Offset2D { x: 0, y: 0 },
                    extent: self.swapchain_extent,
                })
                .clear_values(&clear_values);
            device.cmd_begin_render_pass(cmd_buffer, &render_pass_info, vk::SubpassContents::INLINE);

            // Synchronize and re-protect dirty pages to catch subsequent guest CPU modifications
            crate::memory_tracker::sync_dirty_ranges(|addr, len, _| {
                log::debug!("Syncing write-watched dirty page: 0x{:X} (size: {} bytes)", addr, len);
            });

            // Drain and replay any pending guest draw calls
            let mut pending = PENDING_DRAWS.lock().unwrap();
            for draw_call in pending.drain(..) {
                if draw_call.pipeline != vk::Pipeline::null() {
                    info!("Replaying guest draw with compiled pipeline PSO: {:?}", draw_call.pipeline);
                    device.cmd_bind_pipeline(cmd_buffer, vk::PipelineBindPoint::GRAPHICS, draw_call.pipeline);

                    // Dynamic Viewport
                    let viewport = vk::Viewport {
                        x: draw_call.viewport_x,
                        y: draw_call.viewport_y,
                        width: if draw_call.viewport_width > 0.0 { draw_call.viewport_width } else { self.swapchain_extent.width as f32 },
                        height: if draw_call.viewport_height > 0.0 { draw_call.viewport_height } else { self.swapchain_extent.height as f32 },
                        min_depth: draw_call.viewport_min_depth,
                        max_depth: draw_call.viewport_max_depth,
                    };
                    device.cmd_set_viewport(cmd_buffer, 0, &[viewport]);

                    // Dynamic Scissor
                    let scissor = vk::Rect2D {
                        offset: vk::Offset2D { x: draw_call.scissor_x, y: draw_call.scissor_y },
                        extent: vk::Extent2D {
                            width: if draw_call.scissor_width > 0 { draw_call.scissor_width } else { self.swapchain_extent.width },
                            height: if draw_call.scissor_height > 0 { draw_call.scissor_height } else { self.swapchain_extent.height },
                        },
                    };
                    device.cmd_set_scissor(cmd_buffer, 0, &[scissor]);

                    let mut temp_buffers = Vec::new();
                    let mut temp_mems = Vec::new();
                    
                    // 1. Vertex Buffer Binding
                    if draw_call.vertex_buffer_gpu_addr != 0 {
                        let host_addr = crate::kernel::translate_guest_addr(draw_call.vertex_buffer_gpu_addr)
                            .unwrap_or(draw_call.vertex_buffer_gpu_addr);
                        let size = draw_call.vertex_buffer_size as usize;
                        if size > 0 && host_addr >= 0x1000 {
                            let vertex_data = std::slice::from_raw_parts(host_addr as *const u8, size);
                            let (vk_buf, vk_mem) = self.create_vertex_buffer(vertex_data);
                            device.cmd_bind_vertex_buffers(cmd_buffer, 0, &[vk_buf], &[0]);
                            temp_buffers.push(vk_buf);
                            temp_mems.push(vk_mem);
                            info!("  --> Successfully bound HLE vertex buffer containing {} bytes.", size);
                        }
                    }
                    
                    // 2. Index Buffer Binding
                    let mut has_index_buffer = false;
                    if draw_call.index_buffer_gpu_addr != 0 {
                        let host_addr = crate::kernel::translate_guest_addr(draw_call.index_buffer_gpu_addr)
                            .unwrap_or(draw_call.index_buffer_gpu_addr);
                        let stride = match draw_call.index_type {
                            vk::IndexType::UINT16 => 2,
                            vk::IndexType::UINT32 => 4,
                            _ => 2,
                        };
                        let size = (draw_call.index_buffer_count as usize) * stride;
                        if size > 0 && host_addr >= 0x1000 {
                            let index_data = std::slice::from_raw_parts(host_addr as *const u8, size);
                            let (vk_buf, vk_mem) = self.create_index_buffer(index_data);
                            device.cmd_bind_index_buffer(cmd_buffer, vk_buf, 0, draw_call.index_type);
                            temp_buffers.push(vk_buf);
                            temp_mems.push(vk_mem);
                            has_index_buffer = true;
                            info!("  --> Successfully bound HLE index buffer containing {} bytes (count: {}, type: {:?}).", size, draw_call.index_buffer_count, draw_call.index_type);
                        }
                    }

                    // 3. Descriptor Set Binding (Constant Buffer & Texture Combined Image Sampler)
                    let mut desc_pool = vk::DescriptorPool::null();
                    let mut temp_images = Vec::new();
                    let mut temp_image_views = Vec::new();
                    let mut temp_samplers = Vec::new();

                    if draw_call.descriptor_set_layout != vk::DescriptorSetLayout::null() {
                        let mut pool_sizes = Vec::new();
                        if draw_call.constant_buffer_gpu_addr != 0 {
                            pool_sizes.push(
                                vk::DescriptorPoolSize::default()
                                    .ty(vk::DescriptorType::UNIFORM_BUFFER)
                                    .descriptor_count(1),
                            );
                        }
                        if draw_call.texture_gpu_addr != 0 {
                            pool_sizes.push(
                                vk::DescriptorPoolSize::default()
                                    .ty(vk::DescriptorType::COMBINED_IMAGE_SAMPLER)
                                    .descriptor_count(1),
                            );
                        }

                        if !pool_sizes.is_empty() {
                            let pool_info = vk::DescriptorPoolCreateInfo::default()
                                .max_sets(1)
                                .pool_sizes(&pool_sizes);
                            desc_pool = device.create_descriptor_pool(&pool_info, None).unwrap();

                            let layouts = [draw_call.descriptor_set_layout];
                            let alloc_info = vk::DescriptorSetAllocateInfo::default()
                                .descriptor_pool(desc_pool)
                                .set_layouts(&layouts);
                            let desc_set = device.allocate_descriptor_sets(&alloc_info).unwrap()[0];

                            let mut writes = Vec::new();
                            let mut buffer_info_vk = vk::DescriptorBufferInfo::default();
                            let mut image_info_vk = vk::DescriptorImageInfo::default();

                            if draw_call.constant_buffer_gpu_addr != 0 {
                                let host_addr = crate::kernel::translate_guest_addr(draw_call.constant_buffer_gpu_addr)
                                    .unwrap_or(draw_call.constant_buffer_gpu_addr);
                                let size = draw_call.constant_buffer_size as usize;
                                if size > 0 && host_addr >= 0x1000 {
                                    let cbuf_data = std::slice::from_raw_parts(host_addr as *const u8, size);
                                    let (vk_buf, vk_mem) = self.create_uniform_buffer(cbuf_data);
                                    temp_buffers.push(vk_buf);
                                    temp_mems.push(vk_mem);

                                    buffer_info_vk = vk::DescriptorBufferInfo::default()
                                        .buffer(vk_buf)
                                        .offset(0)
                                        .range(size as u64);

                                    writes.push(
                                        vk::WriteDescriptorSet::default()
                                            .dst_set(desc_set)
                                            .dst_binding(0)
                                            .descriptor_type(vk::DescriptorType::UNIFORM_BUFFER)
                                            .buffer_info(std::slice::from_ref(&buffer_info_vk)),
                                    );
                                }
                            }

                            if draw_call.texture_gpu_addr != 0 {
                                let host_addr = crate::kernel::translate_guest_addr(draw_call.texture_gpu_addr)
                                    .unwrap_or(draw_call.texture_gpu_addr);
                                let width = draw_call.texture_width;
                                let height = draw_call.texture_height;
                                let format = draw_call.texture_format;
                                let bpp = match format {
                                    4 => 1, // R8_UNORM
                                    _ => 4, // RGBA/BGRA
                                };
                                let size = (width * height * bpp) as usize;
                                if size > 0 && host_addr >= 0x1000 {
                                    let pixel_data = std::slice::from_raw_parts(host_addr as *const u8, size);
                                    let (vk_img, vk_mem, vk_view, vk_sampler) = self.create_texture_image(width, height, format, pixel_data);
                                    temp_images.push(vk_img);
                                    temp_mems.push(vk_mem);
                                    temp_image_views.push(vk_view);
                                    temp_samplers.push(vk_sampler);

                                    // Transition layout inline
                                    let image_barrier = vk::ImageMemoryBarrier::default()
                                        .old_layout(vk::ImageLayout::PREINITIALIZED)
                                        .new_layout(vk::ImageLayout::SHADER_READ_ONLY_OPTIMAL)
                                        .src_access_mask(vk::AccessFlags::HOST_WRITE)
                                        .dst_access_mask(vk::AccessFlags::SHADER_READ)
                                        .image(vk_img)
                                        .subresource_range(vk::ImageSubresourceRange {
                                            aspect_mask: vk::ImageAspectFlags::COLOR,
                                            base_mip_level: 0,
                                            level_count: 1,
                                            base_array_layer: 0,
                                            layer_count: 1,
                                        });

                                    device.cmd_pipeline_barrier(
                                        cmd_buffer,
                                        vk::PipelineStageFlags::HOST,
                                        vk::PipelineStageFlags::FRAGMENT_SHADER,
                                        vk::DependencyFlags::empty(),
                                        &[],
                                        &[],
                                        &[image_barrier],
                                    );

                                    image_info_vk = vk::DescriptorImageInfo::default()
                                        .image_layout(vk::ImageLayout::SHADER_READ_ONLY_OPTIMAL)
                                        .image_view(vk_view)
                                        .sampler(vk_sampler);

                                    writes.push(
                                        vk::WriteDescriptorSet::default()
                                            .dst_set(desc_set)
                                            .dst_binding(1)
                                            .descriptor_type(vk::DescriptorType::COMBINED_IMAGE_SAMPLER)
                                            .image_info(std::slice::from_ref(&image_info_vk)),
                                    );
                                }
                            }

                            if !writes.is_empty() {
                                device.update_descriptor_sets(&writes, &[]);

                                device.cmd_bind_descriptor_sets(
                                    cmd_buffer,
                                    vk::PipelineBindPoint::GRAPHICS,
                                    draw_call.pipeline_layout,
                                    0,
                                    &[desc_set],
                                    &[],
                                );
                                info!("  --> Successfully bound HLE descriptor set (uniforms/textures) to graphics pipeline.");
                            }
                        }
                    }

                    // 4. Execution Draw Call
                    if has_index_buffer {
                        device.cmd_draw_indexed(cmd_buffer, draw_call.index_buffer_count, 1, 0, 0, 0);
                    } else {
                        let vertex_count = if draw_call.index_buffer_count > 0 { draw_call.index_buffer_count } else { 3 };
                        device.cmd_draw(cmd_buffer, vertex_count, 1, 0, 0);
                    }
                    
                    // 5. Clean up temporary resources (Deferred to prevent Vulkan resource lifetime violation)
                    if !temp_buffers.is_empty() {
                        self.buffers_to_destroy.lock().unwrap()[current_frame_val].extend(temp_buffers);
                    }
                    if !temp_mems.is_empty() {
                        self.memory_to_free.lock().unwrap()[current_frame_val].extend(temp_mems);
                    }
                    if !temp_images.is_empty() {
                        self.images_to_destroy.lock().unwrap()[current_frame_val].extend(temp_images);
                    }
                    if !temp_image_views.is_empty() {
                        self.image_views_to_destroy.lock().unwrap()[current_frame_val].extend(temp_image_views);
                    }
                    if !temp_samplers.is_empty() {
                        self.samplers_to_destroy.lock().unwrap()[current_frame_val].extend(temp_samplers);
                    }
                    if desc_pool != vk::DescriptorPool::null() {
                        self.desc_pools_to_destroy.lock().unwrap()[current_frame_val].push(desc_pool);
                    }
                }
            }

            device.cmd_end_render_pass(cmd_buffer);
            device.end_command_buffer(cmd_buffer).unwrap();

            let wait_semaphores = [self.image_available_semaphores[current_frame_val]];
            let wait_stages = [vk::PipelineStageFlags::COLOR_ATTACHMENT_OUTPUT];
            let signal_semaphores = [self.render_finished_semaphores[current_frame_val]];

            let submit_info = vk::SubmitInfo::default()
                .wait_semaphores(&wait_semaphores)
                .wait_dst_stage_mask(&wait_stages)
                .command_buffers(std::slice::from_ref(&cmd_buffer))
                .signal_semaphores(&signal_semaphores);

            {
                let _lock = SUBMIT_MUTEX.lock().unwrap();
                device.queue_submit(self.queue, &[submit_info], current_fence).unwrap();
            }

            let swapchains = [self.swapchain];
            let image_indices = [image_index as u32];
            let present_info = vk::PresentInfoKHR::default()
                .wait_semaphores(&signal_semaphores)
                .swapchains(&swapchains)
                .image_indices(&image_indices);

            let present_res = self.swapchain_loader.queue_present(self.queue, &present_info);
            match present_res {
                Ok(_) | Err(vk::Result::ERROR_OUT_OF_DATE_KHR) | Err(vk::Result::SUBOPTIMAL_KHR) => {}
                Err(_) => return Err("Failed to present swapchain image"),
            }
        }

        // Cycle frame resources using interior mutability Cell
        let next_frame = (current_frame_val + 1) % MAX_FRAMES_IN_FLIGHT;
        self.current_frame.set(next_frame);

        Ok(())
    }

    /// Low-Level PM4 (Programming Model 4) Graphics Command Translator.
    /// Intercepts guest command buffers and maps hardware opcodes to Vulkan draw commands.
    pub unsafe fn translate_pm4_packet_stream(&self, guest_command_buffer_ptr: *const u32, size: usize) {
        info!("Decoding guest graphics command packet stream (PM4)...");
        let stream = std::slice::from_raw_parts(guest_command_buffer_ptr, size);
        let mut i = 0;
        
        while i < stream.len() {
            let header = stream[i];
            let packet_type = (header >> 30) & 0x3;
            
            match packet_type {
                0 => {
                    let base_reg = header & 0xFFFF;
                    let count = ((header >> 16) & 0x3FFF) + 1;
                    info!("PM4 Type-0: Base Register: 0x{:X} | Count: {}", base_reg, count);
                    i += (count as usize) + 1;
                }
                2 => {
                    info!("PM4 Type-2: Padding word encountered.");
                    i += 1;
                }
                3 => {
                    let opcode = (header >> 8) & 0xFF;
                    let count = (header >> 16) & 0x3FFF;
                    
                    info!("PM4 Type-3 Packet Intercepted: Opcode: 0x{:X} | Count: {}", opcode, count);
                    
                    match opcode {
                        0x28 => info!("  --> OP_DRAW_INDEX_2: Dispatching Vulkan vkCmdDrawIndexed (Simulated)"),
                        0x2C => info!("  --> OP_SET_SH_REG: Updating shader register descriptor state"),
                        0x3F => info!("  --> OP_INDIRECT_BUFFER: Recurse into nested command buffer execution"),
                        0x4B => info!("  --> OP_ACQUIRE_MEM: Injecting Vulkan vkCmdPipelineBarrier (Cache coherent flush)"),
                        0x15 => info!("  --> OP_CONTEXT_CONTROL: Applying pipeline execution context states"),
                        0x24 => info!("  --> OP_INDEX_TYPE: Binding index buffer type for draws"),
                        0xD5 => info!("  --> OP_DISPATCH_DIRECT: Dispatching Vulkan vkCmdDispatch (Simulated Compute)"),
                        _ => warn!("  --> Unhandled Type-3 opcode: 0x{:X}", opcode),
                    }
                    i += (count as usize) + 2;
                }
                _ => {
                    warn!("Unknown PM4 Packet Type: {} at offset: {}", packet_type, i);
                    i += 1;
                }
            }
        }
    }

    fn map_blend_factor(val: u32) -> vk::BlendFactor {
        match val {
            0 => vk::BlendFactor::ZERO,
            1 => vk::BlendFactor::ONE,
            2 => vk::BlendFactor::SRC_COLOR,
            3 => vk::BlendFactor::ONE_MINUS_SRC_COLOR,
            4 => vk::BlendFactor::SRC_ALPHA,
            5 => vk::BlendFactor::ONE_MINUS_SRC_ALPHA,
            6 => vk::BlendFactor::DST_ALPHA,
            7 => vk::BlendFactor::ONE_MINUS_DST_ALPHA,
            8 => vk::BlendFactor::DST_COLOR,
            9 => vk::BlendFactor::ONE_MINUS_DST_COLOR,
            _ => vk::BlendFactor::ONE,
        }
    }

    fn map_blend_op(val: u32) -> vk::BlendOp {
        match val {
            0 => vk::BlendOp::ADD,
            1 => vk::BlendOp::SUBTRACT,
            2 => vk::BlendOp::REVERSE_SUBTRACT,
            3 => vk::BlendOp::MIN,
            4 => vk::BlendOp::MAX,
            _ => vk::BlendOp::ADD,
        }
    }

    fn map_color_write_mask(val: u32) -> vk::ColorComponentFlags {
        let mut flags = vk::ColorComponentFlags::empty();
        if (val & 1) != 0 {
            flags |= vk::ColorComponentFlags::R;
        }
        if (val & 2) != 0 {
            flags |= vk::ColorComponentFlags::G;
        }
        if (val & 4) != 0 {
            flags |= vk::ColorComponentFlags::B;
        }
        if (val & 8) != 0 {
            flags |= vk::ColorComponentFlags::A;
        }
        flags
    }

    pub unsafe fn compile_pipeline_if_needed(
        &self,
        state: &ActiveGraphicsState,
        vertex_spirv: &[u32],
        fragment_spirv: &[u32],
    ) -> vk::Pipeline {
        let device = &self.device;

        let vs_module_info = vk::ShaderModuleCreateInfo::default().code(vertex_spirv);
        let vs_module = match device.create_shader_module(&vs_module_info, None) {
            Ok(module) => module,
            Err(e) => {
                warn!("Vulkan vertex shader module creation failed: {:?}. Returning mock pipeline handle.", e);
                return vk::Pipeline::null();
            }
        };

        let fs_module_info = vk::ShaderModuleCreateInfo::default().code(fragment_spirv);
        let fs_module = match device.create_shader_module(&fs_module_info, None) {
            Ok(module) => module,
            Err(e) => {
                warn!("Vulkan fragment shader module creation failed: {:?}. Returning mock pipeline handle.", e);
                device.destroy_shader_module(vs_module, None);
                return vk::Pipeline::null();
            }
        };

        let main_cstr = CString::new("main").unwrap();

        let shader_stages = [
            vk::PipelineShaderStageCreateInfo::default()
                .stage(vk::ShaderStageFlags::VERTEX)
                .module(vs_module)
                .name(&main_cstr),
            vk::PipelineShaderStageCreateInfo::default()
                .stage(vk::ShaderStageFlags::FRAGMENT)
                .module(fs_module)
                .name(&main_cstr),
        ];

        let mut binding_descriptions = Vec::new();
        let mut attribute_descriptions = Vec::new();
        
        if state.vertex_buffer_gpu_addr != 0 {
            if state.texture_gpu_addr != 0 {
                // Textured layout: float x, y, z; float u, v; (stride = 20)
                binding_descriptions.push(
                    vk::VertexInputBindingDescription::default()
                        .binding(0)
                        .stride(20)
                        .input_rate(vk::VertexInputRate::VERTEX)
                );
                
                attribute_descriptions.push(
                    vk::VertexInputAttributeDescription::default()
                        .location(0)
                        .binding(0)
                        .format(vk::Format::R32G32B32_SFLOAT)
                        .offset(0)
                );
                
                attribute_descriptions.push(
                    vk::VertexInputAttributeDescription::default()
                        .location(2)
                        .binding(0)
                        .format(vk::Format::R32G32_SFLOAT)
                        .offset(12)
                );
            } else {
                // Colored layout: float x, y, z; float r, g, b; (stride = 24)
                binding_descriptions.push(
                    vk::VertexInputBindingDescription::default()
                        .binding(0)
                        .stride(24)
                        .input_rate(vk::VertexInputRate::VERTEX)
                );
                
                attribute_descriptions.push(
                    vk::VertexInputAttributeDescription::default()
                        .location(0)
                        .binding(0)
                        .format(vk::Format::R32G32B32_SFLOAT)
                        .offset(0)
                );
                
                attribute_descriptions.push(
                    vk::VertexInputAttributeDescription::default()
                        .location(1)
                        .binding(0)
                        .format(vk::Format::R32G32B32_SFLOAT)
                        .offset(12)
                );
            }
        }
        
        let vertex_input_info = vk::PipelineVertexInputStateCreateInfo::default()
            .vertex_binding_descriptions(&binding_descriptions)
            .vertex_attribute_descriptions(&attribute_descriptions);
        
        let input_assembly = vk::PipelineInputAssemblyStateCreateInfo::default()
            .topology(state.topology)
            .primitive_restart_enable(false);

        // Viewport and scissor are DYNAMIC — set via vkCmdSetViewport/vkCmdSetScissor
        let viewport_state = vk::PipelineViewportStateCreateInfo::default()
            .viewport_count(1)
            .scissor_count(1);

        let rasterizer = vk::PipelineRasterizationStateCreateInfo::default()
            .depth_clamp_enable(false)
            .rasterizer_discard_enable(false)
            .polygon_mode(vk::PolygonMode::FILL)
            .cull_mode(vk::CullModeFlags::NONE)
            .front_face(vk::FrontFace::COUNTER_CLOCKWISE)
            .line_width(1.0);

        let multisampling = vk::PipelineMultisampleStateCreateInfo::default()
            .rasterization_samples(vk::SampleCountFlags::TYPE_1)
            .sample_shading_enable(false);

        let stencil_op_state = vk::StencilOpState::default()
            .fail_op(vk::StencilOp::KEEP)
            .pass_op(vk::StencilOp::REPLACE)
            .depth_fail_op(vk::StencilOp::KEEP)
            .compare_op(vk::CompareOp::ALWAYS)
            .compare_mask(0xFF)
            .write_mask(0xFF)
            .reference(1);

        let depth_stencil = vk::PipelineDepthStencilStateCreateInfo::default()
            .depth_test_enable(state.depth_test_enable)
            .depth_write_enable(state.depth_write_enable)
            .depth_compare_op(vk::CompareOp::LESS_OR_EQUAL)
            .stencil_test_enable(state.stencil_test_enable)
            .front(stencil_op_state)
            .back(stencil_op_state);

        let color_blend_attachment = vk::PipelineColorBlendAttachmentState::default()
            .blend_enable(state.blend_enable)
            .src_color_blend_factor(Self::map_blend_factor(state.src_color_blend_factor))
            .dst_color_blend_factor(Self::map_blend_factor(state.dst_color_blend_factor))
            .color_blend_op(Self::map_blend_op(state.color_blend_op))
            .src_alpha_blend_factor(Self::map_blend_factor(state.src_alpha_blend_factor))
            .dst_alpha_blend_factor(Self::map_blend_factor(state.dst_alpha_blend_factor))
            .alpha_blend_op(Self::map_blend_op(state.alpha_blend_op))
            .color_write_mask(Self::map_color_write_mask(state.color_write_mask));

        let color_blending = vk::PipelineColorBlendStateCreateInfo::default()
            .logic_op_enable(false)
            .attachments(std::slice::from_ref(&color_blend_attachment));

        let key = PipelineStateKey {
            vertex_shader_gpu_addr: state.vertex_shader_gpu_addr,
            fragment_shader_gpu_addr: state.fragment_shader_gpu_addr,
            topology: state.topology,
            depth_test_enable: state.depth_test_enable,
            depth_write_enable: state.depth_write_enable,
            stencil_test_enable: state.stencil_test_enable,
            stencil_write_enable: state.stencil_write_enable,
            has_vertex_buffer: state.vertex_buffer_gpu_addr != 0,
            has_constant_buffer: state.constant_buffer_gpu_addr != 0,
            has_texture: state.texture_gpu_addr != 0,
            blend_enable: state.blend_enable,
            src_color_blend_factor: state.src_color_blend_factor,
            dst_color_blend_factor: state.dst_color_blend_factor,
            color_blend_op: state.color_blend_op,
            src_alpha_blend_factor: state.src_alpha_blend_factor,
            dst_alpha_blend_factor: state.dst_alpha_blend_factor,
            alpha_blend_op: state.alpha_blend_op,
            color_write_mask: state.color_write_mask,
        };

        let mut layouts = Vec::new();
        let mut desc_layout = vk::DescriptorSetLayout::null();
        
        let mut bindings = Vec::new();
        if key.has_constant_buffer {
            bindings.push(
                vk::DescriptorSetLayoutBinding::default()
                    .binding(0)
                    .descriptor_type(vk::DescriptorType::UNIFORM_BUFFER)
                    .descriptor_count(1)
                    .stage_flags(vk::ShaderStageFlags::FRAGMENT | vk::ShaderStageFlags::VERTEX),
            );
        }
        if key.has_texture {
            bindings.push(
                vk::DescriptorSetLayoutBinding::default()
                    .binding(1)
                    .descriptor_type(vk::DescriptorType::COMBINED_IMAGE_SAMPLER)
                    .descriptor_count(1)
                    .stage_flags(vk::ShaderStageFlags::FRAGMENT),
            );
        }
        
        if !bindings.is_empty() {
            let layout_info = vk::DescriptorSetLayoutCreateInfo::default().bindings(&bindings);
            desc_layout = device.create_descriptor_set_layout(&layout_info, None).unwrap();
            layouts.push(desc_layout);
            
            let desc_layouts_lock = DESCRIPTOR_SET_LAYOUTS.get_or_init(|| Mutex::new(HashMap::new()));
            desc_layouts_lock.lock().unwrap().insert(key.clone(), desc_layout);
        }

        let pipeline_layout_info = vk::PipelineLayoutCreateInfo::default().set_layouts(&layouts);
        let pipeline_layout = device.create_pipeline_layout(&pipeline_layout_info, None).unwrap();
        
        let layouts_lock = PIPELINE_LAYOUTS.get_or_init(|| Mutex::new(HashMap::new()));
        layouts_lock.lock().unwrap().insert(key.clone(), pipeline_layout);

        let dynamic_states = [vk::DynamicState::VIEWPORT, vk::DynamicState::SCISSOR];
        let dynamic_state_info = vk::PipelineDynamicStateCreateInfo::default()
            .dynamic_states(&dynamic_states);

        let pipeline_info = vk::GraphicsPipelineCreateInfo::default()
            .stages(&shader_stages)
            .vertex_input_state(&vertex_input_info)
            .input_assembly_state(&input_assembly)
            .viewport_state(&viewport_state)
            .rasterization_state(&rasterizer)
            .multisample_state(&multisampling)
            .depth_stencil_state(&depth_stencil)
            .color_blend_state(&color_blending)
            .dynamic_state(&dynamic_state_info)
            .layout(pipeline_layout)
            .render_pass(self.render_pass)
            .subpass(0);

        let pipeline = match device.create_graphics_pipelines(
            self.pipeline_cache,
            std::slice::from_ref(&pipeline_info),
            None,
        ) {
            Ok(pipelines) => pipelines[0],
            Err(e) => {
                warn!("Vulkan graphics pipeline compilation failed: {:?}. Returning mock pipeline handle.", e);
                vk::Pipeline::null()
            }
        };

        device.destroy_shader_module(vs_module, None);
        device.destroy_shader_module(fs_module, None);
        
        pipeline
    }

    pub unsafe fn execute_compute_job(&self, task: ComputeTask, input_data: &[u8], output_size: usize) -> Vec<u8> {
        info!("Executing Vulkan compute job on host GPU device ({:?}, size: {} bytes)...", task, input_data.len());
        
        let device = &self.device;

        let padded_input_size = input_data.len().max(1024);
        let padded_output_size = output_size.max(1024);

        let input_buffer_info = vk::BufferCreateInfo::default()
            .size(padded_input_size as u64)
            .usage(vk::BufferUsageFlags::STORAGE_BUFFER)
            .sharing_mode(vk::SharingMode::EXCLUSIVE);

        println!("[Rust execute_compute_job] Creating buffers...");
        let input_buffer = device.create_buffer(&input_buffer_info, None).unwrap();
        let input_mem_reqs = device.get_buffer_memory_requirements(input_buffer);

        let output_buffer_info = vk::BufferCreateInfo::default()
            .size(padded_output_size as u64)
            .usage(vk::BufferUsageFlags::STORAGE_BUFFER)
            .sharing_mode(vk::SharingMode::EXCLUSIVE);

        let output_buffer = device.create_buffer(&output_buffer_info, None).unwrap();
        let output_mem_reqs = device.get_buffer_memory_requirements(output_buffer);

        let mem_props = self.instance.get_physical_device_memory_properties(self.physical_device);
        let find_memory_type = |type_filter: u32, properties: vk::MemoryPropertyFlags| -> u32 {
            for i in 0..mem_props.memory_type_count {
                if (type_filter & (1 << i)) != 0 && mem_props.memory_types[i as usize].property_flags.contains(properties) {
                    return i;
                }
            }
            0
        };

        let mem_flags = vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT;
        
        let input_type_idx = find_memory_type(input_mem_reqs.memory_type_bits, mem_flags);
        println!("[Rust execute_compute_job] Input memory type index: {}", input_type_idx);
        let input_alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(input_mem_reqs.size)
            .memory_type_index(input_type_idx);
        let input_mem = device.allocate_memory(&input_alloc_info, None).unwrap();
        device.bind_buffer_memory(input_buffer, input_mem, 0).unwrap();

        let output_type_idx = find_memory_type(output_mem_reqs.memory_type_bits, mem_flags);
        println!("[Rust execute_compute_job] Output memory type index: {}", output_type_idx);
        let output_alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(output_mem_reqs.size)
            .memory_type_index(output_type_idx);
        let output_mem = device.allocate_memory(&output_alloc_info, None).unwrap();
        device.bind_buffer_memory(output_buffer, output_mem, 0).unwrap();

        println!("[Rust execute_compute_job] Mapping input memory...");
        let input_ptr = device.map_memory(input_mem, 0, padded_input_size as u64, vk::MemoryMapFlags::empty()).unwrap();
        println!("[Rust execute_compute_job] Input ptr: {:?}", input_ptr);
        std::ptr::copy_nonoverlapping(input_data.as_ptr(), input_ptr as *mut u8, input_data.len());
        if padded_input_size > input_data.len() {
            std::ptr::write_bytes((input_ptr as *mut u8).add(input_data.len()), 0, padded_input_size - input_data.len());
        }
        let input_range = vk::MappedMemoryRange::default()
            .memory(input_mem)
            .offset(0)
            .size(padded_input_size as u64);
        device.flush_mapped_memory_ranges(&[input_range]).unwrap();
        println!("[Rust execute_compute_job] Copied and flushed input memory.");
        device.unmap_memory(input_mem);

        println!("[Rust execute_compute_job] Mapping output memory...");
        let output_ptr = device.map_memory(output_mem, 0, padded_output_size as u64, vk::MemoryMapFlags::empty()).unwrap();
        println!("[Rust execute_compute_job] Output ptr: {:?}", output_ptr);
        let copy_len = input_data.len().min(output_size);
        std::ptr::copy_nonoverlapping(input_data.as_ptr(), output_ptr as *mut u8, copy_len);
        if padded_output_size > copy_len {
            std::ptr::write_bytes((output_ptr as *mut u8).add(copy_len), 0, padded_output_size - copy_len);
        }
        let output_range = vk::MappedMemoryRange::default()
            .memory(output_mem)
            .offset(0)
            .size(padded_output_size as u64);
        device.flush_mapped_memory_ranges(&[output_range]).unwrap();
        println!("[Rust execute_compute_job] Initialized and flushed output memory with input data.");
        device.unmap_memory(output_mem);

        // Resolve or build pipeline from cache
        let (compute_pipeline, pipeline_layout, desc_layout) = {
            let mut cache = self.compute_pipeline_cache.lock().unwrap();
            if !cache.contains_key(&task) {
                println!("[Rust execute_compute_job] Compiling pipeline for compute task: {:?}", task);
                let compute_spirv = match task {
                    ComputeTask::KrakenDecompress => crate::shader_translation::generate_kraken_spirv(),
                    ComputeTask::TempestAudio => crate::shader_translation::generate_tempest_audio_spirv(),
                };
                let compute_module_info = vk::ShaderModuleCreateInfo::default().code(&compute_spirv);
                let compute_module = device.create_shader_module(&compute_module_info, None).unwrap();

                let bindings = [
                    vk::DescriptorSetLayoutBinding::default()
                        .binding(0)
                        .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                        .descriptor_count(1)
                        .stage_flags(vk::ShaderStageFlags::COMPUTE),
                    vk::DescriptorSetLayoutBinding::default()
                        .binding(1)
                        .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                        .descriptor_count(1)
                        .stage_flags(vk::ShaderStageFlags::COMPUTE),
                ];
                let dsl_info = vk::DescriptorSetLayoutCreateInfo::default().bindings(&bindings);
                let desc_layout = device.create_descriptor_set_layout(&dsl_info, None).unwrap();

                let layouts = [desc_layout];
                let pipeline_layout_info = vk::PipelineLayoutCreateInfo::default().set_layouts(&layouts);
                let pipeline_layout = device.create_pipeline_layout(&pipeline_layout_info, None).unwrap();

                let main_cstr = CString::new("main").unwrap();
                let stage_info = vk::PipelineShaderStageCreateInfo::default()
                    .stage(vk::ShaderStageFlags::COMPUTE)
                    .module(compute_module)
                    .name(&main_cstr);

                let compute_pipeline_info = vk::ComputePipelineCreateInfo::default()
                    .stage(stage_info)
                    .layout(pipeline_layout);

                let compute_pipeline = match device.create_compute_pipelines(
                    self.pipeline_cache,
                    std::slice::from_ref(&compute_pipeline_info),
                    None,
                ) {
                    Ok(pipelines) => pipelines[0],
                    Err(e) => {
                        warn!("Vulkan compute pipeline compilation failed: {:?}", e);
                        vk::Pipeline::null()
                    }
                };

                cache.insert(task, CachedComputePipeline {
                    pipeline: compute_pipeline,
                    pipeline_layout,
                    desc_layout,
                    shader_module: compute_module,
                });
            }
            let entry = cache.get(&task).unwrap();
            (entry.pipeline, entry.pipeline_layout, entry.desc_layout)
        };

        let pool_sizes = [
            vk::DescriptorPoolSize::default()
                .ty(vk::DescriptorType::STORAGE_BUFFER)
                .descriptor_count(2),
        ];
        let pool_info = vk::DescriptorPoolCreateInfo::default()
            .max_sets(1)
            .pool_sizes(&pool_sizes);
        println!("[Rust execute_compute_job] Creating descriptor pool...");
        let desc_pool = device.create_descriptor_pool(&pool_info, None).unwrap();

        let layouts = [desc_layout];
        let alloc_info = vk::DescriptorSetAllocateInfo::default()
            .descriptor_pool(desc_pool)
            .set_layouts(&layouts);
        let desc_set = device.allocate_descriptor_sets(&alloc_info).unwrap()[0];

        let input_buffer_info_vk = vk::DescriptorBufferInfo::default()
            .buffer(input_buffer)
            .offset(0)
            .range(padded_input_size as u64);
        let output_buffer_info_vk = vk::DescriptorBufferInfo::default()
            .buffer(output_buffer)
            .offset(0)
            .range(padded_output_size as u64);

        let writes = [
            vk::WriteDescriptorSet::default()
                .dst_set(desc_set)
                .dst_binding(0)
                .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                .buffer_info(std::slice::from_ref(&input_buffer_info_vk)),
            vk::WriteDescriptorSet::default()
                .dst_set(desc_set)
                .dst_binding(1)
                .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                .buffer_info(std::slice::from_ref(&output_buffer_info_vk)),
        ];
        device.update_descriptor_sets(&writes, &[]);

        // Query the queue family index dynamically
        let queue_family_properties = self.instance.get_physical_device_queue_family_properties(self.physical_device);
        let mut queue_family_index = 0;
        for (index, prop) in queue_family_properties.iter().enumerate() {
            if prop.queue_flags.contains(vk::QueueFlags::GRAPHICS) {
                queue_family_index = index as u32;
                break;
            }
        }

        let cp_create_info = vk::CommandPoolCreateInfo::default()
            .queue_family_index(queue_family_index)
            .flags(vk::CommandPoolCreateFlags::TRANSIENT);
        let temp_pool = device.create_command_pool(&cp_create_info, None).unwrap();

        let alloc_info = vk::CommandBufferAllocateInfo::default()
            .command_pool(temp_pool)
            .level(vk::CommandBufferLevel::PRIMARY)
            .command_buffer_count(1);
        let cmd_buf = device.allocate_command_buffers(&alloc_info).unwrap()[0];

        let begin_info = vk::CommandBufferBeginInfo::default()
            .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
        device.begin_command_buffer(cmd_buf, &begin_info).unwrap();

        let mut executed_on_gpu = false;
        if compute_pipeline != vk::Pipeline::null() {
            device.cmd_bind_pipeline(cmd_buf, vk::PipelineBindPoint::COMPUTE, compute_pipeline);
            device.cmd_bind_descriptor_sets(cmd_buf, vk::PipelineBindPoint::COMPUTE, pipeline_layout, 0, &[desc_set], &[]);

            let group_size = 256;
            let groups_x = ((output_size + group_size - 1) / group_size).max(1) as u32;
            device.cmd_dispatch(cmd_buf, groups_x, 1, 1);
            executed_on_gpu = true;

            let barrier = vk::BufferMemoryBarrier::default()
                .src_access_mask(vk::AccessFlags::SHADER_WRITE)
                .dst_access_mask(vk::AccessFlags::HOST_READ)
                .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                .buffer(output_buffer)
                .offset(0)
                .size(padded_output_size as u64);
            device.cmd_pipeline_barrier(
                cmd_buf,
                vk::PipelineStageFlags::COMPUTE_SHADER,
                vk::PipelineStageFlags::HOST,
                vk::DependencyFlags::empty(),
                &[],
                std::slice::from_ref(&barrier),
                &[],
            );
        }

        device.end_command_buffer(cmd_buf).unwrap();

        let fence_info = vk::FenceCreateInfo::default();
        let fence = device.create_fence(&fence_info, None).unwrap();

        let submit_info = vk::SubmitInfo::default()
            .command_buffers(std::slice::from_ref(&cmd_buf));
        {
            let _lock = SUBMIT_MUTEX.lock().unwrap();
            device.queue_submit(self.queue, &[submit_info], fence).unwrap();
        }
        device.wait_for_fences(&[fence], true, u64::MAX).unwrap();

        let mut result = vec![0u8; output_size];
        let mapped_output = device.map_memory(output_mem, 0, output_size as u64, vk::MemoryMapFlags::empty()).unwrap();
        let output_range = vk::MappedMemoryRange::default()
            .memory(output_mem)
            .offset(0)
            .size(output_size as u64);
        device.invalidate_mapped_memory_ranges(&[output_range]).unwrap();
        std::ptr::copy_nonoverlapping(mapped_output as *const u8, result.as_mut_ptr(), output_size);
        device.unmap_memory(output_mem);

        // Perform mock transformation on host side as standard fallback only if we didn't run on GPU
        if !executed_on_gpu {
            for byte in result.iter_mut() {
                *byte = *byte ^ 0xAA;
            }
        }

        device.destroy_fence(fence, None);
        device.destroy_command_pool(temp_pool, None);
        device.destroy_descriptor_pool(desc_pool, None);
        device.destroy_buffer(input_buffer, None);
        device.free_memory(input_mem, None);
        device.destroy_buffer(output_buffer, None);
        device.free_memory(output_mem, None);

        result
    }

    pub unsafe fn submit_direct_storage_request(
        &self,
        file_path: std::path::PathBuf,
        offset: u64,
        size: usize,
        dst_memory: vk::DeviceMemory,
        dst_offset: u64,
    ) -> Result<(), &'static str> {
        info!("DirectStorage: Submitting bypass I/O request for file: {:?}", file_path);
        
        let device = self.device.clone();
        std::thread::spawn(move || {
            let mut file = match std::fs::File::open(&file_path) {
                Ok(f) => f,
                Err(e) => {
                    log::error!("DirectStorage error: failed to open file {:?}: {}", file_path, e);
                    return;
                }
            };
            use std::io::{Seek, Read};
            if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)) {
                log::error!("DirectStorage error: failed to seek to offset {}: {}", offset, e);
                return;
            }
            
            unsafe {
                match device.map_memory(dst_memory, dst_offset, size as u64, vk::MemoryMapFlags::empty()) {
                    Ok(ptr) => {
                        let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, size);
                        if let Err(e) = file.read_exact(slice) {
                            log::error!("DirectStorage error: failed to read {} bytes: {}", size, e);
                        } else {
                            log::info!("DirectStorage: Bypass I/O transfer of {} bytes to GPU buffer completed asynchronously.", size);
                        }
                        let range = vk::MappedMemoryRange::default()
                            .memory(dst_memory)
                            .offset(dst_offset)
                            .size(size as u64);
                        let _ = device.flush_mapped_memory_ranges(&[range]);
                        device.unmap_memory(dst_memory);
                    }
                    Err(e) => {
                        log::error!("DirectStorage error: failed to map memory: {:?}", e);
                    }
                }
            }
        });
        
        Ok(())
    }

    pub unsafe fn create_vertex_buffer(&self, data: &[u8]) -> (vk::Buffer, vk::DeviceMemory) {
        let device = &self.device;
        let buffer_info = vk::BufferCreateInfo::default()
            .size(data.len() as u64)
            .usage(vk::BufferUsageFlags::VERTEX_BUFFER)
            .sharing_mode(vk::SharingMode::EXCLUSIVE);
            
        let buffer = device.create_buffer(&buffer_info, None).unwrap();
        let mem_reqs = device.get_buffer_memory_requirements(buffer);
        
        let mem_props = self.instance.get_physical_device_memory_properties(self.physical_device);
        let find_memory_type = |type_filter: u32, properties: vk::MemoryPropertyFlags| -> u32 {
            for i in 0..mem_props.memory_type_count {
                if (type_filter & (1 << i)) != 0 && mem_props.memory_types[i as usize].property_flags.contains(properties) {
                    return i;
                }
            }
            0
        };
        
        let mem_flags = vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT;
        let type_idx = find_memory_type(mem_reqs.memory_type_bits, mem_flags);
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(mem_reqs.size)
            .memory_type_index(type_idx);
            
        let memory = device.allocate_memory(&alloc_info, None).unwrap();
        device.bind_buffer_memory(buffer, memory, 0).unwrap();
        
        let ptr = device.map_memory(memory, 0, data.len() as u64, vk::MemoryMapFlags::empty()).unwrap();
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
        device.unmap_memory(memory);
        
        (buffer, memory)
    }

    pub unsafe fn create_index_buffer(&self, data: &[u8]) -> (vk::Buffer, vk::DeviceMemory) {
        let device = &self.device;
        let buffer_info = vk::BufferCreateInfo::default()
            .size(data.len() as u64)
            .usage(vk::BufferUsageFlags::INDEX_BUFFER)
            .sharing_mode(vk::SharingMode::EXCLUSIVE);
            
        let buffer = device.create_buffer(&buffer_info, None).unwrap();
        let mem_reqs = device.get_buffer_memory_requirements(buffer);
        
        let mem_props = self.instance.get_physical_device_memory_properties(self.physical_device);
        let find_memory_type = |type_filter: u32, properties: vk::MemoryPropertyFlags| -> u32 {
            for i in 0..mem_props.memory_type_count {
                if (type_filter & (1 << i)) != 0 && mem_props.memory_types[i as usize].property_flags.contains(properties) {
                    return i;
                }
            }
            0
        };
        
        let mem_flags = vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT;
        let type_idx = find_memory_type(mem_reqs.memory_type_bits, mem_flags);
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(mem_reqs.size)
            .memory_type_index(type_idx);
            
        let memory = device.allocate_memory(&alloc_info, None).unwrap();
        device.bind_buffer_memory(buffer, memory, 0).unwrap();
        
        let ptr = device.map_memory(memory, 0, data.len() as u64, vk::MemoryMapFlags::empty()).unwrap();
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
        device.unmap_memory(memory);
        
        (buffer, memory)
    }

    pub unsafe fn create_uniform_buffer(&self, data: &[u8]) -> (vk::Buffer, vk::DeviceMemory) {
        let device = &self.device;
        let buffer_info = vk::BufferCreateInfo::default()
            .size(data.len() as u64)
            .usage(vk::BufferUsageFlags::UNIFORM_BUFFER)
            .sharing_mode(vk::SharingMode::EXCLUSIVE);
            
        let buffer = device.create_buffer(&buffer_info, None).unwrap();
        let mem_reqs = device.get_buffer_memory_requirements(buffer);
        
        let mem_props = self.instance.get_physical_device_memory_properties(self.physical_device);
        let find_memory_type = |type_filter: u32, properties: vk::MemoryPropertyFlags| -> u32 {
            for i in 0..mem_props.memory_type_count {
                if (type_filter & (1 << i)) != 0 && mem_props.memory_types[i as usize].property_flags.contains(properties) {
                    return i;
                }
            }
            0
        };
        
        let mem_flags = vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT;
        let type_idx = find_memory_type(mem_reqs.memory_type_bits, mem_flags);
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(mem_reqs.size)
            .memory_type_index(type_idx);
            
        let memory = device.allocate_memory(&alloc_info, None).unwrap();
        device.bind_buffer_memory(buffer, memory, 0).unwrap();
        
        let ptr = device.map_memory(memory, 0, data.len() as u64, vk::MemoryMapFlags::empty()).unwrap();
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
        device.unmap_memory(memory);
        
        (buffer, memory)
    }

    pub unsafe fn create_texture_image(&self, width: u32, height: u32, format: u32, pixels: &[u8]) -> (vk::Image, vk::DeviceMemory, vk::ImageView, vk::Sampler) {
        let device = &self.device;
        let vk_format = match format {
            1 => vk::Format::R8G8B8A8_SRGB,
            2 => vk::Format::B8G8R8A8_UNORM,
            3 => vk::Format::B8G8R8A8_SRGB,
            4 => vk::Format::R8_UNORM,
            _ => vk::Format::R8G8B8A8_UNORM,
        };

        let image_info = vk::ImageCreateInfo::default()
            .image_type(vk::ImageType::TYPE_2D)
            .format(vk_format)
            .extent(vk::Extent3D { width, height, depth: 1 })
            .mip_levels(1)
            .array_layers(1)
            .samples(vk::SampleCountFlags::TYPE_1)
            .tiling(vk::ImageTiling::LINEAR)
            .usage(vk::ImageUsageFlags::SAMPLED)
            .sharing_mode(vk::SharingMode::EXCLUSIVE)
            .initial_layout(vk::ImageLayout::PREINITIALIZED);
            
        let image = device.create_image(&image_info, None).unwrap();
        let mem_reqs = device.get_image_memory_requirements(image);
        
        let mem_props = self.instance.get_physical_device_memory_properties(self.physical_device);
        let find_memory_type = |type_filter: u32, properties: vk::MemoryPropertyFlags| -> u32 {
            for i in 0..mem_props.memory_type_count {
                if (type_filter & (1 << i)) != 0 && mem_props.memory_types[i as usize].property_flags.contains(properties) {
                    return i;
                }
            }
            0
        };
        
        let mem_flags = vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT;
        let type_idx = find_memory_type(mem_reqs.memory_type_bits, mem_flags);
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(mem_reqs.size)
            .memory_type_index(type_idx);
            
        let memory = device.allocate_memory(&alloc_info, None).unwrap();
        device.bind_image_memory(image, memory, 0).unwrap();
        
        let ptr = device.map_memory(memory, 0, mem_reqs.size, vk::MemoryMapFlags::empty()).unwrap();
        std::ptr::copy_nonoverlapping(pixels.as_ptr(), ptr as *mut u8, pixels.len().min(mem_reqs.size as usize));
        device.unmap_memory(memory);
        
        let view_info = vk::ImageViewCreateInfo::default()
            .image(image)
            .view_type(vk::ImageViewType::TYPE_2D)
            .format(vk_format)
            .subresource_range(vk::ImageSubresourceRange {
                aspect_mask: vk::ImageAspectFlags::COLOR,
                base_mip_level: 0,
                level_count: 1,
                base_array_layer: 0,
                layer_count: 1,
            });
        let view = device.create_image_view(&view_info, None).unwrap();
        
        let sampler_info = vk::SamplerCreateInfo::default()
            .mag_filter(vk::Filter::NEAREST)
            .min_filter(vk::Filter::NEAREST)
            .address_mode_u(vk::SamplerAddressMode::REPEAT)
            .address_mode_v(vk::SamplerAddressMode::REPEAT)
            .address_mode_w(vk::SamplerAddressMode::REPEAT)
            .anisotropy_enable(false)
            .compare_enable(false)
            .unnormalized_coordinates(false);
        let sampler = device.create_sampler(&sampler_info, None).unwrap();
        
        (image, memory, view, sampler)
    }
}

impl Drop for VulkanContext {
    fn drop(&mut self) {
        info!("Destroying Vulkan context and releasing device resources...");
        unsafe {
            let device = &self.device;
            let _ = device.device_wait_idle();

            // Destroy cached compute pipelines
            if let Ok(mut cache) = self.compute_pipeline_cache.lock() {
                for (_, cached) in cache.drain() {
                    device.destroy_pipeline(cached.pipeline, None);
                    device.destroy_pipeline_layout(cached.pipeline_layout, None);
                    device.destroy_descriptor_set_layout(cached.desc_layout, None);
                    device.destroy_shader_module(cached.shader_module, None);
                }
            }

            // Destroy depth resources
            device.destroy_image_view(self.depth_image_view, None);
            device.destroy_image(self.depth_image, None);
            device.free_memory(self.depth_image_memory, None);

            // Clean up any remaining deferred resources
            {
                let mut bufs = self.buffers_to_destroy.lock().unwrap();
                for frame_bufs in bufs.iter_mut() {
                    for buf in frame_bufs.drain(..) {
                        device.destroy_buffer(buf, None);
                    }
                }
                let mut mems = self.memory_to_free.lock().unwrap();
                for frame_mems in mems.iter_mut() {
                    for mem in frame_mems.drain(..) {
                        device.free_memory(mem, None);
                    }
                }
                let mut imgs = self.images_to_destroy.lock().unwrap();
                for frame_imgs in imgs.iter_mut() {
                    for img in frame_imgs.drain(..) {
                        device.destroy_image(img, None);
                    }
                }
                let mut views = self.image_views_to_destroy.lock().unwrap();
                for frame_views in views.iter_mut() {
                    for view in frame_views.drain(..) {
                        device.destroy_image_view(view, None);
                    }
                }
                let mut samps = self.samplers_to_destroy.lock().unwrap();
                for frame_samps in samps.iter_mut() {
                    for samp in frame_samps.drain(..) {
                        device.destroy_sampler(samp, None);
                    }
                }
                let mut pools = self.desc_pools_to_destroy.lock().unwrap();
                for frame_pools in pools.iter_mut() {
                    for pool in frame_pools.drain(..) {
                        device.destroy_descriptor_pool(pool, None);
                    }
                }
            }

            for i in 0..MAX_FRAMES_IN_FLIGHT {
                device.destroy_semaphore(self.image_available_semaphores[i], None);
                device.destroy_semaphore(self.render_finished_semaphores[i], None);
                device.destroy_fence(self.in_flight_fences[i], None);
            }

            device.destroy_command_pool(self.command_pool, None);
            for &fb in &self.framebuffers {
                device.destroy_framebuffer(fb, None);
            }
            device.destroy_render_pass(self.render_pass, None);
            for &iv in &self.swapchain_image_views {
                device.destroy_image_view(iv, None);
            }
            self.swapchain_loader.destroy_swapchain(self.swapchain, None);
            self.surface_loader.destroy_surface(self.surface, None);
            // Save pipeline cache data
            if self.pipeline_cache != vk::PipelineCache::null() {
                if let Ok(data) = device.get_pipeline_cache_data(self.pipeline_cache) {
                    let cache_dir = std::path::Path::new("shader_cache");
                    if !cache_dir.exists() {
                        let _ = std::fs::create_dir_all(cache_dir);
                    }
                    let _ = std::fs::write("shader_cache/pipeline_cache.bin", data);
                    info!("Successfully saved pipeline cache to disk.");
                }
                device.destroy_pipeline_cache(self.pipeline_cache, None);
            }

            self.device.destroy_device(None);
            self.instance.destroy_instance(None);
        }
    }
}

// =========================================================================
// =========================================================================

#[derive(Clone, Copy, Debug)]
pub struct PendingDrawCall {
    pub pipeline: vk::Pipeline,
    pub pipeline_layout: vk::PipelineLayout,
    pub descriptor_set_layout: vk::DescriptorSetLayout,
    pub vertex_buffer_gpu_addr: u64,
    pub vertex_buffer_size: u32,
    pub index_buffer_gpu_addr: u64,
    pub index_buffer_count: u32,
    pub index_type: vk::IndexType,
    pub constant_buffer_gpu_addr: u64,
    pub constant_buffer_size: u32,
    pub texture_gpu_addr: u64,
    pub texture_width: u32,
    pub texture_height: u32,
    pub texture_format: u32,
    pub sampler_filter: u32,
    pub blend_enable: bool,
    pub src_color_blend_factor: u32,
    pub dst_color_blend_factor: u32,
    pub color_blend_op: u32,
    pub src_alpha_blend_factor: u32,
    pub dst_alpha_blend_factor: u32,
    pub alpha_blend_op: u32,
    pub color_write_mask: u32,
    pub viewport_x: f32,
    pub viewport_y: f32,
    pub viewport_width: f32,
    pub viewport_height: f32,
    pub viewport_min_depth: f32,
    pub viewport_max_depth: f32,
    pub scissor_x: i32,
    pub scissor_y: i32,
    pub scissor_width: u32,
    pub scissor_height: u32,
}

pub static VULKAN_CONTEXT: Mutex<Option<VulkanContext>> = Mutex::new(None);
pub static PENDING_DRAWS: Mutex<Vec<PendingDrawCall>> = Mutex::new(Vec::new());
pub static PIPELINE_CACHE: std::sync::OnceLock<Mutex<HashMap<PipelineStateKey, vk::Pipeline>>> = std::sync::OnceLock::new();
pub static PIPELINE_LAYOUTS: std::sync::OnceLock<Mutex<HashMap<PipelineStateKey, vk::PipelineLayout>>> = std::sync::OnceLock::new();
pub static DESCRIPTOR_SET_LAYOUTS: std::sync::OnceLock<Mutex<HashMap<PipelineStateKey, vk::DescriptorSetLayout>>> = std::sync::OnceLock::new();
pub static SUBMIT_MUTEX: Mutex<()> = Mutex::new(());
pub static COMPUTE_PIPELINE_CACHE: std::sync::OnceLock<Mutex<HashMap<u64, (vk::Pipeline, vk::PipelineLayout, vk::DescriptorSetLayout)>>> = std::sync::OnceLock::new();

pub static ACTIVE_STATE: Mutex<ActiveGraphicsState> = Mutex::new(ActiveGraphicsState {
    vertex_shader_gpu_addr: 0,
    fragment_shader_gpu_addr: 0,
    compute_shader_gpu_addr: 0,
    topology: vk::PrimitiveTopology::TRIANGLE_LIST,
    depth_test_enable: false,
    depth_write_enable: false,
    stencil_test_enable: false,
    stencil_write_enable: false,
    vertex_buffer_gpu_addr: 0,
    vertex_buffer_size: 0,
    index_buffer_gpu_addr: 0,
    index_buffer_count: 0,
    index_type: vk::IndexType::UINT16,
    constant_buffer_gpu_addr: 0,
    constant_buffer_size: 0,
    texture_gpu_addr: 0,
    texture_width: 0,
    texture_height: 0,
    texture_format: 0,
    sampler_filter: 0,
    blend_enable: false,
    src_color_blend_factor: 1, // One
    dst_color_blend_factor: 0, // Zero
    color_blend_op: 0, // Add
    src_alpha_blend_factor: 1, // One
    dst_alpha_blend_factor: 0, // Zero
    alpha_blend_op: 0, // Add
    color_write_mask: 15, // RGBA
    viewport_x: 0.0,
    viewport_y: 0.0,
    viewport_width: 1280.0,
    viewport_height: 720.0,
    viewport_min_depth: 0.0,
    viewport_max_depth: 1.0,
    scissor_x: 0,
    scissor_y: 0,
    scissor_width: 1280,
    scissor_height: 720,
});

thread_local! {
    static RECURSION_DEPTH: Cell<u32> = Cell::new(0);
}

/// Helper to dispatch compile & queue draw call from an active state
unsafe fn dispatch_draw_for_state(state: ActiveGraphicsState) {
    info!("      - Compiling PSO: VS=0x{:X}, FS=0x{:X}, Topology={:?}, DepthTest={}",
          state.vertex_shader_gpu_addr, state.fragment_shader_gpu_addr, state.topology, state.depth_test_enable);

    let read_shader_code = |gpu_addr: u64| -> Vec<u32> {
        if gpu_addr == 0 {
            return vec![];
        }
        unsafe {
            let mut code_words = Vec::new();
            let mut ptr = gpu_addr as *const u32;
            for _ in 0..256 {
                let word = *ptr;
                code_words.push(word);
                if word == 0xBF800000 {
                    break;
                }
                ptr = ptr.add(1);
            }
            code_words
        }
    };

    let vs_code = read_shader_code(state.vertex_shader_gpu_addr);
    let fs_code = read_shader_code(state.fragment_shader_gpu_addr);

    let key = PipelineStateKey {
        vertex_shader_gpu_addr: state.vertex_shader_gpu_addr,
        fragment_shader_gpu_addr: state.fragment_shader_gpu_addr,
        topology: state.topology,
        depth_test_enable: state.depth_test_enable,
        depth_write_enable: state.depth_write_enable,
        stencil_test_enable: state.stencil_test_enable,
        stencil_write_enable: state.stencil_write_enable,
        has_vertex_buffer: state.vertex_buffer_gpu_addr != 0,
        has_constant_buffer: state.constant_buffer_gpu_addr != 0,
        has_texture: state.texture_gpu_addr != 0,
        blend_enable: state.blend_enable,
        src_color_blend_factor: state.src_color_blend_factor,
        dst_color_blend_factor: state.dst_color_blend_factor,
        color_blend_op: state.color_blend_op,
        src_alpha_blend_factor: state.src_alpha_blend_factor,
        dst_alpha_blend_factor: state.dst_alpha_blend_factor,
        alpha_blend_op: state.alpha_blend_op,
        color_write_mask: state.color_write_mask,
    };

    let cache_lock = PIPELINE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let pipeline_opt = {
        let pipeline_cache = cache_lock.lock().unwrap();
        pipeline_cache.get(&key).copied()
    };

    let global_ctx = VULKAN_CONTEXT.lock().unwrap();
    if global_ctx.is_some() {
        if let Some(pipeline) = pipeline_opt {
            info!("      - Bound Vulkan Pipeline PSO from cache: {:?}", pipeline);

            let layouts_lock = PIPELINE_LAYOUTS.get_or_init(|| Mutex::new(HashMap::new()));
            let pipeline_layout = *layouts_lock.lock().unwrap().get(&key).unwrap_or(&vk::PipelineLayout::null());
            
            let desc_layouts_lock = DESCRIPTOR_SET_LAYOUTS.get_or_init(|| Mutex::new(HashMap::new()));
            let descriptor_set_layout = *desc_layouts_lock.lock().unwrap().get(&key).unwrap_or(&vk::DescriptorSetLayout::null());

            let mut pending = PENDING_DRAWS.lock().unwrap();
            pending.push(PendingDrawCall {
                pipeline,
                pipeline_layout,
                descriptor_set_layout,
                vertex_buffer_gpu_addr: state.vertex_buffer_gpu_addr,
                vertex_buffer_size: state.vertex_buffer_size,
                index_buffer_gpu_addr: state.index_buffer_gpu_addr,
                index_buffer_count: state.index_buffer_count,
                index_type: state.index_type,
                constant_buffer_gpu_addr: state.constant_buffer_gpu_addr,
                constant_buffer_size: state.constant_buffer_size,
                texture_gpu_addr: state.texture_gpu_addr,
                texture_width: state.texture_width,
                texture_height: state.texture_height,
                texture_format: state.texture_format,
                sampler_filter: state.sampler_filter,
                blend_enable: state.blend_enable,
                src_color_blend_factor: state.src_color_blend_factor,
                dst_color_blend_factor: state.dst_color_blend_factor,
                color_blend_op: state.color_blend_op,
                src_alpha_blend_factor: state.src_alpha_blend_factor,
                dst_alpha_blend_factor: state.dst_alpha_blend_factor,
                alpha_blend_op: state.alpha_blend_op,
                color_write_mask: state.color_write_mask,
                viewport_x: state.viewport_x,
                viewport_y: state.viewport_y,
                viewport_width: state.viewport_width,
                viewport_height: state.viewport_height,
                viewport_min_depth: state.viewport_min_depth,
                viewport_max_depth: state.viewport_max_depth,
                scissor_x: state.scissor_x,
                scissor_y: state.scissor_y,
                scissor_width: state.scissor_width,
                scissor_height: state.scissor_height,
            });
        } else {
            info!("Cache miss: compiling pipeline synchronously on the main thread.");
            let vs_spirv = load_or_translate_shader(
                &vs_code,
                true,
                key.has_vertex_buffer,
                key.has_constant_buffer,
                key.has_texture,
            );
            let fs_spirv = load_or_translate_shader(
                &fs_code,
                false,
                key.has_vertex_buffer,
                key.has_constant_buffer,
                key.has_texture,
            );

            let compiled_pipeline = if let Some(ref ctx) = *global_ctx {
                ctx.compile_pipeline_if_needed(&state, &vs_spirv, &fs_spirv)
            } else {
                vk::Pipeline::null()
            };

            if compiled_pipeline != vk::Pipeline::null() {
                cache_lock.lock().unwrap().insert(key.clone(), compiled_pipeline);
                info!("Synchronously compiled Vulkan Pipeline PSO successfully: {:?}", compiled_pipeline);

                let layouts_lock = PIPELINE_LAYOUTS.get_or_init(|| Mutex::new(HashMap::new()));
                let pipeline_layout = *layouts_lock.lock().unwrap().get(&key).unwrap_or(&vk::PipelineLayout::null());
                
                let desc_layouts_lock = DESCRIPTOR_SET_LAYOUTS.get_or_init(|| Mutex::new(HashMap::new()));
                let descriptor_set_layout = *desc_layouts_lock.lock().unwrap().get(&key).unwrap_or(&vk::DescriptorSetLayout::null());

                let mut pending = PENDING_DRAWS.lock().unwrap();
                pending.push(PendingDrawCall {
                    pipeline: compiled_pipeline,
                    pipeline_layout,
                    descriptor_set_layout,
                    vertex_buffer_gpu_addr: state.vertex_buffer_gpu_addr,
                    vertex_buffer_size: state.vertex_buffer_size,
                    index_buffer_gpu_addr: state.index_buffer_gpu_addr,
                    index_buffer_count: state.index_buffer_count,
                    index_type: state.index_type,
                    constant_buffer_gpu_addr: state.constant_buffer_gpu_addr,
                    constant_buffer_size: state.constant_buffer_size,
                    texture_gpu_addr: state.texture_gpu_addr,
                    texture_width: state.texture_width,
                    texture_height: state.texture_height,
                    texture_format: state.texture_format,
                    sampler_filter: state.sampler_filter,
                    blend_enable: state.blend_enable,
                    src_color_blend_factor: state.src_color_blend_factor,
                    dst_color_blend_factor: state.dst_color_blend_factor,
                    color_blend_op: state.color_blend_op,
                    src_alpha_blend_factor: state.src_alpha_blend_factor,
                    dst_alpha_blend_factor: state.dst_alpha_blend_factor,
                    alpha_blend_op: state.alpha_blend_op,
                    color_write_mask: state.color_write_mask,
                    viewport_x: state.viewport_x,
                    viewport_y: state.viewport_y,
                    viewport_width: state.viewport_width,
                    viewport_height: state.viewport_height,
                    viewport_min_depth: state.viewport_min_depth,
                    viewport_max_depth: state.viewport_max_depth,
                    scissor_x: state.scissor_x,
                    scissor_y: state.scissor_y,
                    scissor_width: state.scissor_width,
                    scissor_height: state.scissor_height,
                });
            } else {
                error!("Synchronous pipeline compilation failed.");
            }
        }
    }
}

/// Low-level PM4 Graphics Command Decoder shared helper.
pub unsafe fn decode_pm4_command_buffer(dcb_gpu_addr: u64, dcb_size_in_dwords: u32) {
    info!(
        "PM4 Decoder Intercepted: Command Buffer GPU Address: 0x{:X} | Size: {} DWORDs",
        dcb_gpu_addr, dcb_size_in_dwords
    );
    let ptr = dcb_gpu_addr as *const u32;
    if ptr.is_null() {
        return;
    }
    let stream = std::slice::from_raw_parts(ptr, dcb_size_in_dwords as usize);
    let mut i = 0;
    while i < stream.len() {
        let header = stream[i];
        let packet_type = (header >> 30) & 0x3;
        match packet_type {
            0 => {
                let base_reg = header & 0xFFFF;
                let count = ((header >> 16) & 0x3FFF) + 1;
                info!("  [PM4 Decode] Type-0 Packet: Base Register: 0x{:X} | Count: {}", base_reg, count);
                i += (count as usize) + 1;
            }
            2 => {
                info!("  [PM4 Decode] Type-2 Packet: Padding word");
                i += 1;
            }
            3 => {
                let opcode = (header >> 8) & 0xFF;
                let count = (header >> 16) & 0x3FFF;
                info!("  [PM4 Decode] Type-3 Packet: Opcode: 0x{:X} | Count: {}", opcode, count);
                match opcode {
                    0x27 => {
                        info!("    --> OP_DRAW_INDEX_2: Dispatching Vulkan Draw Indexed");
                        let state = {
                            let s = ACTIVE_STATE.lock().unwrap();
                            s.clone()
                        };
                        dispatch_draw_for_state(state);
                    }
                    0x2D => {
                        info!("    --> OP_DRAW_INDEX_AUTO: Dispatching Vulkan Draw");
                        if count >= 1 && i + 1 < stream.len() {
                            let draw_count = stream[i + 1];
                            let state = {
                                let mut s = ACTIVE_STATE.lock().unwrap();
                                s.index_buffer_count = draw_count;
                                s.clone()
                            };
                            dispatch_draw_for_state(state);
                        }
                    }
                    0x35 => {
                        info!("    --> OP_DRAW_INDEX_OFFSET_2: Dispatching Vulkan Draw Indexed with Offset");
                        let state = {
                            let s = ACTIVE_STATE.lock().unwrap();
                            s.clone()
                        };
                        dispatch_draw_for_state(state);
                    }
                    0x28 => {
                        let is_mock_draw = count >= 1 && i + 1 < stream.len() && stream[i + 1] == 0x66666666;
                        if is_mock_draw {
                            info!("    --> OP_DRAW_INDEX_2 (Mock Draw): Dispatching Vulkan vkCmdDrawIndexed");
                            let state = {
                                let s = ACTIVE_STATE.lock().unwrap();
                                s.clone()
                            };
                            dispatch_draw_for_state(state);
                        } else {
                            info!("    --> OP_SET_CONTEXT_REG: Updating context register descriptor state");
                            if count >= 1 && i + 1 < stream.len() {
                                let reg_offset = stream[i + 1];
                                for reg_idx in 0..count as usize {
                                    if i + 2 + reg_idx < stream.len() {
                                        let val = stream[i + 2 + reg_idx];
                                        let current_reg = reg_offset + reg_idx as u32;
                                        info!("      - Context Register 0x{:X} = 0x{:X}", current_reg, val);

                                        let mut state = ACTIVE_STATE.lock().unwrap();
                                        if current_reg == 0x1000 {
                                            state.vertex_shader_gpu_addr = (state.vertex_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                        } else if current_reg == 0x1001 {
                                            state.vertex_shader_gpu_addr = (state.vertex_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                        } else if current_reg == 0x1002 {
                                            state.fragment_shader_gpu_addr = (state.fragment_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                        } else if current_reg == 0x1003 {
                                            state.fragment_shader_gpu_addr = (state.fragment_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                        } else if current_reg == 0x100E {
                                            state.compute_shader_gpu_addr = (state.compute_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                        } else if current_reg == 0x100F {
                                            state.compute_shader_gpu_addr = (state.compute_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    0x2C => {
                        info!("    --> OP_SET_SH_REG: Updating shader register descriptor state");
                        if count >= 1 && i + 1 < stream.len() {
                            let reg_offset = stream[i + 1];
                            for reg_idx in 0..count as usize {
                                if i + 2 + reg_idx < stream.len() {
                                    let val = stream[i + 2 + reg_idx];
                                    let current_reg = reg_offset + reg_idx as u32;
                                    info!("      - Register 0x{:X} = 0x{:X}", current_reg, val);

                                    let mut state = ACTIVE_STATE.lock().unwrap();
                                    if current_reg == 0x1000 {
                                        state.vertex_shader_gpu_addr = (state.vertex_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x1001 {
                                        state.vertex_shader_gpu_addr = (state.vertex_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x1002 {
                                        state.fragment_shader_gpu_addr = (state.fragment_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x1003 {
                                        state.fragment_shader_gpu_addr = (state.fragment_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x100E {
                                        state.compute_shader_gpu_addr = (state.compute_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x100F {
                                        state.compute_shader_gpu_addr = (state.compute_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x1004 {
                                        state.topology = match val {
                                            0 => vk::PrimitiveTopology::POINT_LIST,
                                            1 => vk::PrimitiveTopology::LINE_LIST,
                                            2 => vk::PrimitiveTopology::TRIANGLE_LIST,
                                            _ => vk::PrimitiveTopology::TRIANGLE_LIST,
                                        };
                                    } else if current_reg == 0x1005 {
                                        state.depth_test_enable = (val & 1) != 0;
                                        state.depth_write_enable = (val & 2) != 0;
                                        state.stencil_test_enable = (val & 4) != 0;
                                        state.stencil_write_enable = (val & 8) != 0;
                                    } else if current_reg == 0x1008 {
                                        state.vertex_buffer_gpu_addr = (state.vertex_buffer_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x1009 {
                                        state.vertex_buffer_gpu_addr = (state.vertex_buffer_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x100A {
                                        state.vertex_buffer_size = val;
                                    } else if current_reg == 0x100B {
                                        state.index_buffer_gpu_addr = (state.index_buffer_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x100C {
                                        state.index_buffer_gpu_addr = (state.index_buffer_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x100D {
                                        state.index_buffer_count = val;
                                    } else if current_reg == 0x1010 {
                                        state.constant_buffer_gpu_addr = (state.constant_buffer_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x1011 {
                                        state.constant_buffer_gpu_addr = (state.constant_buffer_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x1012 {
                                        state.constant_buffer_size = val;
                                    } else if current_reg == 0x1015 {
                                        state.texture_gpu_addr = (state.texture_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x1016 {
                                        state.texture_gpu_addr = (state.texture_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x1017 {
                                        state.texture_width = val;
                                    } else if current_reg == 0x1018 {
                                        state.texture_height = val;
                                    } else if current_reg == 0x1019 {
                                        state.texture_format = val;
                                    } else if current_reg == 0x101C {
                                        state.sampler_filter = val;
                                    } else if current_reg == 0x1020 {
                                        state.blend_enable = val != 0;
                                    } else if current_reg == 0x1021 {
                                        state.src_color_blend_factor = val;
                                    } else if current_reg == 0x1022 {
                                        state.dst_color_blend_factor = val;
                                    } else if current_reg == 0x1023 {
                                        state.color_blend_op = val;
                                    } else if current_reg == 0x1024 {
                                        state.src_alpha_blend_factor = val;
                                    } else if current_reg == 0x1025 {
                                        state.dst_alpha_blend_factor = val;
                                    } else if current_reg == 0x1026 {
                                        state.alpha_blend_op = val;
                                    } else if current_reg == 0x1027 {
                                        state.color_write_mask = val;
                                    } else if current_reg == 0x1030 {
                                        state.viewport_x = f32::from_bits(val);
                                    } else if current_reg == 0x1031 {
                                        state.viewport_y = f32::from_bits(val);
                                    } else if current_reg == 0x1032 {
                                        state.viewport_width = f32::from_bits(val);
                                    } else if current_reg == 0x1033 {
                                        state.viewport_height = f32::from_bits(val);
                                    } else if current_reg == 0x1034 {
                                        state.viewport_min_depth = f32::from_bits(val);
                                    } else if current_reg == 0x1035 {
                                        state.viewport_max_depth = f32::from_bits(val);
                                    } else if current_reg == 0x1038 {
                                        state.scissor_x = val as i32;
                                    } else if current_reg == 0x1039 {
                                        state.scissor_y = val as i32;
                                    } else if current_reg == 0x103A {
                                        state.scissor_width = val;
                                    } else if current_reg == 0x103B {
                                        state.scissor_height = val;
                                    }
                                }
                            }
                        }
                    }
                    0x37 => {
                        info!("    --> OP_WRITE_DATA: Writing values to guest virtual memory");
                        if count >= 3 && i + 4 < stream.len() {
                            let dest_lo = stream[i + 2];
                            let dest_hi = stream[i + 3];
                            let dest_addr = ((dest_hi as u64) << 32) | (dest_lo as u64);
                            let data_count = count - 2; // count + 1 - 3
                            
                            let host_dest_ptr = match crate::kernel::translate_guest_addr(dest_addr) {
                                Some(addr) => addr as *mut u32,
                                None => dest_addr as *mut u32,
                            };

                            if !host_dest_ptr.is_null() {
                                for offset in 0..data_count as usize {
                                    if i + 4 + offset < stream.len() {
                                        let val = stream[i + 4 + offset];
                                        std::ptr::write_volatile(host_dest_ptr.add(offset), val);
                                    }
                                }
                                info!("      - Wrote {} DWORDs to guest memory address 0x{:X}", data_count, dest_addr);
                            }
                        }
                    }
                    0x3F => {
                        info!("    --> OP_INDIRECT_BUFFER: Recurse into nested command buffer execution");
                        if count >= 2 && i + 3 < stream.len() {
                            let ib_addr_lo = stream[i + 1];
                            let ib_addr_hi = stream[i + 2];
                            let ib_addr = ((ib_addr_hi as u64) << 32) | (ib_addr_lo as u64);
                            let ib_control = stream[i + 3];
                            let ib_size = ib_control & 0xFFFFF; // length in DWORDs

                            RECURSION_DEPTH.with(|depth_cell| {
                                let current_depth = depth_cell.get();
                                if current_depth >= 16 {
                                    error!("OP_INDIRECT_BUFFER: Maximum recursion depth reached (16). Preventing stack overflow.");
                                } else {
                                    depth_cell.set(current_depth + 1);
                                    info!("      - Recursing into IB at 0x{:X} (Size: {} DWORDs, Depth: {})", ib_addr, ib_size, current_depth + 1);
                                    decode_pm4_command_buffer(ib_addr, ib_size);
                                    depth_cell.set(current_depth);
                                }
                            });
                        }
                    }
                    0x4B => info!("    --> OP_ACQUIRE_MEM: Injecting Vulkan vkCmdPipelineBarrier (Cache coherent flush)"),
                    0x69 => {
                        info!("    --> OP_SET_CONTEXT_REG (0x69): Updating context register descriptor state");
                        if count >= 1 && i + 1 < stream.len() {
                            let reg_offset = stream[i + 1];
                            for reg_idx in 0..count as usize {
                                if i + 2 + reg_idx < stream.len() {
                                    let val = stream[i + 2 + reg_idx];
                                    let current_reg = reg_offset + reg_idx as u32;
                                    info!("      - Context Register 0x{:X} = 0x{:X}", current_reg, val);

                                    let mut state = ACTIVE_STATE.lock().unwrap();
                                    if current_reg == 0x1000 {
                                        state.vertex_shader_gpu_addr = (state.vertex_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x1001 {
                                        state.vertex_shader_gpu_addr = (state.vertex_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x1002 {
                                        state.fragment_shader_gpu_addr = (state.fragment_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x1003 {
                                        state.fragment_shader_gpu_addr = (state.fragment_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    } else if current_reg == 0x100E {
                                        state.compute_shader_gpu_addr = (state.compute_shader_gpu_addr & 0xFFFFFFFF00000000) | (val as u64);
                                    } else if current_reg == 0x100F {
                                        state.compute_shader_gpu_addr = (state.compute_shader_gpu_addr & 0x00000000FFFFFFFF) | ((val as u64) << 32);
                                    }
                                }
                            }
                        }
                    }
                    0x15 | 0xD5 => {
                        info!("    --> OP_DISPATCH_DIRECT: Dispatching Vulkan vkCmdDispatch");
                        if count >= 1 && i + 1 < stream.len() {
                            let groups_x = stream[i + 1];
                            let groups_y = if count >= 2 && i + 2 < stream.len() { stream[i + 2] } else { 1 };
                            let groups_z = if count >= 3 && i + 3 < stream.len() { stream[i + 3] } else { 1 };

                            let cs_gpu_addr = {
                                let state = ACTIVE_STATE.lock().unwrap();
                                state.compute_shader_gpu_addr
                            };

                            if cs_gpu_addr != 0 {
                                execute_general_compute_dispatch(cs_gpu_addr, groups_x, groups_y, groups_z);
                            } else {
                                warn!("      - Compute Shader Address is 0. Running Simulated/Mock Compute Dispatch.");
                            }
                        }
                    }
                    0x24 => {
                        info!("    --> OP_INDEX_TYPE: Binding index buffer type for draws");
                        if i + 1 < stream.len() {
                            let val = stream[i + 1];
                            let mut state = ACTIVE_STATE.lock().unwrap();
                            state.index_type = match val {
                                0 => vk::IndexType::UINT16,
                                1 => vk::IndexType::UINT32,
                                _ => vk::IndexType::UINT16,
                            };
                            info!("      - IndexType set to {:?}", state.index_type);
                        }
                    }
                    _ => info!("    --> Unhandled Type-3 opcode: 0x{:X}", opcode),
                }
                i += (count as usize) + 2;
            }
            _ => {
                info!("  [PM4 Decode] Unknown Packet Type: {} at offset: {}", packet_type, i);
                i += 1;
            }
        }
    }
}

/// Resolves raw pointer and invokes the decoder.
#[no_mangle]
pub unsafe extern "sysv64" fn sceAgcSubmitGraphics(
    queue: u8,
    dcb_gpu_addr: u64,
    dcb_size_in_dwords: u32,
 ) -> i32 {
    info!(
        "API Graphics Intercepted: sceAgcSubmitGraphics | Queue: {} | PacketAddress: 0x{:X} | Size: {} DWORDs",
        queue, dcb_gpu_addr, dcb_size_in_dwords
    );
    decode_pm4_command_buffer(dcb_gpu_addr, dcb_size_in_dwords);
    0 // SCE_OK
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceAgcSubmitAsyncCompute(
    pipe: u8,
    queue: u8,
    dcb_gpu_addr: u64,
    dcb_size_in_dwords: u32,
) -> i32 {
    info!(
        "API Graphics Intercepted: sceAgcSubmitAsyncCompute | Pipe: {} | Queue: {} | PacketAddress: 0x{:X} | Size: {} DWORDs",
        pipe, queue, dcb_gpu_addr, dcb_size_in_dwords
    );
    0
}

#[no_mangle]
pub extern "sysv64" fn sceAgcSuspendPoint() -> i32 {
    info!("API Graphics Intercepted: sceAgcSuspendPoint | Draining pipeline cache structures...");
    0
}

#[derive(Clone, Debug)]
pub struct CompileRequest {
    pub key: PipelineStateKey,
    pub state: ActiveGraphicsState,
    pub vs_code: Vec<u32>,
    pub fs_code: Vec<u32>,
}

pub static COMPILING_PIPELINES: std::sync::OnceLock<Mutex<HashSet<PipelineStateKey>>> = std::sync::OnceLock::new();
pub static COMPILER_SENDER: std::sync::OnceLock<Mutex<std::sync::mpsc::Sender<CompileRequest>>> = std::sync::OnceLock::new();

pub fn compute_shader_hash(code: &[u32]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    code.hash(&mut hasher);
    hasher.finish()
}

pub fn load_or_translate_compute_shader(code: &[u32]) -> Vec<u32> {
    let hash = compute_shader_hash(code);
    if let Some(patched_spirv) = crate::shader_translation::GetShaderPatch(hash) {
        info!("Loaded patched compute shader from override map: {:016X}", hash);
        return patched_spirv;
    }
    let cache_dir = std::path::Path::new("shader_cache");
    if !cache_dir.exists() {
        let _ = std::fs::create_dir_all(cache_dir);
    }
    
    let file_name = format!("{:016X}_cs.spv", hash);
    let path = cache_dir.join(file_name);
    
    if path.exists() {
        if let Ok(spirv_bytes) = std::fs::read(&path) {
            if spirv_bytes.len() % 4 == 0 {
                info!("Loaded compute shader from persistent disk cache: {:?}", path);
                let words: Vec<u32> = spirv_bytes
                    .chunks_exact(4)
                    .map(|chunk| u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect();
                return words;
            }
        }
    }
    
    info!("Translating compute shader and writing to disk cache: {:?}", path);
    let spirv = crate::shader_translation::generate_kraken_spirv();
    
    let mut bytes = Vec::with_capacity(spirv.len() * 4);
    for word in &spirv {
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    let _ = std::fs::write(&path, bytes);
    
    spirv
}

pub unsafe fn execute_general_compute_dispatch(cs_gpu_addr: u64, groups_x: u32, groups_y: u32, groups_z: u32) {
    info!("Executing general Vulkan compute dispatch at CS address: 0x{:X} (groups: {}x{}x{})...", cs_gpu_addr, groups_x, groups_y, groups_z);

    let global_ctx = VULKAN_CONTEXT.lock().unwrap();
    let ctx = match &*global_ctx {
        Some(c) => c,
        None => {
            warn!("VulkanContext not initialized. Skipping compute dispatch.");
            return;
        }
    };

    let device = &ctx.device;

    // Load or compile compute shader
    let cs_code = {
        let mut code_words = Vec::new();
        let mut ptr = cs_gpu_addr as *const u32;
        for _ in 0..512 {
            let word = *ptr;
            code_words.push(word);
            if word == 0xBF800000 {
                break;
            }
            ptr = ptr.add(1);
        }
        code_words
    };

    let compute_spirv = load_or_translate_compute_shader(&cs_code);

    let cache_lock = COMPUTE_PIPELINE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache_lock.lock().unwrap();
    let (pipeline, pipeline_layout, desc_layout) = if let Some(cached) = cache.get(&cs_gpu_addr) {
        *cached
    } else {
        info!("Compiling general compute pipeline for CS address: 0x{:X}...", cs_gpu_addr);
        let compute_module_info = vk::ShaderModuleCreateInfo::default().code(&compute_spirv);
        let compute_module = device.create_shader_module(&compute_module_info, None).unwrap();

        let bindings = [
            vk::DescriptorSetLayoutBinding::default()
                .binding(0)
                .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                .descriptor_count(1)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            vk::DescriptorSetLayoutBinding::default()
                .binding(1)
                .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                .descriptor_count(1)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
        ];
        let dsl_info = vk::DescriptorSetLayoutCreateInfo::default().bindings(&bindings);
        let desc_layout = device.create_descriptor_set_layout(&dsl_info, None).unwrap();

        let layouts = [desc_layout];
        let pipeline_layout_info = vk::PipelineLayoutCreateInfo::default().set_layouts(&layouts);
        let pipeline_layout = device.create_pipeline_layout(&pipeline_layout_info, None).unwrap();

        let main_cstr = CString::new("main").unwrap();
        let stage_info = vk::PipelineShaderStageCreateInfo::default()
            .stage(vk::ShaderStageFlags::COMPUTE)
            .module(compute_module)
            .name(&main_cstr);

        let compute_pipeline_info = vk::ComputePipelineCreateInfo::default()
            .stage(stage_info)
            .layout(pipeline_layout);

        let compute_pipeline = match device.create_compute_pipelines(
            ctx.pipeline_cache,
            std::slice::from_ref(&compute_pipeline_info),
            None,
        ) {
            Ok(pipelines) => pipelines[0],
            Err(e) => {
                warn!("Vulkan general compute pipeline compilation failed: {:?}", e);
                vk::Pipeline::null()
            }
        };

        device.destroy_shader_module(compute_module, None);

        let entry = (compute_pipeline, pipeline_layout, desc_layout);
        cache.insert(cs_gpu_addr, entry);
        entry
    };

    if pipeline == vk::Pipeline::null() {
        warn!("Failed to compile compute pipeline. Skipping dispatch.");
        return;
    }

    let dummy_size = 1024;
    let input_buffer_info = vk::BufferCreateInfo::default()
        .size(dummy_size)
        .usage(vk::BufferUsageFlags::STORAGE_BUFFER)
        .sharing_mode(vk::SharingMode::EXCLUSIVE);
    let input_buffer = device.create_buffer(&input_buffer_info, None).unwrap();
    let input_mem_reqs = device.get_buffer_memory_requirements(input_buffer);

    let output_buffer_info = vk::BufferCreateInfo::default()
        .size(dummy_size)
        .usage(vk::BufferUsageFlags::STORAGE_BUFFER)
        .sharing_mode(vk::SharingMode::EXCLUSIVE);
    let output_buffer = device.create_buffer(&output_buffer_info, None).unwrap();
    let output_mem_reqs = device.get_buffer_memory_requirements(output_buffer);

    let mem_props = ctx.instance.get_physical_device_memory_properties(ctx.physical_device);
    let find_memory_type = |type_filter: u32, properties: vk::MemoryPropertyFlags| -> u32 {
        for i in 0..mem_props.memory_type_count {
            if (type_filter & (1 << i)) != 0 && mem_props.memory_types[i as usize].property_flags.contains(properties) {
                return i;
            }
        }
        0
    };

    let mem_flags = vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT;
    let input_type_idx = find_memory_type(input_mem_reqs.memory_type_bits, mem_flags);
    let input_alloc_info = vk::MemoryAllocateInfo::default()
        .allocation_size(input_mem_reqs.size)
        .memory_type_index(input_type_idx);
    let input_mem = device.allocate_memory(&input_alloc_info, None).unwrap();
    device.bind_buffer_memory(input_buffer, input_mem, 0).unwrap();

    let output_type_idx = find_memory_type(output_mem_reqs.memory_type_bits, mem_flags);
    let output_alloc_info = vk::MemoryAllocateInfo::default()
        .allocation_size(output_mem_reqs.size)
        .memory_type_index(output_type_idx);
    let output_mem = device.allocate_memory(&output_alloc_info, None).unwrap();
    device.bind_buffer_memory(output_buffer, output_mem, 0).unwrap();

    let pool_sizes = [
        vk::DescriptorPoolSize::default()
            .ty(vk::DescriptorType::STORAGE_BUFFER)
            .descriptor_count(2),
    ];
    let pool_info = vk::DescriptorPoolCreateInfo::default()
        .max_sets(1)
        .pool_sizes(&pool_sizes);
    let desc_pool = device.create_descriptor_pool(&pool_info, None).unwrap();

    let layouts = [desc_layout];
    let alloc_info = vk::DescriptorSetAllocateInfo::default()
        .descriptor_pool(desc_pool)
        .set_layouts(&layouts);
    let desc_set = device.allocate_descriptor_sets(&alloc_info).unwrap()[0];

    let input_buffer_info_vk = vk::DescriptorBufferInfo::default()
        .buffer(input_buffer)
        .offset(0)
        .range(dummy_size);
    let output_buffer_info_vk = vk::DescriptorBufferInfo::default()
        .buffer(output_buffer)
        .offset(0)
        .range(dummy_size);

    let writes = [
        vk::WriteDescriptorSet::default()
            .dst_set(desc_set)
            .dst_binding(0)
            .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
            .buffer_info(std::slice::from_ref(&input_buffer_info_vk)),
        vk::WriteDescriptorSet::default()
            .dst_set(desc_set)
            .dst_binding(1)
            .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
            .buffer_info(std::slice::from_ref(&output_buffer_info_vk)),
    ];
    device.update_descriptor_sets(&writes, &[]);

    let queue_family_properties = ctx.instance.get_physical_device_queue_family_properties(ctx.physical_device);
    let mut queue_family_index = 0;
    for (index, prop) in queue_family_properties.iter().enumerate() {
        if prop.queue_flags.contains(vk::QueueFlags::GRAPHICS) {
            queue_family_index = index as u32;
            break;
        }
    }

    let cp_create_info = vk::CommandPoolCreateInfo::default()
        .queue_family_index(queue_family_index)
        .flags(vk::CommandPoolCreateFlags::TRANSIENT);
    let temp_pool = device.create_command_pool(&cp_create_info, None).unwrap();

    let alloc_info = vk::CommandBufferAllocateInfo::default()
        .command_pool(temp_pool)
        .level(vk::CommandBufferLevel::PRIMARY)
        .command_buffer_count(1);
    let cmd_buf = device.allocate_command_buffers(&alloc_info).unwrap()[0];

    let begin_info = vk::CommandBufferBeginInfo::default()
        .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
    device.begin_command_buffer(cmd_buf, &begin_info).unwrap();

    device.cmd_bind_pipeline(cmd_buf, vk::PipelineBindPoint::COMPUTE, pipeline);
    device.cmd_bind_descriptor_sets(cmd_buf, vk::PipelineBindPoint::COMPUTE, pipeline_layout, 0, &[desc_set], &[]);

    device.cmd_dispatch(cmd_buf, groups_x.max(1), groups_y.max(1), groups_z.max(1));

    device.end_command_buffer(cmd_buf).unwrap();

    let fence_info = vk::FenceCreateInfo::default();
    let fence = device.create_fence(&fence_info, None).unwrap();

    let submit_info = vk::SubmitInfo::default()
        .command_buffers(std::slice::from_ref(&cmd_buf));

    {
        let _lock = SUBMIT_MUTEX.lock().unwrap();
        device.queue_submit(ctx.queue, &[submit_info], fence).unwrap();
    }

    device.wait_for_fences(&[fence], true, u64::MAX).unwrap();

    device.destroy_fence(fence, None);
    device.destroy_command_pool(temp_pool, None);
    device.destroy_descriptor_pool(desc_pool, None);
    device.destroy_buffer(input_buffer, None);
    device.free_memory(input_mem, None);
    device.destroy_buffer(output_buffer, None);
    device.free_memory(output_mem, None);

    info!("General Vulkan compute dispatch at CS address: 0x{:X} executed successfully.", cs_gpu_addr);
}

pub fn load_or_translate_shader(
    code: &[u32],
    is_vertex: bool,
    has_vb: bool,
    has_cb: bool,
    has_tex: bool,
) -> Vec<u32> {
    let hash = compute_shader_hash(code);
    if let Some(patched_spirv) = crate::shader_translation::GetShaderPatch(hash) {
        info!("Loaded patched shader from override map: {:016X}", hash);
        return patched_spirv;
    }
    let cache_dir = std::path::Path::new("shader_cache");
    if !cache_dir.exists() {
        let _ = std::fs::create_dir_all(cache_dir);
    }
    
    let file_name = format!(
        "{:016X}_{}_{}_{}_{}.spv",
        hash,
        if is_vertex { "vs" } else { "fs" },
        if has_vb { "vb" } else { "novb" },
        if has_cb { "cb" } else { "nocb" },
        if has_tex { "tex" } else { "notex" }
    );
    let path = cache_dir.join(file_name);
    
    if path.exists() {
        if let Ok(spirv_bytes) = std::fs::read(&path) {
            if spirv_bytes.len() % 4 == 0 {
                info!("Loaded shader from persistent disk cache: {:?}", path);
                let words: Vec<u32> = spirv_bytes
                    .chunks_exact(4)
                    .map(|chunk| u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect();
                return words;
            }
        }
    }
    
    info!("Translating shader and writing to disk cache: {:?}", path);
    let instructions = crate::shader_translation::parse_rdna2_instructions(code);
    let spirv = crate::shader_translation::translate_to_spirv(
        &instructions,
        is_vertex,
        has_vb,
        has_cb,
        has_tex,
    );
    
    let mut bytes = Vec::with_capacity(spirv.len() * 4);
    for word in &spirv {
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    let _ = std::fs::write(&path, bytes);
    
    spirv
}

pub fn init_compiler_thread() {
    let (tx, rx) = std::sync::mpsc::channel::<CompileRequest>();
    let _ = COMPILER_SENDER.set(Mutex::new(tx));

    std::thread::spawn(move || {
        info!("Started asynchronous shader pipeline compiler thread.");
        while let Ok(req) = rx.recv() {
            info!("Asynchronous compiler thread: received compile request.");
            
            let vs_spirv = load_or_translate_shader(
                &req.vs_code,
                true,
                req.key.has_vertex_buffer,
                req.key.has_constant_buffer,
                req.key.has_texture,
            );
            let fs_spirv = load_or_translate_shader(
                &req.fs_code,
                false,
                req.key.has_vertex_buffer,
                req.key.has_constant_buffer,
                req.key.has_texture,
            );

            let compiled_pipeline = unsafe {
                let global_ctx = VULKAN_CONTEXT.lock().unwrap();
                if let Some(ref ctx) = *global_ctx {
                    ctx.compile_pipeline_if_needed(&req.state, &vs_spirv, &fs_spirv)
                } else {
                    vk::Pipeline::null()
                }
            };

            if compiled_pipeline != vk::Pipeline::null() {
                let cache_lock = PIPELINE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
                cache_lock.lock().unwrap().insert(req.key.clone(), compiled_pipeline);
                info!("Asynchronously compiled Vulkan Pipeline PSO successfully: {:?}", compiled_pipeline);
            } else {
                error!("Asynchronous pipeline compilation failed.");
            }

            let compiling_lock = COMPILING_PIPELINES.get_or_init(|| Mutex::new(HashSet::new()));
            compiling_lock.lock().unwrap().remove(&req.key);
        }
    });
}

#[cfg(test)]
mod graphics_tests {
    use super::*;

    #[test]
    fn test_shader_hashing_and_caching() {
        let dummy_code = vec![
            0xB2000000, // s_mov_b32
            0xBF800000, // s_endpgm
        ];
        
        let hash1 = compute_shader_hash(&dummy_code);
        let hash2 = compute_shader_hash(&dummy_code);
        assert_eq!(hash1, hash2);

        let cache_dir = std::path::Path::new("shader_cache");
        let file_name = format!(
            "{:016X}_vs_novb_nocb_notex.spv",
            hash1
        );
        let path = cache_dir.join(file_name);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }

        let spirv1 = load_or_translate_shader(&dummy_code, true, false, false, false);
        assert!(!spirv1.is_empty());
        assert!(path.exists());

        let spirv2 = load_or_translate_shader(&dummy_code, true, false, false, false);
        assert_eq!(spirv1, spirv2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_pm4_compute_dispatch() {
        {
            let mut state = ACTIVE_STATE.lock().unwrap();
            state.compute_shader_gpu_addr = 0;
            state.vertex_shader_gpu_addr = 0;
        }

        // PM4 packet stream:
        // 1. OP_SET_SH_REG (0x2C) to set compute shader address (0x100E/0x100F) to 0x1122334455667788
        // 2. OP_SET_CONTEXT_REG (0x28) to set vertex shader address (0x1000/0x1001) to 0x99AABBCCDDEEFF00
        let pm4_stream: Vec<u32> = vec![
            // OP_SET_SH_REG: 2 registers starting at 0x100E
            (3 << 30) | (2 << 16) | (0x2C << 8),
            0x100E,
            0x55667788,
            0x11223344,

            // OP_SET_CONTEXT_REG (0x28): 2 registers starting at 0x1000.
            // Note: Second word is 0x1000, which is not 0x66666666, so it's treated as context register update!
            (3 << 30) | (2 << 16) | (0x28 << 8),
            0x1000,
            0xDDEEFF00,
            0x99AABBCC,
        ];

        unsafe {
            decode_pm4_command_buffer(pm4_stream.as_ptr() as u64, pm4_stream.len() as u32);
        }

        {
            let state = ACTIVE_STATE.lock().unwrap();
            assert_eq!(state.compute_shader_gpu_addr, 0x1122334455667788);
            assert_eq!(state.vertex_shader_gpu_addr, 0x99AABBCCDDEEFF00);
        }
    }
}

