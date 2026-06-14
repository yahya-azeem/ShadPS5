use std::sync::{Arc, Mutex, Condvar, OnceLock};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::collections::HashMap;
use std::thread;
use log::{info, warn, error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuQueueType {
    Graphics,
    Compute,
}

#[derive(Debug, Clone, Copy)]
pub struct GpuRingBuffer {
    pub ring_base: u64,
    pub ring_size: u32,
    pub rptr_addr: u64,
    pub wptr_addr: u64,
    pub doorbell_addr: u64,
    pub queue_type: GpuQueueType,
}

pub struct CommandProcessor {
    pub queue_id: u32,
    pub ring: GpuRingBuffer,
    pub active: Arc<AtomicBool>,
}

static COMMAND_PROCESSORS: OnceLock<Mutex<HashMap<u32, Arc<CommandProcessor>>>> = OnceLock::new();
static DOORBELL_MAP: OnceLock<Mutex<HashMap<u64, u32>>> = OnceLock::new();
static COND_VARS: OnceLock<Mutex<HashMap<u32, Arc<(Mutex<bool>, Condvar)>>>> = OnceLock::new();
static NEXT_QUEUE_ID: AtomicU32 = AtomicU32::new(1);

impl CommandProcessor {
    pub fn new(ring: GpuRingBuffer) -> Arc<Self> {
        let queue_id = NEXT_QUEUE_ID.fetch_add(1, Ordering::SeqCst);
        let cp = Arc::new(Self {
            queue_id,
            ring,
            active: Arc::new(AtomicBool::new(true)),
        });

        // Register CP
        let processors = COMMAND_PROCESSORS.get_or_init(|| Mutex::new(HashMap::new()));
        processors.lock().unwrap().insert(queue_id, cp.clone());

        // Register Doorbell Mapping
        let doorbells = DOORBELL_MAP.get_or_init(|| Mutex::new(HashMap::new()));
        doorbells.lock().unwrap().insert(ring.doorbell_addr, queue_id);

        // Register Condition Variable
        let condvars = COND_VARS.get_or_init(|| Mutex::new(HashMap::new()));
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        condvars.lock().unwrap().insert(queue_id, pair.clone());

        // Spawn background worker thread
        let cp_thread = cp.clone();
        thread::spawn(move || {
            cp_thread.run_loop(pair);
        });

        cp
    }

    fn run_loop(&self, pair: Arc<(Mutex<bool>, Condvar)>) {
        info!("CommandProcessor thread started for Queue ID {} (Doorbell: 0x{:X})", self.queue_id, self.ring.doorbell_addr);
        
        let (lock, cvar) = &*pair;

        while self.active.load(Ordering::SeqCst) {
            // Wait on condvar, or timeout after 10ms for active polling fallback
            let mut triggered = lock.lock().unwrap();
            let result = cvar.wait_timeout(triggered, std::time::Duration::from_millis(10)).unwrap();
            triggered = result.0;
            *triggered = false; // reset trigger
            
            // Check write pointer (translated using translate_guest_addr if identity mapped or direct)
            let wptr_ptr = match crate::kernel::translate_guest_addr(self.ring.wptr_addr) {
                Some(addr) => addr as *const u32,
                None => self.ring.wptr_addr as *const u32,
            };

            let rptr_ptr = match crate::kernel::translate_guest_addr(self.ring.rptr_addr) {
                Some(addr) => addr as *mut u32,
                None => self.ring.rptr_addr as *mut u32,
            };

            if wptr_ptr.is_null() || rptr_ptr.is_null() {
                continue;
            }

            let wptr = unsafe { std::ptr::read_volatile(wptr_ptr) };
            let mut rptr = unsafe { std::ptr::read_volatile(rptr_ptr) };

            if wptr != rptr {
                // Process packets in the ring buffer between rptr and wptr
                let dword_capacity = self.ring.ring_size / 4;
                if dword_capacity == 0 {
                    warn!("Invalid ring buffer size: {}", self.ring.ring_size);
                    continue;
                }

                let ring_base_ptr = match crate::kernel::translate_guest_addr(self.ring.ring_base) {
                    Some(addr) => addr as *const u32,
                    None => self.ring.ring_base as *const u32,
                };

                if ring_base_ptr.is_null() {
                    warn!("Ring buffer base address is null: 0x{:X}", self.ring.ring_base);
                    continue;
                }

                let ring_slice = unsafe { std::slice::from_raw_parts(ring_base_ptr, dword_capacity as usize) };
                
                // Unwrap the circular ring buffer into a sequential command list
                let mut packet_buffer = Vec::new();
                while rptr != wptr {
                    let word = ring_slice[rptr as usize % dword_capacity as usize];
                    packet_buffer.push(word);
                    rptr = (rptr + 1) % dword_capacity;
                }

                // Update guest read pointer to notify guest that we processed these commands
                unsafe {
                    std::ptr::write_volatile(rptr_ptr, rptr);
                }

                // Dispatch the accumulated packets to the graphics engine for execution
                if !packet_buffer.is_empty() {
                    info!("Queue {} dispatching {} DWORD PM4 packet stream...", self.queue_id, packet_buffer.len());
                    unsafe {
                        crate::graphics::decode_pm4_command_buffer(packet_buffer.as_ptr() as u64, packet_buffer.len() as u32);
                    }
                }
            }
        }

        info!("CommandProcessor thread for Queue ID {} exiting.", self.queue_id);
    }
}

pub fn trigger_doorbell(doorbell_addr: u64, value: u32) {
    let doorbells = DOORBELL_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let map = doorbells.lock().unwrap();
    if let Some(&queue_id) = map.get(&doorbell_addr) {
        let condvars = COND_VARS.get_or_init(|| Mutex::new(HashMap::new()));
        let cvar_map = condvars.lock().unwrap();
        if let Some(pair) = cvar_map.get(&queue_id) {
            let (lock, cvar) = &**pair;
            let mut triggered = lock.lock().unwrap();
            *triggered = true;
            cvar.notify_one();
            info!("Triggered doorbell for Queue ID {} with value 0x{:X}", queue_id, value);
        }
    }
}

pub fn shutdown_all_queues() {
    let processors = COMMAND_PROCESSORS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = processors.lock().unwrap();
    for cp in map.values() {
        cp.active.store(false, Ordering::SeqCst);
    }
    map.clear();
    
    let doorbells = DOORBELL_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    doorbells.lock().unwrap().clear();

    let condvars = COND_VARS.get_or_init(|| Mutex::new(HashMap::new()));
    condvars.lock().unwrap().clear();
}

#[cfg(test)]
mod gpu_queue_tests {
    use super::*;

    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_pm4_ring_buffer_submission() {
        let _guard = TEST_MUTEX.lock().unwrap();
        crate::kernel::initialize_kernel();

        {
            let mut state = crate::graphics::ACTIVE_STATE.lock().unwrap();
            state.vertex_buffer_size = 0;
        }

        let ring_size = 16384;
        let ring_base = crate::kernel::allocate_guest_memory(0, ring_size).unwrap() as u64;
        let rptr_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;
        let wptr_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;
        let doorbell_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;

        crate::kernel::register_guest_memory(ring_base, ring_base, ring_size);
        crate::kernel::register_guest_memory(rptr_addr, rptr_addr, 4);
        crate::kernel::register_guest_memory(wptr_addr, wptr_addr, 4);
        crate::kernel::register_guest_memory(doorbell_addr, doorbell_addr, 4);

        unsafe {
            *(rptr_addr as *mut u32) = 0;
            *(wptr_addr as *mut u32) = 0;
            *(doorbell_addr as *mut u32) = 0;
        }

        let test_dest_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;
        crate::kernel::register_guest_memory(test_dest_addr, test_dest_addr, 4);
        unsafe {
            *(test_dest_addr as *mut u32) = 0xAAAA_AAAA;
        }

        let ring_ptr = ring_base as *mut u32;
        unsafe {
            // OP_SET_SH_REG: Set vertex buffer size to 0x55
            *ring_ptr.add(0) = (3 << 30) | (1 << 16) | (0x2C << 8);
            *ring_ptr.add(1) = 0x100A;
            *ring_ptr.add(2) = 0x55;

            // OP_WRITE_DATA: Write 0xDEADBEEF to test_dest_addr
            *ring_ptr.add(3) = (3 << 30) | (3 << 16) | (0x37 << 8);
            *ring_ptr.add(4) = 0;
            *ring_ptr.add(5) = (test_dest_addr & 0xFFFFFFFF) as u32;
            *ring_ptr.add(6) = (test_dest_addr >> 32) as u32;
            *ring_ptr.add(7) = 0xDEADBEEF;

            *(wptr_addr as *mut u32) = 8;
        }

        let ring = GpuRingBuffer {
            ring_base,
            ring_size: ring_size as u32,
            rptr_addr,
            wptr_addr,
            doorbell_addr,
            queue_type: GpuQueueType::Graphics,
        };

        let cp = CommandProcessor::new(ring);
        trigger_doorbell(doorbell_addr, 1);

        std::thread::sleep(std::time::Duration::from_millis(50));

        {
            let state = crate::graphics::ACTIVE_STATE.lock().unwrap();
            assert_eq!(state.vertex_buffer_size, 0x55);
        }

        unsafe {
            let written_val = *(test_dest_addr as *const u32);
            assert_eq!(written_val, 0xDEADBEEF);
        }

        unsafe {
            let final_rptr = *(rptr_addr as *const u32);
            assert_eq!(final_rptr, 8);
        }

        cp.active.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_pm4_indirect_buffer() {
        let _guard = TEST_MUTEX.lock().unwrap();
        crate::kernel::initialize_kernel();

        {
            let mut state = crate::graphics::ACTIVE_STATE.lock().unwrap();
            state.vertex_buffer_size = 0;
        }

        let ring_size = 1024;
        let ring_base = crate::kernel::allocate_guest_memory(0, ring_size).unwrap() as u64;
        let rptr_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;
        let wptr_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;
        let doorbell_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;

        crate::kernel::register_guest_memory(ring_base, ring_base, ring_size);
        crate::kernel::register_guest_memory(rptr_addr, rptr_addr, 4);
        crate::kernel::register_guest_memory(wptr_addr, wptr_addr, 4);
        crate::kernel::register_guest_memory(doorbell_addr, doorbell_addr, 4);

        unsafe {
            *(rptr_addr as *mut u32) = 0;
            *(wptr_addr as *mut u32) = 0;
            *(doorbell_addr as *mut u32) = 0;
        }

        let ib_size = 1024;
        let ib_base = crate::kernel::allocate_guest_memory(0, ib_size).unwrap() as u64;
        crate::kernel::register_guest_memory(ib_base, ib_base, ib_size);

        let ib_ptr = ib_base as *mut u32;
        unsafe {
            // OP_SET_SH_REG: Set vertex buffer size to 0x77
            *ib_ptr.add(0) = (3 << 30) | (1 << 16) | (0x2C << 8);
            *ib_ptr.add(1) = 0x100A;
            *ib_ptr.add(2) = 0x77;
        }

        let ring_ptr = ring_base as *mut u32;
        unsafe {
            // OP_INDIRECT_BUFFER: Link to the IB base address
            *ring_ptr.add(0) = (3 << 30) | (2 << 16) | (0x3F << 8);
            *ring_ptr.add(1) = (ib_base & 0xFFFFFFFF) as u32;
            *ring_ptr.add(2) = (ib_base >> 32) as u32;
            *ring_ptr.add(3) = 3;

            *(wptr_addr as *mut u32) = 4;
        }

        let ring = GpuRingBuffer {
            ring_base,
            ring_size: ring_size as u32,
            rptr_addr,
            wptr_addr,
            doorbell_addr,
            queue_type: GpuQueueType::Graphics,
        };

        let cp = CommandProcessor::new(ring);
        trigger_doorbell(doorbell_addr, 1);

        std::thread::sleep(std::time::Duration::from_millis(50));

        {
            let state = crate::graphics::ACTIVE_STATE.lock().unwrap();
            assert_eq!(state.vertex_buffer_size, 0x77);
        }

        cp.active.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_gpu_compute_queue() {
        let _guard = TEST_MUTEX.lock().unwrap();
        crate::kernel::initialize_kernel();

        {
            let mut state = crate::graphics::ACTIVE_STATE.lock().unwrap();
            state.vertex_buffer_size = 0;
        }

        let ring_size = 1024;
        let ring_base = crate::kernel::allocate_guest_memory(0, ring_size).unwrap() as u64;
        let rptr_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;
        let wptr_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;
        let doorbell_addr = crate::kernel::allocate_guest_memory(0, 4).unwrap() as u64;

        crate::kernel::register_guest_memory(ring_base, ring_base, ring_size);
        crate::kernel::register_guest_memory(rptr_addr, rptr_addr, 4);
        crate::kernel::register_guest_memory(wptr_addr, wptr_addr, 4);
        crate::kernel::register_guest_memory(doorbell_addr, doorbell_addr, 4);

        unsafe {
            *(rptr_addr as *mut u32) = 0;
            *(wptr_addr as *mut u32) = 0;
            *(doorbell_addr as *mut u32) = 0;
        }

        let ring_ptr = ring_base as *mut u32;
        unsafe {
            // OP_SET_SH_REG: Set vertex buffer size to 0x88
            *ring_ptr.add(0) = (3 << 30) | (1 << 16) | (0x2C << 8);
            *ring_ptr.add(1) = 0x100A;
            *ring_ptr.add(2) = 0x88;

            *(wptr_addr as *mut u32) = 3;
        }

        let ring = GpuRingBuffer {
            ring_base,
            ring_size: ring_size as u32,
            rptr_addr,
            wptr_addr,
            doorbell_addr,
            queue_type: GpuQueueType::Compute,
        };

        let cp = CommandProcessor::new(ring);
        trigger_doorbell(doorbell_addr, 1);

        std::thread::sleep(std::time::Duration::from_millis(50));

        {
            let state = crate::graphics::ACTIVE_STATE.lock().unwrap();
            assert_eq!(state.vertex_buffer_size, 0x88);
        }

        cp.active.store(false, Ordering::SeqCst);
    }
}
