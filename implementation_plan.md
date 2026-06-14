# Milestone 7: Command Processor (CP) Ring Buffer Emulation and Direct PM4 Hardware Queue Dispatcher

To achieve compatibility with commercial consumer PS5 games, we must emulate the hardware-level Command Processor (CP) and direct PM4 command submission queues. Modern game engines bypass the high-level SDK graphics wrappers (such as `sceAgcSubmitGraphics`) and instead write PM4 packets directly to GPU-mapped ring buffers managed by host doorbells.

Additionally, this implementation provides full cross-platform compatibility across Windows and Linux systems.

---

## Technical Context: Hardware Queues & Cross-Platform Virtualization

PlayStation 5 games leverage dedicated hardware queues:
1. **Graphics Queue (GFX)**: Handles 3D rendering pipelines, state shadowing, and draw calls.
2. **Compute Queue**: Handles physics, compute jobs, and processing chains.
3. **System DMA Queue (SDMA)**: Handles high-speed memory-to-memory and disk-to-VRAM transfers asynchronously.

### Cross-Platform Doorbell (MMIO) Interception:
- **Windows**: Uses virtual page protection fault handlers (`AddVectoredExceptionHandler` / `PAGE_NOACCESS`) or polling to intercept writes to mapped doorbell registers.
- **Linux**: Uses a signal handler (`SIGSEGV` via `sigaction` with `PROT_NONE` page protection) or `eventfd` to intercept guest writes to doorbell pages, prompting the emulator to parse the command buffer.

---

## Proposed Changes

We will implement CP Ring Buffer Emulation across the graphics recompiler and HLE kernel systems.

### 1. GPU Queue & Command Processor Thread
#### [NEW] [gpu_queue.rs](file:///c:/Users/shama/Documents/Quick/ShadPS5/src/gpu_queue.rs)
- Define `GpuRingBuffer` representing virtual GPU memory rings:
  ```rust
  pub struct GpuRingBuffer {
      pub ring_base: u64,
      pub ring_size: u32,
      pub rptr_addr: u64,
      pub wptr_addr: u64,
      pub doorbell_addr: u64,
  }
  ```
- Implement `CommandProcessor` which spawns a background thread polling or waiting on doorbell modification signals.
- Parse standard AMD PM4 packet headers:
  - **Type-0**: Register writes.
  - **Type-2**: Padding.
  - **Type-3**: Opcode packets.
- Manage thread synchronization using cross-platform conditional variables (`std::sync::Condvar`) triggered by HLE doorbell writes.

---

### 2. Graphics Pipeline Integrations
#### [MODIFY] [graphics.rs](file:///c:/Users/shama/Documents/Quick/ShadPS5/src/graphics.rs)
- Refactor PM4 decoding to run on the background `CommandProcessor` thread.
- Support new PM4 opcodes:
  - `OP_WRITE_DATA` (opcode 0x37): Write values directly to virtual memory registers.
  - `OP_INDIRECT_BUFFER` (opcode 0x3F): Recurse into nested command buffers, with safety recursion counters to prevent stack overflows.
  - `OP_SET_SH_REG` (opcode 0x2C): Expand shader registers mapping real AMD GCN register indices to internal pipeline states.
- Synchronize background commands execution with the Vulkan context queues.

---

### 3. Kernel Doorbell and MMIO Virtualization
#### [MODIFY] [kernel.rs](file:///c:/Users/shama/Documents/Quick/ShadPS5/src/kernel.rs)
- Register memory-mapped virtual doorbell regions.
- Intercept writes to the doorbell registers to trigger `CommandProcessor` wakeups.
- **Linux Specific**: Register `SIGSEGV` handler using `sigaction` to catch writes to doorbell pages mapped with `PROT_NONE`, restoring access briefly or virtualizing the write, then waking up the dispatcher thread.
- **Windows Specific**: Use `AddVectoredExceptionHandler` with `PAGE_NOACCESS` mapping to intercept writes on Windows.

#### [MODIFY] [kernel_hle.rs](file:///c:/Users/shama/Documents/Quick/ShadPS5/src/kernel_hle.rs)
- Implement stubs for queue initialization:
  - `sceKernelCreateGpuQueue`: Instantiates and registers a GFX/Compute/SDMA ring buffer.
  - `sceKernelMapGpuRing`: Maps guest virtual memory regions to the command processor ring.

---

## Verification Plan

### Automated Tests
1. **Asynchronous Ring Buffer Submission Test (`test_pm4_ring_buffer_submission`)**:
   - Write a test creating a virtual ring buffer, registering a doorbell write, inserting Type-3 commands (`OP_WRITE_DATA` & `OP_SET_SH_REG`), and verifying that state updates occur correctly.
2. **Indirect Buffer Execution Test (`test_pm4_indirect_buffer`)**:
   - Verify that nested command buffers via `OP_INDIRECT_BUFFER` are correctly resolved, parsed, and executed up to the maximum recursion depth.
3. **Cross-Platform Doorbell Write Interception Test (`test_doorbell_write_interception`)**:
   - Test writing to mapped doorbell pages under Windows and Linux, confirming signal/exception handlers capture the write events and trigger dispatch.

### Manual Verification
- Execute `cargo test` to verify all ring buffer emulation runs cleanly and passes.
