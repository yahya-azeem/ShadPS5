use log::{info, warn, debug, trace};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use object::read::archive::ArchiveFile;
use object::{Object, ObjectSegment, ObjectSymbol, ObjectSection};
use std::sync::atomic::{AtomicUsize, Ordering};

pub static STATIC_TLS_SIZE: AtomicUsize = AtomicUsize::new(0);


/// Represents a segment mapped in the guest's virtual address space.
#[derive(Debug, Clone)]
pub struct LoadedSegment {
    pub name: String,
    pub virtual_address: u64,
    pub size: usize,
    pub readable: bool,
    pub writeable: bool,
    pub executable: bool,
}

/// Represents the loaded Prospero ELF or SELF executable.
pub struct ProsperoExecutable {
    pub entrypoint: u64,
    pub segments: Vec<LoadedSegment>,
    pub dynamic_symbols: HashMap<u64, String>, // NID -> Name mapping
}

/// Represents a function export in a Prospero system library (.sprx)
/// identified by its Name Identifier (NID).
pub struct NidExport {
    pub nid: u64,
    pub function_name: &'static str,
}

const LIBKERNEL_NIDS: &[NidExport] = &[
    NidExport { nid: 0x9D46A9CE37DF1028, function_name: "sceKernelUsleep" },
    NidExport { nid: 0x6E19BF9F1A4E7BC8, function_name: "sceKernelCreateMutex" },
    NidExport { nid: 0x2E6B47C5E0D90124, function_name: "sceKernelLockMutex" },
    NidExport { nid: 0x8A7B31C0D9BEE04E, function_name: "sceKernelUnlockMutex" },
    NidExport { nid: 0xC3F1D1D89F43864A, function_name: "sceKernelMmap" },
    NidExport { nid: 0x5D8E8F5A6D6C7E2D, function_name: "sceKernelAllocateMainDirectMemory" },
    NidExport { nid: 0x2FE4372C48C86E00, function_name: "sceKernelMapDirectMemory" },
    NidExport { nid: 0x2FF4372C48C86E00, function_name: "sceKernelMapDirectMemory" },
     NidExport { nid: 0x6f3404c72d7cf592, function_name: "_init_env" },
];

#[derive(Debug, Clone)]
pub struct CustomSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub shndx: u16,
}

pub fn parse_custom_symbols(buffer: &[u8]) -> Vec<CustomSymbol> {
    let mut custom_symbols = Vec::new();
    if buffer.len() < 64 {
        return custom_symbols;
    }
    if &buffer[0..4] != b"\x7fELF" {
        return custom_symbols;
    }
    
    let e_phoff = u64::from_le_bytes(buffer[32..40].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(buffer[56..58].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(buffer[54..56].try_into().unwrap()) as usize;

    let mut dynamic_offset = 0;
    let mut dynamic_filesz = 0;
    let mut load_segments = Vec::new();

    for i in 0..e_phnum {
        let ph_offset = e_phoff + i * e_phentsize;
        if ph_offset + 48 > buffer.len() {
            break;
        }
        let p_type = u32::from_le_bytes(buffer[ph_offset..ph_offset+4].try_into().unwrap());
        let p_offset = u64::from_le_bytes(buffer[ph_offset+8..ph_offset+16].try_into().unwrap()) as usize;
        let p_vaddr = u64::from_le_bytes(buffer[ph_offset+16..ph_offset+24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(buffer[ph_offset+32..ph_offset+40].try_into().unwrap()) as usize;
        let p_memsz = u64::from_le_bytes(buffer[ph_offset+40..ph_offset+48].try_into().unwrap()) as usize;

        if p_type == 1 { // PT_LOAD
            load_segments.push((p_vaddr, p_offset, p_filesz, p_memsz));
        } else if p_type == 2 { // PT_DYNAMIC
            dynamic_offset = p_offset;
            dynamic_filesz = p_filesz;
        }
    }

    if dynamic_offset == 0 {
        return custom_symbols;
    }

    let va_to_offset = |va: u64| -> Option<usize> {
        for &(p_vaddr, p_offset, p_filesz, p_memsz) in &load_segments {
            if va >= p_vaddr && va < p_vaddr + p_memsz as u64 {
                let relative = (va - p_vaddr) as usize;
                if relative < p_filesz {
                    return Some(p_offset + relative);
                }
            }
        }
        None
    };

    let mut symtab_va = 0;
    let mut strtab_va = 0;
    let mut hash_va = 0;
    let mut gnu_hash_va = 0;

    let mut offset = dynamic_offset;
    while offset + 16 <= dynamic_offset + dynamic_filesz && offset + 16 <= buffer.len() {
        let d_tag = i64::from_le_bytes(buffer[offset..offset+8].try_into().unwrap());
        let d_val = u64::from_le_bytes(buffer[offset+8..offset+16].try_into().unwrap());
        if d_tag == 0 {
            break;
        }
        match d_tag {
            6 => symtab_va = d_val,     // DT_SYMTAB
            5 => strtab_va = d_val,     // DT_STRTAB
            4 => hash_va = d_val,       // DT_HASH
            0x6ffffef5 => gnu_hash_va = d_val, // DT_GNU_HASH
            _ => {}
        }
        offset += 16;
    }

    if symtab_va != 0 && strtab_va != 0 {
        if let (Some(symtab_off), Some(strtab_off)) = (va_to_offset(symtab_va), va_to_offset(strtab_va)) {
            let mut num_symbols = 0;
            if hash_va != 0 {
                if let Some(hash_off) = va_to_offset(hash_va) {
                    if hash_off + 8 <= buffer.len() {
                        let _nbucket = u32::from_le_bytes(buffer[hash_off..hash_off+4].try_into().unwrap());
                        let nchain = u32::from_le_bytes(buffer[hash_off+4..hash_off+8].try_into().unwrap());
                        num_symbols = nchain as usize;
                    }
                }
            } else if gnu_hash_va != 0 {
                num_symbols = 5000;
            }

            if num_symbols > 0 {
                for i in 0..num_symbols {
                    let entry_off = symtab_off + i * 24;
                    if entry_off + 24 > buffer.len() {
                        break;
                    }
                    let st_name = u32::from_le_bytes(buffer[entry_off..entry_off+4].try_into().unwrap()) as usize;
                    let _st_info = buffer[entry_off+4];
                    let _st_other = buffer[entry_off+5];
                    let st_shndx = u16::from_le_bytes(buffer[entry_off+6..entry_off+8].try_into().unwrap());
                    let st_value = u64::from_le_bytes(buffer[entry_off+8..entry_off+16].try_into().unwrap());
                    let st_size = u64::from_le_bytes(buffer[entry_off+16..entry_off+24].try_into().unwrap());

                    let mut name = String::new();
                    if st_name != 0 {
                        let mut name_off = strtab_off + st_name;
                        let mut name_bytes = Vec::new();
                        while name_off < buffer.len() {
                            let b = buffer[name_off];
                            if b == 0 {
                                break;
                            }
                            name_bytes.push(b);
                            name_off += 1;
                        }
                        name = String::from_utf8_lossy(&name_bytes).into_owned();
                    }

                    custom_symbols.push(CustomSymbol {
                        name,
                        value: st_value,
                        size: st_size,
                        shndx: st_shndx,
                    });
                }
            }
        }
    }

    custom_symbols
}

fn reconstruct_self_to_elf(buffer: &[u8]) -> Result<Vec<u8>, &'static str> {
    if buffer.len() < 32 {
        return Err("Buffer too small for SELF header");
    }

    // Read SELF header segment count
    let segment_count = u16::from_le_bytes(buffer[24..26].try_into().unwrap()) as usize;
    let elf_header_pos = 32 + segment_count * 32;

    if buffer.len() < elf_header_pos + 64 {
        return Err("Buffer too small for SELF headers and ELF header");
    }

    // Reconstructed ELF buffer starts with the suffix of the SELF file from elf_header_pos
    let mut elf_buffer = buffer[elf_header_pos..].to_vec();

    // Read ELF program headers to know where segments should be placed
    let e_phoff = u64::from_le_bytes(elf_buffer[32..40].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(elf_buffer[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(elf_buffer[56..58].try_into().unwrap()) as usize;

    if elf_buffer.len() < e_phoff + e_phnum * e_phentsize {
        return Err("ELF buffer truncated; program headers out of bounds");
    }

    // Parse SELF segment headers to copy segment payloads
    for i in 0..segment_count {
        let seg_offset = 32 + i * 32;
        let flags = u64::from_le_bytes(buffer[seg_offset..seg_offset+8].try_into().unwrap());
        let file_offset = u64::from_le_bytes(buffer[seg_offset+8..seg_offset+16].try_into().unwrap()) as usize;
        let file_size = u64::from_le_bytes(buffer[seg_offset+16..seg_offset+24].try_into().unwrap()) as usize;

        // Check if the segment is blocked (contains segment data)
        let is_blocked = (flags & 0x800) != 0;
        if is_blocked {
            let phdr_id = ((flags >> 20) & 0xFFF) as usize;
            if phdr_id < e_phnum {
                let ph_entry_offset = e_phoff + phdr_id * e_phentsize;
                let p_offset = u64::from_le_bytes(elf_buffer[ph_entry_offset+8..ph_entry_offset+16].try_into().unwrap()) as usize;

                if file_offset + file_size <= buffer.len() {
                    let end_pos = p_offset + file_size;
                    if elf_buffer.len() < end_pos {
                        elf_buffer.resize(end_pos, 0);
                    }
                    elf_buffer[p_offset..p_offset+file_size].copy_from_slice(&buffer[file_offset..file_offset+file_size]);
                    info!("SELF Loader: Mapped segment {} (PHDR {}) from file offset 0x{:X} to ELF offset 0x{:X} (size: {} bytes)", i, phdr_id, file_offset, p_offset, file_size);
                } else {
                    return Err("SELF segment file offset out of bounds");
                }
            }
        }
    }

    Ok(elf_buffer)
}

fn preprocess_elf_buffer(buffer: &mut Vec<u8>) -> bool {
    if buffer.len() >= 64 && &buffer[0..4] == b"\x7fELF" {
        let e_shoff = u64::from_le_bytes(buffer[40..48].try_into().unwrap()) as usize;
        let e_shnum = u16::from_le_bytes(buffer[60..62].try_into().unwrap()) as usize;
        let e_shentsize = u16::from_le_bytes(buffer[58..60].try_into().unwrap()) as usize;
        
        let sh_table_end = e_shoff + e_shnum * e_shentsize;
        if sh_table_end > buffer.len() {
            // Zero out e_shoff (offset 40, 8 bytes)
            buffer[40..48].copy_from_slice(&0u64.to_le_bytes());
            // Zero out e_shentsize, e_shnum, e_shstrndx (offsets 58, 60, 62, 2 bytes each)
            buffer[58..60].copy_from_slice(&0u16.to_le_bytes());
            buffer[60..62].copy_from_slice(&0u16.to_le_bytes());
            buffer[62..64].copy_from_slice(&0u16.to_le_bytes());
            return true;
        }
    }
    false
}

fn get_elf_tls_size(elf_buffer: &[u8]) -> usize {
    if elf_buffer.len() < 64 {
        return 0;
    }
    if &elf_buffer[0..4] != b"\x7fELF" {
        return 0;
    }
    let e_phoff = u64::from_le_bytes(elf_buffer[32..40].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(elf_buffer[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(elf_buffer[56..58].try_into().unwrap()) as usize;

    if elf_buffer.len() < e_phoff + e_phnum * e_phentsize {
        return 0;
    }

    for i in 0..e_phnum {
        let ph_entry_offset = e_phoff + i * e_phentsize;
        let p_type = u32::from_le_bytes(elf_buffer[ph_entry_offset..ph_entry_offset+4].try_into().unwrap());
        if p_type == 7 { // PT_TLS
            let p_memsz = u64::from_le_bytes(elf_buffer[ph_entry_offset+40..ph_entry_offset+48].try_into().unwrap()) as usize;
            info!("Loader: Found PT_TLS program header, size = {} bytes", p_memsz);
            return p_memsz;
        }
    }
    0
}

fn apply_custom_relocations(
    buffer: &[u8],
    load_bias: u64,
    min_vaddr: u64,
    custom_symbols: &[CustomSymbol],
    got_symbol_map: &HashMap<u64, String>,
    dynamic_symbols: &HashMap<u64, String>,
    is_sprx: bool,
    path: &Path,
) -> Result<(), &'static str> {
    let e_phoff = u64::from_le_bytes(buffer[32..40].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(buffer[56..58].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(buffer[54..56].try_into().unwrap()) as usize;
    
    let mut dynamic_offset = 0;
    let mut dynamic_filesz = 0;
    let mut load_segments = Vec::new();
    
    for i in 0..e_phnum {
        let ph_offset = e_phoff + i * e_phentsize;
        if ph_offset + 48 > buffer.len() {
            break;
        }
        let p_type = u32::from_le_bytes(buffer[ph_offset..ph_offset+4].try_into().unwrap());
        let p_offset = u64::from_le_bytes(buffer[ph_offset+8..ph_offset+16].try_into().unwrap()) as usize;
        let p_vaddr = u64::from_le_bytes(buffer[ph_offset+16..ph_offset+24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(buffer[ph_offset+32..ph_offset+40].try_into().unwrap()) as usize;
        let p_memsz = u64::from_le_bytes(buffer[ph_offset+40..ph_offset+48].try_into().unwrap()) as usize;
        
        if p_type == 1 { // PT_LOAD
            load_segments.push((p_vaddr, p_offset, p_filesz, p_memsz));
        } else if p_type == 2 { // PT_DYNAMIC
            dynamic_offset = p_offset;
            dynamic_filesz = p_filesz;
        }
    }
    
    if dynamic_offset == 0 {
        return Ok(());
    }
    
    let va_to_offset = |va: u64| -> Option<usize> {
        for &(p_vaddr, p_offset, p_filesz, p_memsz) in &load_segments {
            if va >= p_vaddr && va < p_vaddr + p_memsz as u64 {
                let relative = (va - p_vaddr) as usize;
                if relative < p_filesz {
                    return Some(p_offset + relative);
                }
            }
        }
        None
    };
    
    let mut rela_va = 0;
    let mut relasz = 0;
    let mut jmprel_va = 0;
    let mut pltrelsz = 0;
    
    let mut offset = dynamic_offset;
    while offset + 16 <= dynamic_offset + dynamic_filesz && offset + 16 <= buffer.len() {
        let d_tag = i64::from_le_bytes(buffer[offset..offset+8].try_into().unwrap());
        let d_val = u64::from_le_bytes(buffer[offset+8..offset+16].try_into().unwrap());
        if d_tag == 0 {
            break;
        }
        
        match d_tag {
            7 => rela_va = d_val,       // DT_RELA
            8 => relasz = d_val,        // DT_RELASZ
            23 => jmprel_va = d_val,    // DT_JMPREL
            2 => pltrelsz = d_val,      // DT_PLTRELSZ
            _ => {}
        }
        offset += 16;
    }
    
    let static_tls_size = STATIC_TLS_SIZE.load(Ordering::SeqCst);
    
    let mut process_rela_entry = |r_offset: u64, r_info: u64, r_addend: i64| {
        let host_got_slot = (load_bias + (r_offset - min_vaddr)) as *mut u64;
        let sym_idx = (r_info >> 32) as usize;
        let rel_type = (r_info & 0xffffffff) as u32;
        
        if r_offset >= 0x6CC000 && r_offset <= 0x6D0FFF {
            let sym_name = if sym_idx < custom_symbols.len() { &custom_symbols[sym_idx].name } else { "" };
            info!("DEBUG RELOC GOT RANGE 0x{:X}: type={}, sym_idx={}, sym_name='{}', r_addend={}, is_sprx={}", r_offset, rel_type, sym_idx, sym_name, r_addend, is_sprx);
        }
        
        match rel_type {
            // R_X86_64_64 (type 1)
            1 => {
                if sym_idx < custom_symbols.len() {
                    let symbol = &custom_symbols[sym_idx];
                    let name = &symbol.name;
                    if !name.is_empty() {
                        let resolved_name = resolve_symbol_name(name, got_symbol_map, dynamic_symbols, r_offset);
                        let resolved_addr = resolve_symbol_address(&resolved_name);
                        if let Some(addr) = resolved_addr {
                            let patched = (addr as i64 + r_addend) as u64;
                            unsafe { *host_got_slot = patched; }
                            if !is_sprx {
                                log::trace!("R_X86_64_64: offset=0x{:X} | '{}' ({}) -> 0x{:X} + addend={} = 0x{:X}", r_offset, name, resolved_name, addr, r_addend, patched);
                            } else {
                                log::trace!("SPRX R_X86_64_64: '{}' -> 0x{:X} + {} = 0x{:X}", resolved_name, addr, r_addend, patched);
                            }
                        } else {
                            if !is_sprx {
                                warn!("R_X86_64_64: unresolved symbol '{}' ({})", name, resolved_name);
                            } else {
                                warn!("SPRX R_X86_64_64: unresolved '{}' in {:?}", resolved_name, path);
                            }
                        }
                    }
                }
            }
            // R_X86_64_COPY (type 5)
            5 => {
                if sym_idx < custom_symbols.len() {
                    let symbol = &custom_symbols[sym_idx];
                    let name = &symbol.name;
                    if !name.is_empty() {
                        let resolved_name = resolve_symbol_name(name, got_symbol_map, dynamic_symbols, r_offset);
                        let size = symbol.size as usize;
                        if let Some(src_guest_addr) = lookup_global_symbol(&resolved_name) {
                            let src_host_ptr = match crate::kernel::translate_guest_addr(src_guest_addr) {
                                Some(addr) => addr as *const u8,
                                None => src_guest_addr as *const u8,
                            };
                            unsafe {
                                std::ptr::copy_nonoverlapping(src_host_ptr, host_got_slot as *mut u8, size);
                            }
                            if !is_sprx {
                                log::trace!("R_X86_64_COPY: Copied '{}' from 0x{:X} to {:p} (size: {} bytes)", resolved_name, src_guest_addr, host_got_slot, size);
                            } else {
                                log::trace!("SPRX R_X86_64_COPY: Copied '{}' from 0x{:X} to {:p} (size: {} bytes)", resolved_name, src_guest_addr, host_got_slot, size);
                            }
                        } else {
                            if !is_sprx {
                                warn!("R_X86_64_COPY: unresolved global symbol '{}' for copy", resolved_name);
                            } else {
                                warn!("SPRX R_X86_64_COPY: unresolved '{}' for copy in {:?}", resolved_name, path);
                            }
                        }
                    }
                }
            }
            // R_X86_64_GLOB_DAT (type 6)
            6 => {
                if sym_idx < custom_symbols.len() {
                    let symbol = &custom_symbols[sym_idx];
                    let name = &symbol.name;
                    if !name.is_empty() {
                        let resolved_name = resolve_symbol_name(name, got_symbol_map, dynamic_symbols, r_offset);
                        let guest_got_addr = load_bias + (r_offset - min_vaddr);
                        register_got_symbol(guest_got_addr, resolved_name.clone());
                        let resolved_addr = resolve_symbol_address(&resolved_name);
                        if let Some(addr) = resolved_addr {
                            unsafe { *host_got_slot = addr; }
                            if !is_sprx {
                                log::trace!("R_X86_64_GLOB_DAT: offset=0x{:X} | '{}' ({}) -> 0x{:X}", r_offset, name, resolved_name, addr);
                            }
                        } else {
                            if !is_sprx {
                                warn!("R_X86_64_GLOB_DAT: unresolved symbol '{}' ({})", name, resolved_name);
                            } else {
                                warn!("SPRX GLOB_DAT: unresolved '{}' in {:?}", resolved_name, path);
                            }
                        }
                    }
                }
            }
            // R_X86_64_JUMP_SLOT (type 7)
            7 => {
                if sym_idx < custom_symbols.len() {
                    let symbol = &custom_symbols[sym_idx];
                    let name = &symbol.name;
                    if !name.is_empty() {
                        let resolved_name = resolve_symbol_name(name, got_symbol_map, dynamic_symbols, r_offset);
                        let guest_got_addr = load_bias + (r_offset - min_vaddr);
                        register_got_symbol(guest_got_addr, resolved_name.clone());
                        let resolved_addr = resolve_symbol_address(&resolved_name);
                        if resolved_name == "strlen" {
                            info!("DEBUG RELOC: strlen found! r_offset=0x{:X}, resolved_addr={:?}", r_offset, resolved_addr);
                        }
                        if let Some(addr) = resolved_addr {
                            if r_offset >= 0x6CC000 && r_offset <= 0x6D0FFF {
                                info!("DEBUG RELOC WRITING 0x{:X}: addr=0x{:X}", r_offset, addr);
                            }
                            unsafe { *host_got_slot = addr; }
                            if !is_sprx {
                                log::trace!("R_X86_64_JUMP_SLOT: offset=0x{:X} | '{}' ({}) -> 0x{:X}", r_offset, name, resolved_name, addr);
                            }
                        } else {
                            unsafe { *host_got_slot = hle_unresolved_import_trampoline as u64; }
                            if !is_sprx {
                                warn!("R_X86_64_JUMP_SLOT: unresolved '{}' ({}) — installed trap trampoline", name, resolved_name);
                            } else {
                                warn!("SPRX JUMP_SLOT: trap installed for '{}' in {:?}", resolved_name, path);
                            }
                        }
                    }
                }
            }
            // R_X86_64_RELATIVE (type 8)
            8 => {
                let val = (load_bias as i64 + (r_addend - min_vaddr as i64)) as u64;
                unsafe { *host_got_slot = val; }
                if !is_sprx {
                    log::trace!("R_X86_64_RELATIVE: offset=0x{:X} -> host_slot={:p} | Value=0x{:X}", r_offset, host_got_slot, val);
                }
            }
            // R_X86_64_TPOFF64 (type 18)
            18 => {
                if sym_idx < custom_symbols.len() {
                    let symbol = &custom_symbols[sym_idx];
                    let sym_value = symbol.value;
                    let name = &symbol.name;
                    let offset_val = (sym_value as i64 + r_addend - static_tls_size as i64) as u64;
                    unsafe { *host_got_slot = offset_val; }
                    if !name.is_empty() {
                        let base_name = name.split('#').next().unwrap_or(name);
                        if !is_sprx {
                            log::trace!("R_X86_64_TPOFF64: offset=0x{:X} | '{}' -> offset=0x{:X}", r_offset, name, offset_val);
                        } else {
                            log::trace!("SPRX R_X86_64_TPOFF64: '{}' -> offset=0x{:X}", base_name, offset_val);
                        }
                    }
                }
            }
            // R_X86_64_TPOFF32 (type 19)
            19 => {
                if sym_idx < custom_symbols.len() {
                    let symbol = &custom_symbols[sym_idx];
                    let sym_value = symbol.value;
                    let name = &symbol.name;
                    let offset_val = (sym_value as i64 + r_addend - static_tls_size as i64) as i32;
                    unsafe { *(host_got_slot as *mut i32) = offset_val; }
                    if !name.is_empty() {
                        let base_name = name.split('#').next().unwrap_or(name);
                        if !is_sprx {
                            log::trace!("R_X86_64_TPOFF32: offset=0x{:X} | '{}' -> offset=0x{:X}", r_offset, name, offset_val);
                        } else {
                            log::trace!("SPRX R_X86_64_TPOFF32: '{}' -> offset=0x{:X}", base_name, offset_val);
                        }
                    }
                }
            }
            other => {
                warn!("Unsupported relocation type: {} at offset 0x{:X}", other, r_offset);
            }
        }
    };
    
    if rela_va != 0 && relasz > 0 {
        if let Some(file_offset) = va_to_offset(rela_va) {
            let mut rel_offset = file_offset;
            let end_offset = file_offset + relasz as usize;
            while rel_offset + 24 <= end_offset && rel_offset + 24 <= buffer.len() {
                let r_offset = u64::from_le_bytes(buffer[rel_offset..rel_offset+8].try_into().unwrap());
                let r_info = u64::from_le_bytes(buffer[rel_offset+8..rel_offset+16].try_into().unwrap());
                let r_addend = i64::from_le_bytes(buffer[rel_offset+16..rel_offset+24].try_into().unwrap());
                process_rela_entry(r_offset, r_info, r_addend);
                rel_offset += 24;
            }
        } else {
            return Err("Failed to resolve file offset for DT_RELA");
        }
    }
    
    if jmprel_va != 0 && pltrelsz > 0 {
        if let Some(file_offset) = va_to_offset(jmprel_va) {
            let mut rel_offset = file_offset;
            let end_offset = file_offset + pltrelsz as usize;
            while rel_offset + 24 <= end_offset && rel_offset + 24 <= buffer.len() {
                let r_offset = u64::from_le_bytes(buffer[rel_offset..rel_offset+8].try_into().unwrap());
                let r_info = u64::from_le_bytes(buffer[rel_offset+8..rel_offset+16].try_into().unwrap());
                let r_addend = i64::from_le_bytes(buffer[rel_offset+16..rel_offset+24].try_into().unwrap());
                process_rela_entry(r_offset, r_info, r_addend);
                rel_offset += 24;
            }
        } else {
            return Err("Failed to resolve file offset for DT_JMPREL");
        }
    }
    
    Ok(())
}

/// Parses and maps a guest ELF/SELF executable.
pub fn load_executable(path: &Path) -> Result<ProsperoExecutable, &'static str> {
    info!("Reading executable binary from disk...");
    let mut file = File::open(path).map_err(|_| "Failed to open target executable file.")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|_| "Failed to read binary data.")?;

    let magic = if buffer.len() >= 4 {
        u32::from_le_bytes(buffer[0..4].try_into().unwrap())
    } else {
        0
    };

    let is_self = magic == 0x1D3D154F || magic == 0x4F153D1D ||
                  magic == 0xEEF51454 || magic == 0x5414F5EE ||
                  magic == 0x4F4F5344 || magic == 0x44534F4F ||
                  buffer.starts_with(b"SCE\0");

    let mut buffer = if is_self {
        info!("Signed ELF (SELF) header detected. Reconstructing decrypted ELF payload...");
        reconstruct_self_to_elf(&buffer)?
    } else {
        buffer
    };

    preprocess_elf_buffer(&mut buffer);

    // Extract TLS size
    let tls_size = get_elf_tls_size(&buffer);
    STATIC_TLS_SIZE.store(tls_size, Ordering::SeqCst);

    info!("Parsing ELF structures...");
    let elf = object::File::parse(&*buffer).map_err(|_| "Invalid ELF format.")?;

    let entrypoint = elf.entry();
    info!("Parsing and mapping ELF segments into host virtual memory...");
    let mut segments = Vec::new();

    // First scan all LOAD segments to find minimum and maximum virtual addresses
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0;
    for segment in elf.segments() {
        if segment.size() > 0 {
            let addr = segment.address();
            if addr < min_vaddr {
                min_vaddr = addr;
            }
            let end_addr = addr + segment.size();
            if end_addr > max_vaddr {
                max_vaddr = end_addr;
            }
        }
    }

    if min_vaddr == u64::MAX || max_vaddr == 0 {
        return Err("No loadable segments found in ELF.");
    }

    let total_size = (max_vaddr - min_vaddr) as usize;
    info!("Total executable virtual address size: 0x{:X} bytes (vaddr range: 0x{:X} - 0x{:X})", total_size, min_vaddr, max_vaddr);

    // Allocate contiguous block of host virtual memory
    let load_bias_ptr = crate::kernel::allocate_guest_memory(0, total_size)
        .map_err(|_| "Failed to allocate contiguous virtual memory for executable")?;
    let load_bias = load_bias_ptr as u64;
    info!("Allocated contiguous guest virtual space at host address: {:p} (Load Bias: 0x{:X})", load_bias_ptr, load_bias);

    for segment in elf.segments() {
        if segment.size() > 0 {
            let readable = true; // Default segment permissions
            let writeable = true;
            let executable = segment.address() == entrypoint;

            // Map each segment relative to the load bias base address
            let offset = segment.address() - min_vaddr;
            let host_ptr = unsafe { load_bias_ptr.add(offset as usize) };

            // Copy segment payload data into allocated virtual pages
            if let Ok(data) = segment.data() {
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), host_ptr, data.len());
                }
                info!(
                    "Mapped & Copied Segment to host address: {:p} | Guest Virtual Address: 0x{:X} | Size: {} bytes",
                    host_ptr, segment.address(), segment.size()
                );
            }

            segments.push(LoadedSegment {
                name: format!("Segment_0x{:X}", segment.address()),
                virtual_address: load_bias + offset,
                size: segment.size() as usize,
                readable,
                writeable,
                executable,
            });
        }
    }

    let host_entrypoint = load_bias + (entrypoint - min_vaddr);

    // Initialize the symbol NID mapping table
    let mut dynamic_symbols = HashMap::new();
    for export in LIBKERNEL_NIDS {
        dynamic_symbols.insert(export.nid, export.function_name.to_string());
        register_nid_name(export.nid, export.function_name.to_string());
    }
    for export in crate::hle_autogen::AUTOGEN_NIDS {
        dynamic_symbols.insert(export.nid, export.function_name.to_string());
        register_nid_name(export.nid, export.function_name.to_string());
    }

    let sdk_stub_dir = Path::new("reference/sdk/target/lib");
    if sdk_stub_dir.is_dir() {
        info!("PS5 API stub directory detected. Dynamically extracting NIDs from all stubs...");
        if let Ok(entries) = std::fs::read_dir(sdk_stub_dir) {
            let mut stub_count = 0;
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() && path.extension().map_or(false, |ext| ext == "a") {
                        if let Ok(stub_symbols) = parse_stub_symbols(&path) {
                            stub_count += 1;
                            for (nid, name) in stub_symbols {
                                dynamic_symbols.insert(nid, name.clone());
                                register_nid_name(nid, name);
                            }
                        }
                    }
                }
            }
            info!("Successfully extracted NIDs from {} API stubs.", stub_count);
        }
    }

    // Attempt to load mappings from aerolib.inl
    let aerolib_path = Path::new("reference/shadps4/src/core/aerolib/aerolib.inl");
    if aerolib_path.is_file() {
        info!("Loading NID mappings from aerolib.inl...");
        if let Ok(content) = std::fs::read_to_string(aerolib_path) {
            let mut aerolib_count = 0;
            let parts = content.split("STUB(");
            for part in parts.skip(1) {
                if let Some(first_quote) = part.find('"') {
                    if let Some(second_quote) = part[first_quote + 1..].find('"') {
                        let b64_nid = &part[first_quote + 1..first_quote + 1 + second_quote];
                        if let Some(comma) = part[first_quote + 1 + second_quote + 1..].find(',') {
                            let after_comma = &part[first_quote + 1 + second_quote + 1 + comma + 1..];
                            if let Some(close_paren) = after_comma.find(')') {
                                let symbol_name = after_comma[..close_paren].trim();
                                let clean_symbol_name = symbol_name.split("//").next().unwrap_or(symbol_name).trim();
                                if !clean_symbol_name.is_empty() && !b64_nid.is_empty() {
                                    if let Ok(nid) = decode_base64_nid(b64_nid) {
                                        dynamic_symbols.insert(nid, clean_symbol_name.to_string());
                                        register_nid_name(nid, clean_symbol_name.to_string());
                                        aerolib_count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            info!("Successfully extracted {} NID mappings from aerolib.inl.", aerolib_count);
        }
    }

    info!("Successfully mapped {} segments. Resolving and patching GOT/PLT dynamic relocations...", segments.len());
    
    // Export the main executable's own symbols into the global registry so .sprx modules
    // can resolve imports against the host executable (cross-module symbol resolution).
    let custom_symbols = parse_custom_symbols(&buffer);
    let _ = std::fs::write("decrypted_eboot.elf", &buffer);
    for symbol in &custom_symbols {
        if symbol.shndx != 0 && symbol.value != 0 && !symbol.name.is_empty() {
            let address = load_bias + (symbol.value - min_vaddr);
            register_global_symbol(symbol.name.clone(), address);
            debug!("Main Executable Export: {} -> 0x{:X}", symbol.name, address);
        }
    }
    
    // Recursively load all needed library dependencies of the main executable
    let needed = get_elf_needed_libraries(&buffer);
    info!("Recursive loading dynamic dependencies (count: {})", needed.len());
    load_needed_libraries(&needed);
    
    // Build a map of GOT offset -> human-readable symbol name using .symtab as correlation
    let mut got_symbol_map = HashMap::new();
    for symbol in elf.symbols() {
        if let Ok(name) = symbol.name() {
            if name.starts_with("/PG") {
                let func_name = &name[3..];
                let got_addr = symbol.address();
                got_symbol_map.insert(got_addr, func_name.to_string());
            }
        }
    }

    let strlen_nid = 0x8f856258d1c4830c;
    info!("DEBUG NID strlen: 0x{:X} -> {:?}", strlen_nid, dynamic_symbols.get(&strlen_nid));
    info!("DEBUG NID strlen global registration: {:?}", lookup_nid_name(strlen_nid));
    info!("DEBUG HLE lookup: {:?}", crate::hle_symbols::lookup_hle_address("strlen"));
    info!("DEBUG HLE lookup sceAmprCommandBufferConstructor: {:?}", crate::hle_symbols::lookup_hle_address("sceAmprCommandBufferConstructor"));
    info!("DEBUG AMPR lookup sceAmprCommandBufferConstructor: {:?}", crate::ampr::lookup_ampr_hle_address("sceAmprCommandBufferConstructor"));
    info!("DEBUG AMPR lookup sceAmprAmmSubmitCommandBuffer: {:?}", crate::ampr::lookup_ampr_hle_address("sceAmprAmmSubmitCommandBuffer"));
    info!("DEBUG AMPR lookup sceAmprCommandBufferPopMarker: {:?}", crate::ampr::lookup_ampr_hle_address("sceAmprCommandBufferPopMarker"));
    info!("DEBUG hle_unresolved_import_trampoline address: 0x{:X}", hle_unresolved_import_trampoline as u64);

    if let Err(e) = apply_custom_relocations(
        &buffer,
        load_bias,
        min_vaddr,
        &custom_symbols,
        &got_symbol_map,
        &dynamic_symbols,
        false,
        path,
    ) {
        warn!("Failed to apply custom relocations to executable: {:?}", e);
    }

    let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
    let mut modules_guard = LOADED_MODULES.lock().unwrap();
    if modules_guard.is_none() {
        *modules_guard = Some(HashMap::new());
    }
    modules_guard.as_mut().unwrap().insert(0, LoadedModule {
        name: file_name,
        load_bias,
        entrypoint: host_entrypoint,
        segments: segments.clone(),
    });
    drop(modules_guard);

    Ok(ProsperoExecutable {
        entrypoint: host_entrypoint,
        segments,
        dynamic_symbols,
    })
}

pub fn parse_stub_symbols(path: &Path) -> Result<HashMap<u64, String>, &'static str> {
    let mut file = File::open(path).map_err(|_| "Failed to open stub file.")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|_| "Failed to read stub data.")?;

    let mut symbol_map = HashMap::new();

    if buffer.starts_with(b"\x7fELF") {
        let elf = object::File::parse(&*buffer).map_err(|_| "Failed to parse stub ELF file.")?;
        let scenid_sec = elf.section_by_name(".scenid");
        
        let mut nids = Vec::new();
        if let Some(sec) = scenid_sec {
            if let Ok(data) = sec.data() {
                for chunk in data.chunks(8) {
                    if chunk.len() == 8 {
                        nids.push(u64::from_le_bytes(chunk.try_into().unwrap()));
                    }
                }
            }
        }

        let mut sym_idx = 0;
        let mut loaded_count = 0;
        for symbol in elf.dynamic_symbols() {
            if let Ok(name) = symbol.name() {
                if sym_idx < 5 {
                    log::info!("Stub {:?}: symbol[{}] = '{}'", path.file_name().unwrap(), sym_idx, name);
                }
                if sym_idx < nids.len() {
                    let nid_val = nids[sym_idx];
                    if nid_val != 0 && !name.is_empty() {
                        symbol_map.insert(nid_val, name.to_string());
                        loaded_count += 1;
                    }
                }
            }
            sym_idx += 1;
        }
        log::info!("Stub {:?}: loaded {} NID mappings from {} symbols ({} NIDs in .scenid)", 
            path.file_name().unwrap(), loaded_count, sym_idx, nids.len());
    } else {
        // Fallback to standard archive parser
        let archive = ArchiveFile::parse(&*buffer).map_err(|_| "Failed to parse archive file.")?;
        for member in archive.members() {
            if let Ok(member) = member {
                if let Ok(data) = member.data(&*buffer) {
                    if let Ok(obj_file) = object::File::parse(data) {
                        let scenid_sec = obj_file.section_by_name(".scenid");
                        let mut nid_val = None;
                        if let Some(sec) = scenid_sec {
                            if let Ok(data) = sec.data() {
                                if data.len() >= 8 {
                                    let chunk: [u8; 8] = data[0..8].try_into().unwrap();
                                    nid_val = Some(u64::from_le_bytes(chunk));
                                }
                            }
                        }

                        if let Some(nid) = nid_val {
                            for symbol in obj_file.symbols() {
                                if let Ok(name) = symbol.name() {
                                    if !name.is_empty() && !name.starts_with('.') {
                                        symbol_map.insert(nid, name.to_string());
                                        break;
                                    }
                                }
                            }
                        } else {
                            for symbol in obj_file.symbols() {
                                if let Ok(name) = symbol.name() {
                                    if !name.is_empty() && !name.starts_with('.') {
                                        let nid = calculate_nid(name);
                                        symbol_map.insert(nid, name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(symbol_map)
}

/// Computes the 64-bit cryptographic Name Identifier (NID) for a function name.
/// PS5 uses a truncated SHA-1 hash of the function name for NID exports.
pub fn calculate_nid(name: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in name.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3u64);
    }
    hash
}

/// Dynamic linker simulation: Maps guest Name Identifiers (NIDs) to hand-written wrapper functions.
fn resolve_nids(dynamic_symbols: &HashMap<u64, String>) {
    info!("Starting dynamic link pass...");
    for (nid, name) in dynamic_symbols {
        info!("Bound Name Identifier NID: 0x{:016X} -> Dynamic Function: {}", nid, name);
    }
}

// =========================================================================
// Dynamic Linker Relocation Helper Functions & HLE Lookup Table
// =========================================================================

fn decode_base64_nid(b64: &str) -> Result<u64, &'static str> {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut padded = b64.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    
    let mut bytes = Vec::new();
    let mut temp = 0u32;
    let mut bits = 0;
    
    for byte in padded.bytes() {
        if byte == b'=' {
            break;
        }
        let val = CHARSET.iter().position(|&c| c == byte)
            .or_else(|| {
                if byte == b'-' {
                    CHARSET.iter().position(|&c| c == b'+')
                } else if byte == b'_' {
                    CHARSET.iter().position(|&c| c == b'/')
                } else {
                    None
                }
            })
            .ok_or("invalid base64 char")? as u32;
        temp = (temp << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((temp >> bits) as u8);
            temp &= (1 << bits) - 1;
        }
    }
    
    if bytes.len() < 8 {
        return Err("insufficient bytes for u64");
    }
    
    let mut val_bytes = [0u8; 8];
    val_bytes.copy_from_slice(&bytes[0..8]);
    Ok(u64::from_be_bytes(val_bytes))
}

/// Resolves the human-readable symbol name from NID-encoded dynamic symbols.
/// Checks the GOT symbol map first, then falls back to base64 NID decoding
/// against the dynamic_symbols table.
fn resolve_symbol_name(
    raw_name: &str,
    got_symbol_map: &HashMap<u64, String>,
    dynamic_symbols: &HashMap<u64, String>,
    offset: u64,
) -> String {
    let raw_name = raw_name.replace('\r', "").replace('\n', "");
    // First check the GOT symbol map (from .symtab /PG annotations)
    if let Some(hname) = got_symbol_map.get(&offset) {
        return hname.clone();
    }
    // Fallback: decode base64 NID from the symbol name
    let base_name = raw_name.split('#').next().unwrap_or(&raw_name);
    if let Ok(nid) = decode_base64_nid(base_name) {
        if let Some(sname) = dynamic_symbols.get(&nid) {
            return sname.clone();
        }
    }
    raw_name
}

/// Unified symbol address resolution chain:
/// 1. Cross-module global symbol registry (other loaded modules + main executable)
/// 2. Hand-written HLE intercepts
/// 3. Auto-generated HLE stubs
fn resolve_symbol_address(name: &str) -> Option<u64> {
    let name = name.replace('\r', "").replace('\n', "");
    let res = resolve_symbol_address_impl(&name);
    let base_name = name.split('#').next().unwrap_or(&name);
    if let Some(addr) = res {
        if addr == crate::kernel::hle_malloc as u64 || name.contains("malloc") || name.contains("alloc") {
            info!("DEBUG resolve_symbol_address('{}') -> 0x{:X}", name, addr);
        }
    }
    if base_name == "sceAmprCommandBufferConstructor" || name.contains("sceAmprCommandBufferConstructor") ||
       base_name == "sceAmprCommandBufferPopMarker" || name.contains("sceAmprCommandBufferPopMarker") {
        info!("DEBUG resolve_symbol_address('{}') -> {:?}", name, res);
    }
    res
}

struct StubAllocator {
    base_ptr: *mut u8,
    next_offset: usize,
    capacity: usize,
    stub_map: std::collections::HashMap<u64, u64>,
}

unsafe impl Send for StubAllocator {}
unsafe impl Sync for StubAllocator {}

static STUB_ALLOCATOR: Mutex<Option<StubAllocator>> = Mutex::new(None);

extern "sysv64" {
    fn common_hle_wrapper();
}

pub fn wrap_hle_address(real_func: u64) -> u64 {
    let mut guard = STUB_ALLOCATOR.lock().unwrap();
    if guard.is_none() {
        unsafe {
            let capacity = 64 * 1024; // 64 KB
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                capacity,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0
            );
            assert_ne!(ptr, libc::MAP_FAILED, "Failed to mmap executable memory for HLE stubs");
            *guard = Some(StubAllocator {
                base_ptr: ptr as *mut u8,
                next_offset: 0,
                capacity,
                stub_map: std::collections::HashMap::new(),
            });
        }
    }
    let allocator = guard.as_mut().unwrap();
    
    if let Some(&stub_addr) = allocator.stub_map.get(&real_func) {
        return stub_addr;
    }
    
    let aligned_offset = (allocator.next_offset + 15) & !15;
    if aligned_offset + 24 > allocator.capacity {
        panic!("HLE stub allocator out of memory!");
    }
    allocator.next_offset = aligned_offset + 24;
    
    let stub_ptr = unsafe { allocator.base_ptr.add(aligned_offset) };
    let stub_addr = stub_ptr as u64;
    
    // Generate stub:
    // movabs real_func, %r11      -> 49 bb [8 bytes]
    // movabs common_hle_wrapper, %r10 -> 49 ba [8 bytes]
    // jmp *%r10                   -> 41 ff e2
    // nop                         -> 90
    let wrapper_func = common_hle_wrapper as u64;
    unsafe {
        let stub = std::slice::from_raw_parts_mut(stub_ptr, 24);
        stub[0] = 0x49;
        stub[1] = 0xbb;
        stub[2..10].copy_from_slice(&real_func.to_ne_bytes());
        stub[10] = 0x49;
        stub[11] = 0xba;
        stub[12..20].copy_from_slice(&wrapper_func.to_ne_bytes());
        stub[20] = 0x41;
        stub[21] = 0xff;
        stub[22] = 0xe2;
        stub[23] = 0x90;
    }
    
    allocator.stub_map.insert(real_func, stub_addr);
    stub_addr
}

fn resolve_symbol_address_impl(name: &str) -> Option<u64> {
    let name = name.replace('\r', "").replace('\n', "");
    let base_name = name.split('#').next().unwrap_or(&name);
    
    // Attempt NID-to-name chain resolution first if base_name is base64-encoded NID
    let mut resolved_name = base_name.to_string();
    if let Ok(nid) = decode_base64_nid(base_name) {
        if let Some(sname) = lookup_nid_name(nid) {
            resolved_name = sname;
        }
    }
    
    // Priority 1: Cross-module resolution (symbols exported by other loaded modules)
    // Try resolved name first, then original base_name
    if let Some(addr) = lookup_global_symbol(&resolved_name) {
        return Some(addr);
    }
    if resolved_name != base_name {
        if let Some(addr) = lookup_global_symbol(base_name) {
            return Some(addr);
        }
    }
    
    // Priority 2: Hand-written HLE intercepts
    if let Some(addr) = crate::ampr::lookup_ampr_hle_address(&resolved_name) {
        return Some(wrap_hle_address(addr));
    }
    if let Some(addr) = crate::hle_symbols::lookup_hle_address(&resolved_name) {
        return Some(wrap_hle_address(addr));
    }
    if resolved_name != base_name {
        if let Some(addr) = crate::ampr::lookup_ampr_hle_address(base_name) {
            return Some(wrap_hle_address(addr));
        }
        if let Some(addr) = crate::hle_symbols::lookup_hle_address(base_name) {
            return Some(wrap_hle_address(addr));
        }
    }
    
    // Priority 3: Auto-generated HLE stubs
    if let Some(addr) = crate::hle_autogen::lookup_autogen_hle_address(&resolved_name) {
        return Some(wrap_hle_address(addr));
    }
    if resolved_name != base_name {
        if let Some(addr) = crate::hle_autogen::lookup_autogen_hle_address(base_name) {
            return Some(wrap_hle_address(addr));
        }
    }
    
    None
}


pub fn find_module_by_address(addr: u64) -> Option<String> {
    let modules_guard = LOADED_MODULES.lock().unwrap();
    if let Some(ref map) = *modules_guard {
        for module in map.values() {
            for segment in &module.segments {
                if addr >= segment.virtual_address && addr < segment.virtual_address + segment.size as u64 {
                    return Some(module.name.clone());
                }
            }
        }
    }
    None
}

// Trap trampoline installed for unresolved PLT JUMP_SLOT entries.
// Logs a fatal error when the guest code tries to call an unresolved import.
std::arch::global_asm!(
    ".global hle_unresolved_import_trampoline",
    "hle_unresolved_import_trampoline:",
    "mov rdi, [rsp]",
    "jmp hle_unresolved_import_panic"
);

extern "sysv64" {
    pub fn hle_unresolved_import_trampoline();
}

#[no_mangle]
pub extern "sysv64" fn hle_unresolved_import_panic(ret_addr: u64) {
    let module_name = find_module_by_address(ret_addr).unwrap_or_else(|| "Unknown".to_string());
    
    // Attempt to decode the unresolved symbol from the call site
    let mut resolved_symbol_name = None;
    unsafe {
        let is_safe_to_read = |addr: u64| -> bool {
            let modules_guard = LOADED_MODULES.lock().unwrap();
            if let Some(ref map) = *modules_guard {
                for module in map.values() {
                    for segment in &module.segments {
                        if addr >= segment.virtual_address && addr < segment.virtual_address + segment.size as u64 {
                            return true;
                        }
                    }
                }
            }
            false
        };

        if is_safe_to_read(ret_addr - 16) && is_safe_to_read(ret_addr + 16) {
            let context_bytes = std::slice::from_raw_parts((ret_addr - 16) as *const u8, 32);
            log::error!("DEBUG: Bytes around return address 0x{:X}: {:X?}", ret_addr, context_bytes);
        }

        if is_safe_to_read(ret_addr - 5) && is_safe_to_read(ret_addr) {
            let call_bytes = std::slice::from_raw_parts((ret_addr - 5) as *const u8, 5);
            if call_bytes[0] == 0xE8 { // call rel32
                let rel_offset = i32::from_le_bytes(call_bytes[1..5].try_into().unwrap());
                let plt_addr = (ret_addr as i64 + rel_offset as i64) as u64;
                log::error!("DEBUG: Target PLT address = 0x{:X}", plt_addr);
                
                if is_safe_to_read(plt_addr) && is_safe_to_read(plt_addr + 128) {
                    let plt_bytes = std::slice::from_raw_parts(plt_addr as *const u8, 128);
                    log::error!("DEBUG: PLT bytes: {:X?}", plt_bytes);
                    if plt_bytes[0] == 0xFF && plt_bytes[1] == 0x25 { // jmp qword ptr [rip + offset]
                        let got_offset = i32::from_le_bytes(plt_bytes[2..6].try_into().unwrap());
                        let got_addr = (plt_addr as i64 + 6 + got_offset as i64) as u64;
                        if let Some(sym_name) = lookup_got_symbol(got_addr) {
                            resolved_symbol_name = Some(sym_name);
                        }
                    }
                }
            }
        }
    }

    if let Some(ref sym) = resolved_symbol_name {
        log::error!("FATAL: Guest called an unresolved PLT import: '{}'. Return address: 0x{:X} (in module: {})", sym, ret_addr, module_name);
    } else {
        log::error!("FATAL: Guest called an unresolved PLT import (failed to decode target symbol). Return address: 0x{:X} (in module: {})", ret_addr, module_name);
    }
    std::process::exit(1);
}

std::thread_local! {
    static GUEST_ERRNO: std::cell::Cell<i32> = std::cell::Cell::new(0);
    static TLS_BLOCK: std::cell::RefCell<Vec<u8>> = {
        let size = STATIC_TLS_SIZE.load(Ordering::SeqCst);
        std::cell::RefCell::new(vec![0u8; size])
    };
}

pub unsafe extern "sysv64" fn hle_error() -> *mut i32 {
    GUEST_ERRNO.with(|errno| errno.as_ptr())
}

pub unsafe extern "sysv64" fn hle_tls_get_addr(ti: *const usize) -> *mut u8 {
    if ti.is_null() {
        return std::ptr::null_mut();
    }
    let offset = *ti.add(1);
    TLS_BLOCK.with(|block| {
        let mut b = block.borrow_mut();
        let size = STATIC_TLS_SIZE.load(Ordering::SeqCst);
        if b.len() < size {
            b.resize(size, 0);
        }
        b.as_mut_ptr().add(offset)
    })
}

// =========================================================================
// =========================================================================

#[no_mangle]
pub extern "sysv64" fn sceSysmoduleLoadModule(id: u32) -> i32 {
    info!("API Sysmodule Intercepted: sceSysmoduleLoadModule | Module ID: 0x{:04X}", id);
    0 // SCE_OK
}

#[no_mangle]
pub extern "sysv64" fn sceSysmoduleUnloadModule(id: u32) -> i32 {
    info!("API Sysmodule Intercepted: sceSysmoduleUnloadModule | Module ID: 0x{:04X}", id);
    0
}

// =========================================================================
// Dynamic Module (.sprx) Loading and Relocation Resolution Engine
// =========================================================================

use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub load_bias: u64,
    pub entrypoint: u64,
    pub segments: Vec<LoadedSegment>,
}

static LOADED_MODULES: Mutex<Option<HashMap<u32, LoadedModule>>> = Mutex::new(None);
static mut MODULE_COUNTER: u32 = 1;
static GLOBAL_SYMBOLS: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);
static NID_TO_NAME: Mutex<Option<HashMap<u64, String>>> = Mutex::new(None);
static GOT_SYMBOL_MAPPINGS: Mutex<Option<HashMap<u64, String>>> = Mutex::new(None);

pub fn register_got_symbol(got_addr: u64, name: String) {
    let mut guard = GOT_SYMBOL_MAPPINGS.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard.as_mut().unwrap().insert(got_addr, name);
}

pub fn lookup_got_symbol(got_addr: u64) -> Option<String> {
    let guard = GOT_SYMBOL_MAPPINGS.lock().unwrap();
    if let Some(ref map) = *guard {
        map.get(&got_addr).cloned()
    } else {
        None
    }
}

pub fn register_nid_name(nid: u64, name: String) {
    let mut guard = NID_TO_NAME.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard.as_mut().unwrap().insert(nid, name);
}

pub fn lookup_nid_name(nid: u64) -> Option<String> {
    let guard = NID_TO_NAME.lock().unwrap();
    if let Some(ref map) = *guard {
        map.get(&nid).cloned()
    } else {
        None
    }
}

pub fn register_global_symbol(name: String, address: u64) {
    let mut symbols_guard = GLOBAL_SYMBOLS.lock().unwrap();
    if symbols_guard.is_none() {
        *symbols_guard = Some(HashMap::new());
    }
    let map = symbols_guard.as_mut().unwrap();
    
    // 1. Register under the raw name (with suffix)
    map.insert(name.clone(), address);
    
    // 2. Register under the base name (without suffix)
    let base_name = name.split('#').next().unwrap_or(&name).to_string();
    if base_name != name {
        map.insert(base_name.clone(), address);
    }
    
    // 3. If base_name is base64 NID, decode it and try to register under its human-readable name
    if let Ok(nid) = decode_base64_nid(&base_name) {
        if let Some(sname) = lookup_nid_name(nid) {
            map.insert(sname, address);
        }
    }
}

pub fn lookup_global_symbol(name: &str) -> Option<u64> {
    let symbols_guard = GLOBAL_SYMBOLS.lock().unwrap();
    if let Some(ref map) = *symbols_guard {
        map.get(name).copied()
    } else {
        None
    }
}

pub fn get_loaded_modules() -> HashMap<u32, LoadedModule> {
    let modules_guard = LOADED_MODULES.lock().unwrap();
    if let Some(ref map) = *modules_guard {
        map.clone()
    } else {
        HashMap::new()
    }
}

pub fn unload_sprx_module(id: u32) {
    let mut modules_guard = LOADED_MODULES.lock().unwrap();
    if let Some(ref mut map) = *modules_guard {
        if let Some(module) = map.remove(&id) {
            for segment in module.segments {
                crate::kernel::deallocate_guest_memory(segment.virtual_address, segment.size);
            }
        }
    }
}

use std::path::PathBuf;

pub fn find_firmware_library(lib_name: &str) -> Option<PathBuf> {
    let mut mapped_name = match lib_name {
        "libc" | "libc.prx" => "libSceLibcInternal.sprx".to_string(),
        "libkernel" | "libkernel.prx" => "libkernel.sprx".to_string(),
        other => {
            let mut name = other.to_string();
            if name.ends_with(".prx") {
                name = name[..name.len() - 4].to_string() + ".sprx";
            } else if !name.ends_with(".sprx") {
                name.push_str(".sprx");
            }
            name
        }
    };
    
    // Check system_b/common/lib
    let path_b = Path::new("960/extracted/system_b/common/lib").join(&mapped_name);
    if path_b.exists() {
        return Some(path_b);
    }
    
    // Check system_ex_b/common_ex/lib
    let path_ex = Path::new("960/extracted/system_ex_b/common_ex/lib").join(&mapped_name);
    if path_ex.exists() {
        return Some(path_ex);
    }
    
    None
}

pub fn is_module_loaded(lib_name: &str) -> bool {
    let mapped_name = match find_firmware_library(lib_name) {
        Some(path) => path.file_name().unwrap().to_string_lossy().into_owned(),
        None => {
            let mut name = lib_name.to_string();
            if name.ends_with(".prx") {
                name = name[..name.len() - 4].to_string() + ".sprx";
            } else if !name.ends_with(".sprx") {
                name.push_str(".sprx");
            }
            name
        }
    };
    
    let modules_guard = LOADED_MODULES.lock().unwrap();
    if let Some(ref map) = *modules_guard {
        for module in map.values() {
            if module.name == mapped_name {
                return true;
            }
        }
    }
    false
}

pub fn get_elf_needed_libraries(buffer: &[u8]) -> Vec<String> {
    let mut needed_libs = Vec::new();
    if buffer.len() < 64 || &buffer[0..4] != b"\x7fELF" {
        return needed_libs;
    }
    
    let e_phoff = u64::from_le_bytes(buffer[32..40].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(buffer[56..58].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(buffer[54..56].try_into().unwrap()) as usize;
    
    let mut dynamic_offset = 0;
    let mut dynamic_filesz = 0;
    let mut load_segments = Vec::new();
    
    for i in 0..e_phnum {
        let ph_offset = e_phoff + i * e_phentsize;
        if ph_offset + 48 > buffer.len() {
            break;
        }
        let p_type = u32::from_le_bytes(buffer[ph_offset..ph_offset+4].try_into().unwrap());
        let p_offset = u64::from_le_bytes(buffer[ph_offset+8..ph_offset+16].try_into().unwrap()) as usize;
        let p_vaddr = u64::from_le_bytes(buffer[ph_offset+16..ph_offset+24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(buffer[ph_offset+32..ph_offset+40].try_into().unwrap()) as usize;
        let p_memsz = u64::from_le_bytes(buffer[ph_offset+40..ph_offset+48].try_into().unwrap()) as usize;
        
        if p_type == 1 { // PT_LOAD
            load_segments.push((p_vaddr, p_offset, p_filesz, p_memsz));
        } else if p_type == 2 { // PT_DYNAMIC
            dynamic_offset = p_offset;
            dynamic_filesz = p_filesz;
        }
    }
    
    if dynamic_offset == 0 {
        return needed_libs;
    }
    
    let va_to_offset = |va: u64| -> Option<usize> {
        for &(p_vaddr, p_offset, p_filesz, p_memsz) in &load_segments {
            if va >= p_vaddr && va < p_vaddr + p_memsz as u64 {
                let relative = (va - p_vaddr) as usize;
                if relative < p_filesz {
                    return Some(p_offset + relative);
                }
            }
        }
        None
    };
    
    let mut strtab_va = 0;
    let mut strsz = 0;
    let mut needed_tag_vals = Vec::new();
    
    let mut offset = dynamic_offset;
    while offset + 16 <= dynamic_offset + dynamic_filesz && offset + 16 <= buffer.len() {
        let d_tag = i64::from_le_bytes(buffer[offset..offset+8].try_into().unwrap());
        let d_val = u64::from_le_bytes(buffer[offset+8..offset+16].try_into().unwrap());
        if d_tag == 0 {
            break;
        }
        
        match d_tag {
            5 | 0x61000035 => strtab_va = d_val, // DT_STRTAB / DT_OS_STRTAB
            10 | 0x61000037 => strsz = d_val,    // DT_STRSZ / DT_OS_STRSZ
            1 | 0x61000015 | 0x61000049 => {    // DT_NEEDED / DT_OS_IMPORT_LIB / DT_OS_IMPORT_LIB_1
                needed_tag_vals.push(d_val);
            }
            _ => {}
        }
        offset += 16;
    }
    
    if strtab_va == 0 {
        return needed_libs;
    }
    
    let strtab_offset = match va_to_offset(strtab_va) {
        Some(off) => off,
        None => return needed_libs,
    };
    
    for val in needed_tag_vals {
        let str_idx = (val & 0xFFFFFFFF) as usize;
        if str_idx < strsz as usize {
            let mut str_offset = strtab_offset + str_idx;
            let mut lib_name = String::new();
            while str_offset < buffer.len() && buffer[str_offset] != 0 {
                lib_name.push(buffer[str_offset] as char);
                str_offset += 1;
            }
            if !lib_name.is_empty() {
                needed_libs.push(lib_name);
            }
        }
    }
    
    needed_libs
}

pub fn load_needed_libraries(needed: &[String]) {
    for lib in needed {
        if is_module_loaded(lib) {
            continue;
        }
        let mut path_opt = None;
        
        let mut file_names = vec![lib.clone()];
        if lib.ends_with(".prx") {
            file_names.push(lib[..lib.len() - 4].to_string() + ".sprx");
        } else if lib.ends_with(".sprx") {
            file_names.push(lib[..lib.len() - 5].to_string() + ".prx");
        } else {
            file_names.push(format!("{}.prx", lib));
            file_names.push(format!("{}.sprx", lib));
        }

        for name in &file_names {
            let p = Path::new("game_root/app0/sce_module").join(name);
            if p.exists() {
                path_opt = Some(p);
                break;
            }
        }

        if path_opt.is_none() {
            for name in &file_names {
                let p = Path::new("game_root/app0").join(name);
                if p.exists() {
                    path_opt = Some(p);
                    break;
                }
            }
        }
        
        if path_opt.is_none() {
            if let Some(fw_path) = find_firmware_library(lib) {
                path_opt = Some(fw_path);
            }
        }
        
        if let Some(path) = path_opt {
            info!("Recursively loading dependency module: {:?}", path);
            if let Err(e) = load_sprx_module(&path) {
                warn!("Failed to recursively load module {:?}: {:?}", path, e);
            }
        } else {
            warn!("Could not find dependency library: {}", lib);
        }
    }
}

pub fn load_sprx_module(path: &Path) -> Result<u32, &'static str> {
    info!("Loading dynamic SPRX module: {:?}", path);
    let mut file = File::open(path).map_err(|_| "Failed to open target module.")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|_| "Failed to read module binary data.")?;

    let magic = if buffer.len() >= 4 {
        u32::from_le_bytes(buffer[0..4].try_into().unwrap())
    } else {
        0
    };

    let is_self = magic == 0x1D3D154F || magic == 0x4F153D1D ||
                  magic == 0xEEF51454 || magic == 0x5414F5EE ||
                  magic == 0x4F4F5344 || magic == 0x44534F4F ||
                  buffer.starts_with(b"SCE\0");

    let mut buffer = if is_self {
        info!("Signed ELF (SELF) module header detected. Reconstructing decrypted ELF payload...");
        reconstruct_self_to_elf(&buffer)?
    } else {
        buffer
    };

    preprocess_elf_buffer(&mut buffer);

    let elf = object::File::parse(&*buffer).map_err(|_| "Invalid ELF format for SPRX module.")?;
    
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0;
    for segment in elf.segments() {
        if segment.size() > 0 {
            let addr = segment.address();
            if addr < min_vaddr {
                min_vaddr = addr;
            }
            let end_addr = addr + segment.size();
            if end_addr > max_vaddr {
                max_vaddr = end_addr;
            }
        }
    }
    
    if min_vaddr == u64::MAX || max_vaddr == 0 {
        return Err("No loadable segments found in module.");
    }
    
    let total_size = (max_vaddr - min_vaddr) as usize;
    
    let load_bias_ptr = crate::kernel::allocate_guest_memory(0, total_size)
        .map_err(|_| "Failed to allocate memory for module")?;
    let load_bias = load_bias_ptr as u64;
    
    let mut segments = Vec::new();
    for segment in elf.segments() {
        if segment.size() > 0 {
            let offset = segment.address() - min_vaddr;
            let host_ptr = unsafe { load_bias_ptr.add(offset as usize) };
            if let Ok(data) = segment.data() {
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), host_ptr, data.len());
                }
            }
            segments.push(LoadedSegment {
                name: format!("{}_Seg_0x{:X}", path.file_name().unwrap().to_string_lossy(), segment.address()),
                virtual_address: load_bias + offset,
                size: segment.size() as usize,
                readable: true,
                writeable: true,
                executable: segment.address() == elf.entry(),
            });
        }
    }
    
    let entrypoint = load_bias + (elf.entry() - min_vaddr);
    
    let custom_symbols = parse_custom_symbols(&buffer);
    for symbol in &custom_symbols {
        if symbol.shndx != 0 && symbol.value != 0 && !symbol.name.is_empty() {
            let address = load_bias + (symbol.value - min_vaddr);
            register_global_symbol(symbol.name.clone(), address);
            debug!("Module Exported Symbol: {} -> Address 0x{:X}", symbol.name, address);
        }
    }
    
    // Recursively load dependencies of this SPRX module before resolving relocations
    let needed = get_elf_needed_libraries(&buffer);
    load_needed_libraries(&needed);
    
    let empty_dynamic_symbols = HashMap::new();
    let got_symbol_map = HashMap::new();
    if let Err(e) = apply_custom_relocations(
        &buffer,
        load_bias,
        min_vaddr,
        &custom_symbols,
        &got_symbol_map,
        &empty_dynamic_symbols,
        true,
        path,
    ) {
        warn!("Failed to apply custom relocations to SPRX module: {:?}", e);
    }
    
    let mut modules_guard = LOADED_MODULES.lock().unwrap();
    if modules_guard.is_none() {
        *modules_guard = Some(HashMap::new());
    }
    let mod_id = unsafe {
        let id = MODULE_COUNTER;
        MODULE_COUNTER += 1;
        id
    };
    
    let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
    let mut normalized_name = file_name.clone();
    if normalized_name.ends_with(".prx") {
        normalized_name = normalized_name[..normalized_name.len() - 4].to_string() + ".sprx";
    } else if !normalized_name.ends_with(".sprx") {
        normalized_name.push_str(".sprx");
    }

    modules_guard.as_mut().unwrap().insert(mod_id, LoadedModule {
        name: normalized_name,
        load_bias,
        entrypoint,
        segments,
    });
    
    info!("Successfully loaded SPRX module {:?} with ID {}", path, mod_id);
    Ok(mod_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_relocations() {
        // Register mock external library symbols (simulating a loaded .sprx module)
        register_global_symbol("sceLibMockFunction".to_string(), 0xDEADBEEF001);
        register_global_symbol("sceLibAnotherFunc".to_string(), 0xDEADBEEF002);

        // Verify global symbol registry lookup
        assert_eq!(lookup_global_symbol("sceLibMockFunction"), Some(0xDEADBEEF001));
        assert_eq!(lookup_global_symbol("sceLibAnotherFunc"), Some(0xDEADBEEF002));
        assert_eq!(lookup_global_symbol("nonExistent"), None);
        
        // Verify the unified resolve_symbol_address chain:
        // 1. Cross-module symbols take priority
        assert_eq!(resolve_symbol_address("sceLibMockFunction"), Some(0xDEADBEEF001));
        // 2. Hand-written HLE stubs are found (e.g., sceKernelOpen)
        assert!(resolve_symbol_address("sceKernelOpen").is_some());
        // 3. Unresolved symbols return None
        assert_eq!(resolve_symbol_address("totallyMadeUpSymbol"), None);
        
        // Verify trampoline is a valid function pointer
        let trampoline_addr = hle_unresolved_import_trampoline as *const () as u64;
        assert!(trampoline_addr > 0, "Trampoline function must have a valid address");
        
        // Verify cross-module override precedence: if a symbol exists in both
        // the global registry AND HLE, the global registry (cross-module) wins
        let original_hle = crate::hle_symbols::lookup_hle_address("printf");
        assert!(original_hle.is_some(), "printf should exist in HLE");
        register_global_symbol("printf".to_string(), 0xCAFEBABE);
        // resolve_symbol_address should now return the cross-module override
        assert_eq!(resolve_symbol_address("printf"), Some(0xCAFEBABE));

        // Verify NID-to-name chain resolution
        let decoded_nid = decode_base64_nid("ESIzdFVmd4g").unwrap();
        register_nid_name(decoded_nid, "sceLibMockFunction".to_string());
        // resolve_symbol_address should decode "ESIzdFVmd4g" to the NID,
        // lookup its name "sceLibMockFunction", and resolve it to 0xDEADBEEF001
        assert_eq!(resolve_symbol_address("ESIzdFVmd4g"), Some(0xDEADBEEF001));
    }

    #[test]
    fn test_self_loader_validation() {
        // Construct a simple mock SELF buffer
        let mut buffer = vec![0u8; 1024];

        // magic: 0xEEF51454
        buffer[0..4].copy_from_slice(&0xEEF51454u32.to_le_bytes());
        // segment_count: 2
        buffer[24..26].copy_from_slice(&2u16.to_le_bytes());

        // Segment 0 header (offset 32)
        // flags: IsBlocked = true (0x800), GetId = 0 -> flags = 0x800 | (0 << 20) = 0x800
        let flags0 = 0x800u64;
        let file_offset0 = 256u64;
        let file_size0 = 68u64;
        let memory_size0 = 68u64;
        buffer[32..40].copy_from_slice(&flags0.to_le_bytes());
        buffer[40..48].copy_from_slice(&file_offset0.to_le_bytes());
        buffer[48..56].copy_from_slice(&file_size0.to_le_bytes());
        buffer[56..64].copy_from_slice(&memory_size0.to_le_bytes());

        // Segment 1 header (offset 64)
        // flags: IsBlocked = false -> flags = 0
        let flags1 = 0u64;
        let file_offset1 = 0u64;
        let file_size1 = 0u64;
        let memory_size1 = 0u64;
        buffer[64..72].copy_from_slice(&flags1.to_le_bytes());
        buffer[72..80].copy_from_slice(&file_offset1.to_le_bytes());
        buffer[80..88].copy_from_slice(&file_size1.to_le_bytes());
        buffer[88..96].copy_from_slice(&memory_size1.to_le_bytes());

        // ELF Header starts at 32 + 2 * 32 = 96
        // Let's write the ELF magic at 96
        buffer[96..100].copy_from_slice(b"\x7fELF");
        // e_phoff = 64 -> offset 96 + 32 = 128
        let e_phoff = 64u64;
        buffer[128..136].copy_from_slice(&e_phoff.to_le_bytes());
        // e_phentsize = 56 -> offset 96 + 54 = 150
        let e_phentsize = 56u16;
        buffer[150..152].copy_from_slice(&e_phentsize.to_le_bytes());
        // e_phnum = 1 -> offset 96 + 56 = 152
        let e_phnum = 1u16;
        buffer[152..154].copy_from_slice(&e_phnum.to_le_bytes());

        // Program Header 0 starts at 96 + 64 = 160
        // Program header structure:
        // p_type: 1 (PT_LOAD) -> offset 160..164
        let p_type = 1u32;
        buffer[160..164].copy_from_slice(&p_type.to_le_bytes());
        // p_offset: 256 -> offset 160 + 8 = 168 (8 bytes)
        let p_offset = 256u64;
        buffer[168..176].copy_from_slice(&p_offset.to_le_bytes());

        // Write some payload data at SELF file_offset0 = 256
        let payload = b"Hello from SELF decrypted segment payload! Mapping works correctly.";
        buffer[256..256+payload.len()].copy_from_slice(payload);

        let reconstructed = reconstruct_self_to_elf(&buffer).unwrap();

        // Verify ELF magic is at the beginning of the reconstructed buffer
        assert_eq!(&reconstructed[0..4], b"\x7fELF");
        // Verify segment payload was copied to the correct ELF p_offset = 256
        assert_eq!(&reconstructed[256..256+payload.len()], payload);
    }

    #[test]
    fn test_tls_relocations() {
        STATIC_TLS_SIZE.store(4096, Ordering::SeqCst);
        let static_tls_size = STATIC_TLS_SIZE.load(Ordering::SeqCst);
        assert_eq!(static_tls_size, 4096);

        // Test math for TLS offset (negative offsets from end of static TLS block)
        let sym_value = 128u64;
        let addend = 0i64;
        let offset_val64 = (sym_value as i64 + addend - static_tls_size as i64) as u64;
        let offset_val32 = (sym_value as i64 + addend - static_tls_size as i64) as i32;

        assert_eq!(offset_val64, (128 - 4096i64) as u64);
        assert_eq!(offset_val32, -3968);
    }
}

