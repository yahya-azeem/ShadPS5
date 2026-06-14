use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::collections::HashMap;
use object::read::archive::ArchiveFile;
use object::{Object, ObjectSymbol, ObjectSection};

// Helper function to decode base64 NID
fn decode_base64_nid(b64: &str) -> Option<u64> {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut padded = b64.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    
    for byte in padded.bytes() {
        if byte == b'=' {
            break;
        }
        let val = CHARSET.iter().position(|&c| c == byte).or_else(|| {
            if byte == b'-' {
                CHARSET.iter().position(|&c| c == b'+')
            } else if byte == b'_' {
                CHARSET.iter().position(|&c| c == b'/')
            } else {
                None
            }
        })? as u32;
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    
    if bytes.len() < 8 {
        return None;
    }
    
    let mut val_bytes = [0u8; 8];
    val_bytes.copy_from_slice(&bytes[0..8]);
    Some(u64::from_be_bytes(val_bytes))
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
        for symbol in elf.dynamic_symbols() {
            if let Ok(name) = symbol.name() {
                if sym_idx < nids.len() {
                    let nid_val = nids[sym_idx];
                    if nid_val != 0 && !name.is_empty() {
                        symbol_map.insert(nid_val, name.to_string());
                    }
                }
            }
            sym_idx += 1;
        }
    } else {
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
                        }
                    }
                }
            }
        }
    }
    Ok(symbol_map)
}

fn load_aerolib_mappings(path: &Path) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
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
                                if let Some(nid) = decode_base64_nid(b64_nid) {
                                    map.insert(nid, clean_symbol_name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

fn main() {
    let aerolib_path = Path::new("reference/shadps4/src/core/aerolib/aerolib.inl");
    println!("Loading aerolib mappings from {:?}", aerolib_path);
    let start = std::time::Instant::now();
    let mappings = load_aerolib_mappings(aerolib_path);
    let duration = start.elapsed();
    println!("Loaded {} mappings in {:?}", mappings.len(), duration);

    // Test a few known NIDs
    let test_nids = vec![
        ("-hJRce8wn1U", "_ZN3sce4Json12MemAllocatorC2Ev"),
        ("L-Q3LEjIbgA", "sceKernelMapDirectMemory"),
        ("eLdDw6l0-bU", "unresolved"),
    ];

    for &(b64, expected) in &test_nids {
        let nid = decode_base64_nid(b64).unwrap();
        if let Some(name) = mappings.get(&nid) {
            println!("NID 0x{:X} ({}) -> {} (Expected: {})", nid, b64, name, expected);
        } else {
            println!("NID 0x{:X} ({}) NOT found (Expected: {})", nid, b64, expected);
        }
    }
}
