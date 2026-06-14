use log::{info, error, warn};
use std::collections::HashMap;
use std::sync::Mutex;
use std::net::TcpStream;
use std::io::{Read, Write};

// Thread-safe registry for mapping guest socket file descriptors to host TCP connections
static ACTIVE_SOCKETS: Mutex<Option<HashMap<i32, TcpStream>>> = Mutex::new(None);
static mut SOCKET_COUNTER: i32 = 500;

/// Initialize the HLE networking subsystem. Called during emulator startup.
pub fn initialize_network() {
    info!("Initializing HLE Network Subsystem...");
    let mut sockets = ACTIVE_SOCKETS.lock().unwrap();
    *sockets = Some(HashMap::new());

    // Spawn a background thread to run the host TCP echo server on port 8080
    std::thread::spawn(|| {
        use std::net::TcpListener;
        match TcpListener::bind("127.0.0.1:58080") {
            Ok(listener) => {
                info!("Host mock TCP server listening on 127.0.0.1:58080");
                for stream in listener.incoming() {
                    match stream {
                        Ok(mut stream) => {
                            std::thread::spawn(move || {
                                let mut buffer = [0u8; 1024];
                                loop {
                                    match stream.read(&mut buffer) {
                                        Ok(0) => break, // EOF
                                        Ok(bytes_read) => {
                                            let received = String::from_utf8_lossy(&buffer[..bytes_read]);
                                            info!("Host mock TCP server received: {}", received.trim());
                                            
                                            // Format echo response
                                            let mut response = b"Echo: ".to_vec();
                                            response.extend_from_slice(&buffer[..bytes_read]);
                                            if let Err(e) = stream.write_all(&response) {
                                                error!("Host mock TCP server write error: {}", e);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!("Host mock TCP server read error: {}", e);
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("Host mock TCP server accept error: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Host mock TCP server failed to bind to 127.0.0.1:58080 (already in use?): {}", e);
            }
        }
    });

    info!("HLE Network Subsystem initialized successfully.");
}

// =========================================================================
// =========================================================================

#[no_mangle]
pub extern "sysv64" fn sceNetInit() -> i32 {
    info!("API Network Intercepted: sceNetInit");
    0 // SCE_OK
}

/// Signature aligned with: SceNetId sceNetSocket(const char *name, int domain, int type, int protocol);
#[no_mangle]
pub unsafe extern "sysv64" fn sceNetSocket(
    name: *const std::ffi::c_char,
    domain: i32,
    socket_type: i32,
    protocol: i32,
) -> i32 {
    let name_str = if name.is_null() {
        "unnamed".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    
    info!(
        "API Network Intercepted: sceNetSocket | Name: {} | Domain: {} | Type: {} | Protocol: {}",
        name_str, domain, socket_type, protocol
    );
    
    let mut sockets = ACTIVE_SOCKETS.lock().unwrap();
    if let Some(ref mut _map) = *sockets {
        let fd = SOCKET_COUNTER;
        SOCKET_COUNTER += 1;
        info!("Created Virtual Socket File Descriptor: {}", fd);
        fd
    } else {
        error!("Network subsystem not initialized.");
        -1
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SceNetSockaddrIn {
    pub sin_len: u8,
    pub sin_family: u8,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

/// Establishes a real host TCP socket connection from the virtual socket descriptor.
#[no_mangle]
pub unsafe extern "sysv64" fn sceNetConnect(fd: i32, addr_ptr: *const std::ffi::c_void, addrlen: u32) -> i32 {
    info!("API Network Intercepted: sceNetConnect | Socket FD: {} | AddrLen: {}", fd, addrlen);
    if addr_ptr.is_null() {
        return -1;
    }

    let mut ip_str = "127.0.0.1:58080".to_string();
    if addrlen >= 16 {
        let sockaddr = *(addr_ptr as *const SceNetSockaddrIn);
        let port = u16::from_be(sockaddr.sin_port);
        let ip_u32 = u32::from_be(sockaddr.sin_addr);
        let ip = std::net::Ipv4Addr::from(ip_u32);
        ip_str = format!("{}:{}", ip, port);
        info!("  --> Parsed guest connection destination: {}", ip_str);
    } else {
        info!("  --> Using default fallback connection: {}", ip_str);
    }

    match TcpStream::connect(&ip_str) {
        Ok(stream) => {
            let mut sockets = ACTIVE_SOCKETS.lock().unwrap();
            if let Some(ref mut map) = *sockets {
                map.insert(fd, stream);
                info!("Socket FD {} successfully bound to host TCP connection ({}).", fd, ip_str);
                0 // SCE_OK
            } else {
                -1
            }
        }
        Err(e) => {
            warn!("Failed to establish host TCP connection to {}: {}. Trying local mock server...", ip_str, e);
            // Fallback to local mock echo server
            match TcpStream::connect("127.0.0.1:58080") {
                Ok(stream) => {
                    let mut sockets = ACTIVE_SOCKETS.lock().unwrap();
                    if let Some(ref mut map) = *sockets {
                        map.insert(fd, stream);
                        info!("Socket FD {} successfully bound to fallback local mock TCP server.", fd);
                        0
                    } else {
                        -1
                    }
                }
                Err(_) => {
                    warn!("Local mock server unavailable. Mapping virtual socket to offline state.");
                    0 // Mock success to allow games to run offline
                }
            }
        }
    }
}

/// Routes guest payload sends to the host TCP stream.
#[no_mangle]
pub unsafe extern "sysv64" fn sceNetSend(fd: i32, buf: *const std::ffi::c_void, len: usize, flags: i32) -> i32 {
    if buf.is_null() {
        return -1;
    }

    let mut sockets = ACTIVE_SOCKETS.lock().unwrap();
    if let Some(ref mut map) = *sockets {
        if let Some(stream) = map.get_mut(&fd) {
            let slice = std::slice::from_raw_parts(buf as *const u8, len);
            match stream.write(slice) {
                Ok(bytes) => {
                    info!("Socket FD {}: Sent {} bytes via host TCP stream (flags: {})", fd, bytes, flags);
                    bytes as i32
                }
                Err(e) => {
                    error!("Socket send error: {}", e);
                    -1
                }
            }
        } else {
            // Offline/unconnected socket mockup
            info!("Socket FD {}: Mocked send of {} bytes (Offline)", fd, len);
            len as i32
        }
    } else {
        -1
    }
}

/// Routes guest payload reads to the host TCP stream.
#[no_mangle]
pub unsafe extern "sysv64" fn sceNetRecv(fd: i32, buf: *mut std::ffi::c_void, len: usize, flags: i32) -> i32 {
    if buf.is_null() {
        return -1;
    }

    let mut sockets = ACTIVE_SOCKETS.lock().unwrap();
    if let Some(ref mut map) = *sockets {
        if let Some(stream) = map.get_mut(&fd) {
            let slice = std::slice::from_raw_parts_mut(buf as *mut u8, len);
            match stream.read(slice) {
                Ok(bytes) => {
                    info!("Socket FD {}: Received {} bytes via host TCP stream (flags: {})", fd, bytes, flags);
                    bytes as i32
                }
                Err(e) => {
                    error!("Socket receive error: {}", e);
                    -1
                }
            }
        } else {
            // Return 0 for EOF simulation on unconnected socket
            0
        }
    } else {
        -1
    }
}

#[no_mangle]
pub extern "sysv64" fn sceNetSocketClose(fd: i32) -> i32 {
    info!("API Network Intercepted: sceNetSocketClose | Socket FD: {}", fd);
    let mut sockets = ACTIVE_SOCKETS.lock().unwrap();
    if let Some(ref mut map) = *sockets {
        if map.remove(&fd).is_some() {
            info!("Closed Socket FD: {}", fd);
        }
    }
    0
}

#[no_mangle]
pub extern "sysv64" fn sceNetClose(fd: i32) -> i32 {
    info!("API Network Intercepted: sceNetClose | Socket FD: {}", fd);
    sceNetSocketClose(fd)
}

#[no_mangle]
pub unsafe extern "sysv64" fn sceNetPoolCreate(name: *const std::ffi::c_char, size: i32, flags: i32) -> i32 {
    let name_str = if name.is_null() {
        "unnamed".to_string()
    } else {
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    info!("API Network Intercepted: sceNetPoolCreate | Name: {} | Size: {} | Flags: {}", name_str, size, flags);
    1 // Return virtual memory pool ID
}

#[no_mangle]
pub extern "sysv64" fn sceNetPoolDestroy(memid: i32) -> i32 {
    info!("API Network Intercepted: sceNetPoolDestroy | MemID: {}", memid);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hle_socket_connect() {
        initialize_network();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let name_cstr = std::ffi::CString::new("test_sock").unwrap();
        let fd = unsafe { sceNetSocket(name_cstr.as_ptr(), 2, 1, 6) };
        assert!(fd >= 500);

        let addr = SceNetSockaddrIn {
            sin_len: 16,
            sin_family: 2,
            sin_port: 58080u16.to_be(),
            sin_addr: 0x7F000001u32.to_be(),
            sin_zero: [0; 8],
        };

        let connect_res = unsafe {
            sceNetConnect(fd, &addr as *const _ as *const std::ffi::c_void, 16)
        };
        assert_eq!(connect_res, 0);

        let msg = b"Ping";
        let send_res = unsafe {
            sceNetSend(fd, msg.as_ptr() as *const std::ffi::c_void, 4, 0)
        };
        assert_eq!(send_res, 4);

        let mut recv_buf = [0u8; 10];
        let recv_res = unsafe {
            sceNetRecv(fd, recv_buf.as_mut_ptr() as *mut std::ffi::c_void, 10, 0)
        };
        assert_eq!(recv_res, 10);
        assert_eq!(&recv_buf, b"Echo: Ping");

        let close_res = sceNetSocketClose(fd);
        assert_eq!(close_res, 0);
    }
}


