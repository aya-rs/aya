use std::{net::TcpListener, os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _}, time::Duration};

use aya::{
    Ebpf,
    maps::ReusePortSockArray,
    programs::{SkReuseport, loaded_programs},
};
use libc::{setsockopt, SOL_SOCKET, SO_REUSEPORT, socket, bind, listen, AF_INET, SOCK_STREAM, sockaddr_in};
use tokio::time::sleep;

use crate::utils::NetNsGuard;

#[tokio::test]
async fn sk_reuseport_load() {
    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let prog: &mut SkReuseport = ebpf
        .program_mut("select_socket")
        .unwrap()
        .try_into()
        .unwrap();

    // Test that the program loads successfully
    prog.load().unwrap();

    // Test that it's properly loaded
    let info = prog.info().unwrap();
    assert_eq!(
        info.program_type().unwrap(),
        aya::programs::ProgramType::SkReuseport
    );
}

#[tokio::test]
async fn sk_reuseport_loaded_programs_iteration() {
    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let prog: &mut SkReuseport = ebpf
        .program_mut("select_socket")
        .unwrap()
        .try_into()
        .unwrap();

    let programs = loaded_programs().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(!programs.iter().any(|p| matches!(
        p.program_type().unwrap(),
        aya::programs::ProgramType::SkReuseport
    )));

    prog.load().unwrap();
    sleep(Duration::from_millis(500)).await;

    let programs = loaded_programs().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(programs.iter().any(|p| matches!(
        p.program_type().unwrap(),
        aya::programs::ProgramType::SkReuseport
    )));
}

#[tokio::test]
async fn sk_reuseport_map_operations() {
    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    
    // Test that we can access the ReusePortSockArray map
    // Note: This test checks map creation and basic operations
    // In a real scenario, you would need actual SO_REUSEPORT sockets
    let map: ReusePortSockArray<_> = ebpf.take_map("socket_map")
        .expect("socket_map should exist")
        .try_into()
        .expect("map should convert to ReusePortSockArray");
    
    // Test that the map has the correct properties
    let fd = map.fd();
    assert!(!fd.as_fd().as_raw_fd() < 0, "Map fd should be valid");
    
    // Test indices iterator (array maps have all indices pre-allocated)
    let indices_count = map.indices().count();
    assert_eq!(indices_count, 10, "Array map should have all 10 indices available");
}

#[test_log::test]
fn sk_reuseport_attach_detach() {
    let _netns = NetNsGuard::new();
    
    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let prog: &mut SkReuseport = ebpf
        .program_mut("select_socket")
        .unwrap()
        .try_into()
        .unwrap();
    
    prog.load().unwrap();
    
    // Create a socket with SO_REUSEPORT enabled - a simpler approach
    // First create a normal listener to get a port, then create SO_REUSEPORT sockets
    let temp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = temp_listener.local_addr().unwrap();
    drop(temp_listener); // Release the port
    
    // Create socket with SO_REUSEPORT before binding
    let socket_fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
    assert!(socket_fd >= 0, "Failed to create socket");
    
    let enable = 1i32;
    unsafe {
        let ret = setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_REUSEPORT,
            &enable as *const _ as *const _,
            std::mem::size_of_val(&enable) as u32,
        );
        assert_eq!(ret, 0, "Failed to set SO_REUSEPORT");
    }
    
    // Manually bind and listen
    let addr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: local_addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
        },
        sin_zero: [0; 8],
    };
    
    let bind_result = unsafe {
        bind(
            socket_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        )
    };
    assert_eq!(bind_result, 0, "Failed to bind socket");
    
    let listen_result = unsafe { listen(socket_fd, 1024) };
    assert_eq!(listen_result, 0, "Failed to listen on socket");
    
    // Convert to TcpListener
    let listener = unsafe { TcpListener::from_raw_fd(socket_fd) };
    
    // Test program attachment
    let link_id = prog.attach(&listener).unwrap();
    
    // Test program detachment
    prog.detach(link_id).unwrap();
}

#[test_log::test]
fn sk_reuseport_socket_array_operations() {
    let _netns = NetNsGuard::new();
    
    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    
    // Get the socket array map
    let mut socket_array: ReusePortSockArray<_> = ebpf
        .take_map("socket_map")
        .unwrap()
        .try_into()
        .unwrap();
    
    // Create multiple SO_REUSEPORT sockets that bind to the same port
    let temp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = temp_listener.local_addr().unwrap();
    drop(temp_listener); // Release the port
    
    // Create first socket with SO_REUSEPORT
    let socket1_fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
    assert!(socket1_fd >= 0, "Failed to create socket1");
    
    // Create second socket with SO_REUSEPORT  
    let socket2_fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
    assert!(socket2_fd >= 0, "Failed to create socket2");
    
    let enable = 1i32;
    // Set SO_REUSEPORT on both sockets before binding
    unsafe {
        let ret1 = setsockopt(
            socket1_fd,
            SOL_SOCKET,
            SO_REUSEPORT,
            &enable as *const _ as *const _,
            std::mem::size_of_val(&enable) as u32,
        );
        let ret2 = setsockopt(
            socket2_fd,
            SOL_SOCKET,
            SO_REUSEPORT,
            &enable as *const _ as *const _,
            std::mem::size_of_val(&enable) as u32,
        );
        assert_eq!(ret1, 0, "Failed to set SO_REUSEPORT on socket1");
        assert_eq!(ret2, 0, "Failed to set SO_REUSEPORT on socket2");
    }
    
    // Bind both sockets to the same address to create SO_REUSEPORT group
    let addr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: local_addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
        },
        sin_zero: [0; 8],
    };
    
    unsafe {
        let bind_result1 = bind(
            socket1_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        );
        let bind_result2 = bind(
            socket2_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        );
        assert_eq!(bind_result1, 0, "Failed to bind socket1");
        assert_eq!(bind_result2, 0, "Failed to bind socket2");
        
        let listen_result1 = listen(socket1_fd, 1024);
        let listen_result2 = listen(socket2_fd, 1024);
        assert_eq!(listen_result1, 0, "Failed to listen on socket1");
        assert_eq!(listen_result2, 0, "Failed to listen on socket2");
    }
    
    // Convert to TcpListeners
    let listener1 = unsafe { TcpListener::from_raw_fd(socket1_fd) };
    let listener2 = unsafe { TcpListener::from_raw_fd(socket2_fd) };
    
    // Test storing sockets in the array
    socket_array.set(0, &listener1, 0).unwrap();
    socket_array.set(1, &listener2, 0).unwrap();
    
    // Test removing sockets from the array
    socket_array.clear_index(&0).unwrap();
    socket_array.clear_index(&1).unwrap();
}

#[test_log::test]
fn sk_reuseport_error_conditions() {
    let _netns = NetNsGuard::new();
    
    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    
    // Get the socket array map
    let mut socket_array: ReusePortSockArray<_> = ebpf
        .take_map("socket_map")
        .unwrap()
        .try_into()
        .unwrap();
    
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    
    // Test bounds checking - should fail for out-of-bounds index
    let result = socket_array.set(100, &socket, 0);
    assert!(result.is_err(), "Setting socket at out-of-bounds index should fail");
    
    let result = socket_array.clear_index(&100);
    assert!(result.is_err(), "Clearing out-of-bounds index should fail");
}

#[tokio::test]
async fn sk_reuseport_context_access() {
    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let prog: &mut SkReuseport = ebpf
        .program_mut("test_context_access")
        .unwrap()
        .try_into()
        .unwrap();

    // Test that the program loads successfully with context field access
    prog.load().unwrap();

    // Test that it's properly loaded
    let info = prog.info().unwrap();
    assert_eq!(
        info.program_type().unwrap(),
        aya::programs::ProgramType::SkReuseport
    );
}

#[tokio::test] 
async fn sk_reuseport_helper_usage() {
    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let prog: &mut SkReuseport = ebpf
        .program_mut("test_helper_usage")
        .unwrap()
        .try_into()
        .unwrap();

    // Test that the program loads successfully with helper usage
    prog.load().unwrap();

    // Test that it's properly loaded  
    let info = prog.info().unwrap();
    assert_eq!(
        info.program_type().unwrap(),
        aya::programs::ProgramType::SkReuseport
    );

    // Test that we can access the socket map used by the helper
    let map: ReusePortSockArray<_> = ebpf.take_map("socket_map")
        .expect("socket_map should exist")
        .try_into()
        .expect("map should convert to ReusePortSockArray");
    
    // Verify map properties
    let indices_count = map.indices().count();
    assert_eq!(indices_count, 10, "Array map should have all 10 indices available");
}
