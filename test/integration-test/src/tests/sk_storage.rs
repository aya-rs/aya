use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};

use assert_matches::assert_matches;
use aya::{
    EbpfLoader,
    maps::{MapError, SkStorage},
    programs::{CgroupAttachMode, CgroupSockAddr},
};
use integration_common::sk_storage::{Ip, Value};
use libc::{self};
use test_log::test;

use crate::utils::{Cgroup, NetNsGuard};

#[test]
fn sk_storage_connect() {
    let mut ebpf = EbpfLoader::new().load(crate::SK_STORAGE).unwrap();

    let storage = ebpf.take_map("SOCKET_STORAGE").unwrap();
    let mut storage = SkStorage::<_, Value>::try_from(storage).unwrap();

    let _netns = NetNsGuard::new();
    let root_cgroup = Cgroup::root();
    let cgroup = root_cgroup.create_child("aya-test-sk-storage");
    let cgroup_fd = cgroup.fd();

    let guards = ebpf
        .programs_mut()
        .map(|(name, prog)| {
            let prog: &mut CgroupSockAddr = prog.try_into().expect(name);
            prog.load().expect(name);
            let link_id = prog
                .attach(cgroup_fd, CgroupAttachMode::Single)
                .expect(name);
            scopeguard::guard((), |()| {
                prog.detach(link_id).expect(name);
            })
        })
        .collect::<Vec<_>>();

    let cgroup = cgroup.into_cgroup();
    cgroup.write_pid(std::process::id());

    let listener4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr4 = listener4.local_addr().unwrap();
    let listener6 = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    let addr6 = listener6.local_addr().unwrap();

    {
        let client4 = TcpStream::connect(addr4).unwrap();
        assert_matches!(storage.get(&client4, 0), Ok(value4) => {
            assert_eq!(value4, expected_value(&addr4));
        });
        storage.remove(&client4).unwrap();
        assert_matches!(storage.get(&client4, 0), Err(MapError::KeyNotFound));

        let client6 = TcpStream::connect(addr6).unwrap();
        assert_matches!(storage.get(&client6, 0), Ok(value6) => {
            assert_eq!(value6, expected_value(&addr6));
        });
        storage.remove(&client6).unwrap();
        assert_matches!(storage.get(&client6, 0), Err(MapError::KeyNotFound));
    }

    // Detach.
    drop(guards);

    {
        let client4 = TcpStream::connect(addr4).unwrap();
        assert_matches!(storage.get(&client4, 0), Err(MapError::KeyNotFound));

        let client6 = TcpStream::connect(addr6).unwrap();
        assert_matches!(storage.get(&client6, 0), Err(MapError::KeyNotFound));
    }
}

fn expected_value(addr: &SocketAddr) -> Value {
    match addr {
        SocketAddr::V4(addr) => Value {
            user_family: libc::AF_INET as u32,
            user_ip: Ip::V4(u32::from_ne_bytes(addr.ip().octets())),
            user_port: u32::from(addr.port().to_be()),
            family: libc::AF_INET as u32,
            type_: libc::SOCK_STREAM as u32,
            protocol: libc::IPPROTO_TCP as u32,
        },
        SocketAddr::V6(addr) => Value {
            user_family: libc::AF_INET6 as u32,
            user_ip: Ip::V6(unsafe {
                core::mem::transmute::<[u8; 16], [u32; 4]>(addr.ip().octets())
            }),
            user_port: u32::from(addr.port().to_be()),
            family: libc::AF_INET6 as u32,
            type_: libc::SOCK_STREAM as u32,
            protocol: libc::IPPROTO_TCP as u32,
        },
    }
}
