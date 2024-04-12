//! Utilities to run tests

use std::{
    ffi::CStr,
    io::{self, Write},
    net::Ipv4Addr,
    process::{self, Command},
    sync::atomic::{AtomicU64, Ordering},
};

use aya::{
    netlink_add_ip_addr, netlink_add_veth_pair, netlink_delete_link, netlink_set_link_down,
    netlink_set_link_up,
};
use libc::if_nametoindex;
use netns_rs::{get_from_current_thread, NetNs};

pub const IF_NAME_1: &CStr = c"aya-test-1";
pub const IF_NAME_2: &CStr = c"aya-test-2";
pub const IP_ADDR_1: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const IP_ADDR_2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub const IP_PREFIX: u8 = 24;

pub fn setup_test_veth_pair() {
    unsafe { netlink_add_veth_pair(IF_NAME_1, IF_NAME_2) }.unwrap_or_else(|e| {
        panic!(
            "Failed to set up veth pair ({}, {}): {e}",
            IF_NAME_1.to_string_lossy(),
            IF_NAME_2.to_string_lossy()
        )
    })
}

pub struct NetNsGuard {
    name: String,
    old_ns: NetNs,
    ns: Option<NetNs>,
    pub if_idx1: u32,
    pub if_idx2: u32,
}

impl NetNsGuard {
    pub fn new() -> Self {
        let old_ns = get_from_current_thread().expect("Failed to get current netns");

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = process::id();
        let name = format!("aya-test-{pid}-{}", COUNTER.fetch_add(1, Ordering::Relaxed));

        // Create and enter netns
        let ns = NetNs::new(&name).unwrap_or_else(|e| panic!("Failed to create netns {name}: {e}"));

        ns.enter()
            .unwrap_or_else(|e| panic!("Failed to enter network namespace {}: {e}", name));
        println!("Entered network namespace {}", name);

        // By default, the loopback in a new netns is down. Set it up.
        let lo_idx = unsafe { if_nametoindex(c"lo".as_ptr()) };
        if lo_idx == 0 {
            panic!(
                "Interface `lo` not found in netns {}: {}",
                name,
                io::Error::last_os_error()
            );
        }

        unsafe { netlink_set_link_up(lo_idx as i32) }
            .unwrap_or_else(|e| panic!("Failed to set `lo` up in netns {}: {e}", name));

        let ls_output = Command::new("sh").args(["-c", "ls -la /"]).output();
        match ls_output {
            Ok(output) => {
                eprintln!("ls status: {}", output.status);
                io::stdout().write_all(&output.stdout).unwrap();
                io::stderr().write_all(&output.stderr).unwrap();
            }
            Err(e) => {
                eprintln!("Failed to run ls -la: {e}");
            }
        }

        let check_config_output = Command::new("release-check-config.sh").output();
        match check_config_output {
            Ok(output) => {
                eprintln!("check_config status: {}", output.status);
                io::stdout().write_all(&output.stdout).unwrap();
                io::stderr().write_all(&output.stderr).unwrap();
            }
            Err(e) => {
                eprintln!("Failed to run check-config.sh: {e}");
            }
        }

        setup_test_veth_pair();

        let if_idx1 = unsafe { if_nametoindex(IF_NAME_1.as_ptr()) };
        if if_idx1 == 0 {
            panic!(
                "Interface `{}` not found in netns {}: {}",
                IF_NAME_1.to_string_lossy(),
                name,
                io::Error::last_os_error()
            );
        }

        let if_idx2 = unsafe { if_nametoindex(IF_NAME_2.as_ptr()) };
        if if_idx2 == 0 {
            panic!(
                "Interface `{}` not found in netns {}: {}",
                IF_NAME_2.to_string_lossy(),
                name,
                io::Error::last_os_error()
            );
        }

        unsafe { netlink_add_ip_addr(if_idx1, IP_ADDR_1, IP_PREFIX) }.unwrap_or_else(|e| {
            panic!(
                "Failed to add IP `{}` to `{}` in netns {}: {e}",
                IP_ADDR_1,
                IF_NAME_1.to_string_lossy(),
                name
            )
        });

        unsafe { netlink_add_ip_addr(if_idx2, IP_ADDR_2, IP_PREFIX) }.unwrap_or_else(|e| {
            panic!(
                "Failed to add IP `{}` to `{}` in netns {}: {e}",
                IP_ADDR_2,
                IF_NAME_2.to_string_lossy(),
                name
            )
        });

        unsafe { netlink_set_link_up(if_idx1 as i32) }.unwrap_or_else(|e| {
            panic!(
                "Failed to set `{}` up in netns {}: {e}",
                IF_NAME_1.to_string_lossy(),
                name
            )
        });

        unsafe { netlink_set_link_up(if_idx2 as i32) }.unwrap_or_else(|e| {
            panic!(
                "Failed to set `{}` up in netns {}: {e}",
                IF_NAME_2.to_string_lossy(),
                name
            )
        });

        Self {
            old_ns,
            ns: Some(ns),
            name,
            if_idx1,
            if_idx2,
        }
    }
}

impl Drop for NetNsGuard {
    fn drop(&mut self) {
        // Avoid panic in panic
        if let Err(e) = unsafe { netlink_set_link_down(self.if_idx1 as i32) } {
            eprintln!(
                "Failed to set `{}` down in netns {}: {e}",
                IF_NAME_1.to_string_lossy(),
                self.name
            )
        }
        if let Err(e) = unsafe { netlink_set_link_down(self.if_idx2 as i32) } {
            eprintln!(
                "Failed to set `{}` down in netns {}: {e}",
                IF_NAME_2.to_string_lossy(),
                self.name
            )
        }

        if let Err(e) = unsafe { netlink_delete_link(self.if_idx1 as i32) } {
            eprintln!(
                "Failed to delete `{}` in netns {}: {e}",
                IF_NAME_1.to_string_lossy(),
                self.name
            )
        }

        if let Err(e) = self.old_ns.enter() {
            eprintln!("Failed to return to original netns: {e}");
        }
        if let Some(ns) = self.ns.take() {
            if let Err(e) = ns.remove() {
                eprintln!("Failed to remove netns {}: {e}", self.name);
            }
        }
        println!("Exited network namespace {}", self.name);
    }
}
