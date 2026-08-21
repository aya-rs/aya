#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{bindings::sk_action, macros::cgroup_sock_addr, programs::SockAddrContext};

#[cgroup_sock_addr(connect4)]
const fn cgroup_connect(_ctx: SockAddrContext) -> i32 {
    sk_action::SK_PASS as i32
}
