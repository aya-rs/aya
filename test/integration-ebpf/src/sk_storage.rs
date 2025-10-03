#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::sk_action,
    btf_maps::SkStorage,
    macros::{btf_map, cgroup_sock_addr},
    programs::SockAddrContext,
};
use integration_common::sk_storage::{Ip, Value};
#[cfg(not(test))]
extern crate ebpf_panic;

#[btf_map]
static SOCKET_STORAGE: SkStorage<Value> = SkStorage::new();

#[cgroup_sock_addr(connect4)]
pub(crate) fn sk_storage_connect4(ctx: SockAddrContext) -> i32 {
    let sock_addr = unsafe { &*ctx.sock_addr };

    let storage = unsafe { SOCKET_STORAGE.get_or_insert_ptr_mut(&ctx, None) };
    if !storage.is_null() {
        unsafe {
            *storage = Value {
                user_family: sock_addr.user_family,
                user_ip: Ip::V4(sock_addr.user_ip4),
                user_port: sock_addr.user_port,
                family: sock_addr.family,
                type_: sock_addr.type_,
                protocol: sock_addr.protocol,
            }
        }
    }

    sk_action::SK_PASS as _
}

#[cgroup_sock_addr(connect6)]
pub(crate) fn sk_storage_connect6(ctx: SockAddrContext) -> i32 {
    let sock_addr = unsafe { &*ctx.sock_addr };

    let storage = unsafe { SOCKET_STORAGE.get_or_insert_ptr_mut(&ctx, None) };
    if !storage.is_null() {
        let mut user_ip6 = [0u32; 4];
        unsafe {
            // Verifier dislikes the naive thing:
            //
            // ; let sk = unsafe { sock_addr.__bindgen_anon_1.sk };
            // 0: (79) r2 = *(u64 *)(r1 +64)         ; R1=ctx(off=0,imm=0) R2_w=sock(off=0,imm=0)
            // ; user_family: sock_addr.user_family,
            // 1: (61) r3 = *(u32 *)(r1 +0)          ; R1=ctx(off=0,imm=0) R3_w=scalar(umax=4294967295,var_off=(0x0; 0xffffffff))
            // ; user_ip: Ip::V6(sock_addr.user_ip6),
            // 2: (bf) r4 = r1                       ; R1=ctx(off=0,imm=0) R4_w=ctx(off=0,imm=0)
            // 3: (07) r4 += 8                       ; R4_w=ctx(off=8,imm=0)
            // ; let mut value = Value {
            // 4: (bf) r5 = r10                      ; R5_w=fp0 R10=fp0
            // 5: (07) r5 += -32                     ; R5_w=fp-32
            // ; user_ip: Ip::V6(sock_addr.user_ip6),
            // 6: (61) r0 = *(u32 *)(r4 +0)
            // dereference of modified ctx ptr R4 off=8 disallowed
            user_ip6[0] = sock_addr.user_ip6[0];
            user_ip6[1] = sock_addr.user_ip6[1];
            user_ip6[2] = sock_addr.user_ip6[2];
            user_ip6[3] = sock_addr.user_ip6[3];
            *storage = Value {
                user_family: sock_addr.user_family,
                user_ip: Ip::V6(user_ip6),
                user_port: sock_addr.user_port,
                family: sock_addr.family,
                type_: sock_addr.type_,
                protocol: sock_addr.protocol,
            }
        }
    }

    sk_action::SK_PASS as _
}
