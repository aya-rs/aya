#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]
#![expect(
    deprecated,
    reason = "exercising the deprecated cgroup storage map types"
)]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    bindings::sk_action,
    btf_maps::{CgroupStorage as BtfCgroupStorage, PerCpuCgroupStorage as BtfPerCpuCgroupStorage},
    macros::{btf_map, cgroup_sock_addr, map},
    maps::{
        CgroupStorage as LegacyCgroupStorage, PerCpuCgroupStorage as LegacyPerCpuCgroupStorage,
    },
    programs::SockAddrContext,
};

#[map]
static STORAGE_LEGACY: LegacyCgroupStorage<u64> = LegacyCgroupStorage::new();

#[map]
static PERCPU_LEGACY: LegacyPerCpuCgroupStorage<u64> = LegacyPerCpuCgroupStorage::new();

#[btf_map]
static STORAGE: BtfCgroupStorage<u64> = BtfCgroupStorage::new();

#[btf_map]
static PERCPU: BtfPerCpuCgroupStorage<u64> = BtfPerCpuCgroupStorage::new();

// The kernel allows a program to reference at most one map of each cgroup
// storage type, so the legacy and BTF maps are exercised by separate programs.
macro_rules! define_connect4_test {
    ($storage:ident, $percpu:ident, $prog:ident $(,)?) => {
        #[cgroup_sock_addr(connect4)]
        fn $prog(_ctx: SockAddrContext) -> i32 {
            // The helper returns a valid pointer for any cgroup-attached program,
            // so the dereference needs no null check.
            unsafe { *$storage.get_ptr_mut() += 1 };
            unsafe { *$percpu.get_ptr_mut() += 1 };
            sk_action::SK_PASS as i32
        }
    };
}

define_connect4_test!(STORAGE_LEGACY, PERCPU_LEGACY, connect4_legacy);
define_connect4_test!(STORAGE, PERCPU, connect4_btf);
