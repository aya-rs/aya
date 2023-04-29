#![no_std]
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

#[cfg(bpf_target_arch = "x86_64")]
mod x86_64;

#[cfg(bpf_target_arch = "arm")]
mod armv7;

#[cfg(bpf_target_arch = "aarch64")]
mod aarch64;

#[cfg(bpf_target_arch = "riscv64")]
mod riscv64;

mod gen {
    #[cfg(bpf_target_arch = "x86_64")]
    pub use super::x86_64::*;

    #[cfg(bpf_target_arch = "arm")]
    pub use super::armv7::*;

    #[cfg(bpf_target_arch = "aarch64")]
    pub use super::aarch64::*;

    #[cfg(bpf_target_arch = "riscv64")]
    pub use super::riscv64::*;
}
pub use gen::helpers;

pub mod bindings {
    pub use crate::gen::bindings::*;

    pub const TC_ACT_OK: i32 = crate::gen::bindings::TC_ACT_OK as i32;
    pub const TC_ACT_RECLASSIFY: i32 = crate::gen::bindings::TC_ACT_RECLASSIFY as i32;
    pub const TC_ACT_SHOT: i32 = crate::gen::bindings::TC_ACT_SHOT as i32;
    pub const TC_ACT_PIPE: i32 = crate::gen::bindings::TC_ACT_PIPE as i32;
    pub const TC_ACT_STOLEN: i32 = crate::gen::bindings::TC_ACT_STOLEN as i32;
    pub const TC_ACT_QUEUED: i32 = crate::gen::bindings::TC_ACT_QUEUED as i32;
    pub const TC_ACT_REPEAT: i32 = crate::gen::bindings::TC_ACT_REPEAT as i32;
    pub const TC_ACT_REDIRECT: i32 = crate::gen::bindings::TC_ACT_REDIRECT as i32;
    pub const TC_ACT_TRAP: i32 = crate::gen::bindings::TC_ACT_TRAP as i32;
    pub const TC_ACT_VALUE_MAX: i32 = crate::gen::bindings::TC_ACT_VALUE_MAX as i32;
    pub const TC_ACT_EXT_VAL_MASK: i32 = 268435455;

    // TODO(vadorovsky): Handle that with a macro.
    pub mod bpf_map_type {
        pub const BPF_MAP_TYPE_UNSPEC: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_UNSPEC as usize;
        pub const BPF_MAP_TYPE_HASH: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_HASH as usize;
        pub const BPF_MAP_TYPE_ARRAY: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_ARRAY as usize;
        pub const BPF_MAP_TYPE_PROG_ARRAY: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY as usize;
        pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY as usize;
        pub const BPF_MAP_TYPE_PERCPU_HASH: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH as usize;
        pub const BPF_MAP_TYPE_PERCPU_ARRAY: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as usize;
        pub const BPF_MAP_TYPE_STACK_TRACE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_STACK_TRACE as usize;
        pub const BPF_MAP_TYPE_CGROUP_ARRAY: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_CGROUP_ARRAY as usize;
        pub const BPF_MAP_TYPE_LRU_HASH: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_LRU_HASH as usize;
        pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_LRU_PERCPU_HASH as usize;
        pub const BPF_MAP_TYPE_LPM_TRIE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_LPM_TRIE as usize;
        pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS as usize;
        pub const BPF_MAP_TYPE_HASH_OF_MAPS: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS as usize;
        pub const BPF_MAP_TYPE_DEVMAP: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_DEVMAP as usize;
        pub const BPF_MAP_TYPE_SOCKMAP: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_SOCKMAP as usize;
        pub const BPF_MAP_TYPE_CPUMAP: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_CPUMAP as usize;
        pub const BPF_MAP_TYPE_XSKMAP: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_XSKMAP as usize;
        pub const BPF_MAP_TYPE_SOCKHASH: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_SOCKHASH as usize;
        pub const BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED as usize;
        pub const BPF_MAP_TYPE_CGROUP_STORAGE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_CGROUP_STORAGE as usize;
        pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY as usize;
        pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE as usize;
        pub const BPF_MAP_TYPE_QUEUE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_QUEUE as usize;
        pub const BPF_MAP_TYPE_STACK: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_STACK as usize;
        pub const BPF_MAP_TYPE_SK_STORAGE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_SK_STORAGE as usize;
        pub const BPF_MAP_TYPE_DEVMAP_HASH: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH as usize;
        pub const BPF_MAP_TYPE_STRUCT_OPS: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_STRUCT_OPS as usize;
        pub const BPF_MAP_TYPE_RINGBUF: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_RINGBUF as usize;
        pub const BPF_MAP_TYPE_INODE_STORAGE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_INODE_STORAGE as usize;
        pub const BPF_MAP_TYPE_TASK_STORAGE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE as usize;
        pub const BPF_MAP_TYPE_BLOOM_FILTER: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER as usize;
        pub const BPF_MAP_TYPE_USER_RINGBUF: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_USER_RINGBUF as usize;
        pub const BPF_MAP_TYPE_CGRP_STORAGE: usize =
            crate::gen::bindings::bpf_map_type::BPF_MAP_TYPE_CGRP_STORAGE as usize;
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bpf_map_def {
        pub type_: ::aya_bpf_cty::c_uint,
        pub key_size: ::aya_bpf_cty::c_uint,
        pub value_size: ::aya_bpf_cty::c_uint,
        pub max_entries: ::aya_bpf_cty::c_uint,
        pub map_flags: ::aya_bpf_cty::c_uint,
        pub id: ::aya_bpf_cty::c_uint,
        pub pinning: ::aya_bpf_cty::c_uint,
    }
}
