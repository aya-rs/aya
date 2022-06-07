#![no_std]
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

#[cfg(bpf_target_arch = "x86_64")]
mod x86_64;

#[cfg(bpf_target_arch = "armv7")]
mod armv7;

#[cfg(bpf_target_arch = "aarch64")]
mod aarch64;

#[cfg(bpf_target_arch = "riscv64")]
mod riscv64;

mod gen {
    #[cfg(bpf_target_arch = "x86_64")]
    pub use super::x86_64::*;

    #[cfg(bpf_target_arch = "armv7")]
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
