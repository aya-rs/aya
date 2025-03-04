#![expect(
    clippy::all,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unsafe_op_in_unsafe_fn
)]
#![no_std]

#[allow(dead_code)]
mod aarch64 {
    pub mod bindings;
    pub mod helpers;
}
#[allow(dead_code)]
mod armv7 {
    pub mod bindings;
    pub mod helpers;
}
#[allow(dead_code)]
mod loongarch64 {
    pub mod bindings;
    pub mod helpers;
}
#[allow(dead_code)]
mod mips {
    pub mod bindings;
    pub mod helpers;
}
#[allow(dead_code)]
mod powerpc64 {
    pub mod bindings;
    pub mod helpers;
}
#[allow(dead_code)]
mod riscv64 {
    pub mod bindings;
    pub mod helpers;
}
#[allow(dead_code)]
mod s390x {
    pub mod bindings;
    pub mod helpers;
}
#[allow(dead_code)]
mod x86_64 {
    pub mod bindings;
    pub mod helpers;
}

mod generated {
    #[cfg(bpf_target_arch = "aarch64")]
    pub use super::aarch64::*;
    #[cfg(bpf_target_arch = "arm")]
    pub use super::armv7::*;
    #[cfg(bpf_target_arch = "loongarch64")]
    pub use super::loongarch64::*;
    #[cfg(bpf_target_arch = "mips")]
    pub use super::mips::*;
    #[cfg(bpf_target_arch = "powerpc64")]
    pub use super::powerpc64::*;
    #[cfg(bpf_target_arch = "riscv64")]
    pub use super::riscv64::*;
    #[cfg(bpf_target_arch = "s390x")]
    pub use super::s390x::*;
    #[cfg(bpf_target_arch = "x86_64")]
    pub use super::x86_64::*;
}

pub use generated::helpers;

pub mod bindings {
    pub use crate::generated::bindings::*;

    pub const TC_ACT_OK: i32 = crate::generated::bindings::TC_ACT_OK as i32;
    pub const TC_ACT_RECLASSIFY: i32 = crate::generated::bindings::TC_ACT_RECLASSIFY as i32;
    pub const TC_ACT_SHOT: i32 = crate::generated::bindings::TC_ACT_SHOT as i32;
    pub const TC_ACT_PIPE: i32 = crate::generated::bindings::TC_ACT_PIPE as i32;
    pub const TC_ACT_STOLEN: i32 = crate::generated::bindings::TC_ACT_STOLEN as i32;
    pub const TC_ACT_QUEUED: i32 = crate::generated::bindings::TC_ACT_QUEUED as i32;
    pub const TC_ACT_REPEAT: i32 = crate::generated::bindings::TC_ACT_REPEAT as i32;
    pub const TC_ACT_REDIRECT: i32 = crate::generated::bindings::TC_ACT_REDIRECT as i32;
    pub const TC_ACT_TRAP: i32 = crate::generated::bindings::TC_ACT_TRAP as i32;
    pub const TC_ACT_VALUE_MAX: i32 = crate::generated::bindings::TC_ACT_VALUE_MAX as i32;
    pub const TC_ACT_EXT_VAL_MASK: i32 = crate::generated::bindings::TC_ACT_EXT_VAL_MASK as i32;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bpf_map_def {
        pub type_: ::aya_ebpf_cty::c_uint,
        pub key_size: ::aya_ebpf_cty::c_uint,
        pub value_size: ::aya_ebpf_cty::c_uint,
        pub max_entries: ::aya_ebpf_cty::c_uint,
        pub map_flags: ::aya_ebpf_cty::c_uint,
        pub id: ::aya_ebpf_cty::c_uint,
        pub pinning: ::aya_ebpf_cty::c_uint,
    }
}
