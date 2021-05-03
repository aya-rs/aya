#![no_std]
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

#[cfg(bpf_target_arch = "x86_64")]
mod x86_64;

#[cfg(bpf_target_arch = "aarch64")]
mod aarch64;

mod gen {
    #[cfg(bpf_target_arch = "x86_64")]
    pub use super::x86_64::*;

    #[cfg(bpf_target_arch = "aarch64")]
    pub use super::aarch64::*;
}
pub use gen::*;

use aya_bpf_cty::{c_long, c_void};
use core::mem::{self, MaybeUninit};

#[inline]
unsafe fn bpf_probe_read<T>(src: *const T) -> Result<T, c_long> {
    let mut v: MaybeUninit<T> = MaybeUninit::uninit();
    let ret = helpers::bpf_probe_read(
        v.as_mut_ptr() as *mut c_void,
        mem::size_of::<T>() as u32,
        src as *const c_void,
    );
    if ret < 0 {
        return Err(ret);
    }

    Ok(v.assume_init())
}

pub const TC_ACT_OK: i32 = gen::bindings::TC_ACT_OK as i32;
pub const TC_ACT_RECLASSIFY: i32 = gen::bindings::TC_ACT_RECLASSIFY as i32;
pub const TC_ACT_SHOT: i32 = gen::bindings::TC_ACT_SHOT as i32;
pub const TC_ACT_PIPE: i32 = gen::bindings::TC_ACT_PIPE as i32;
pub const TC_ACT_STOLEN: i32 = gen::bindings::TC_ACT_STOLEN as i32;
pub const TC_ACT_QUEUED: i32 = gen::bindings::TC_ACT_QUEUED as i32;
pub const TC_ACT_REPEAT: i32 = gen::bindings::TC_ACT_REPEAT as i32;
pub const TC_ACT_REDIRECT: i32 = gen::bindings::TC_ACT_REDIRECT as i32;
pub const TC_ACT_TRAP: i32 = gen::bindings::TC_ACT_TRAP as i32;
pub const TC_ACT_VALUE_MAX: i32 = gen::bindings::TC_ACT_VALUE_MAX as i32;
pub const TC_ACT_EXT_VAL_MASK: i32 = 268435455;
