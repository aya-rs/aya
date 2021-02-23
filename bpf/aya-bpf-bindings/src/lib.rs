#![no_std]
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

#[cfg(bpf_target_arch = "x86_64")]
mod x86_64;

#[cfg(bpf_target_arch = "aarch64")]
mod aarch64;

#[cfg(bpf_target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(bpf_target_arch = "aarch64")]
pub use aarch64::*;

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
