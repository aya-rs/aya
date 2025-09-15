//! [![](https://aya-rs.dev/assets/images/aya_logo_docs.svg)](https://aya-rs.dev)
//!
//! A library to write eBPF programs.
//!
//! Aya-bpf is an eBPF library built with a focus on operability and developer experience.
//! It is the kernel-space counterpart of [Aya](https://docs.rs/aya)
#![doc(
    html_logo_url = "https://aya-rs.dev/assets/images/crabby.svg",
    html_favicon_url = "https://aya-rs.dev/assets/images/crabby.svg"
)]
#![cfg_attr(
    generic_const_exprs,
    expect(incomplete_features),
    expect(unstable_features),
    feature(generic_const_exprs)
)]
#![cfg_attr(
    target_arch = "bpf",
    expect(unused_crate_dependencies, reason = "compiler_builtins"),
    expect(unstable_features),
    feature(asm_experimental_arch)
)]
#![warn(clippy::cast_lossless, clippy::cast_sign_loss)]
#![no_std]

pub use aya_ebpf_bindings::bindings;

mod args;
pub use args::{PtRegs, RawTracepointArgs};
pub mod btf_maps;
#[expect(clippy::missing_safety_doc, unsafe_op_in_unsafe_fn)]
pub mod helpers;
pub mod maps;
pub mod programs;

use core::ptr::{self, NonNull};

pub use aya_ebpf_cty as cty;
pub use aya_ebpf_macros as macros;
use cty::{c_long, c_void};
use helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_map_delete_elem,
    bpf_map_lookup_elem, bpf_map_update_elem,
};

pub const TASK_COMM_LEN: usize = 16;

pub trait EbpfContext {
    fn as_ptr(&self) -> *mut c_void;

    #[inline]
    fn command(&self) -> Result<[u8; TASK_COMM_LEN], c_long> {
        bpf_get_current_comm()
    }

    fn pid(&self) -> u32 {
        bpf_get_current_pid_tgid() as u32
    }

    fn tgid(&self) -> u32 {
        (bpf_get_current_pid_tgid() >> 32) as u32
    }

    fn uid(&self) -> u32 {
        bpf_get_current_uid_gid() as u32
    }

    fn gid(&self) -> u32 {
        (bpf_get_current_uid_gid() >> 32) as u32
    }
}

mod intrinsics {
    use super::cty::c_int;

    #[unsafe(no_mangle)]
    unsafe extern "C" fn memset(s: *mut u8, c: c_int, n: usize) {
        #[expect(clippy::cast_sign_loss)]
        let b = c as u8;
        for i in 0..n {
            unsafe { *s.add(i) = b }
        }
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn memcpy(dest: *mut u8, src: *mut u8, n: usize) {
        unsafe { copy_forward(dest, src, n) }
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn memmove(dest: *mut u8, src: *mut u8, n: usize) {
        let delta = (dest as usize).wrapping_sub(src as usize);
        if delta >= n {
            // We can copy forwards because either dest is far enough ahead of src,
            // or src is ahead of dest (and delta overflowed).
            unsafe { copy_forward(dest, src, n) }
        } else {
            unsafe { copy_backward(dest, src, n) }
        }
    }

    #[inline(always)]
    unsafe fn copy_forward(dest: *mut u8, src: *mut u8, n: usize) {
        for i in 0..n {
            unsafe { *dest.add(i) = *src.add(i) }
        }
    }

    #[inline(always)]
    unsafe fn copy_backward(dest: *mut u8, src: *mut u8, n: usize) {
        for i in (0..n).rev() {
            unsafe { *dest.add(i) = *src.add(i) }
        }
    }
}

// A reimplementation of the BPF_F_ADJ_ROOM_ENCAP_L2(len) macro of the kernel, to use to construct
// flags to pass to bpf_skb_adjust_room.
// https://elixir.bootlin.com/linux/v6.16.4/source/include/uapi/linux/bpf.h#L6149
#[inline(always)]
#[allow(non_snake_case)]
pub fn BPF_F_ADJ_ROOM_ENCAP_L2(len: u64) -> u64 {
    (len & u64::from(bindings::BPF_ADJ_ROOM_ENCAP_L2_MASK)) << bindings::BPF_ADJ_ROOM_ENCAP_L2_SHIFT
}

/// Check if a value is within a range, using conditional forms compatible with
/// the verifier.
#[inline(always)]
pub fn check_bounds_signed(value: i64, lower: i64, upper: i64) -> bool {
    #[cfg(target_arch = "bpf")]
    unsafe {
        let mut in_bounds = 0u64;
        core::arch::asm!(
            "if {value} s< {lower} goto +2",
            "if {value} s> {upper} goto +1",
            "{i} = 1",
            i = inout(reg) in_bounds,
            lower = in(reg) lower,
            upper = in(reg) upper,
            value = in(reg) value,
        );
        in_bounds == 1
    }
    // We only need this for doc tests which are compiled for the host target
    #[cfg(not(target_arch = "bpf"))]
    {
        let _ = value;
        let _ = lower;
        let _ = upper;
        unimplemented!()
    }
}

#[inline]
fn insert<K, V>(def: *mut c_void, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
    let key = ptr::from_ref(key);
    let value = ptr::from_ref(value);
    match unsafe { bpf_map_update_elem(def.cast(), key.cast(), value.cast(), flags) } {
        0 => Ok(()),
        ret => Err(ret),
    }
}

#[inline]
fn remove<K>(def: *mut c_void, key: &K) -> Result<(), c_long> {
    let key = ptr::from_ref(key);
    match unsafe { bpf_map_delete_elem(def.cast(), key.cast()) } {
        0 => Ok(()),
        ret => Err(ret),
    }
}

#[inline]
fn lookup<K, V>(def: *mut c_void, key: &K) -> Option<NonNull<V>> {
    let key = ptr::from_ref(key);
    NonNull::new(unsafe { bpf_map_lookup_elem(def.cast(), key.cast()) }.cast())
}
