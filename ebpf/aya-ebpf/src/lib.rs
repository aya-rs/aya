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
    expect(
        incomplete_features,
        reason = "generic_const_exprs requires incomplete features"
    ),
    expect(
        unstable_features,
        reason = "generic_const_exprs requires unstable features"
    ),
    feature(generic_const_exprs)
)]
#![cfg_attr(
    target_arch = "bpf",
    expect(unused_crate_dependencies, reason = "compiler_builtins"),
    expect(
        unstable_features,
        reason = "asm_experimental_arch requires unstable features"
    ),
    feature(asm_experimental_arch)
)]
#![warn(clippy::cast_lossless, clippy::cast_sign_loss)]
#![no_std]

mod args;
pub mod bindings;
#[cfg(generic_const_exprs)]
mod const_assert;
pub use args::Argument;
pub mod btf_maps;
#[expect(
    clippy::missing_safety_doc,
    reason = "helpers mirror kernel helpers with implicit safety contracts"
)]
pub mod helpers;
pub mod maps;
pub mod programs;

use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    ptr::{self, NonNull},
};

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
        #[expect(clippy::cast_sign_loss, reason = "architecture-specific")]
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
    #[expect(clippy::unreachable, reason = "only used for doc tests")]
    #[cfg(not(target_arch = "bpf"))]
    {
        unreachable!("value={value} lower={lower} upper={upper}");
    }
}

#[inline]
fn insert<K, V>(def: *mut c_void, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
    let key = ptr::from_ref(key);
    let value = ptr::from_ref(value);
    match unsafe { bpf_map_update_elem(def, key.cast(), value.cast(), flags) } {
        0 => Ok(()),
        ret => Err(ret),
    }
}

#[inline]
fn remove<K>(def: *mut c_void, key: &K) -> Result<(), c_long> {
    let key = ptr::from_ref(key);
    match unsafe { bpf_map_delete_elem(def, key.cast()) } {
        0 => Ok(()),
        ret => Err(ret),
    }
}

#[inline]
fn lookup<K, V>(def: *mut c_void, key: &K) -> Option<NonNull<V>> {
    let key = ptr::from_ref(key);
    NonNull::new(unsafe { bpf_map_lookup_elem(def, key.cast()) }.cast())
}

/// A read-only global value that will be initialized by the loader.
/// Prefer using this to a plain `static` variable to avoid compiler optimizations eliding reads.
#[repr(transparent)]
pub struct BpfGlobal<T> {
    value: SyncUnsafeCell<MaybeUninit<T>>,
}

impl<T> BpfGlobal<T> {
    /// Returns a new, uninitialized [`BpfGlobal`], to be initialized at load
    /// time by the loader.
    pub const fn new() -> Self {
        Self {
            value: SyncUnsafeCell {
                value: UnsafeCell::new(MaybeUninit::uninit()),
            },
        }
    }
}

impl<T> Default for BpfGlobal<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> BpfGlobal<T>
where
    T: Copy,
{
    /// Load the global variable set by the loader. Uses a volatile load to avoid
    /// read elision.
    ///
    /// # SAFETY
    /// Global must have been initialized by `EbpfLoader::set_global`.
    /// `T` must match the data type that was used by the loader.
    #[inline]
    pub unsafe fn load(&self) -> T {
        unsafe { ptr::read_volatile(self.value.value.get() as *const T) }
    }
}

/// [`UnsafeCell`] but [`Sync`].
///
/// Copy of the standard library's unstable `SyncUnsafeCell`
#[repr(transparent)]
struct SyncUnsafeCell<T> {
    value: UnsafeCell<T>,
}

unsafe impl<T: Sync> Sync for SyncUnsafeCell<T> {}
