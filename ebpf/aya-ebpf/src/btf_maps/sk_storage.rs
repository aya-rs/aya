use core::{cell::UnsafeCell, ptr};

use aya_ebpf_bindings::bindings::{
    BPF_F_NO_PREALLOC, bpf_map_type::BPF_MAP_TYPE_SK_STORAGE, bpf_sock,
};
use aya_ebpf_cty::{c_long, c_void};

use crate::{
    btf_map_def,
    helpers::generated::{bpf_sk_storage_delete, bpf_sk_storage_get},
};

btf_map_def!(SkStorageDef, BPF_MAP_TYPE_SK_STORAGE);

// TODO(https://github.com/rust-lang/rust/issues/76560): this should be:
//
// { F | BPF_F_NO_PREALLOC as usize }.
#[repr(transparent)]
pub struct SkStorage<T>(UnsafeCell<SkStorageDef<i32, T, 0, { BPF_F_NO_PREALLOC as usize }>>);

unsafe impl<T: Sync> Sync for SkStorage<T> {}

impl<T> SkStorage<T> {
    #[expect(
        clippy::new_without_default,
        reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
    )]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(SkStorageDef::new()))
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut c_void {
        self.0.get().cast()
    }

    /// Gets the value associated with `sk`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `sk`.
    #[inline(always)]
    pub unsafe fn get(&self, sk: *mut bpf_sock, value: Option<&mut T>, flags: u64) -> Option<&T> {
        unsafe { self.get_ptr(sk.cast(), value, flags).as_ref() }
    }

    /// Gets a pointer to the value associated with `sk`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `sk`.
    #[inline(always)]
    pub unsafe fn get_ptr(&self, sk: *mut bpf_sock, value: Option<&mut T>, flags: u64) -> *const T {
        unsafe { self.get_ptr_mut(sk.cast(), value, flags).cast_const() }
    }

    /// Gets a mutable pointer to the value associated with `sk`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `sk`.
    #[inline(always)]
    pub unsafe fn get_ptr_mut(
        &self,
        sk: *mut bpf_sock,
        value: Option<&mut T>,
        flags: u64,
    ) -> *mut T {
        let value = value.map_or(ptr::null_mut(), |value| ptr::from_mut(value).cast());
        unsafe { bpf_sk_storage_get(self.as_ptr(), sk.cast(), value, flags) }.cast()
    }

    /// Deletes the value associated with `sk`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `sk`.
    #[inline(always)]
    pub unsafe fn delete(&self, sk: *mut bpf_sock) -> Result<(), c_long> {
        let ret = unsafe { bpf_sk_storage_delete(self.as_ptr(), sk.cast()) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}
