use core::{borrow::Borrow, ptr::NonNull};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_ARRAY, btf_maps::AyaBtfMapMarker, cty::c_long, insert,
    lookup,
};

/// A BTF-compatible BPF array map.
///
/// This map type stores elements of type `T` indexed by `u32` keys.
/// The `#[repr(C)]` struct with flat fields (`type`, `key`, `value`, etc.) defines
/// the map in BTF format.
///
/// # Example
///
/// ```rust
/// use aya_ebpf::{btf_maps::Array, macros::btf_map};
///
/// #[btf_map]
/// static ARRAY: Array<u32, 10 /* max_elements */, 0> = Array::new();
/// ```
#[repr(C)]
#[allow(dead_code)]
pub struct Array<T, const M: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_ARRAY as usize],
    key: *const u32,
    value: *const T,
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],
    // Anonymize the struct in BTF.
    _anon: AyaBtfMapMarker,
}

unsafe impl<T: Sync, const M: usize, const F: usize> Sync for Array<T, M, F> {}

impl<T, const M: usize, const F: usize> Array<T, M, F> {
    /// Creates a new [`Array`] instance with elements of type `T`, maximum
    /// capacity of `M` and additional flags `F`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::Array, macros::btf_map};
    ///
    /// #[btf_map]
    /// static ARRAY: Array<u32, 10 /* max_elements */, 0> = Array::new();
    /// ```
    #[expect(
        clippy::new_without_default,
        reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
    )]
    pub const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
            map_flags: core::ptr::null(),
            _anon: AyaBtfMapMarker::new(),
        }
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        core::ptr::from_ref(self).cast_mut().cast()
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&T> {
        unsafe { self.lookup(index).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    pub fn get_ptr(&self, index: u32) -> Option<*const T> {
        unsafe { self.lookup(index).map(|p| p.as_ptr().cast_const()) }
    }

    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> Option<*mut T> {
        unsafe { self.lookup(index).map(|p| p.as_ptr()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        lookup(self.as_ptr(), &index)
    }

    /// Sets the value of the element at the given index.
    #[inline(always)]
    pub fn set(&self, index: u32, value: impl Borrow<T>, flags: u64) -> Result<(), c_long> {
        insert(self.as_ptr(), &index, value.borrow(), flags)
    }
}
