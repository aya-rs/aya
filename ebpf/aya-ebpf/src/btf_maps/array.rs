use core::{borrow::Borrow, ptr::NonNull};

use crate::{btf_maps::btf_map_def, cty::c_long, insert, lookup};

btf_map_def!(
    /// A BTF-compatible BPF array map.
    ///
    /// This map type stores elements of type `T` indexed by `u32` keys.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type of values stored in the array.
    /// * `M` - Maximum number of entries in the array.
    /// * `F` - BPF map flags (e.g., `BPF_F_MMAPABLE`). Defaults to 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::Array, macros::btf_map};
    ///
    /// #[btf_map]
    /// static ARRAY: Array<u32, 10, 0> = Array::new();
    /// ```
    pub struct Array<T, const M: usize, const F: usize = 0>,
    map_type: BPF_MAP_TYPE_ARRAY,
    max_entries: M,
    map_flags: F,
    key: *const u32,
    value: *const T,
);

impl<T, const M: usize, const F: usize> Array<T, M, F> {
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
