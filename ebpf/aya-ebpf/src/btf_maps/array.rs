use core::{cell::UnsafeCell, ptr::NonNull};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_ARRAY, btf_map_def, cty::c_long, error::EINVAL, insert,
    lookup,
};

btf_map_def!(ArrayDef, BPF_MAP_TYPE_ARRAY);

#[repr(transparent)]
pub struct Array<T, const M: usize, const F: usize = 0>(UnsafeCell<ArrayDef<u32, T, M, F>>);

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
    // BPF maps are always used as static variables, therefore this method has
    // to be `const`. `Default::default` is not const.
    #[expect(clippy::new_without_default)]
    pub const fn new() -> Self {
        Array(UnsafeCell::new(ArrayDef::new()))
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Result<Option<&T>, c_long> {
        unsafe {
            match self.lookup(index) {
                Some(p) => {
                    if p.is_aligned() {
                        Ok(Some(p.as_ref()))
                    } else {
                        Err(-EINVAL)
                    }
                }
                None => Ok(None),
            }
        }
    }

    #[inline(always)]
    pub fn get_ptr(&self, index: u32) -> Option<*const T> {
        unsafe { self.lookup(index).map(|p| p.as_ptr() as *const T) }
    }

    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> Option<*mut T> {
        unsafe { self.lookup(index).map(|p| p.as_ptr()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        lookup(self.0.get().cast(), &index)
    }

    /// Sets the value of the element at the given index.
    #[inline(always)]
    pub fn set(&self, index: u32, value: &T, flags: u64) -> Result<(), c_long> {
        insert(self.0.get().cast(), &index, value, flags)
    }
}
