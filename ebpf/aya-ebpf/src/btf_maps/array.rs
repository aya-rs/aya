use core::{cell::UnsafeCell, ptr::NonNull};

use crate::{bindings::bpf_map_type::BPF_MAP_TYPE_ARRAY, btf_map_def, btf_maps::lookup};

btf_map_def!(ArrayDef, BPF_MAP_TYPE_ARRAY);

#[repr(transparent)]
pub struct Array<T, const M: usize, const F: usize = 0>(UnsafeCell<ArrayDef<u32, T, M, F>>);

unsafe impl<T: Sync, const M: usize, const F: usize> Sync for Array<T, M, F> {}

impl<T, const M: usize, const F: usize> Array<T, M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Array(UnsafeCell::new(ArrayDef::new()))
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&T> {
        // FIXME: alignment
        unsafe { self.lookup(index).map(|p| p.as_ref()) }
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
        lookup(&self.0, &index)
    }
}
