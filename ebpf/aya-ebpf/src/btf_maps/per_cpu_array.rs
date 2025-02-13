use core::{cell::UnsafeCell, ptr::NonNull};

use aya_ebpf_bindings::helpers::bpf_map_lookup_elem;

use crate::{bindings::bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY, btf_map_def, cty::c_void};

btf_map_def!(PerCpuArrayDef, BPF_MAP_TYPE_PERCPU_ARRAY);

#[repr(transparent)]
pub struct PerCpuArray<T, const M: usize, const F: usize = 0>(
    UnsafeCell<PerCpuArrayDef<u32, T, M, F>>,
);

unsafe impl<T: Sync, const M: usize, const F: usize> Sync for PerCpuArray<T, M, F> {}

impl<T, const M: usize, const F: usize> PerCpuArray<T, M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(PerCpuArrayDef::new()))
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&T> {
        unsafe {
            // FIXME: alignment
            self.lookup(index).map(|p| p.as_ref())
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
        let ptr = bpf_map_lookup_elem(self.0.get() as *mut _, &index as *const _ as *const c_void);
        NonNull::new(ptr as *mut T)
    }
}
