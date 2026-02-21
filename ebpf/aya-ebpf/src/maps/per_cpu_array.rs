use core::{marker::PhantomData, ptr::NonNull};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY,
    lookup,
    maps::{MapDef, PinningType},
};

#[repr(transparent)]
pub struct PerCpuArray<T> {
    def: MapDef,
    _t: PhantomData<T>,
}

impl<T> super::private::Map for PerCpuArray<T> {
    type Key = u32;
    type Value = T;
}

impl<T> PerCpuArray<T> {
    map_constructors!(u32, T, BPF_MAP_TYPE_PERCPU_ARRAY, phantom _t);

    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&T> {
        unsafe {
            // FIXME: alignment
            self.lookup(index).map(|p| p.as_ref())
        }
    }

    #[inline(always)]
    pub fn get_ptr(&self, index: u32) -> Option<*const T> {
        unsafe { self.lookup(index).map(|p| p.as_ptr().cast_const()) }
    }

    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> Option<*mut T> {
        unsafe { self.lookup(index).map(NonNull::as_ptr) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        lookup(self.def.as_ptr(), &index)
    }
}
