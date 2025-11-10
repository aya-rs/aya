use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr::NonNull};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY},
    lookup,
    maps::PinningType,
};

#[repr(transparent)]
pub struct PerCpuArray<T> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

unsafe impl<T> Sync for PerCpuArray<T> {}

impl<T> PerCpuArray<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERCPU_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERCPU_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _t: PhantomData,
        }
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
        unsafe { self.lookup(index).map(|p| p.as_ptr().cast_const()) }
    }

    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> Option<*mut T> {
        unsafe { self.lookup(index).map(|p| p.as_ptr()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        lookup(self.def.get().cast(), &index)
    }
}
