use core::{marker::PhantomData, mem, ptr::NonNull};

use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY},
    helpers::bpf_map_lookup_elem,
    maps::PinningType,
};

#[repr(transparent)]
pub struct PerCpuArray<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

impl<T> PerCpuArray<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> PerCpuArray<T> {
        PerCpuArray {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_PERCPU_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> PerCpuArray<T> {
        PerCpuArray {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_PERCPU_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
            _t: PhantomData,
        }
    }

    #[inline(always)]
    pub fn get(&mut self, index: u32) -> Option<&T> {
        unsafe {
            // FIXME: alignment
            self.lookup(index).map(|p| p.as_ref())
        }
    }

    #[inline(always)]
    pub fn get_mut(&mut self, index: u32) -> Option<&mut T> {
        unsafe {
            // FIXME: alignment
            self.lookup(index).map(|mut p| p.as_mut())
        }
    }

    #[inline(always)]
    unsafe fn lookup(&mut self, index: u32) -> Option<NonNull<T>> {
        let ptr = bpf_map_lookup_elem(
            &mut self.def as *mut _ as *mut _,
            &index as *const _ as *const c_void,
        );
        NonNull::new(ptr as *mut T)
    }
}
