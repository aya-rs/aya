use core::{marker::PhantomData, mem, ptr::NonNull};

use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_ARRAY},
    helpers::bpf_map_lookup_elem,
    maps::PinningType,
};

#[repr(transparent)]
pub struct Array<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

impl<T> Array<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Array<T> {
        Array {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY,
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

    pub const fn pinned(max_entries: u32, flags: u32) -> Array<T> {
        Array {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY,
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

    pub fn get(&mut self, index: u32) -> Option<&T> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                &index as *const _ as *const c_void,
            );
            // FIXME: alignment
            NonNull::new(value as *mut T).map(|p| p.as_ref())
        }
    }
}
