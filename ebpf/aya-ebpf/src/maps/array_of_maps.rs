use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr::NonNull};

use aya_ebpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS},
    helpers::bpf_map_lookup_elem,
    maps::{InnerMap, PinningType},
};

#[repr(transparent)]
pub struct ArrayOfMaps<T: InnerMap> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

unsafe impl<T: InnerMap> Sync for ArrayOfMaps<T> {}

impl<T: InnerMap> ArrayOfMaps<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> ArrayOfMaps<T> {
        ArrayOfMaps {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY_OF_MAPS,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> ArrayOfMaps<T> {
        ArrayOfMaps {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY_OF_MAPS,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
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
        // FIXME: alignment
        unsafe { self.lookup(index).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        let ptr = unsafe {
            bpf_map_lookup_elem(
                self.def.get() as *mut _,
                &index as *const _ as *const c_void,
            )
        };
        NonNull::new(ptr as *mut T)
    }
}
