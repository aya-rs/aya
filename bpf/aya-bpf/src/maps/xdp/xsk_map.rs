use core::{mem, ptr::NonNull};

use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_XSKMAP},
    helpers::bpf_map_lookup_elem,
    maps::PinningType,
};

#[repr(transparent)]
pub struct XskMap {
    def: bpf_map_def,
}

impl XskMap {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> XskMap {
        XskMap {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_XSKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> XskMap {
        XskMap {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_XSKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
        }
    }

    pub fn get(&mut self, index: u32) -> Option<&u32> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                &index as *const _ as *const c_void,
            );
            // FIXME: alignment
            NonNull::new(value as *mut u32).map(|p| p.as_ref())
        }
    }
}
