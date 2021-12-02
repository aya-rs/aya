use core::mem;

use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS},
    helpers::bpf_map_lookup_elem,
    maps::PinningType,
};

#[repr(transparent)]
pub struct ArrayOfMaps {
    def: bpf_map_def,
}

impl ArrayOfMaps {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> ArrayOfMaps {
        ArrayOfMaps {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY_OF_MAPS,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> ArrayOfMaps {
        ArrayOfMaps {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY_OF_MAPS,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
        }
    }

    pub unsafe fn get(&mut self, index: u32) -> Option<&u32> {
        let value = bpf_map_lookup_elem(
            &mut self.def as *mut _ as *mut _,
            &index as *const _ as *const c_void,
        );
        if value.is_null() {
            None
        } else {
            // FIXME: alignment
            Some(&*(value as *const u32))
        }
    }
}
