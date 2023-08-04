use core::{cell::UnsafeCell, mem, ptr::NonNull};

use aya_bpf_bindings::bindings::bpf_devmap_val;
use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_DEVMAP},
    helpers::{bpf_map_lookup_elem, bpf_redirect_map},
    maps::PinningType,
};

#[repr(transparent)]
pub struct DevMap {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for DevMap {}

impl DevMap {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> DevMap {
        DevMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_DEVMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<bpf_devmap_val>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> DevMap {
        DevMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_DEVMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<bpf_devmap_val>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<bpf_devmap_val> {
        unsafe {
            let value = bpf_map_lookup_elem(
                self.def.get() as *mut _,
                &index as *const _ as *const c_void,
            );
            NonNull::new(value as *mut bpf_devmap_val).map(|p| *p.as_ref())
        }
    }

    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> u32 {
        // Return XDP_REDIRECT on success, or the value of the two lower bits of the flags
        // argument on error. Thus I have no idea why it returns a long (i64) instead of
        // something saner, hence the unsigned_abs.
        unsafe {
            bpf_redirect_map(self.def.get() as *mut _, index.into(), flags).unsigned_abs() as u32
        }
    }
}
