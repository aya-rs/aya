use core::{cell::UnsafeCell, mem};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_CPUMAP},
    helpers::bpf_redirect_map,
    maps::PinningType,
};

#[repr(transparent)]
pub struct CpuMap {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for CpuMap {}

impl CpuMap {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> CpuMap {
        CpuMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_CPUMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> CpuMap {
        CpuMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_CPUMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> u32 {
        unsafe {
            // Return XDP_REDIRECT on success, or the value of the two lower bits of the flags
            // argument on error. Thus I have no idea why it returns a long (i64) instead of
            // something saner, hence the unsigned_abs.
            bpf_redirect_map(self.def.get() as *mut _, index.into(), flags).unsigned_abs() as u32
        }
    }
}
