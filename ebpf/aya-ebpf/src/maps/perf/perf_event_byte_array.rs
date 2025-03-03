use core::{cell::UnsafeCell, mem};

use crate::{
    EbpfContext,
    bindings::{BPF_F_CURRENT_CPU, bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY},
    helpers::bpf_perf_event_output,
    maps::PinningType,
};

#[repr(transparent)]
pub struct PerfEventByteArray {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for PerfEventByteArray {}

impl PerfEventByteArray {
    pub const fn new(flags: u32) -> PerfEventByteArray {
        PerfEventByteArray {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries: 0,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    pub const fn pinned(flags: u32) -> PerfEventByteArray {
        PerfEventByteArray {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries: 0,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    pub fn output<C: EbpfContext>(&self, ctx: &C, data: &[u8], flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags)
    }

    pub fn output_at_index<C: EbpfContext>(&self, ctx: &C, index: u32, data: &[u8], flags: u32) {
        let flags = (u64::from(flags) << 32) | u64::from(index);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.def.get() as *mut _,
                flags,
                data.as_ptr() as *mut _,
                data.len() as u64,
            );
        }
    }
}
