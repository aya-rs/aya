use core::{marker::PhantomData, mem};

use crate::{
    bindings::{
        bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY, BPF_F_CURRENT_CPU,
        BPF_F_INDEX_MASK,
    },
    helpers::bpf_perf_event_output,
    BpfContext,
};

#[repr(transparent)]
pub struct PerfMap<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

impl<T> PerfMap<T> {
    pub const fn new(flags: u32) -> PerfMap<T> {
        PerfMap::with_max_entries(0, flags)
    }

    pub const fn with_max_entries(max_entries: u32, flags: u32) -> PerfMap<T> {
        PerfMap {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: 0,
            },
            _t: PhantomData,
        }
    }

    pub fn output<C: BpfContext>(&mut self, ctx: &C, data: &T, flags: u32) {
        self.output_at_index(ctx, None, data, flags)
    }

    pub fn output_at_index<C: BpfContext>(
        &mut self,
        ctx: &C,
        index: Option<u32>,
        data: &T,
        flags: u32,
    ) {
        let index = index
            .map(|index| index & BPF_F_INDEX_MASK)
            .unwrap_or(BPF_F_CURRENT_CPU) as u64;
        let flags = (flags as u64) << 32 | index;
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                &mut self.def as *mut _ as *mut _,
                flags,
                data as *const _ as *mut _,
                mem::size_of::<T>() as u64,
            );
        }
    }
}
