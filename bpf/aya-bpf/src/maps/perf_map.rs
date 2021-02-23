use core::{marker::PhantomData, mem};

use crate::{
    bindings::{bpf_map_def, BPF_F_CURRENT_CPU, BPF_MAP_TYPE_PERF_EVENT_ARRAY},
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
            },
            _t: PhantomData,
        }
    }

    pub fn output<C: BpfContext>(&mut self, ctx: &C, data: &T) {
        self.output_at_index(ctx, None, data, 0)
    }

    pub fn output_at_index<C: BpfContext>(
        &mut self,
        ctx: &C,
        index: Option<u32>,
        data: &T,
        flags: u32,
    ) {
        let index = index.map(|i| (i as u64) << 32).unwrap_or(BPF_F_CURRENT_CPU);
        let flags = index | flags as u64;
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
