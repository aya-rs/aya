use core::{borrow::Borrow, cell::UnsafeCell, marker::PhantomData, mem, ptr};

use crate::{
    EbpfContext,
    bindings::{BPF_F_CURRENT_CPU, bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY},
    helpers::bpf_perf_event_output,
    maps::PinningType,
};

#[repr(transparent)]
pub struct PerfEventArray<T> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

unsafe impl<T: Sync> Sync for PerfEventArray<T> {}

impl<T> PerfEventArray<T> {
    pub const fn new(flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries: 0,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _t: PhantomData,
        }
    }

    pub const fn pinned(flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries: 0,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _t: PhantomData,
        }
    }

    pub fn output<C: EbpfContext>(&self, ctx: &C, data: impl Borrow<T>, flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags)
    }

    pub fn output_at_index<C: EbpfContext>(
        &self,
        ctx: &C,
        index: u32,
        data: impl Borrow<T>,
        flags: u32,
    ) {
        let data = data.borrow();
        let flags = (u64::from(flags) << 32) | u64::from(index);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.def.get().cast(),
                flags,
                ptr::from_ref(data).cast_mut().cast(),
                mem::size_of_val(data) as u64,
            );
        }
    }
}
