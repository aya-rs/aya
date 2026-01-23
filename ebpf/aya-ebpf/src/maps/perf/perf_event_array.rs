use core::{borrow::Borrow, marker::PhantomData, ptr};

use crate::{
    EbpfContext,
    bindings::{BPF_F_CURRENT_CPU, bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY},
    helpers::bpf_perf_event_output,
    maps::{MapDef, PinningType},
};

#[repr(transparent)]
pub struct PerfEventArray<T> {
    def: MapDef,
    _t: PhantomData<T>,
}

impl<T> PerfEventArray<T> {
    pub const fn new(flags: u32) -> Self {
        Self::new_with_pinning(flags, PinningType::None)
    }

    pub const fn pinned(flags: u32) -> Self {
        Self::new_with_pinning(flags, PinningType::ByName)
    }

    const fn new_with_pinning(flags: u32, pinning: PinningType) -> Self {
        Self {
            def: MapDef::new::<u32, u32>(BPF_MAP_TYPE_PERF_EVENT_ARRAY, 0, flags, pinning),
            _t: PhantomData,
        }
    }

    pub fn output<C: EbpfContext>(&self, ctx: &C, data: impl Borrow<T>, flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags);
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
                self.def.as_ptr().cast(),
                flags,
                ptr::from_ref(data).cast_mut().cast(),
                size_of_val(data) as u64,
            );
        }
    }
}
