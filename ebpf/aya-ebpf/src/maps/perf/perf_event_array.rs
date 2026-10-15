use core::{marker::PhantomData, ptr};

use super::{PerfEventValue, read_value};
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

impl<T> super::super::__MapLayout for PerfEventArray<T> {
    type Key = u32;
    type Value = u32;
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

    /// Reads the perf event stored at `index`.
    ///
    /// The returned value includes the counter and the time it was enabled and running. The latter
    /// two values allow callers to account for PMU multiplexing.
    ///
    /// # Locality
    ///
    /// The [`PerfEventScope`] used to open the event determines where it can be read from eBPF. For
    /// `PerfEventScope::CallingProcess` and `PerfEventScope::OneProcess`, the eBPF program must
    /// execute in the target task. For `PerfEventScope::AllProcessesOneCpu`, it must execute on the
    /// target CPU. Otherwise, this method returns `Err(-EINVAL)`.
    ///
    /// [`PerfEventScope`]: https://docs.rs/aya/latest/aya/programs/perf_event/enum.PerfEventScope.html
    ///
    /// # Errors
    ///
    /// Returns a negative error code from `bpf_perf_event_read_value()`.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this method is 4.15.
    #[inline(always)]
    pub fn read_value(&self, index: u32) -> Result<PerfEventValue, i32> {
        read_value(self.def.as_ptr(), index)
    }

    pub fn output<C: EbpfContext>(&self, ctx: &C, data: &T, flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags);
    }

    pub fn output_at_index<C: EbpfContext>(&self, ctx: &C, index: u32, data: &T, flags: u32) {
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
