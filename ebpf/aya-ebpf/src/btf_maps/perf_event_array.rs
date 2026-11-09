use core::ptr;

use crate::{
    EbpfContext,
    bindings::BPF_F_CURRENT_CPU,
    btf_maps::btf_map_def,
    helpers::bpf_perf_event_output,
    maps::perf::{PerfEventValue, read_value},
};

btf_map_def!(
    /// A BTF-compatible BPF perf event array.
    ///
    /// Each element of a [`PerfEventArray`] can hold a perf event used by
    /// `bpf_perf_event_output()` or `bpf_perf_event_read_value()`. A
    /// `MAX_ENTRIES` value of zero asks the loader to size the map to the
    /// number of possible CPUs.
    ///
    /// The payload type is specified at each `output` call site. Unlike the
    /// legacy [`crate::maps::PerfEventArray`], which ties the payload type to
    /// the map at compile time, the BTF variant leaves the payload type to
    /// the caller. Use the legacy type when a compile-time one-payload-per-map
    /// guarantee is required.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::PerfEventArray, macros::btf_map};
    ///
    /// #[btf_map]
    /// static EVENTS: PerfEventArray<0, 0> = PerfEventArray::new();
    /// ```
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.18.
    pub struct PerfEventArray<; const MAX_ENTRIES: usize, const FLAGS: usize>,
    map_type: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: u32,
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize> PerfEventArray<MAX_ENTRIES, FLAGS> {
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
    /// The minimum kernel version required to use this method is 4.18.
    #[inline(always)]
    pub fn read_value(&self, index: u32) -> Result<PerfEventValue, i32> {
        read_value(self.as_ptr(), index)
    }

    pub fn output<T, C: EbpfContext>(&self, ctx: &C, data: &T, flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags);
    }

    pub fn output_at_index<T, C: EbpfContext>(&self, ctx: &C, index: u32, data: &T, flags: u32) {
        let flags = (u64::from(flags) << 32) | u64::from(index);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.as_ptr(),
                flags,
                ptr::from_ref(data).cast_mut().cast(),
                size_of_val(data) as u64,
            );
        }
    }
}
