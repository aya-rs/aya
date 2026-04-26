use core::ptr;

use crate::{
    EbpfContext, bindings::BPF_F_CURRENT_CPU, btf_maps::btf_map_def, helpers::bpf_perf_event_output,
};

btf_map_def!(
    /// A BTF-compatible BPF perf event array.
    ///
    /// Each element of a [`PerfEventArray`] is a separate perf buffer which
    /// can be used to receive events sent by eBPF programs that use
    /// `bpf_perf_event_output()`. The array is sized to the number of online
    /// CPUs at load time.
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
    /// static EVENTS: PerfEventArray = PerfEventArray::new();
    /// ```
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.18.
    pub struct PerfEventArray<; const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    max_entries: 0,
    map_flags: FLAGS,
    key_type: u32,
    value_type: u32,
);

impl<const FLAGS: usize> PerfEventArray<FLAGS> {
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
