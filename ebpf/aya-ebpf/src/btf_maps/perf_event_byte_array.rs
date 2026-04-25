use crate::{
    EbpfContext, bindings::BPF_F_CURRENT_CPU, btf_maps::btf_map_def, helpers::bpf_perf_event_output,
};

btf_map_def!(
    /// A BTF-compatible BPF perf event array for byte-slice payloads.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::PerfEventByteArray, macros::btf_map};
    ///
    /// #[btf_map]
    /// static EVENTS: PerfEventByteArray = PerfEventByteArray::new();
    /// ```
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.18.
    pub struct PerfEventByteArray<; const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    max_entries: 0,
    map_flags: FLAGS,
    key_type: u32,
    value_type: u32,
);

impl<const FLAGS: usize> PerfEventByteArray<FLAGS> {
    pub fn output<C: EbpfContext>(&self, ctx: &C, data: &[u8], flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags);
    }

    pub fn output_at_index<C: EbpfContext>(&self, ctx: &C, index: u32, data: &[u8], flags: u32) {
        let flags = (u64::from(flags) << 32) | u64::from(index);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.as_ptr(),
                flags,
                data.as_ptr().cast_mut().cast(),
                data.len() as u64,
            );
        }
    }
}
