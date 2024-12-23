use core::cell::UnsafeCell;

use crate::{
    bindings::BPF_F_CURRENT_CPU, btf_maps::perf::PerfEventArrayDef, helpers::bpf_perf_event_output,
    EbpfContext,
};

#[repr(transparent)]
pub struct PerfEventByteArray<const F: usize = 0>(UnsafeCell<PerfEventArrayDef<F>>);

unsafe impl<const F: usize> Sync for PerfEventByteArray<F> {}

impl<const F: usize> PerfEventByteArray<F> {
    pub const fn new() -> Self {
        Self(UnsafeCell::new(PerfEventArrayDef::new()))
    }

    pub fn output<C: EbpfContext>(&self, ctx: &C, data: &[u8], flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags)
    }

    pub fn output_at_index<C: EbpfContext>(&self, ctx: &C, index: u32, data: &[u8], flags: u32) {
        let flags = u64::from(flags) << 32 | u64::from(index);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.0.get() as *mut _,
                flags,
                data.as_ptr() as *mut _,
                data.len() as u64,
            );
        }
    }
}
