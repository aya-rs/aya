use core::ffi::c_void;

use aya_ebpf_bindings::bindings::bpf_perf_event_data;

use crate::EbpfContext;

pub struct PerfEventContext {
    pub ctx: *mut bpf_perf_event_data,
}

impl PerfEventContext {
    pub const fn new(ctx: *mut bpf_perf_event_data) -> Self {
        Self { ctx }
    }
}

impl EbpfContext for PerfEventContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx.cast()
    }
}
