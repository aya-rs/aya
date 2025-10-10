use core::ffi::c_void;

use aya_ebpf_bindings::bindings::bpf_perf_event_data;

use crate::EbpfContext;

pub struct PerfEventContext {
    pub ctx: *mut bpf_perf_event_data,
}

impl PerfEventContext {
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx: ctx.cast() }
    }
}

impl EbpfContext for PerfEventContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx.cast()
    }
}
