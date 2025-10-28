use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::raw_tracepoint_arg, bindings::bpf_raw_tracepoint_args};

pub struct RawTracePointContext {
    ctx: *mut bpf_raw_tracepoint_args,
}

impl RawTracePointContext {
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx: ctx.cast() }
    }

    pub fn arg<T: Argument>(&self, n: usize) -> T {
        raw_tracepoint_arg(unsafe { &*self.ctx }, n)
    }
}

impl EbpfContext for RawTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx.cast()
    }
}
