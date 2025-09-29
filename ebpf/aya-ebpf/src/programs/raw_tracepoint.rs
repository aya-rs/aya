use core::ffi::c_void;

use crate::{EbpfContext, args::FromRawTracepointArgs, bindings::bpf_raw_tracepoint_args};

pub struct RawTracePointContext {
    ctx: *mut bpf_raw_tracepoint_args,
}

impl RawTracePointContext {
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx: ctx.cast() }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn arg<T: FromRawTracepointArgs>(&self, n: usize) -> T {
        unsafe { T::from_argument(&*self.ctx, n) }
    }
}

impl EbpfContext for RawTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx.cast()
    }
}
