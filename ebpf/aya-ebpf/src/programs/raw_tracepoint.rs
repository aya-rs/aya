use core::ffi::c_void;

use crate::{args::FromRawTracepointArgs, bindings::bpf_raw_tracepoint_args, EbpfContext};

pub struct RawTracePointContext {
    ctx: *mut bpf_raw_tracepoint_args,
}

impl RawTracePointContext {
    pub fn new(ctx: *mut c_void) -> RawTracePointContext {
        RawTracePointContext {
            ctx: ctx as *mut bpf_raw_tracepoint_args,
        }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn arg<T: FromRawTracepointArgs>(&self, n: usize) -> T {
        T::from_argument(&*self.ctx, n)
    }
}

impl EbpfContext for RawTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut c_void
    }
}
