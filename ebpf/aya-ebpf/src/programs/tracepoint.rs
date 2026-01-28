use core::ffi::c_void;

use crate::{EbpfContext, helpers::bpf_probe_read_kernel};

pub struct TracePointContext {
    ctx: *mut c_void,
}

impl TracePointContext {
    pub const fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }

    #[expect(
        clippy::missing_safety_doc,
        reason = "safety requirements come from the underlying helper"
    )]
    pub unsafe fn read_at<T>(&self, offset: usize) -> Result<T, i32> {
        unsafe { bpf_probe_read_kernel(self.ctx.add(offset).cast()) }
    }
}

impl EbpfContext for TracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
