use core::ffi::c_void;

use crate::{helpers::bpf_probe_read, EbpfContext};

pub struct TracePointContext {
    ctx: *mut c_void,
}

impl TracePointContext {
    pub fn new(ctx: *mut c_void) -> TracePointContext {
        TracePointContext { ctx }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn read_at<T>(&self, offset: usize) -> Result<T, i64> {
        bpf_probe_read(self.ctx.add(offset) as *const T)
    }
}

impl EbpfContext for TracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
