use core::ffi::c_void;

use crate::EbpfContext;

pub struct RawTracePointContext {
    ctx: *mut c_void,
}

impl RawTracePointContext {
    pub fn new(ctx: *mut c_void) -> RawTracePointContext {
        RawTracePointContext { ctx }
    }
}

impl EbpfContext for RawTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
