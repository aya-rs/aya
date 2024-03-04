use core::ffi::c_void;

use crate::BpfContext;

pub struct RawTracePointContext {
    ctx: *mut c_void,
}

impl RawTracePointContext {
    pub fn new(ctx: *mut c_void) -> RawTracePointContext {
        RawTracePointContext { ctx }
    }
}

impl BpfContext for RawTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
