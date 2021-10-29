use core::ffi::c_void;

use crate::BpfContext;

pub struct BtfTracePointContext {
    ctx: *mut c_void,
}

impl BtfTracePointContext {
    pub fn new(ctx: *mut c_void) -> BtfTracePointContext {
        BtfTracePointContext { ctx }
    }
}

impl BpfContext for BtfTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
