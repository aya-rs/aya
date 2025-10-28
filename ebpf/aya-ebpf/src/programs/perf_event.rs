use core::ffi::c_void;

use crate::EbpfContext;

pub struct PerfEventContext {
    ctx: *mut c_void,
}

impl PerfEventContext {
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }
}

impl EbpfContext for PerfEventContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
