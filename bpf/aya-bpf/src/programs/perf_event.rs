use crate::BpfContext;
use core::ffi::c_void;

pub struct PerfEventContext {
    ctx: *mut c_void,
}

impl PerfEventContext {
    pub fn new(ctx: *mut c_void) -> PerfEventContext {
        PerfEventContext { ctx }
    }
}

impl BpfContext for PerfEventContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
