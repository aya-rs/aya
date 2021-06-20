use core::ffi::c_void;

use crate::BpfContext;

pub struct LsmContext {
    ctx: *mut c_void,
}

impl LsmContext {
    pub fn new(ctx: *mut c_void) -> LsmContext {
        LsmContext { ctx }
    }
}

impl BpfContext for LsmContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
