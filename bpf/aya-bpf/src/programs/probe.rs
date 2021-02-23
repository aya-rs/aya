use core::ffi::c_void;

use crate::{bindings::pt_regs, BpfContext};

pub struct ProbeContext {
    regs: *mut pt_regs,
}

impl ProbeContext {
    pub fn new(ctx: *mut c_void) -> ProbeContext {
        ProbeContext {
            regs: ctx as *mut pt_regs,
        }
    }
}

impl BpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs as *mut c_void
    }
}
