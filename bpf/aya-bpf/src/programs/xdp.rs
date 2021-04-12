use core::ffi::c_void;

use crate::{bindings::xdp_md, BpfContext};

pub struct XdpContext {
    ctx: *mut xdp_md,
}

impl XdpContext {
    pub fn new(ctx: *mut xdp_md) -> XdpContext {
        XdpContext { ctx }
    }

    pub fn data(&self) -> usize {
        unsafe { (*self.ctx).data as usize }
    }

    pub fn data_end(&self) -> usize {
        unsafe { (*self.ctx).data_end as usize }
    }
}

impl BpfContext for XdpContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut _
    }
}
