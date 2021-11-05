use core::ffi::c_void;

use crate::{bindings::xdp_md, BpfContext};

pub struct XdpContext {
    ctx: *mut xdp_md,
}

impl XdpContext {

    #[inline(always)]
    pub fn new(ctx: *mut xdp_md) -> XdpContext {
        XdpContext { ctx }
    }

    #[inline(always)]
    pub fn data(&self) -> usize {
        unsafe { (*self.ctx).data as usize }
    }

    #[inline(always)]
    pub fn data_end(&self) -> usize {
        unsafe { (*self.ctx).data_end as usize }
    }

    #[inline(always)]
    pub fn data_buffer(&self) -> Option<&[u8]> {
        unsafe {
            let data_buffer: *const u8 = (*self.ctx).data as usize as *const u8;
            if (*self.ctx).data_end <= (*self.ctx).data {
                return None;
            }
            let data_buffer_size = ((*self.ctx).data_end - (*self.ctx).data) as usize;
            Some(core::slice::from_raw_parts(data_buffer, data_buffer_size))
        }
    }

    #[inline(always)]
    pub fn data_pointer(&self) -> (*const u8, *const u8) {
        unsafe {
        (
            (*self.ctx).data as usize as *const u8,
            (*self.ctx).data_end as usize as *const u8,
        )
        }
    }
}

impl BpfContext for XdpContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut _
    }
}
