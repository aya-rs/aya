use core::ffi::c_void;

use crate::{
    bindings::xdp_md,
    helpers::{bpf_xdp_adjust_head, bpf_xdp_adjust_meta, bpf_xdp_adjust_tail},
    EbpfContext,
};

pub struct XdpContext {
    pub ctx: *mut xdp_md,
}

impl XdpContext {
    pub fn new(ctx: *mut xdp_md) -> XdpContext {
        XdpContext { ctx }
    }

    #[inline]
    pub fn data(&self) -> usize {
        unsafe { (*self.ctx).data as usize }
    }

    #[inline]
    pub fn data_end(&self) -> usize {
        unsafe { (*self.ctx).data_end as usize }
    }

    /// Return the raw address of the XdpContext metadata.
    #[inline(always)]
    pub fn metadata(&self) -> usize {
        unsafe { (*self.ctx).data_meta as usize }
    }

    /// Return the raw address immediately after the XdpContext's metadata.
    #[inline(always)]
    pub fn metadata_end(&self) -> usize {
        self.data()
    }

    /// Adjusts the head of the Packet by given 'delta' (both positive and negative values are
    /// possible.)
    #[inline(always)]
    pub fn adjust_head(&mut self, delta: crate::cty::c_int) -> Result<(), ()> {
        unsafe {
            match bpf_xdp_adjust_head(self.ctx, delta) {
                0 => Ok(()),
                _ => Err(()),
            }
        }
    }

    /// Adjusts the tail of the Packet by given 'delta' (both positive and negative values are
    /// possible.)
    #[inline(always)]
    pub fn adjust_tail(&mut self, delta: crate::cty::c_int) -> Result<(), ()> {
        unsafe {
            match bpf_xdp_adjust_tail(self.ctx, delta) {
                0 => Ok(()),
                _ => Err(()),
            }
        }
    }

    /// Adjusts the tail of the Packet by given 'delta' (both positive and negative values are
    /// possible.)
    #[inline(always)]
    pub fn adjust_metadata(&mut self, delta: crate::cty::c_int) -> Result<(), ()> {
        unsafe {
            match bpf_xdp_adjust_meta(self.ctx, delta) {
                0 => Ok(()),
                _ => Err(()),
            }
        }
    }
}

impl EbpfContext for XdpContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut _
    }
}
