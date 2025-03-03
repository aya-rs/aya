use core::ffi::c_void;

use crate::{EbpfContext, bindings::xdp_md};

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

    /// Return the interface of the index as determined by the OS.
    #[inline]
    pub fn ingress_ifindex(&self) -> usize {
        unsafe { (*self.ctx).ingress_ifindex as usize }
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
}

impl EbpfContext for XdpContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut _
    }
}
