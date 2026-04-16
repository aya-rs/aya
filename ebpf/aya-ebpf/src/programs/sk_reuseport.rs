//! Socket load balancing with `SO_REUSEPORT`.

use crate::{EbpfContext, bindings::sk_reuseport_md, cty::c_void, programs::SockContext};

pub struct SkReuseportContext {
    pub md: *mut sk_reuseport_md,
}

impl SkReuseportContext {
    pub const fn new(md: *mut sk_reuseport_md) -> Self {
        Self { md }
    }

    #[inline]
    fn md(&self) -> &sk_reuseport_md {
        unsafe { &*self.md }
    }

    #[inline]
    fn data_ptr(&self) -> usize {
        unsafe { self.md().__bindgen_anon_1.data as usize }
    }

    #[inline]
    fn data_end_ptr(&self) -> usize {
        unsafe { self.md().__bindgen_anon_2.data_end as usize }
    }

    #[inline]
    fn sk_ptr(&self) -> *mut crate::bindings::bpf_sock {
        unsafe { self.md().__bindgen_anon_3.sk }
    }

    #[inline]
    fn migrating_sk_ptr(&self) -> *mut crate::bindings::bpf_sock {
        unsafe { self.md().__bindgen_anon_4.migrating_sk }
    }

    /// Returns the start of the directly accessible data.
    #[inline]
    pub fn data(&self) -> usize {
        self.data_ptr()
    }

    /// Returns the end of the directly accessible data.
    #[inline]
    pub fn data_end(&self) -> usize {
        self.data_end_ptr()
    }

    /// Returns the total packet length.
    #[inline]
    pub fn len(&self) -> usize {
        self.md().len as usize
    }

    /// Returns whether the packet length is zero.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the Ethernet protocol from the packet in network byte order.
    #[inline]
    pub fn eth_protocol(&self) -> u32 {
        self.md().eth_protocol
    }

    /// Returns the IP protocol.
    #[inline]
    pub fn ip_protocol(&self) -> u32 {
        self.md().ip_protocol
    }

    /// Returns whether the socket is bound to an INANY address.
    #[inline]
    pub fn bind_inany(&self) -> u32 {
        self.md().bind_inany
    }

    /// Returns the hash of the packet's 4-tuple.
    #[inline]
    pub fn hash(&self) -> u32 {
        self.md().hash
    }

    /// Returns a socket from the current `SO_REUSEPORT` group.
    ///
    /// This socket can be used to inspect the local listener that is being
    /// considered for selection.
    ///
    /// Available on Linux 5.14 and later. On older kernels the verifier
    /// rejects programs that access this field.
    #[inline]
    pub fn sk(&self) -> SockContext {
        SockContext::new(self.sk_ptr())
    }

    /// Returns the socket being migrated, if the program is running in a
    /// migrate path.
    ///
    /// When this returns `None`, the program is handling initial socket
    /// selection for a new packet or connection.
    ///
    /// Available on Linux 5.14 and later. On older kernels the verifier
    /// rejects programs that access this field.
    #[inline]
    pub fn migrating_sk(&self) -> Option<SockContext> {
        let sock = self.migrating_sk_ptr();
        if sock.is_null() {
            None
        } else {
            Some(SockContext::new(sock))
        }
    }
}

impl EbpfContext for SkReuseportContext {
    fn as_ptr(&self) -> *mut c_void {
        self.md.cast()
    }
}
