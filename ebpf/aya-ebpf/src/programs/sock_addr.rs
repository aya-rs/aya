use core::ffi::c_void;

use crate::{EbpfContext, bindings::bpf_sock_addr};

pub struct SockAddrContext {
    pub sock_addr: *mut bpf_sock_addr,
}

impl SockAddrContext {
    pub const fn new(sock_addr: *mut bpf_sock_addr) -> Self {
        Self { sock_addr }
    }
}

impl EbpfContext for SockAddrContext {
    fn as_ptr(&self) -> *mut c_void {
        self.sock_addr.cast()
    }
}
