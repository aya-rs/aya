use core::ffi::c_void;

use crate::{bindings::bpf_sock_addr, BpfContext};

pub struct SockAddrContext {
    pub sock_addr: *mut bpf_sock_addr,
}

impl SockAddrContext {
    pub fn new(sock_addr: *mut bpf_sock_addr) -> SockAddrContext {
        SockAddrContext { sock_addr }
    }
}

impl BpfContext for SockAddrContext {
    fn as_ptr(&self) -> *mut c_void {
        self.sock_addr as *mut _
    }
}
