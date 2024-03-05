use core::ffi::c_void;

use crate::{bindings::bpf_sock, EbpfContext};

pub struct SockContext {
    pub sock: *mut bpf_sock,
}

impl SockContext {
    pub fn new(sock: *mut bpf_sock) -> SockContext {
        SockContext { sock }
    }
}

impl EbpfContext for SockContext {
    fn as_ptr(&self) -> *mut c_void {
        self.sock as *mut _
    }
}
