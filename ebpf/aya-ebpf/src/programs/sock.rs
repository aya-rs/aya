use core::ffi::c_void;

use crate::{EbpfContext, bindings::bpf_sock};

pub struct SockContext {
    pub sock: *mut bpf_sock,
}

impl SockContext {
    pub fn new(sock: *mut bpf_sock) -> Self {
        Self { sock }
    }
}

impl EbpfContext for SockContext {
    fn as_ptr(&self) -> *mut c_void {
        self.sock.cast()
    }
}
