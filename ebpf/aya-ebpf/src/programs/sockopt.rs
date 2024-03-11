use core::ffi::c_void;

use crate::{bindings::bpf_sockopt, EbpfContext};

pub struct SockoptContext {
    pub sockopt: *mut bpf_sockopt,
}

impl SockoptContext {
    pub fn new(sockopt: *mut bpf_sockopt) -> SockoptContext {
        SockoptContext { sockopt }
    }
}

impl EbpfContext for SockoptContext {
    fn as_ptr(&self) -> *mut c_void {
        self.sockopt as *mut _
    }
}
