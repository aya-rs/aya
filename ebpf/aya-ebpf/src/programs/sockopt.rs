use core::ffi::c_void;

use crate::{EbpfContext, bindings::bpf_sockopt};

pub struct SockoptContext {
    pub sockopt: *mut bpf_sockopt,
}

impl SockoptContext {
    pub const fn new(sockopt: *mut bpf_sockopt) -> Self {
        Self { sockopt }
    }
}

impl EbpfContext for SockoptContext {
    fn as_ptr(&self) -> *mut c_void {
        self.sockopt.cast()
    }
}
