use core::ffi::c_void;

use crate::{bindings::bpf_sock_ops, BpfContext};

pub struct SockOpsContext {
    ops: *mut bpf_sock_ops,
}

impl SockOpsContext {
    pub fn new(ops: *mut bpf_sock_ops) -> SockOpsContext {
        SockOpsContext { ops }
    }

    pub fn op(&self) -> u32 {
        unsafe { (*self.ops).op }
    }
}

impl BpfContext for SockOpsContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ops as *mut _
    }
}
