use core::ffi::c_void;

use aya_bpf_bindings::helpers::bpf_sock_ops_cb_flags_set;

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

    pub fn cb_flags(&self) -> u32 {
        unsafe { (*self.ops).bpf_sock_ops_cb_flags }
    }

    pub fn set_cb_flags(&self, flags: i32) -> Result<(), i64> {
        let ret = unsafe { bpf_sock_ops_cb_flags_set(self.ops, flags) };
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }

    pub fn arg(&self, n: usize) -> u32 {
        unsafe { (*self.ops).__bindgen_anon_1.args[n] }
    }
}

impl BpfContext for SockOpsContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ops as *mut _
    }
}
