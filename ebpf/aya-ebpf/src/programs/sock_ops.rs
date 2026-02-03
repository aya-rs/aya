use core::ffi::c_void;

use aya_ebpf_bindings::helpers::bpf_sock_ops_cb_flags_set;

use crate::{EbpfContext, bindings::bpf_sock_ops};

pub struct SockOpsContext {
    pub ops: *mut bpf_sock_ops,
}

impl SockOpsContext {
    pub const fn new(ops: *mut bpf_sock_ops) -> Self {
        Self { ops }
    }

    pub fn op(&self) -> u32 {
        unsafe { (*self.ops).op }
    }

    pub fn family(&self) -> u32 {
        unsafe { (*self.ops).family }
    }

    pub fn cb_flags(&self) -> u32 {
        unsafe { (*self.ops).bpf_sock_ops_cb_flags }
    }

    pub fn set_cb_flags(&self, flags: i32) -> Result<(), i64> {
        let ret = unsafe { bpf_sock_ops_cb_flags_set(self.ops, flags) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }

    pub fn remote_ip4(&self) -> u32 {
        unsafe { (*self.ops).remote_ip4 }
    }

    pub fn local_ip4(&self) -> u32 {
        unsafe { (*self.ops).local_ip4 }
    }

    pub fn remote_ip6(&self) -> [u32; 4] {
        unsafe { (*self.ops).remote_ip6 }
    }

    pub fn local_ip6(&self) -> [u32; 4] {
        unsafe { (*self.ops).local_ip6 }
    }

    pub fn local_port(&self) -> u32 {
        unsafe { (*self.ops).local_port }
    }

    pub fn remote_port(&self) -> u32 {
        unsafe { (*self.ops).remote_port }
    }

    pub fn arg(&self, n: usize) -> u32 {
        unsafe { (*self.ops).__bindgen_anon_1.args[n] }
    }

    pub fn set_reply(&mut self, reply: u32) {
        unsafe { (*self.ops).__bindgen_anon_1.reply = reply }
    }
}

impl EbpfContext for SockOpsContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ops.cast()
    }
}
