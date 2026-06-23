use core::ffi::c_void;

use crate::{
    EbpfContext,
    bindings::sk_msg_md,
    helpers::{bpf_msg_pop_data, bpf_msg_push_data},
};

pub struct SkMsgContext {
    pub msg: *mut sk_msg_md,
}

impl SkMsgContext {
    pub const fn new(msg: *mut sk_msg_md) -> Self {
        Self { msg }
    }

    pub fn size(&self) -> u32 {
        unsafe { (*self.msg).size }
    }

    pub fn family(&self) -> u32 {
        unsafe { (*self.msg).family }
    }

    pub fn remote_ip4(&self) -> u32 {
        unsafe { (*self.msg).remote_ip4 }
    }

    pub fn local_ip4(&self) -> u32 {
        unsafe { (*self.msg).local_ip4 }
    }

    pub fn remote_ip6(&self) -> [u32; 4] {
        unsafe { (*self.msg).remote_ip6 }
    }

    pub fn local_ip6(&self) -> [u32; 4] {
        unsafe { (*self.msg).local_ip6 }
    }

    pub fn local_port(&self) -> u32 {
        unsafe { (*self.msg).local_port }
    }

    pub fn remote_port(&self) -> u32 {
        unsafe { (*self.msg).remote_port }
    }

    pub fn data(&self) -> usize {
        unsafe { (*self.msg).__bindgen_anon_1.data as usize }
    }

    pub fn data_end(&self) -> usize {
        unsafe { (*self.msg).__bindgen_anon_2.data_end as usize }
    }

    pub fn push_data(&self, start: u32, len: u32, flags: u64) -> Result<(), i32> {
        let ret = unsafe { bpf_msg_push_data(self.msg, start, len, flags) };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }

    pub fn pop_data(&self, start: u32, len: u32, flags: u64) -> Result<(), i32> {
        let ret = unsafe { bpf_msg_pop_data(self.msg, start, len, flags) };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }
}

impl EbpfContext for SkMsgContext {
    fn as_ptr(&self) -> *mut c_void {
        self.msg.cast()
    }
}
