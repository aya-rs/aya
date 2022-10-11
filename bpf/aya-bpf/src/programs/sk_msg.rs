use core::ffi::c_void;

use crate::{
    bindings::sk_msg_md,
    helpers::{bpf_msg_pop_data, bpf_msg_push_data},
    BpfContext,
};

pub struct SkMsgContext {
    pub msg: *mut sk_msg_md,
}

impl SkMsgContext {
    pub fn new(msg: *mut sk_msg_md) -> SkMsgContext {
        SkMsgContext { msg }
    }

    pub fn size(&self) -> u32 {
        unsafe { (*self.msg).size }
    }

    pub fn data(&self) -> usize {
        unsafe { (*self.msg).__bindgen_anon_1.data as usize }
    }

    pub fn data_end(&self) -> usize {
        unsafe { (*self.msg).__bindgen_anon_2.data_end as usize }
    }

    pub fn push_data(&self, start: u32, len: u32, flags: u64) -> Result<(), i64> {
        let ret = unsafe { bpf_msg_push_data(self.msg, start, len, flags) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }

    pub fn pop_data(&self, start: u32, len: u32, flags: u64) -> Result<(), i64> {
        let ret = unsafe { bpf_msg_pop_data(self.msg, start, len, flags) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

impl BpfContext for SkMsgContext {
    fn as_ptr(&self) -> *mut c_void {
        self.msg as *mut _
    }
}
