use core::ffi::c_void;

use crate::{bindings::__sk_buff, BpfContext};

pub struct SkSkbContext {
    skb: *mut __sk_buff,
}

impl SkSkbContext {
    pub fn new(skb: *mut __sk_buff) -> SkSkbContext {
        SkSkbContext { skb }
    }
}

impl BpfContext for SkSkbContext {
    fn as_ptr(&self) -> *mut c_void {
        self.skb as *mut _
    }
}
