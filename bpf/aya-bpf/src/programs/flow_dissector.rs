use aya_bpf_cty::c_void;

use crate::{bindings::__sk_buff, BpfContext};

pub struct FlowDissectorContext {
    skb: *mut __sk_buff,
}

impl FlowDissectorContext {
    pub fn new(skb: *mut __sk_buff) -> FlowDissectorContext {
        FlowDissectorContext { skb }
    }

    #[inline]
    pub fn data(&self) -> usize {
        unsafe { (*self.skb).data as usize }
    }

    #[inline]
    pub fn data_end(&self) -> usize {
        unsafe { (*self.skb).data_end as usize }
    }

    #[inline]
    pub fn flow_keys(&self) -> usize {
        unsafe { (*self.skb).__bindgen_anon_1.flow_keys as usize }
    }
}

impl BpfContext for FlowDissectorContext {
    fn as_ptr(&self) -> *mut c_void {
        self.skb as *mut _
    }
}
