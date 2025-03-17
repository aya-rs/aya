use aya_ebpf_cty::{c_long, c_void};

use crate::{
    EbpfContext,
    bindings::{__sk_buff, bpf_flow_keys},
    programs::sk_buff::SkBuff,
};

pub struct FlowDissectorContext {
    skb: SkBuff,
}

impl FlowDissectorContext {
    pub fn new(skb: *mut __sk_buff) -> FlowDissectorContext {
        let skb = SkBuff { skb };
        FlowDissectorContext { skb }
    }

    #[inline]
    pub fn data(&self) -> usize {
        self.skb.data()
    }

    #[inline]
    pub fn data_end(&self) -> usize {
        self.skb.data_end()
    }

    #[inline]
    pub fn flow_keys(&self) -> &bpf_flow_keys {
        unsafe { &*(*self.skb.skb).__bindgen_anon_1.flow_keys }
    }

    #[inline(always)]
    pub fn load_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<usize, c_long> {
        self.skb.load_bytes(offset, dst)
    }
}

impl EbpfContext for FlowDissectorContext {
    fn as_ptr(&self) -> *mut c_void {
        self.skb.as_ptr()
    }
}
