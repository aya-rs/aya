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
    #[inline]
    #[expect(
        clippy::not_unsafe_ptr_arg_deref,
        reason = "skb is initialization context from kernel"
    )]
    pub const fn new(skb: *mut __sk_buff) -> Self {
        let skb = unsafe { SkBuff::new(skb) };
        Self { skb }
    }

    #[inline]
    pub const fn data(&self) -> usize {
        self.skb.data()
    }

    #[inline]
    pub const fn data_end(&self) -> usize {
        self.skb.data_end()
    }

    #[inline]
    pub fn flow_keys(&mut self) -> &mut bpf_flow_keys {
        unsafe { &mut *(*self.skb.as_raw_ptr()).__bindgen_anon_1.flow_keys }
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
