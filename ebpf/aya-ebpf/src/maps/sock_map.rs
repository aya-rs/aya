use crate::{
    EbpfContext as _,
    bindings::{bpf_map_type::BPF_MAP_TYPE_SOCKMAP, bpf_sock_ops},
    helpers::{
        bpf_msg_redirect_map, bpf_sk_assign, bpf_sk_redirect_map, bpf_sk_release,
        bpf_sock_map_update,
    },
    lookup,
    maps::{MapDef, PinningType},
    programs::{SkBuffContext, SkLookupContext, SkMsgContext},
};

#[repr(transparent)]
pub struct SockMap {
    def: MapDef,
}

impl SockMap {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::None)
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::ByName)
    }

    const fn new(max_entries: u32, flags: u32, pinning: PinningType) -> Self {
        Self {
            def: MapDef::new::<u32, u32>(BPF_MAP_TYPE_SOCKMAP, max_entries, flags, pinning),
        }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn update(
        &self,
        mut index: u32,
        sk_ops: *mut bpf_sock_ops,
        flags: u64,
    ) -> Result<(), i64> {
        let index: *mut _ = &mut index;
        let ret =
            unsafe { bpf_sock_map_update(sk_ops, self.def.as_ptr().cast(), index.cast(), flags) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn redirect_msg(&self, ctx: &SkMsgContext, index: u32, flags: u64) -> i64 {
        unsafe { bpf_msg_redirect_map(ctx.as_ptr().cast(), self.def.as_ptr().cast(), index, flags) }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn redirect_skb(&self, ctx: &SkBuffContext, index: u32, flags: u64) -> i64 {
        unsafe { bpf_sk_redirect_map(ctx.as_ptr().cast(), self.def.as_ptr().cast(), index, flags) }
    }

    pub fn redirect_sk_lookup(
        &self,
        ctx: &SkLookupContext,
        index: u32,
        flags: u64,
    ) -> Result<(), u32> {
        let sk = lookup(self.def.as_ptr(), &index).ok_or(1u32)?;
        let ret = unsafe { bpf_sk_assign(ctx.as_ptr().cast(), sk.as_ptr(), flags) };
        unsafe { bpf_sk_release(sk.as_ptr()) };
        match ret {
            0 => Ok(()),
            _ret => Err(1),
        }
    }
}
