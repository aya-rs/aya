use core::{cell::UnsafeCell, mem};

use aya_ebpf_cty::c_void;

use crate::{
    EbpfContext,
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_SOCKMAP, bpf_sock_ops},
    helpers::{
        bpf_map_lookup_elem, bpf_msg_redirect_map, bpf_sk_assign, bpf_sk_redirect_map,
        bpf_sk_release, bpf_sock_map_update,
    },
    maps::PinningType,
    programs::{SkBuffContext, SkLookupContext, SkMsgContext},
};

#[repr(transparent)]
pub struct SockMap {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for SockMap {}

impl SockMap {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> SockMap {
        SockMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> SockMap {
        SockMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
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
            unsafe { bpf_sock_map_update(sk_ops, self.def.get().cast(), index.cast(), flags) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn redirect_msg(&self, ctx: &SkMsgContext, index: u32, flags: u64) -> i64 {
        unsafe { bpf_msg_redirect_map(ctx.as_ptr().cast(), self.def.get().cast(), index, flags) }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn redirect_skb(&self, ctx: &SkBuffContext, index: u32, flags: u64) -> i64 {
        unsafe { bpf_sk_redirect_map(ctx.as_ptr().cast(), self.def.get().cast(), index, flags) }
    }

    pub fn redirect_sk_lookup(
        &mut self,
        ctx: &SkLookupContext,
        index: u32,
        flags: u64,
    ) -> Result<(), u32> {
        unsafe {
            let sk = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                &index as *const _ as *const c_void,
            );
            if sk.is_null() {
                return Err(1);
            }
            let ret = bpf_sk_assign(ctx.as_ptr() as *mut _, sk, flags);
            bpf_sk_release(sk);
            (ret == 0).then_some(()).ok_or(1)
        }
    }
}
