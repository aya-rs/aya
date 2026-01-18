use core::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    ptr,
};

use crate::{
    EbpfContext as _,
    bindings::{bpf_map_type::BPF_MAP_TYPE_SOCKHASH, bpf_sock_ops},
    helpers::{
        bpf_msg_redirect_hash, bpf_sk_assign, bpf_sk_redirect_hash, bpf_sk_release,
        bpf_sock_hash_update,
    },
    lookup,
    maps::{MapDef, PinningType},
    programs::{SkBuffContext, SkLookupContext, SkMsgContext},
};

#[repr(transparent)]
pub struct SockHash<K> {
    def: MapDef,
    _k: PhantomData<K>,
}

impl<K> SockHash<K> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::None)
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::ByName)
    }

    const fn new(max_entries: u32, flags: u32, pinning: PinningType) -> Self {
        Self {
            def: MapDef::new::<K, u32>(BPF_MAP_TYPE_SOCKHASH, max_entries, flags, pinning),
            _k: PhantomData,
        }
    }

    pub fn update(
        &self,
        mut key: impl BorrowMut<K>,
        mut sk_ops: impl BorrowMut<bpf_sock_ops>,
        flags: u64,
    ) -> Result<(), i64> {
        let ret = unsafe {
            bpf_sock_hash_update(
                ptr::from_mut(sk_ops.borrow_mut()),
                self.def.as_ptr().cast(),
                ptr::from_mut(key.borrow_mut()).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    pub fn redirect_msg(
        &self,
        ctx: impl Borrow<SkMsgContext>,
        mut key: impl BorrowMut<K>,
        flags: u64,
    ) -> i64 {
        unsafe {
            bpf_msg_redirect_hash(
                ctx.borrow().msg,
                self.def.as_ptr().cast(),
                ptr::from_mut(key.borrow_mut()).cast(),
                flags,
            )
        }
    }

    pub fn redirect_skb(
        &self,
        ctx: impl Borrow<SkBuffContext>,
        mut key: impl BorrowMut<K>,
        flags: u64,
    ) -> i64 {
        unsafe {
            bpf_sk_redirect_hash(
                ctx.borrow().skb.skb,
                self.def.as_ptr().cast(),
                ptr::from_mut(key.borrow_mut()).cast(),
                flags,
            )
        }
    }

    pub fn redirect_sk_lookup(
        &self,
        ctx: impl Borrow<SkLookupContext>,
        key: impl Borrow<K>,
        flags: u64,
    ) -> Result<(), u32> {
        let sk = lookup(self.def.as_ptr(), key.borrow()).ok_or(1u32)?;
        let ret = unsafe { bpf_sk_assign(ctx.borrow().as_ptr().cast(), sk.as_ptr(), flags) };
        unsafe { bpf_sk_release(sk.as_ptr()) };
        match ret {
            0 => Ok(()),
            _ret => Err(1),
        }
    }
}
