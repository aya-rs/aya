use core::{borrow::Borrow, cell::UnsafeCell, marker::PhantomData, mem, ptr};

use crate::{
    EbpfContext as _,
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_SOCKHASH, bpf_sock_ops},
    helpers::{
        bpf_msg_redirect_hash, bpf_sk_assign, bpf_sk_redirect_hash, bpf_sk_release,
        bpf_sock_hash_update,
    },
    lookup,
    maps::PinningType,
    programs::{SkBuffContext, SkLookupContext, SkMsgContext},
};

#[repr(transparent)]
pub struct SockHash<K> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
}

unsafe impl<K: Sync> Sync for SockHash<K> {}

impl<K> SockHash<K> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKHASH,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _k: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKHASH,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _k: PhantomData,
        }
    }

    pub fn update(&self, key: &mut K, sk_ops: &mut bpf_sock_ops, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_sock_hash_update(
                ptr::from_mut(sk_ops),
                self.def.get().cast(),
                ptr::from_mut(key).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    pub fn redirect_msg(&self, ctx: &SkMsgContext, key: &mut K, flags: u64) -> i64 {
        unsafe {
            bpf_msg_redirect_hash(
                ctx.msg,
                self.def.get().cast(),
                ptr::from_mut(key).cast(),
                flags,
            )
        }
    }

    pub fn redirect_skb(&self, ctx: &SkBuffContext, key: &mut K, flags: u64) -> i64 {
        unsafe {
            bpf_sk_redirect_hash(
                ctx.skb.skb,
                self.def.get().cast(),
                ptr::from_mut(key).cast(),
                flags,
            )
        }
    }

    pub fn redirect_sk_lookup(
        &mut self,
        ctx: &SkLookupContext,
        key: impl Borrow<K>,
        flags: u64,
    ) -> Result<(), u32> {
        let sk = lookup(self.def.get().cast(), key.borrow()).ok_or(1u32)?;
        let ret = unsafe { bpf_sk_assign(ctx.as_ptr().cast(), sk.as_ptr(), flags) };
        unsafe { bpf_sk_release(sk.as_ptr()) };
        match ret {
            0 => Ok(()),
            _ret => Err(1),
        }
    }
}
