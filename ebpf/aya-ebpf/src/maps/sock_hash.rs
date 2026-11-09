use core::{marker::PhantomData, ptr};

use crate::{
    ENOENT, EbpfContext as _,
    bindings::{bpf_map_type::BPF_MAP_TYPE_SOCKHASH, bpf_sock_ops},
    cty::c_long,
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

impl<K> super::private::Map for SockHash<K> {
    type Key = K;
    type Value = u32;
}

impl<K> SockHash<K> {
    map_constructors!(K, u32, BPF_MAP_TYPE_SOCKHASH, phantom _k);

    pub fn update(&self, key: &mut K, sk_ops: &mut bpf_sock_ops, flags: u64) -> Result<(), i32> {
        let ret = unsafe {
            bpf_sock_hash_update(
                ptr::from_mut(sk_ops),
                self.def.as_ptr().cast(),
                ptr::from_mut(key).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }

    pub fn redirect_msg(&self, ctx: &SkMsgContext, key: &mut K, flags: u64) -> c_long {
        unsafe {
            bpf_msg_redirect_hash(
                ctx.msg,
                self.def.as_ptr().cast(),
                ptr::from_mut(key).cast(),
                flags,
            )
        }
    }

    pub fn redirect_skb(&self, ctx: &SkBuffContext, key: &mut K, flags: u64) -> c_long {
        unsafe {
            bpf_sk_redirect_hash(
                ctx.skb.as_raw_ptr(),
                self.def.as_ptr().cast(),
                ptr::from_mut(key).cast(),
                flags,
            )
        }
    }

    pub fn redirect_sk_lookup(
        &self,
        ctx: &SkLookupContext,
        key: &K,
        flags: u64,
    ) -> Result<(), i32> {
        let sk = lookup(self.def.as_ptr(), key).ok_or(-ENOENT)?;
        let ret = unsafe { bpf_sk_assign(ctx.as_ptr().cast(), sk.as_ptr(), flags) };
        let _: c_long = unsafe { bpf_sk_release(sk.as_ptr()) };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }
}
