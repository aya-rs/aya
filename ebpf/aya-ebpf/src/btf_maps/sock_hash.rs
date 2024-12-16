use core::{borrow::Borrow, cell::UnsafeCell, ptr};

use aya_ebpf_cty::c_void;

use crate::{
    bindings::{bpf_map_type::BPF_MAP_TYPE_SOCKHASH, bpf_sock_ops},
    btf_maps::AyaBtfMapMarker,
    helpers::{
        bpf_map_lookup_elem, bpf_msg_redirect_hash, bpf_sk_assign, bpf_sk_redirect_hash,
        bpf_sk_release, bpf_sock_hash_update,
    },
    programs::{SkBuffContext, SkLookupContext, SkMsgContext},
    EbpfContext,
};

#[allow(dead_code)]
pub struct SockHashDef<K, const M: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_SOCKHASH as usize],
    key: *const K,
    value: *const u32,
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

#[repr(transparent)]
pub struct SockHash<K, const M: usize, const F: usize = 0>(UnsafeCell<SockHashDef<K, M, F>>);

unsafe impl<K: Sync, const M: usize, const F: usize> Sync for SockHash<K, M, F> {}

impl<K, const M: usize, const F: usize> SockHash<K, M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(SockHashDef {
            r#type: &[0i32; BPF_MAP_TYPE_SOCKHASH as usize],
            key: ptr::null(),
            value: ptr::null(),
            max_entries: &[0i32; M],
            map_flags: &[0i32; F],
            _anon: AyaBtfMapMarker::new(),
        }))
    }

    pub fn update(&self, key: &mut K, sk_ops: &mut bpf_sock_ops, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_sock_hash_update(
                sk_ops as *mut _,
                self.0.get() as *mut _,
                key as *mut _ as *mut c_void,
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    pub fn redirect_msg(&self, ctx: &SkMsgContext, key: &mut K, flags: u64) -> i64 {
        unsafe {
            bpf_msg_redirect_hash(
                ctx.as_ptr() as *mut _,
                self.0.get() as *mut _,
                key as *mut _ as *mut _,
                flags,
            )
        }
    }

    pub fn redirect_skb(&self, ctx: &SkBuffContext, key: &mut K, flags: u64) -> i64 {
        unsafe {
            bpf_sk_redirect_hash(
                ctx.as_ptr() as *mut _,
                self.0.get() as *mut _,
                key as *mut _ as *mut _,
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
        unsafe {
            let sk = bpf_map_lookup_elem(
                &mut self.0 as *mut _ as *mut _,
                &key as *const _ as *const c_void,
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
