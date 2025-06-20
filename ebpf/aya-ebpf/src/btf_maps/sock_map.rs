use core::{cell::UnsafeCell, ptr};

use aya_ebpf_cty::c_void;

use crate::{
    EbpfContext as _,
    bindings::{bpf_map_type::BPF_MAP_TYPE_SOCKMAP, bpf_sock_ops},
    btf_maps::AyaBtfMapMarker,
    helpers::{
        bpf_map_lookup_elem, bpf_msg_redirect_map, bpf_sk_assign, bpf_sk_redirect_map,
        bpf_sk_release, bpf_sock_map_update,
    },
    programs::{SkBuffContext, SkLookupContext, SkMsgContext},
};

#[allow(dead_code)]
pub struct SockMapDef<const M: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_SOCKMAP as usize],
    key: *const u32,
    value: *const u32,
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

#[repr(transparent)]
pub struct SockMap<const M: usize, const F: usize = 0>(UnsafeCell<SockMapDef<M, F>>);

unsafe impl<const M: usize, const F: usize> Sync for SockMap<M, F> {}

impl<const M: usize, const F: usize> SockMap<M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(SockMapDef {
            r#type: &[0i32; BPF_MAP_TYPE_SOCKMAP as usize],
            key: ptr::null(),
            value: ptr::null(),
            max_entries: &[0i32; M],
            map_flags: &[0i32; F],
            _anon: AyaBtfMapMarker::new(),
        }))
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn update(
        &self,
        mut index: u32,
        sk_ops: *mut bpf_sock_ops,
        flags: u64,
    ) -> Result<(), i64> {
        let ret = unsafe {
            bpf_sock_map_update(
                sk_ops,
                self.0.get() as *mut _,
                &mut index as *mut _ as *mut c_void,
                flags,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn redirect_msg(&self, ctx: &SkMsgContext, index: u32, flags: u64) -> i64 {
        unsafe {
            bpf_msg_redirect_map(ctx.as_ptr() as *mut _, self.0.get() as *mut _, index, flags)
        }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn redirect_skb(&self, ctx: &SkBuffContext, index: u32, flags: u64) -> i64 {
        unsafe { bpf_sk_redirect_map(ctx.as_ptr() as *mut _, self.0.get() as *mut _, index, flags) }
    }

    pub fn redirect_sk_lookup(
        &mut self,
        ctx: &SkLookupContext,
        index: u32,
        flags: u64,
    ) -> Result<(), u32> {
        unsafe {
            let sk = bpf_map_lookup_elem(
                &mut self.0 as *mut _ as *mut _,
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
