use crate::{
    ENOENT, EbpfContext as _,
    bindings::bpf_sock_ops,
    btf_maps::btf_map_def,
    cty::c_long,
    helpers::{
        bpf_msg_redirect_map, bpf_sk_assign, bpf_sk_redirect_map, bpf_sk_release,
        bpf_sock_map_update,
    },
    lookup,
    programs::{SkBuffContext, SkLookupContext, SkMsgContext},
};

btf_map_def!(
    /// A BTF-compatible BPF sockmap.
    ///
    /// `SockMap` stores sockets keyed by a `u32` index. Sockets can be
    /// inserted from `SOCK_OPS` programs via [`SockMap::update`] or from
    /// userspace, and consumed by `SK_SKB`, `SK_MSG`, or `SK_LOOKUP`
    /// programs to redirect or assign packets.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.14.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::SockMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static SOCKS: SockMap<128> = SockMap::new();
    /// ```
    pub struct SockMap<; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_SOCKMAP,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: u32,
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize> SockMap<MAX_ENTRIES, FLAGS> {
    // Enforces kernel constraints (kernel/net/core/sock_map.c sock_map_alloc):
    // max_entries must be > 0. `const _: ()` is forbidden in a generic impl,
    // and a named associated const is lazy without a reference, hence
    // `let () = Self::_CHECK` in every method.
    const _CHECK: () = {
        assert!(
            MAX_ENTRIES > 0,
            "SockMap max_entries must be greater than zero.",
        );
    };

    /// Inserts the socket from `sk_ops` into the map at `index`.
    ///
    /// Wraps `bpf_sock_map_update`. Intended for `SOCK_OPS` programs.
    ///
    /// # Safety
    ///
    /// `sk_ops` must be a valid pointer to a `bpf_sock_ops` structure,
    /// typically the `ops` field of a [`SockOpsContext`]. The kernel
    /// guarantees its validity within the program's execution context.
    ///
    /// [`SockOpsContext`]: crate::programs::SockOpsContext
    pub unsafe fn update(
        &self,
        mut index: u32,
        sk_ops: *mut bpf_sock_ops,
        flags: u64,
    ) -> Result<(), i32> {
        let () = Self::_CHECK;
        let ret = unsafe {
            bpf_sock_map_update(
                sk_ops,
                self.as_ptr().cast(),
                core::ptr::from_mut(&mut index).cast(),
                flags,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }

    /// Redirects the message in `ctx` to the socket at `index`.
    pub fn redirect_msg(&self, ctx: &SkMsgContext, index: u32, flags: u64) -> c_long {
        let () = Self::_CHECK;
        unsafe { bpf_msg_redirect_map(ctx.as_ptr().cast(), self.as_ptr().cast(), index, flags) }
    }

    /// Redirects the socket buffer in `ctx` to the socket at `index`.
    pub fn redirect_skb(&self, ctx: &SkBuffContext, index: u32, flags: u64) -> c_long {
        let () = Self::_CHECK;
        unsafe { bpf_sk_redirect_map(ctx.as_ptr().cast(), self.as_ptr().cast(), index, flags) }
    }

    /// Assigns the socket at `index` as the result of the `SK_LOOKUP` `ctx`.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this method is
    /// [5.9](https://github.com/torvalds/linux/commit/e9ddbb7707ff5891616240026062b8c1e29864ca),
    /// when `bpf_sk_assign` was extended to `SK_LOOKUP` programs.
    ///
    /// # Errors
    ///
    /// Returns `Err(-ENOENT)` if `index` is not present in the map. Otherwise
    /// propagates the [`bpf_sk_assign`] errno.
    ///
    /// [`bpf_sk_assign`]: https://docs.ebpf.io/linux/helper-function/bpf_sk_assign/
    pub fn redirect_sk_lookup(
        &self,
        ctx: &SkLookupContext,
        index: u32,
        flags: u64,
    ) -> Result<(), i32> {
        let () = Self::_CHECK;
        let sk = lookup(self.as_ptr(), &index).ok_or(-ENOENT)?;
        let ret = unsafe { bpf_sk_assign(ctx.as_ptr().cast(), sk.as_ptr(), flags) };
        let _: c_long = unsafe { bpf_sk_release(sk.as_ptr()) };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }
}
