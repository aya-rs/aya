use core::{
    borrow::{Borrow, BorrowMut},
    ptr,
};

use crate::{
    ENOENT, EbpfContext as _,
    bindings::bpf_sock_ops,
    btf_maps::btf_map_def,
    cty::c_long,
    helpers::{
        bpf_msg_redirect_hash, bpf_sk_assign, bpf_sk_redirect_hash, bpf_sk_release,
        bpf_sock_hash_update,
    },
    lookup,
    programs::{SkBuffContext, SkLookupContext, SkMsgContext},
};

btf_map_def!(
    /// A BTF-compatible BPF sockhash.
    ///
    /// `SockHash` stores sockets keyed by an arbitrary `K`. Sockets can be
    /// inserted from `SOCK_OPS` programs via [`SockHash::update`] or from
    /// userspace, and consumed by `SK_SKB`, `SK_MSG`, or `SK_LOOKUP`
    /// programs to redirect or assign packets.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.18.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::SockHash, macros::btf_map};
    ///
    /// #[btf_map]
    /// static SOCKS: SockHash<u32, 128> = SockHash::new();
    /// ```
    pub struct SockHash<K; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_SOCKHASH,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: K,
    value_type: u32,
);

impl<K, const MAX_ENTRIES: usize, const FLAGS: usize> SockHash<K, MAX_ENTRIES, FLAGS> {
    // Enforces kernel constraints (kernel/net/core/sock_map.c sock_hash_alloc):
    // key_size must be > 0 and <= MAX_BPF_STACK (512). `const _: ()` is
    // forbidden in a generic impl, and a named associated const is lazy
    // without a reference, hence `let () = Self::_CHECK` in every method.
    const _CHECK: () = {
        assert!(size_of::<K>() > 0, "SockHash key must be non-zero sized.");
        assert!(
            size_of::<K>() <= 512,
            "SockHash key must be at most 512 bytes (MAX_BPF_STACK).",
        );
        assert!(
            MAX_ENTRIES > 0,
            "SockHash max_entries must be greater than zero.",
        );
    };

    /// Inserts the socket from `sk_ops` into the map under `key`.
    pub fn update(
        &self,
        mut key: impl BorrowMut<K>,
        mut sk_ops: impl BorrowMut<bpf_sock_ops>,
        flags: u64,
    ) -> Result<(), i32> {
        let () = Self::_CHECK;
        let ret = unsafe {
            bpf_sock_hash_update(
                ptr::from_mut(sk_ops.borrow_mut()),
                self.as_ptr().cast(),
                ptr::from_mut(key.borrow_mut()).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }

    /// Redirects the message in `ctx` to the socket at `key`.
    pub fn redirect_msg(
        &self,
        ctx: impl Borrow<SkMsgContext>,
        mut key: impl BorrowMut<K>,
        flags: u64,
    ) -> c_long {
        let () = Self::_CHECK;
        unsafe {
            bpf_msg_redirect_hash(
                ctx.borrow().msg,
                self.as_ptr().cast(),
                ptr::from_mut(key.borrow_mut()).cast(),
                flags,
            )
        }
    }

    /// Redirects the socket buffer in `ctx` to the socket at `key`.
    pub fn redirect_skb(
        &self,
        ctx: impl Borrow<SkBuffContext>,
        mut key: impl BorrowMut<K>,
        flags: u64,
    ) -> c_long {
        let () = Self::_CHECK;
        unsafe {
            bpf_sk_redirect_hash(
                ctx.borrow().skb.skb,
                self.as_ptr().cast(),
                ptr::from_mut(key.borrow_mut()).cast(),
                flags,
            )
        }
    }

    /// Assigns the socket at `key` as the result of the `SK_LOOKUP` `ctx`.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this method is
    /// [5.9](https://github.com/torvalds/linux/commit/e9ddbb7707ff5891616240026062b8c1e29864ca),
    /// when `bpf_sk_assign` was extended to `SK_LOOKUP` programs.
    ///
    /// # Errors
    ///
    /// Returns `Err(-ENOENT)` if `key` is not present in the map. Otherwise
    /// propagates the [`bpf_sk_assign`] errno.
    ///
    /// [`bpf_sk_assign`]: https://docs.ebpf.io/linux/helper-function/bpf_sk_assign/
    pub fn redirect_sk_lookup(
        &self,
        ctx: impl Borrow<SkLookupContext>,
        key: impl Borrow<K>,
        flags: u64,
    ) -> Result<(), i32> {
        let () = Self::_CHECK;
        let sk = lookup(self.as_ptr(), key.borrow()).ok_or(-ENOENT)?;
        let ret = unsafe { bpf_sk_assign(ctx.borrow().as_ptr().cast(), sk.as_ptr(), flags) };
        let _: c_long = unsafe { bpf_sk_release(sk.as_ptr()) };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }
}
