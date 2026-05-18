use crate::{bindings::bpf_xdp_sock, btf_maps::btf_map_def, lookup};

btf_map_def!(
    /// A BTF-compatible array of `AF_XDP` sockets.
    ///
    /// XDP programs use this map to redirect packets to a target `AF_XDP`
    /// socket via [`XskMap::redirect`]. Userspace populates each slot
    /// with the socket's file descriptor; the kernel rejects redirection
    /// when the socket's bound queue does not match the current RX queue.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.18.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::XskMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static SOCKS: XskMap<8> = XskMap::new();
    /// ```
    pub struct XskMap<; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_XSKMAP,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: u32,
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize> XskMap<MAX_ENTRIES, FLAGS> {
    const _CHECK: () = {
        assert!(
            MAX_ENTRIES > 0,
            "XskMap max_entries must be greater than zero.",
        );
    };

    /// Returns the queue id the socket at `index` is bound to.
    ///
    /// Returns `None` when `index` is out of range or no socket has been
    /// inserted there.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<u32> {
        let () = Self::_CHECK;
        let value = lookup(self.as_ptr(), &index)?;
        let value: &bpf_xdp_sock = unsafe { value.as_ref() };
        Some(value.queue_id)
    }

    /// Redirects the current packet to the `AF_XDP` socket at `index`.
    ///
    /// On lookup miss the kernel encodes the fallback XDP action in the
    /// lower two bits of `flags`, propagated as the `Err` variant.
    ///
    /// If the socket at `index` is bound to a RX queue other than the
    /// current one, the kernel drops the packet.
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> Result<u32, u32> {
        let () = Self::_CHECK;
        super::try_redirect_map(self.as_ptr(), index, flags)
    }
}
