use crate::{
    bindings::bpf_devmap_val,
    btf_maps::{
        btf_map_def,
        dev_map::{devmap_get, devmap_redirect},
    },
    maps::xdp::DevMapValue,
};

btf_map_def!(
    /// A BTF-compatible hash map of network devices.
    ///
    /// Similar to [`super::DevMap`], but indexed by an arbitrary `u32`
    /// key rather than a contiguous slot, at the cost of a hashing step
    /// per lookup. Userspace populates each entry with a
    /// `struct bpf_devmap_val` carrying the target `ifindex` and an
    /// optional chained XDP program.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 5.4.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::DevMapHash, macros::btf_map};
    ///
    /// #[btf_map]
    /// static DEVS: DevMapHash<8> = DevMapHash::new();
    /// ```
    pub struct DevMapHash<; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_DEVMAP_HASH,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: bpf_devmap_val,
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize> DevMapHash<MAX_ENTRIES, FLAGS> {
    const _CHECK: () = {
        assert!(
            MAX_ENTRIES > 0,
            "DevMapHash max_entries must be greater than zero.",
        );
    };

    /// Returns the device stored under `key`.
    ///
    /// Returns `None` when no entry exists for `key`.
    #[inline(always)]
    pub fn get(&self, key: u32) -> Option<DevMapValue> {
        let () = Self::_CHECK;
        devmap_get(self.as_ptr(), key)
    }

    /// Redirects the current packet to the device stored under `key`.
    ///
    /// On lookup miss the kernel encodes the fallback XDP action in the
    /// lower two bits of `flags`, propagated as the `Err` variant.
    #[inline(always)]
    pub fn redirect(&self, key: u32, flags: u64) -> Result<u32, u32> {
        let () = Self::_CHECK;
        devmap_redirect(self.as_ptr(), key, flags)
    }
}
