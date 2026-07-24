use core::{num::NonZeroU32, ptr::NonNull};

use crate::{
    bindings::bpf_devmap_val, btf_maps::btf_map_def, cty::c_void, lookup, maps::xdp::DevMapValue,
};

// Private helpers shared with DevMapHash.
pub(super) fn devmap_get(ptr: *mut c_void, key: u32) -> Option<DevMapValue> {
    let value = lookup(ptr, &key)?;
    let value: &bpf_devmap_val = unsafe { value.as_ref() };
    Some(DevMapValue {
        if_index: value.ifindex,
        // SAFETY: `bpf_devmap_val::bpf_prog` is a union of `fd` and `id`; the
        // kernel populates `id` on map lookup (`fd` is only consumed on
        // userspace writes), so reading from `id` is the active variant.
        // https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h#L6136
        prog_id: NonZeroU32::new(unsafe { value.bpf_prog.id }),
    })
}

pub(super) fn devmap_get_ifindex(ptr: *mut c_void, key: u32) -> Option<u32> {
    let value: NonNull<u32> = lookup(ptr, &key)?;
    // SAFETY: the first 4 bytes of every devmap value are `ifindex`, both for
    // the legacy 4-byte layout (kernel < 5.8) and the 8-byte `bpf_devmap_val`
    // layout (kernel >= 5.8); a 4-byte read at offset 0 is in-bounds either way.
    Some(unsafe { *value.as_ptr() })
}

btf_map_def!(
    /// A BTF-compatible array of network devices.
    ///
    /// XDP programs use this map to redirect packets to other network
    /// devices via [`DevMap::redirect`]. Userspace populates each slot
    /// with a `struct bpf_devmap_val` carrying the target `ifindex` and
    /// an optional chained XDP program; [`DevMap::get`] reads the entry
    /// back as a [`DevMapValue`].
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.14.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::DevMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static DEVS: DevMap<8> = DevMap::new();
    /// ```
    pub struct DevMap<; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_DEVMAP,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: bpf_devmap_val,
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize> DevMap<MAX_ENTRIES, FLAGS> {
    const _CHECK: () = {
        assert!(
            MAX_ENTRIES > 0,
            "DevMap max_entries must be greater than zero.",
        );
    };

    /// Returns the device at `index`.
    ///
    /// Reads the entry as a [`DevMapValue`], including `prog_id`; this
    /// requires kernel 5.8 or newer because `bpf_devmap_val::bpf_prog` was
    /// only introduced then. On older kernels use
    /// [`get_ifindex`](Self::get_ifindex) instead.
    ///
    /// Returns `None` when `index` is out of range or no entry has been
    /// written there.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<DevMapValue> {
        let () = Self::_CHECK;
        devmap_get(self.as_ptr(), index)
    }

    /// Returns the `ifindex` stored at `index`.
    ///
    /// Reads only the leading 4 bytes of the map value, so it works on every
    /// kernel that supports `BPF_MAP_TYPE_DEVMAP` (4.14 and newer), unlike
    /// [`get`](Self::get) which also reads `bpf_devmap_val::bpf_prog`.
    ///
    /// Returns `None` when `index` is out of range or no entry has been
    /// written there.
    #[inline(always)]
    pub fn get_ifindex(&self, index: u32) -> Option<u32> {
        let () = Self::_CHECK;
        devmap_get_ifindex(self.as_ptr(), index)
    }

    /// Redirects the current packet to the device at `index`.
    ///
    /// On lookup miss the kernel encodes the fallback XDP action in the
    /// lower two bits of `flags`, propagated as the `Err` variant.
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> Result<u32, u32> {
        let () = Self::_CHECK;
        super::try_redirect_map(self.as_ptr(), index, flags)
    }
}
