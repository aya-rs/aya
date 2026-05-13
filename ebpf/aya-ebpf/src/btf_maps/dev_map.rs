use core::num::NonZeroU32;

use crate::{
    bindings::{bpf_devmap_val, xdp_action::XDP_REDIRECT},
    btf_maps::btf_map_def,
    cty::c_void,
    helpers::bpf_redirect_map,
    lookup,
    maps::xdp::DevMapValue,
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

pub(super) fn devmap_redirect(ptr: *mut c_void, key: u32, flags: u64) -> Result<u32, u32> {
    let ret = unsafe { bpf_redirect_map(ptr.cast(), key.into(), flags) };
    match ret.unsigned_abs() as u32 {
        XDP_REDIRECT => Ok(XDP_REDIRECT),
        ret => Err(ret),
    }
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
    /// Returns `None` when `index` is out of range or no entry has been
    /// written there.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<DevMapValue> {
        let () = Self::_CHECK;
        devmap_get(self.as_ptr(), index)
    }

    /// Redirects the current packet to the device at `index`.
    ///
    /// On lookup miss the kernel encodes the fallback XDP action in the
    /// lower two bits of `flags`, propagated as the `Err` variant.
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> Result<u32, u32> {
        let () = Self::_CHECK;
        devmap_redirect(self.as_ptr(), index, flags)
    }
}
