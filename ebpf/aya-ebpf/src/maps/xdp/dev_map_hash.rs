use core::{num::NonZeroU32, ptr::NonNull};

use aya_ebpf_bindings::bindings::bpf_devmap_val;

use super::{dev_map::DevMapValue, try_redirect_map};
use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH,
    lookup,
    maps::{MapDef, PinningType},
};

/// A map of network devices.
///
/// XDP programs can use this map to redirect packets to other network devices. It is similar to
/// [`DevMap`](super::DevMap), but is an hash map rather than an array. Keys do not need to be
/// contiguous nor start at zero, but there is a hashing cost to every lookup.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.4.
///
/// # Examples
///
/// ```rust,no_run
/// use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::DevMapHash, programs::XdpContext};
///
/// #[map]
/// static MAP: DevMapHash = DevMapHash::with_max_entries(1, 0);
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> u32 {
///     MAP.redirect(42, xdp_action::XDP_PASS as u64).unwrap_or(xdp_action::XDP_DROP)
/// }
/// ```
#[repr(transparent)]
pub struct DevMapHash {
    def: MapDef,
}

impl super::super::private::Map for DevMapHash {
    type Key = u32;
    type Value = bpf_devmap_val;
}

impl DevMapHash {
    map_constructors!(
        u32,
        bpf_devmap_val,
        BPF_MAP_TYPE_DEVMAP_HASH,
        with_docs {
            /// Creates a [`DevMapHash`] with a set maximum number of elements.
            ///
            /// # Examples
            ///
            /// ```rust,no_run
            /// use aya_ebpf::{macros::map, maps::DevMapHash};
            ///
            /// #[map]
            /// static MAP: DevMapHash = DevMapHash::with_max_entries(8, 0);
            /// ```
        },
        pinned_docs {
            /// Creates a [`DevMapHash`] with a set maximum number of elements that can be pinned
            /// to the BPF File System (bpffs).
            ///
            /// # Examples
            ///
            /// ```rust,no_run
            /// use aya_ebpf::{macros::map, maps::DevMapHash};
            ///
            /// #[map]
            /// static MAP: DevMapHash = DevMapHash::pinned(8, 0);
            /// ```
        },
    );

    /// Retrieves the device stored under `key` in the map.
    ///
    /// Reads the entry as a [`DevMapValue`] including `prog_id`, which
    /// requires kernel 5.8 or newer because `bpf_devmap_val::bpf_prog` was
    /// only introduced then. On older kernels use
    /// [`get_ifindex`](Self::get_ifindex) instead.
    ///
    /// To actually redirect a packet, see [`DevMapHash::redirect`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{macros::map, maps::DevMapHash};
    ///
    /// #[map]
    /// static MAP: DevMapHash = DevMapHash::with_max_entries(1, 0);
    ///
    /// let target_if_index = MAP.get(42).unwrap().if_index;
    ///
    /// // redirect to ifindex
    /// ```
    #[inline(always)]
    pub fn get(&self, key: u32) -> Option<DevMapValue> {
        let value = lookup(self.def.as_ptr(), &key)?;
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

    /// Retrieves the interface index stored under `key` in the map.
    ///
    /// Reads only the leading 4 bytes of the map value, so it works on every
    /// kernel that supports `BPF_MAP_TYPE_DEVMAP_HASH` (5.4 and newer), unlike
    /// [`get`](Self::get) which also reads `bpf_devmap_val::bpf_prog`.
    ///
    /// To actually redirect a packet, see [`DevMapHash::redirect`].
    #[inline(always)]
    pub fn get_ifindex(&self, key: u32) -> Option<u32> {
        let value: NonNull<u32> = lookup(self.def.as_ptr(), &key)?;
        // SAFETY: the first 4 bytes of every devmap value are `ifindex`, both
        // for the legacy 4-byte layout (kernel < 5.8) and the 8-byte
        // `bpf_devmap_val` layout (kernel >= 5.8); a 4-byte read at offset 0 is
        // in-bounds either way.
        Some(unsafe { *value.as_ptr() })
    }

    /// Redirects the current packet on the interface at `key`.
    ///
    /// The lower two bits of `flags` are used for the return code if the map lookup fails, which
    /// can be used as the XDP program's return code if a CPU cannot be found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::DevMapHash, programs::XdpContext};
    ///
    /// #[map]
    /// static MAP: DevMapHash = DevMapHash::with_max_entries(8, 0);
    ///
    /// #[xdp]
    /// fn xdp(_ctx: XdpContext) -> u32 {
    ///     MAP.redirect(7, 0).unwrap_or(xdp_action::XDP_DROP)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, key: u32, flags: u64) -> Result<u32, u32> {
        try_redirect_map(self.def.as_ptr(), key, flags)
    }
}
