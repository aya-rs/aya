use core::num::NonZeroU32;

use aya_ebpf_bindings::bindings::bpf_devmap_val;

use super::try_redirect_map;
use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_DEVMAP,
    lookup,
    maps::{MapDef, PinningType},
};

/// An array of network devices.
///
/// XDP programs can use this map to redirect packets to other network deviecs.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
///
/// # Examples
///
/// ```rust,no_run
/// use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::DevMap, programs::XdpContext};
///
/// #[map]
/// static MAP: DevMap = DevMap::with_max_entries(1, 0);
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> u32 {
///     MAP.redirect(0, xdp_action::XDP_PASS as u64).unwrap_or(xdp_action::XDP_DROP)
/// }
/// ```
#[repr(transparent)]
pub struct DevMap {
    def: MapDef,
}

impl super::super::private::Map for DevMap {
    type Key = u32;
    type Value = bpf_devmap_val;
}

impl DevMap {
    map_constructors!(
        u32,
        bpf_devmap_val,
        BPF_MAP_TYPE_DEVMAP,
        with_docs {
            /// Creates a [`DevMap`] with a set maximum number of elements.
            ///
            /// # Examples
            ///
            /// ```rust,no_run
            /// use aya_ebpf::{macros::map, maps::DevMap};
            ///
            /// #[map]
            /// static MAP: DevMap = DevMap::with_max_entries(8, 0);
            /// ```
        },
        pinned_docs {
            /// Creates a [`DevMap`] with a set maximum number of elements that can be pinned to
            /// the BPF File System (bpffs).
            ///
            /// # Examples
            ///
            /// ```rust,no_run
            /// use aya_ebpf::{macros::map, maps::DevMap};
            ///
            /// #[map]
            /// static MAP: DevMap = DevMap::pinned(8, 0);
            /// ```
        },
    );

    /// Retrieves the interface index at `index` in the array.
    ///
    /// To actually redirect a packet, see [`DevMap::redirect`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{macros::map, maps::DevMap};
    ///
    /// #[map]
    /// static MAP: DevMap = DevMap::with_max_entries(1, 0);
    ///
    /// let target_if_index = MAP.get(0).unwrap().if_index;
    ///
    /// // redirect to if_index
    /// ```
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<DevMapValue> {
        let value = lookup(self.def.as_ptr(), &index)?;
        let value: &bpf_devmap_val = unsafe { value.as_ref() };
        Some(DevMapValue {
            if_index: value.ifindex,
            // SAFETY: map writes use fd, map reads use id.
            // https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L6136
            prog_id: NonZeroU32::new(unsafe { value.bpf_prog.id }),
        })
    }

    /// Redirects the current packet on the interface at `index`.
    ///
    /// The lower two bits of `flags` are used for the return code if the map lookup fails, which
    /// can be used as the XDP program's return code if a CPU cannot be found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::DevMap, programs::XdpContext};
    ///
    /// #[map]
    /// static MAP: DevMap = DevMap::with_max_entries(8, 0);
    ///
    /// #[xdp]
    /// fn xdp(_ctx: XdpContext) -> u32 {
    ///     MAP.redirect(7, 0).unwrap_or(xdp_action::XDP_DROP)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> Result<u32, u32> {
        try_redirect_map(self.def.as_ptr(), index, flags)
    }
}

#[derive(Clone, Copy)]
#[expect(
    unnameable_types,
    reason = "this value type is exposed via the map API, not by path"
)]
/// The value of a device map.
pub struct DevMapValue {
    /// Target interface index to redirect to.
    pub if_index: u32,
    /// Chained XDP program ID.
    pub prog_id: Option<NonZeroU32>,
}
