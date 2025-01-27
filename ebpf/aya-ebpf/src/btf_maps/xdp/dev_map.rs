use core::{cell::UnsafeCell, mem, num::NonZeroU32, ptr::NonNull};

use aya_ebpf_bindings::bindings::bpf_devmap_val;
use aya_ebpf_cty::c_void;

use super::try_redirect_map;
use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_DEVMAP, btf_maps::AyaBtfMapMarker,
    helpers::bpf_map_lookup_elem,
};

#[allow(dead_code)]
pub struct DevMapDef<const M: usize, const F: usize> {
    r#type: *const [i32; BPF_MAP_TYPE_DEVMAP as usize],
    key_size: *const [i32; mem::size_of::<u32>()],
    value_size: *const [i32; mem::size_of::<bpf_devmap_val>()],
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

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
/// use aya_ebpf::{
///     bindings::xdp_action,
///     btf_maps::DevMap,
///     macros::{btf_map, xdp},
///     programs::XdpContext,
/// };
///
/// #[btf_map]
/// static MAP: DevMap<1> = DevMap::new();
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> u32 {
///     MAP.redirect(0, xdp_action::XDP_PASS as u64).unwrap_or(xdp_action::XDP_DROP)
/// }
/// ```
#[repr(transparent)]
pub struct DevMap<const M: usize, const F: usize = 0>(UnsafeCell<DevMapDef<M, F>>);

unsafe impl<const M: usize, const F: usize> Sync for DevMap<M, F> {}

impl<const M: usize, const F: usize> DevMap<M, F> {
    /// Creates a [`DevMap`] with a set maximum number of elements.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{macros::btf_map, btf_maps::DevMap};
    ///
    /// #[btf_map]
    /// static MAP: DevMap<8> = DevMap::new();
    /// ```
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(DevMapDef {
            r#type: &[0; BPF_MAP_TYPE_DEVMAP as usize],
            key_size: &[0; mem::size_of::<u32>()],
            value_size: &[0; mem::size_of::<bpf_devmap_val>()],
            max_entries: &[0; M],
            map_flags: &[0; F],
            _anon: AyaBtfMapMarker::new(),
        }))
    }

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
        unsafe {
            let value =
                bpf_map_lookup_elem(self.0.get() as *mut _, &index as *const _ as *const c_void);
            NonNull::new(value as *mut bpf_devmap_val).map(|p| DevMapValue {
                if_index: p.as_ref().ifindex,
                // SAFETY: map writes use fd, map reads use id.
                // https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L6136
                prog_id: NonZeroU32::new(p.as_ref().bpf_prog.id),
            })
        }
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
        try_redirect_map(&self.0, index, flags)
    }
}

#[derive(Clone, Copy)]
/// The value of a device map.
pub struct DevMapValue {
    /// Target interface index to redirect to.
    pub if_index: u32,
    /// Chained XDP program ID.
    pub prog_id: Option<NonZeroU32>,
}
