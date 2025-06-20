use core::{cell::UnsafeCell, mem, num::NonZeroU32, ptr::NonNull};

use aya_ebpf_bindings::bindings::bpf_devmap_val;
use aya_ebpf_cty::c_void;

use super::{dev_map::DevMapValue, try_redirect_map};
use crate::{bindings::bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH, helpers::bpf_map_lookup_elem};

#[allow(dead_code)]
pub struct DevMapHashDef<const M: usize, const F: usize> {
    r#type: *const [i32; BPF_MAP_TYPE_DEVMAP_HASH as usize],
    key_size: *const [i32; mem::size_of::<u32>()],
    value_size: *const [i32; mem::size_of::<bpf_devmap_val>()],
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],
}

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
/// use aya_ebpf::{bindings::xdp_action, btf_maps::DevMapHash, macros::{btf_map, xdp}, programs::XdpContext};
///
/// #[btf_map]
/// static MAP: DevMapHash<1> = DevMapHash::new();
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> u32 {
///     MAP.redirect(42, xdp_action::XDP_PASS as u64).unwrap_or(xdp_action::XDP_DROP)
/// }
/// ```
#[repr(transparent)]
pub struct DevMapHash<const M: usize, const F: usize = 0>(UnsafeCell<DevMapHashDef<M, F>>);

unsafe impl<const M: usize, const F: usize> Sync for DevMapHash<M, F> {}

impl<const M: usize, const F: usize> DevMapHash<M, F> {
    /// Creates a [`DevMapHash`] with a set maximum number of elements.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{btf_maps::DevMapHash, macros::btf_map};
    ///
    /// #[btf_map]
    /// static MAP: DevMapHash<8> = DevMapHash::new();
    /// ```
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(DevMapHashDef {
            r#type: &[0; BPF_MAP_TYPE_DEVMAP_HASH as usize],
            key_size: &[0; mem::size_of::<u32>()],
            value_size: &[0; mem::size_of::<bpf_devmap_val>()],
            max_entries: &[0; M],
            map_flags: &[0; F],
        }))
    }

    /// Retrieves the interface index with `key` in the map.
    ///
    /// To actually redirect a packet, see [`DevMapHash::redirect`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{btf_maps::DevMapHash, macros::btf_map};
    ///
    /// #[btf_map]
    /// static MAP: DevMapHash<1> = DevMapHash::new();
    ///
    /// let target_if_index = MAP.get(42).unwrap().if_index;
    ///
    /// // redirect to ifindex
    /// ```
    #[inline(always)]
    pub fn get(&self, key: u32) -> Option<DevMapValue> {
        unsafe {
            let value =
                bpf_map_lookup_elem(self.0.get() as *mut _, &key as *const _ as *const c_void);
            NonNull::new(value as *mut bpf_devmap_val).map(|p| DevMapValue {
                if_index: p.as_ref().ifindex,
                // SAFETY: map writes use fd, map reads use id.
                // https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L6136
                prog_id: NonZeroU32::new(p.as_ref().bpf_prog.id),
            })
        }
    }

    /// Redirects the current packet on the interface at `key`.
    ///
    /// The lower two bits of `flags` are used for the return code if the map lookup fails, which
    /// can be used as the XDP program's return code if a CPU cannot be found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{bindings::xdp_action, btf_maps::DevMapHash, macros::{btf_map, xdp}, programs::XdpContext};
    ///
    /// #[btf_map]
    /// static MAP: DevMapHash<8> = DevMapHash::new();
    ///
    /// #[xdp]
    /// fn xdp(_ctx: XdpContext) -> u32 {
    ///     MAP.redirect(7, 0).unwrap_or(xdp_action::XDP_DROP)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, key: u32, flags: u64) -> Result<u32, u32> {
        try_redirect_map(&self.0, key, flags)
    }
}
