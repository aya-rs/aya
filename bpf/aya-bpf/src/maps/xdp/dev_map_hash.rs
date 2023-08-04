use core::{cell::UnsafeCell, mem, ptr::NonNull};

use aya_bpf_bindings::bindings::bpf_devmap_val;
use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH},
    helpers::{bpf_map_lookup_elem, bpf_redirect_map},
    maps::PinningType,
};

use super::dev_map::DevMapValue;

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
/// use aya_bpf::{bindings::xdp_action, macros::{map, xdp}, maps::DevMapHash, programs::XdpContext};
///
/// #[map]
/// static MAP: DevMapHash = DevMapHash::with_max_entries(1, 0);
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> i32 {
///     MAP.redirect(42, xdp_action::XDP_PASS as u64)
/// }
/// ```
#[repr(transparent)]
pub struct DevMapHash {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for DevMapHash {}

impl DevMapHash {
    /// Creates a [`DevMapHash`] with a set maximum number of elements.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{macros::map, maps::DevMapHash};
    ///
    /// #[map]
    /// static MAP: DevMapHash = DevMapHash::with_max_entries(8, 0);
    /// ```
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> DevMapHash {
        DevMapHash {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_DEVMAP_HASH,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<bpf_devmap_val>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    /// Creates a [`DevMapHash`] with a set maximum number of elements that can be pinned to the BPF
    /// File System (bpffs).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{macros::map, maps::DevMapHash};
    ///
    /// #[map]
    /// static MAP: DevMapHash = DevMapHash::pinned(8, 0);
    /// ```
    pub const fn pinned(max_entries: u32, flags: u32) -> DevMapHash {
        DevMapHash {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_DEVMAP_HASH,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<bpf_devmap_val>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    /// Retrieves the interface index with `key` in the map.
    ///
    /// To actually redirect a packet, see [`DevMapHash::redirect`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{macros::map, maps::DevMapHash};
    ///
    /// #[map]
    /// static MAP: DevMapHash = DevMapHash::with_max_entries(1, 0);
    ///
    /// let ifindex = MAP.get(42);
    ///
    /// // redirect to ifindex
    /// ```
    #[inline(always)]
    pub fn get(&self, key: u32) -> Option<DevMapValue> {
        unsafe {
            let value =
                bpf_map_lookup_elem(self.def.get() as *mut _, &key as *const _ as *const c_void);
            NonNull::new(value as *mut bpf_devmap_val).map(|p| DevMapValue {
                ifindex: p.as_ref().ifindex,
                // SAFETY: map writes use fd, map reads use id.
                // https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L6136
                prog_id: p.as_ref().bpf_prog.id,
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
    /// use aya_bpf::{bindings::xdp_action, macros::{map, xdp}, maps::DevMapHash, programs::XdpContext};
    ///
    /// #[map]
    /// static MAP: DevMapHash = DevMapHash::with_max_entries(8, 0);
    ///
    /// #[xdp]
    /// fn xdp(_ctx: XdpContext) -> i32 {
    ///     MAP.redirect(7, xdp_action::XDP_PASS as u64)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, key: u32, flags: u64) -> u32 {
        unsafe {
            // Return XDP_REDIRECT on success, or the value of the two lower bits of the flags
            // argument on error. Thus I have no idea why it returns a long (i64) instead of
            // something saner, hence the unsigned_abs.
            bpf_redirect_map(self.def.get() as *mut _, key.into(), flags).unsigned_abs() as u32
        }
    }
}
