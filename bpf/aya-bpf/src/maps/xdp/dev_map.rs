use core::{cell::UnsafeCell, mem, ptr::NonNull};

use aya_bpf_bindings::bindings::bpf_devmap_val;
use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_DEVMAP},
    helpers::{bpf_map_lookup_elem, bpf_redirect_map},
    maps::PinningType,
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
/// use aya_bpf::{bindings::xdp_action, macros::{map, xdp}, maps::DevMap, programs::XdpContext};
///
/// #[map]
/// static MAP: DevMap = DevMap::with_max_entries(1, 0);
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> i32 {
///     MAP.redirect(0, xdp_action::XDP_PASS as u64)
/// }
/// ```
#[repr(transparent)]
pub struct DevMap {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for DevMap {}

impl DevMap {
    /// Creates a [`DevMap`] with a set maximum number of elements.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{macros::map, maps::DevMap};
    ///
    /// #[map]
    /// static MAP: DevMap = DevMap::with_max_entries(8, 0);
    /// ```
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> DevMap {
        DevMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_DEVMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<bpf_devmap_val>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    /// Creates a [`DevMap`] with a set maximum number of elements that can be pinned to the BPF
    /// File System (bpffs).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{macros::map, maps::DevMap};
    ///
    /// #[map]
    /// static MAP: DevMap = DevMap::pinned(8, 0);
    /// ```
    pub const fn pinned(max_entries: u32, flags: u32) -> DevMap {
        DevMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_DEVMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<bpf_devmap_val>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    /// Retrieves the interface index at `index` in the array.
    ///
    /// To actually redirect a packet, see [`DevMap::redirect`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{macros::map, maps::DevMap};
    ///
    /// #[map]
    /// static MAP: DevMap = DevMap::with_max_entries(1, 0);
    ///
    /// let ifindex = MAP.get(0);
    ///
    /// // redirect to ifindex
    /// ```
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<DevMapValue> {
        unsafe {
            let value = bpf_map_lookup_elem(
                self.def.get() as *mut _,
                &index as *const _ as *const c_void,
            );
            NonNull::new(value as *mut bpf_devmap_val).map(|p| DevMapValue {
                ifindex: p.as_ref().ifindex,
                // SAFETY: map writes use fd, map reads use id.
                // https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L6136
                prog_id: p.as_ref().bpf_prog.id,
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
    /// use aya_bpf::{bindings::xdp_action, macros::{map, xdp}, maps::DevMap, programs::XdpContext};
    ///
    /// #[map]
    /// static MAP: DevMap = DevMap::with_max_entries(8, 0);
    ///
    /// #[xdp]
    /// fn xdp(_ctx: XdpContext) -> i32 {
    ///     MAP.redirect(7, xdp_action::XDP_PASS as u64)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> u32 {
        // Return XDP_REDIRECT on success, or the value of the two lower bits of the flags
        // argument on error. Thus I have no idea why it returns a long (i64) instead of
        // something saner, hence the unsigned_abs.
        unsafe {
            bpf_redirect_map(self.def.get() as *mut _, index.into(), flags).unsigned_abs() as u32
        }
    }
}

#[derive(Clone, Copy)]
pub struct DevMapValue {
    pub ifindex: u32,
    pub prog_id: u32,
}
