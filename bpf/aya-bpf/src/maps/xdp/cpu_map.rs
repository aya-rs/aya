use core::{cell::UnsafeCell, mem};

use aya_bpf_bindings::bindings::bpf_cpumap_val;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_CPUMAP},
    helpers::bpf_redirect_map,
    maps::PinningType,
};

/// An array of available CPUs.
///
/// XDP programs can use this map to redirect packets to a target CPU for processing.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.15.
///
/// # Examples
///
/// ```rust,no_run
/// use aya_bpf::{bindings::xdp_action, macros::{map, xdp}, maps::CpuMap, programs::XdpContext};
///
/// #[map]
/// static MAP: CpuMap = CpuMap::with_max_entries(8, 0);
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> i32 {
///     // Redirect to CPU 7 or drop packet if no entry found.
///     MAP.redirect(7, xdp_action::XDP_DROP as u64)
/// }
/// ```
#[repr(transparent)]
pub struct CpuMap {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for CpuMap {}

impl CpuMap {
    /// Creates a [`CpuMap`] with a set maximum number of elements.
    ///
    /// In a CPU Map, an entry represents a CPU core. Thus there should be as many entries as there
    /// are CPU cores on the system. To dynamically set the entry count at runtime, refer to the
    /// userspace documentation.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{macros::map, maps::CpuMap};
    ///
    /// #[map]
    /// static MAP: CpuMap = CpuMap::with_max_entries(8, 0);
    /// ```
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> CpuMap {
        CpuMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_CPUMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<bpf_cpumap_val>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    /// Creates a [`CpuMap`] with a set maximum number of elements that can be pinned to the BPF
    /// File System (bpffs).
    ///
    /// See [`CpuMap::with_max_entries`] for more information.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{macros::map, maps::CpuMap};
    ///
    /// #[map]
    /// static MAP: CpuMap = CpuMap::pinned(8, 0);
    /// ```
    pub const fn pinned(max_entries: u32, flags: u32) -> CpuMap {
        CpuMap {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_CPUMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<bpf_cpumap_val>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    /// Redirects the current packet on the CPU at `index`.
    ///
    /// The lower two bits of `flags` are used for the return code if the map lookup fails, which
    /// can be used as the XDP program's return code if a CPU cannot be found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_bpf::{bindings::xdp_action, macros::{map, xdp}, maps::CpuMap, programs::XdpContext};
    ///
    /// #[map]
    /// static MAP: CpuMap = CpuMap::with_max_entries(8, 0);
    ///
    /// #[xdp]
    /// fn xdp(_ctx: XdpContext) -> u32 {
    ///     // Redirect to CPU 7 or drop packet if no entry found.
    ///     MAP.redirect(7, xdp_action::XDP_DROP as u64)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> u32 {
        unsafe {
            // Return XDP_REDIRECT on success, or the value of the two lower bits of the flags
            // argument on error. Thus I have no idea why it returns a long (i64) instead of
            // something saner, hence the unsigned_abs.
            bpf_redirect_map(self.def.get() as *mut _, index.into(), flags).unsigned_abs() as u32
        }
    }
}
