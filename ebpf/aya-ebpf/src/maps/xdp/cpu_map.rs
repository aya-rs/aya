use core::{cell::UnsafeCell, mem};

use aya_ebpf_bindings::bindings::bpf_cpumap_val;

use super::try_redirect_map;
use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_CPUMAP},
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
/// use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::CpuMap, programs::XdpContext};
///
/// #[map]
/// static MAP: CpuMap = CpuMap::with_max_entries(8, 0);
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> u32 {
///     // Redirect to CPU 7 or drop packet if no entry found.
///     MAP.redirect(7, xdp_action::XDP_DROP as u64).unwrap_or(xdp_action::XDP_DROP)
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
    /// In a CPU map, an entry represents a CPU core. Thus there should be as many entries as there
    /// are CPU cores on the system. `max_entries` can be set to zero here, and updated by userspace
    /// at runtime. Refer to the userspace documentation for more information.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{macros::map, maps::CpuMap};
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
    /// use aya_ebpf::{macros::map, maps::CpuMap};
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
    /// use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::CpuMap, programs::XdpContext};
    ///
    /// #[map]
    /// static MAP: CpuMap = CpuMap::with_max_entries(8, 0);
    ///
    /// #[xdp]
    /// fn xdp(_ctx: XdpContext) -> u32 {
    ///     // Redirect to CPU 7 or drop packet if no entry found.
    ///     MAP.redirect(7, 0).unwrap_or(xdp_action::XDP_DROP)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> Result<u32, u32> {
        try_redirect_map(&self.def, index, flags)
    }
}
