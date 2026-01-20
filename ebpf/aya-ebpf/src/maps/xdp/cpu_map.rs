use aya_ebpf_bindings::bindings::bpf_cpumap_val;

use super::try_redirect_map;
use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_CPUMAP,
    maps::{MapDef, PinningType},
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
    def: MapDef,
}

impl CpuMap {
    map_constructors!(u32, bpf_cpumap_val, BPF_MAP_TYPE_CPUMAP);

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
        try_redirect_map(self.def.as_ptr(), index, flags)
    }
}
