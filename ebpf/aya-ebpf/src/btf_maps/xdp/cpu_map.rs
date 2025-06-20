use core::{cell::UnsafeCell, mem};

use aya_ebpf_bindings::bindings::bpf_cpumap_val;

use super::try_redirect_map;
use crate::bindings::bpf_map_type::BPF_MAP_TYPE_CPUMAP;

#[allow(dead_code)]
pub struct CpuMapDef<const M: usize, const F: usize> {
    r#type: *const [i32; BPF_MAP_TYPE_CPUMAP as usize],
    key_size: *const [i32; mem::size_of::<u32>()],
    value_size: *const [i32; mem::size_of::<bpf_cpumap_val>()],
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],
}

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
/// use aya_ebpf::{bindings::xdp_action, btf_maps::CpuMap, macros::{btf_map, xdp}, programs::XdpContext};
///
/// #[btf_map]
/// static MAP: CpuMap<8> = CpuMap::new();
///
/// #[xdp]
/// fn xdp(_ctx: XdpContext) -> u32 {
///     // Redirect to CPU 7 or drop packet if no entry found.
///     MAP.redirect(7, xdp_action::XDP_DROP as u64).unwrap_or(xdp_action::XDP_DROP)
/// }
/// ```
#[repr(transparent)]
pub struct CpuMap<const M: usize, const F: usize = 0>(UnsafeCell<CpuMapDef<M, F>>);

unsafe impl<const M: usize, const F: usize> Sync for CpuMap<M, F> {}

impl<const M: usize, const F: usize> CpuMap<M, F> {
    /// Creates a [`CpuMap`] with a set maximum number of elements.
    ///
    /// In a CPU map, an entry represents a CPU core. Thus there should be as many entries as there
    /// are CPU cores on the system. `max_entries` can be set to zero here, and updated by userspace
    /// at runtime. Refer to the userspace documentation for more information.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{macros::btf_map, btf_maps::CpuMap};
    ///
    /// #[btf_map]
    /// static MAP: CpuMap<8, 0> = CpuMap::new();
    /// ```
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(CpuMapDef {
            r#type: &[0i32; BPF_MAP_TYPE_CPUMAP as usize],
            key_size: &[0i32; mem::size_of::<u32>()],
            value_size: &[0i32; mem::size_of::<bpf_cpumap_val>()],
            max_entries: &[0i32; M],
            map_flags: &[0i32; F],
        }))
    }

    /// Redirects the current packet on the CPU at `index`.
    ///
    /// The lower two bits of `flags` are used for the return code if the map lookup fails, which
    /// can be used as the XDP program's return code if a CPU cannot be found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{bindings::xdp_action, btf_maps::CpuMap, macros::{btf_map, xdp}, programs::XdpContext};
    ///
    /// #[btf_map]
    /// static MAP: CpuMap<8> = CpuMap::new();
    ///
    /// #[xdp]
    /// fn xdp(_ctx: XdpContext) -> u32 {
    ///     // Redirect to CPU 7 or drop packet if no entry found.
    ///     MAP.redirect(7, 0).unwrap_or(xdp_action::XDP_DROP)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> Result<u32, u32> {
        try_redirect_map(&self.0, index, flags)
    }
}
