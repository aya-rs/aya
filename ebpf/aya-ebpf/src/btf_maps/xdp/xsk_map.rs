use core::{cell::UnsafeCell, mem, ptr::NonNull};

use aya_ebpf_bindings::bindings::bpf_xdp_sock;
use aya_ebpf_cty::c_void;

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_XSKMAP,
    btf_maps::{xdp::try_redirect_map, AyaBtfMapMarker},
    helpers::bpf_map_lookup_elem,
};

#[allow(dead_code)]
pub struct XskMapDef<const M: usize, const F: usize> {
    r#type: *const [i32; BPF_MAP_TYPE_XSKMAP as usize],
    key_size: *const [i32; mem::size_of::<u32>()],
    value_size: *const [i32; mem::size_of::<u32>()],
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

/// An array of AF_XDP sockets.
///
/// XDP programs can use this map to redirect packets to a target AF_XDP socket using the
/// `XDP_REDIRECT` action.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.18.
///
/// # Examples
///
/// ```rust,no_run
/// use aya_ebpf::{bindings::xdp_action, btf_maps::XskMap, macros::{btf_map, xdp}, programs::XdpContext};
///
/// #[btf_map]
/// static SOCKS: XskMap<8> = XskMap::new();
///
/// #[xdp]
/// fn xdp(ctx: XdpContext) -> u32 {
///     let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
///     SOCKS.redirect(queue_id, xdp_action::XDP_DROP as u64).unwrap_or(xdp_action::XDP_DROP)
/// }
/// ```
///
/// # Queue management
///
/// Packets received on a RX queue can only be redirected to sockets bound on the same queue. Most
/// hardware NICs have multiple RX queue to spread the load across multiple CPU cores using RSS.
///
/// Three strategies are possible:
///
/// - Reduce the RX queue count to a single one. This option is great for development, but is
///   detrimental for performance as the single CPU core recieving packets will get overwhelmed.
///   Setting the queue count for a NIC can be achieved using `ethtool -L <ifname> combined 1`.
/// - Create a socket for every RX queue. Most modern NICs will have an RX queue per CPU thread, so
///   a socket per CPU thread is best for performance. To dynamically size the map depending on the
///   recieve queue count, see the userspace documentation of `CpuMap`.
/// - Create a single socket and use a [`CpuMap`](super::CpuMap) to redirect the packet to the
///   correct CPU core. This way, the packet is sent to another CPU, and a chained XDP program can
///   the redirect to the AF_XDP socket. Using a single socket simplifies the userspace code but
///   will not perform great unless not a lot of traffic is redirected to the socket. Regular
///   traffic however will not be impacted, contrary to reducing the queue count.
#[repr(transparent)]
pub struct XskMap<const M: usize, const F: usize = 0>(UnsafeCell<XskMapDef<M, F>>);

unsafe impl<const M: usize, const F: usize> Sync for XskMap<M, F> {}

impl<const M: usize, const F: usize> XskMap<M, F> {
    /// Creates a [`XskMap`] with a set maximum number of elements.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{btf_maps::XskMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static SOCKS: XskMap<8> =  XskMap::new();
    /// ```
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(XskMapDef {
            r#type: &[0; BPF_MAP_TYPE_XSKMAP as usize],
            key_size: &[0; mem::size_of::<u32>()],
            value_size: &[0; mem::size_of::<u32>()],
            max_entries: &[0; M],
            map_flags: &[0; F],
            _anon: AyaBtfMapMarker::new(),
        }))
    }

    /// Retrieves the queue to which the socket is bound at `index` in the array.
    ///
    /// To actually redirect a packet, see [`XskMap::redirect`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{macros::map, maps::XskMap};
    ///
    /// #[map]
    /// static SOCKS: XskMap = XskMap::with_max_entries(8, 0);
    ///
    /// let queue_id = SOCKS.get(0);
    /// ```
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<u32> {
        unsafe {
            let value =
                bpf_map_lookup_elem(self.0.get() as *mut _, &index as *const _ as *const c_void);
            NonNull::new(value as *mut bpf_xdp_sock).map(|p| p.as_ref().queue_id)
        }
    }

    /// Redirects the current packet to the AF_XDP socket at `index`.
    ///
    /// The lower two bits of `flags` are used for the return code if the map lookup fails, which
    /// can be used as the XDP program's return code if a matching socket cannot be found.
    ///
    /// However, if the socket at `index` is bound to a RX queue which is not the current RX queue,
    /// the packet will be dropped.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::XskMap, programs::XdpContext};
    ///
    /// #[map]
    /// static SOCKS: XskMap = XskMap::with_max_entries(8, 0);
    ///
    /// #[xdp]
    /// fn xdp(ctx: XdpContext) -> u32 {
    ///     let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    ///     SOCKS.redirect(queue_id, 0).unwrap_or(xdp_action::XDP_DROP)
    /// }
    /// ```
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> Result<u32, u32> {
        try_redirect_map(&self.0, index, flags)
    }
}
