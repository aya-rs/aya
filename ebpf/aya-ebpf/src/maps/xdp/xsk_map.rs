use core::{cell::UnsafeCell, mem};

use aya_ebpf_bindings::bindings::bpf_xdp_sock;

use super::try_redirect_map;
use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_XSKMAP},
    lookup,
    maps::PinningType,
};

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
/// use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::XskMap, programs::XdpContext};
///
/// #[map]
/// static SOCKS: XskMap = XskMap::with_max_entries(8, 0);
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
pub struct XskMap {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for XskMap {}

impl XskMap {
    /// Creates a [`XskMap`] with a set maximum number of elements.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{macros::map, maps::XskMap};
    ///
    /// #[map]
    /// static SOCKS: XskMap =  XskMap::with_max_entries(8, 0);
    /// ```
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_XSKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    /// Creates a [`XskMap`] with a set maximum number of elements that can be pinned to the BPF
    /// filesystem (bpffs).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use aya_ebpf::{macros::map, maps::XskMap};
    ///
    /// #[map]
    /// static SOCKS: XskMap = XskMap::pinned(8, 0);
    /// ```
    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_XSKMAP,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
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
        let value = lookup(self.def.get().cast(), &index)?;
        let value: &bpf_xdp_sock = unsafe { value.as_ref() };
        Some(value.queue_id)
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
        try_redirect_map(&self.def, index, flags)
    }
}
