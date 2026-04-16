use aya_ebpf_cty::{c_long, c_void};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    helpers::{ReusePortSockArrayMap, sk_select_reuseport},
    maps::{MapDef, PinningType},
    programs::SkReuseportContext,
};

/// An array of sockets for use with `SO_REUSEPORT` socket selection.
///
/// `ReusePortSockArray` stores sockets that participate in `SO_REUSEPORT`
/// groups. [`ReusePortSockArray::select_reuseport`] uses this map to choose
/// which socket should receive the packet.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.19.
#[repr(transparent)]
pub struct ReusePortSockArray {
    def: MapDef,
}

impl ReusePortSockArray {
    map_constructors!(u32, u32, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);

    /// Selects a socket from this map using `key`.
    ///
    /// The map must be populated with sockets from the same `SO_REUSEPORT`
    /// group before calling this helper.
    #[inline]
    pub fn select_reuseport(&self, ctx: &SkReuseportContext, key: u32) -> Result<(), c_long> {
        sk_select_reuseport(ctx, self, key)
    }
}

impl ReusePortSockArrayMap for ReusePortSockArray {
    fn as_ptr(&self) -> *mut c_void {
        self.def.as_ptr()
    }
}
