use aya_ebpf_cty::c_void;

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    maps::{MapDef, PinningType},
};

/// An array of sockets for use with `SO_REUSEPORT` socket selection.
///
/// `ReusePortSockArray` stores sockets that participate in `SO_REUSEPORT` groups.
/// [`SkReuseportContext::select_reuseport`](crate::programs::SkReuseportContext::select_reuseport)
/// uses this map to choose which socket should receive the packet.
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

    pub(crate) const fn as_ptr(&self) -> *mut c_void {
        self.def.as_ptr()
    }
}
