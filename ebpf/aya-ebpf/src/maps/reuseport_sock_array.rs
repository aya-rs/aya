use core::ptr;

use aya_ebpf_cty::{c_long, c_void};

use crate::{
    EbpfContext as _,
    bindings::bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    helpers::bpf_sk_select_reuseport,
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
    ///
    /// The `flags` argument is forwarded to `bpf_sk_select_reuseport()`.
    #[inline]
    pub fn select_reuseport(
        &self,
        ctx: &SkReuseportContext,
        key: u32,
        flags: u64,
    ) -> Result<(), c_long> {
        let mut key = key;
        let ret = unsafe {
            bpf_sk_select_reuseport(
                ctx.as_ptr().cast(),
                self.as_ptr(),
                ptr::from_mut(&mut key).cast(),
                flags,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }

    pub(crate) const fn as_ptr(&self) -> *mut c_void {
        self.def.as_ptr()
    }
}
