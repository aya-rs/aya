use core::ptr;

use aya_ebpf_cty::c_long;

use crate::{
    EbpfContext as _, btf_maps::btf_map_def, helpers::bpf_sk_select_reuseport,
    programs::SkReuseportContext,
};

btf_map_def!(
    /// A BTF-compatible BPF reuseport socket array.
    ///
    /// `ReusePortSockArray` stores sockets that participate in `SO_REUSEPORT`
    /// groups. [`ReusePortSockArray::select_reuseport`] uses this map to choose
    /// which socket should receive the packet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::ReusePortSockArray, macros::btf_map};
    ///
    /// #[btf_map]
    /// static SOCKETS: ReusePortSockArray<4, 0> = ReusePortSockArray::new();
    /// ```
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.19.
    pub struct ReusePortSockArrayImpl<T; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: T,
);

// Reuseport sock arrays have fixed `u32` values; this alias keeps that public
// API while reusing the generic `btf_map_def!` helper.
pub type ReusePortSockArray<const MAX_ENTRIES: usize, const FLAGS: usize = 0> =
    ReusePortSockArrayImpl<u32, MAX_ENTRIES, FLAGS>;

impl<const MAX_ENTRIES: usize, const FLAGS: usize> ReusePortSockArray<MAX_ENTRIES, FLAGS> {
    /// Selects a socket from this map using `key`.
    ///
    /// The map must be populated with sockets from the same `SO_REUSEPORT`
    /// group before calling this helper. The kernel does not currently define
    /// any flags for `bpf_sk_select_reuseport()`, so this wrapper always
    /// passes `0`.
    #[inline]
    pub fn select_reuseport(&self, ctx: &SkReuseportContext, mut key: u32) -> Result<(), c_long> {
        let ret = unsafe {
            bpf_sk_select_reuseport(
                ctx.as_ptr().cast(),
                self.as_ptr(),
                ptr::from_mut(&mut key).cast(),
                0,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}
