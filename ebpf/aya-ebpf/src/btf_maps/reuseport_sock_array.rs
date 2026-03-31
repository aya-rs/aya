use crate::btf_maps::btf_map_def;

btf_map_def!(
    /// A BTF-compatible BPF reuseport socket array.
    ///
    /// `ReusePortSockArray` stores sockets that participate in `SO_REUSEPORT`
    /// groups. [`SkReuseportContext::select_reuseport`](crate::programs::SkReuseportContext::select_reuseport)
    /// uses this map to choose which socket should receive the packet.
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
