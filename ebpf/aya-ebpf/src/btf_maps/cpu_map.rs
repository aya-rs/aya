use crate::{bindings::bpf_cpumap_val, btf_maps::btf_map_def};

btf_map_def!(
    /// A BTF-compatible array of CPUs available for XDP redirect.
    ///
    /// XDP programs use this map to redirect packets to a target CPU for
    /// processing via [`CpuMap::redirect`]. Userspace populates each slot
    /// with a `struct bpf_cpumap_val` carrying the per-CPU queue size and
    /// an optional chained XDP program; on kernels older than 5.9 only the
    /// `qsize` field is honoured and aya truncates the value size to 4
    /// bytes at map creation.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.15.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::CpuMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static CPUS: CpuMap<8> = CpuMap::new();
    /// ```
    pub struct CpuMap<; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_CPUMAP,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: bpf_cpumap_val,
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize> CpuMap<MAX_ENTRIES, FLAGS> {
    const _CHECK: () = {
        assert!(
            MAX_ENTRIES > 0,
            "CpuMap max_entries must be greater than zero.",
        );
    };

    /// Redirects the current packet to the CPU at `index`.
    ///
    /// On lookup miss the kernel encodes the fallback XDP action in the
    /// lower two bits of `flags`, propagated as the `Err` variant.
    #[inline(always)]
    pub fn redirect(&self, index: u32, flags: u64) -> Result<u32, u32> {
        let () = Self::_CHECK;
        super::try_redirect_map(self.as_ptr(), index, flags)
    }
}
