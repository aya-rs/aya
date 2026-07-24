use aya_ebpf_cty::c_long;

use crate::{btf_maps::btf_map_def, helpers::bpf_current_task_under_cgroup};

btf_map_def!(
    /// A BTF-compatible array of cgroups.
    ///
    /// `CgroupArray` stores cgroups, set from userspace by writing a cgroup
    /// directory file descriptor into a slot. eBPF programs use it with the
    /// `bpf_skb_under_cgroup` and `bpf_current_task_under_cgroup` helpers to
    /// test whether a packet or the current task belongs to one of those
    /// cgroups.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.8.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::CgroupArray, macros::btf_map};
    ///
    /// #[btf_map]
    /// static CGROUPS: CgroupArray<8> = CgroupArray::new();
    /// ```
    pub struct CgroupArray<; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_CGROUP_ARRAY,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: u32,
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize> CgroupArray<MAX_ENTRIES, FLAGS> {
    const _CHECK: () = {
        assert!(
            MAX_ENTRIES > 0,
            "CgroupArray max_entries must be greater than zero."
        );
    };

    /// Returns whether the current task is a descendant of the cgroup at `index`.
    ///
    /// Wraps the `bpf_current_task_under_cgroup` helper, which requires kernel
    /// 4.9 or newer. This is only callable from tracing programs, for example
    /// kprobes and tracepoints.
    pub fn current_task_under_cgroup(&self, index: u32) -> Result<bool, c_long> {
        let () = Self::_CHECK;
        // SAFETY: `self` is a valid pointer managed by aya.
        let ret = unsafe { bpf_current_task_under_cgroup(self.as_ptr().cast(), index) };
        match ret {
            1 => Ok(true),
            0 => Ok(false),
            ret => Err(ret),
        }
    }
}

impl<const MAX_ENTRIES: usize, const FLAGS: usize> crate::programs::tc::sealed::CgroupArrayMap
    for CgroupArray<MAX_ENTRIES, FLAGS>
{
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        // `skb_under_cgroup` reaches the map only through this method, so it is
        // the sole enforcement site for `_CHECK` on that path.
        let () = Self::_CHECK;
        self.as_ptr()
    }
}
