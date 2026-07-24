use aya_ebpf_cty::c_long;

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_CGROUP_ARRAY,
    helpers::bpf_current_task_under_cgroup,
    maps::{MapDef, PinningType},
};

/// An array of cgroups.
///
/// `CgroupArray` stores cgroups, set from userspace by writing a cgroup
/// directory file descriptor into a slot. eBPF programs use it with the
/// `bpf_skb_under_cgroup` and `bpf_current_task_under_cgroup` helpers to test
/// whether a packet or the current task belongs to one of those cgroups.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.8.
///
/// # Examples
///
/// ```no_run
/// use aya_ebpf::{macros::map, maps::CgroupArray, programs::ProbeContext};
///
/// #[map]
/// static CGROUPS: CgroupArray = CgroupArray::with_max_entries(8, 0);
///
/// # fn try_test(_ctx: ProbeContext) -> Result<(), i64> {
/// if CGROUPS.current_task_under_cgroup(0)? {
///     // The current task is under the cgroup at index 0.
/// }
/// # Ok(())
/// # }
/// ```
#[repr(transparent)]
pub struct CgroupArray {
    def: MapDef,
}

impl CgroupArray {
    map_constructors!(u32, u32, BPF_MAP_TYPE_CGROUP_ARRAY);

    /// Returns whether the current task is a descendant of the cgroup at `index`.
    ///
    /// Wraps the `bpf_current_task_under_cgroup` helper, which requires kernel
    /// 4.9 or newer. This is only callable from tracing programs, for example
    /// kprobes and tracepoints.
    pub fn current_task_under_cgroup(&self, index: u32) -> Result<bool, c_long> {
        // SAFETY: `self.def` is a valid pointer managed by aya.
        let ret = unsafe { bpf_current_task_under_cgroup(self.def.as_ptr(), index) };
        match ret {
            1 => Ok(true),
            0 => Ok(false),
            ret => Err(ret),
        }
    }
}

impl crate::programs::tc::sealed::CgroupArrayMap for CgroupArray {
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.def.as_ptr().cast()
    }
}
