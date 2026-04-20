use aya_ebpf_bindings::bindings::BPF_F_STACK_BUILD_ID;

use crate::{EbpfContext, btf_maps::btf_map_def, cty::c_long, helpers::bpf_get_stackid};

// Default maximum stack-trace depth enforced by the kernel (UAPI
// `PERF_MAX_STACK_DEPTH` in <linux/perf_event.h>).
const PERF_MAX_STACK_DEPTH: usize = 127;

btf_map_def!(
    /// A BTF-compatible BPF stack-trace map.
    ///
    /// Stores hashed stack traces keyed by a `u32` stack ID, where each value
    /// is a fixed-depth array of return addresses. Populate a stack trace by
    /// calling [`StackTrace::get_stackid`] from a tracing program; read the
    /// resulting trace from user space via
    /// `aya::maps::StackTraceMap`.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.6.
    ///
    /// # Flag restrictions
    ///
    /// `BPF_F_STACK_BUILD_ID` switches the kernel element layout to
    /// `struct bpf_stack_build_id` (32 bytes), which this type does not
    /// model. Calling [`StackTrace::get_stackid`] on a monomorphisation
    /// that sets the flag fails to compile, and loading such a map for
    /// reading through `aya::maps::StackTraceMap` is rejected at load
    /// time.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::StackTrace, macros::btf_map};
    ///
    /// #[btf_map]
    /// static STACK_TRACES: StackTrace<1024> = StackTrace::new();
    /// ```
    pub struct StackTrace<;
        const MAX_ENTRIES: usize,
        const FLAGS: usize = 0,
        const DEPTH: usize = PERF_MAX_STACK_DEPTH,
    >,
    map_type: BPF_MAP_TYPE_STACK_TRACE,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: [u64; DEPTH],
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize, const DEPTH: usize>
    StackTrace<MAX_ENTRIES, FLAGS, DEPTH>
{
    // `const _: ()` is forbidden in a generic impl; named associated
    // const is lazy without reference — hence `let () = Self::_CHECK`
    // in each public method.
    const _CHECK: () = {
        assert!(DEPTH > 0, "stack trace DEPTH must be greater than zero.");
        assert!(
            MAX_ENTRIES > 0,
            "stack trace max_entries must be greater than zero.",
        );
        assert!(
            FLAGS & BPF_F_STACK_BUILD_ID as usize == 0,
            "BPF_F_STACK_BUILD_ID is not supported by StackTrace.",
        );
    };

    /// Obtain an identifier for the current stack trace.
    ///
    /// # Safety
    ///
    /// `bpf_get_stackid` is only available to tracing program types
    /// (kprobe, tracepoint, `perf_event`, `raw_tracepoint`). Calling
    /// it from any other program type fails verification.
    #[inline(always)]
    pub unsafe fn get_stackid<C: EbpfContext>(&self, ctx: &C, flags: u64) -> Result<c_long, i32> {
        let () = Self::_CHECK;
        // SAFETY: `ctx` and `self` are valid pointers managed by aya.
        let ret = unsafe { bpf_get_stackid(ctx.as_ptr(), self.as_ptr(), flags) };
        if ret < 0 { Err(ret as i32) } else { Ok(ret) }
    }
}
