use crate::{EbpfContext, btf_maps::btf_map_def, cty::c_long, helpers::bpf_tail_call};

btf_map_def!(
    /// A BTF-compatible BPF program array map.
    ///
    /// This map type stores an array of program indices for tail calling.
    /// Both keys and values are `u32`; values are file descriptors of BPF
    /// programs to tail-call into.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.20.
    /// `BPF_MAP_TYPE_PROG_ARRAY` itself dates back to 4.2, but kernels
    /// prior to 4.20 either silently dropped BTF for prog-array maps
    /// (4.18) or rejected BTF `BPF_MAP_CREATE` with `-ENOTSUPP` (4.19).
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::ProgramArray, macros::btf_map};
    ///
    /// #[btf_map]
    /// static JUMP_TABLE: ProgramArray<16> = ProgramArray::new();
    /// ```
    pub struct ProgramArray<; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_PROG_ARRAY,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: u32,
);

impl<const MAX_ENTRIES: usize, const FLAGS: usize> ProgramArray<MAX_ENTRIES, FLAGS> {
    /// Performs a tail call into a program indexed by this map.
    ///
    /// # Safety
    ///
    /// This function is inherently unsafe, since it causes control flow to
    /// jump into another eBPF program. This can have side effects, such as
    /// drop methods not being called. Note that tail calling into an eBPF
    /// program is not the same thing as a function call -- control flow
    /// never returns to the caller.
    ///
    /// # Return Value
    ///
    /// On success, this function does not return into the original program.
    /// On failure, control returns to the caller with `Err(-1)`.
    ///
    /// The kernel's `bpf_tail_call` helper is declared with
    /// `ret_type = RET_VOID` and does not write `R0` on failure, so
    /// callers cannot distinguish between the three failure modes
    /// (out-of-bounds index, empty slot, or `MAX_TAIL_CALL_CNT` exceeded).
    /// The returned `-1` is synthetic.
    pub unsafe fn tail_call<C: EbpfContext>(
        &self,
        ctx: &C,
        index: u32,
    ) -> Result<core::convert::Infallible, i32> {
        // The helper never writes `R0` on failure (see the doc comment
        // above), so the return value carries no information; discard
        // it. A successful tail call does not return here.
        //
        // SAFETY: `ctx` and `self` are valid pointers managed by aya.
        let _: c_long = unsafe { bpf_tail_call(ctx.as_ptr(), self.as_ptr(), index) };
        Err(-1)
    }
}
