use crate::{
    EbpfContext,
    bindings::bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY,
    cty::c_long,
    helpers::bpf_tail_call,
    maps::{MapDef, PinningType},
};

/// A BPF map that stores an array of program indices for tail calling.
///
/// # Examples
///
/// ```no_run
/// use aya_ebpf::{macros::map, maps::ProgramArray};
/// # use aya_ebpf::{programs::LsmContext};
///
/// #[map]
/// static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(16, 0);
///
/// # unsafe fn try_test(ctx: &LsmContext) -> Result<(), i32> {
/// let index: u32 = 13;
///
/// unsafe {
///     JUMP_TABLE.tail_call(ctx, index)?;
/// }
///
/// # Err(-1)
/// }
/// ```
#[repr(transparent)]
pub struct ProgramArray {
    def: MapDef,
}

impl ProgramArray {
    map_constructors!(u32, u32, BPF_MAP_TYPE_PROG_ARRAY);

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
        // SAFETY: `ctx` and `self.def` are valid pointers managed by aya.
        let _: c_long = unsafe { bpf_tail_call(ctx.as_ptr(), self.def.as_ptr().cast(), index) };
        Err(-1)
    }
}
