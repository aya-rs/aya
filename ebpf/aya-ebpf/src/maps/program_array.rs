use core::hint::unreachable_unchecked;

use crate::{
    EbpfContext,
    bindings::bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY,
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

    /// Perform a tail call into a program indexed by this map.
    ///
    /// # Safety
    ///
    /// This function is inherently unsafe, since it causes control flow to jump into
    /// another eBPF program. This can have side effects, such as drop methods not being
    /// called. Note that tail calling into an eBPF program is not the same thing as
    /// a function call -- control flow never returns to the caller.
    ///
    /// # Return Value
    ///
    /// On success, this function **does not return** into the original program.
    /// On failure, a negative error is returned, wrapped in `Err()`.
    pub unsafe fn tail_call<C: EbpfContext>(
        &self,
        ctx: &C,
        index: u32,
    ) -> Result<core::convert::Infallible, i32> {
        let res = unsafe { bpf_tail_call(ctx.as_ptr(), self.def.as_ptr().cast(), index) };
        if res < 0 {
            Err(res as i32)
        } else {
            unsafe { unreachable_unchecked() }
        }
    }
}
