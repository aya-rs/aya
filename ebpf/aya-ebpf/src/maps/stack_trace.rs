use core::borrow::Borrow;

use crate::{
    EbpfContext,
    bindings::bpf_map_type::BPF_MAP_TYPE_STACK_TRACE,
    helpers::bpf_get_stackid,
    maps::{InnerMap, MapDef, PinningType},
};

#[repr(transparent)]
pub struct StackTrace {
    def: MapDef,
}

unsafe impl Sync for StackTrace {}
impl super::private::Sealed for StackTrace {}
unsafe impl InnerMap for StackTrace {}

const PERF_MAX_STACK_DEPTH: usize = 127;

impl StackTrace {
    map_constructors!(u32, [u64; PERF_MAX_STACK_DEPTH], BPF_MAP_TYPE_STACK_TRACE);

    #[expect(
        clippy::missing_safety_doc,
        reason = "safety requirements come from the underlying helper"
    )]
    pub unsafe fn get_stackid<C: EbpfContext>(
        &self,
        ctx: impl Borrow<C>,
        flags: u64,
    ) -> Result<i64, i64> {
        let ret =
            unsafe { bpf_get_stackid(ctx.borrow().as_ptr(), self.def.as_ptr().cast(), flags) };
        if ret < 0 { Err(ret) } else { Ok(ret) }
    }
}
