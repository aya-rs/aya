use core::borrow::Borrow;

use aya_ebpf_bindings::bindings::PERF_MAX_STACK_DEPTH;

use crate::{
    EbpfContext,
    bindings::bpf_map_type::BPF_MAP_TYPE_STACK_TRACE,
    cty::c_long,
    helpers::bpf_get_stackid,
    maps::{MapDef, PinningType},
};

#[repr(transparent)]
pub struct StackTrace {
    def: MapDef,
}

impl StackTrace {
    map_constructors!(
        u32,
        [u64; PERF_MAX_STACK_DEPTH as usize],
        BPF_MAP_TYPE_STACK_TRACE
    );

    #[expect(
        clippy::missing_safety_doc,
        reason = "safety requirements come from the underlying helper"
    )]
    pub unsafe fn get_stackid<C: EbpfContext>(
        &self,
        ctx: impl Borrow<C>,
        flags: u64,
    ) -> Result<c_long, i32> {
        let ret =
            unsafe { bpf_get_stackid(ctx.borrow().as_ptr(), self.def.as_ptr().cast(), flags) };
        if ret < 0 { Err(ret as i32) } else { Ok(ret) }
    }
}

impl crate::programs::tracing::private::StackTraceMap for StackTrace {
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.def.as_ptr().cast()
    }
}
