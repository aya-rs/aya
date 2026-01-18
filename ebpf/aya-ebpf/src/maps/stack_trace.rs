use core::borrow::Borrow;

use crate::{
    EbpfContext,
    bindings::bpf_map_type::BPF_MAP_TYPE_STACK_TRACE,
    helpers::bpf_get_stackid,
    maps::{MapDef, PinningType},
};

#[repr(transparent)]
pub struct StackTrace {
    def: MapDef,
}

const PERF_MAX_STACK_DEPTH: usize = 127;

impl StackTrace {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::None)
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::ByName)
    }

    const fn new(max_entries: u32, flags: u32, pinning: PinningType) -> Self {
        Self {
            def: MapDef::new::<u32, [u64; PERF_MAX_STACK_DEPTH]>(
                BPF_MAP_TYPE_STACK_TRACE,
                max_entries,
                flags,
                pinning,
            ),
        }
    }

    #[expect(clippy::missing_safety_doc)]
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
