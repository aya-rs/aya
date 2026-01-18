use core::{borrow::Borrow, cell::UnsafeCell, mem};

use crate::{
    EbpfContext,
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_STACK_TRACE},
    helpers::bpf_get_stackid,
    maps::{InnerMap, PinningType},
};

#[repr(transparent)]
pub struct StackTrace {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for StackTrace {}
impl super::private::Sealed for StackTrace {}
unsafe impl InnerMap for StackTrace {}

const PERF_MAX_STACK_DEPTH: u32 = 127;

impl StackTrace {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_STACK_TRACE,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u64>() as u32 * PERF_MAX_STACK_DEPTH,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_STACK_TRACE,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u64>() as u32 * PERF_MAX_STACK_DEPTH,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
        }
    }

    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn get_stackid<C: EbpfContext>(
        &self,
        ctx: impl Borrow<C>,
        flags: u64,
    ) -> Result<i64, i64> {
        let ret = unsafe { bpf_get_stackid(ctx.borrow().as_ptr(), self.def.get().cast(), flags) };
        if ret < 0 { Err(ret) } else { Ok(ret) }
    }
}
