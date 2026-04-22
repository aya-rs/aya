use aya_ebpf_bindings::bindings::PERF_MAX_STACK_DEPTH;

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_STACK_TRACE,
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
}

impl crate::programs::tracing::private::StackTraceMap for StackTrace {
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.def.as_ptr().cast()
    }
}
