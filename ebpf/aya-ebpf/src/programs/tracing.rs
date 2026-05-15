use crate::{EbpfContext, cty::c_long, helpers::bpf_get_stackid};

pub(crate) mod sealed {
    #[expect(unnameable_types, reason = "this is the sealed trait pattern")]
    pub trait StackIdContext: super::EbpfContext {}

    #[expect(unnameable_types, reason = "this is the sealed trait pattern")]
    pub trait StackTraceMap {
        fn as_ptr(&self) -> *mut core::ffi::c_void;
    }
}

/// Contexts from which [`bpf_get_stackid`] can be called.
///
/// The kernel verifier restricts `bpf_get_stackid` to program types whose
/// `get_func_proto` callback returns `&bpf_get_stackid_proto`, either via a
/// direct `BPF_FUNC_get_stackid` arm or via the `raw_tp_prog_func_proto`
/// fallthrough chain. This trait is sealed and implemented only for the
/// aya context types whose underlying `BPF_PROG_TYPE_*` is in that set.
///
/// [`bpf_get_stackid`]: crate::helpers::bpf_get_stackid
pub trait StackIdContext: sealed::StackIdContext {
    /// Obtain an identifier for the current stack trace.
    fn get_stackid<M: StackTraceMap>(&self, map: &M, flags: u64) -> Result<c_long, i32> {
        let ret = unsafe { bpf_get_stackid(self.as_ptr(), map.as_ptr(), flags) };
        if ret < 0 { Err(ret as i32) } else { Ok(ret) }
    }
}

impl<T: sealed::StackIdContext> StackIdContext for T {}

/// Map types that [`StackIdContext::get_stackid`] can target.
///
/// This trait is sealed; aya implements it for both the legacy
/// [`crate::maps::StackTrace`] and the BTF [`crate::btf_maps::StackTrace`].
pub trait StackTraceMap: sealed::StackTraceMap {}

impl<T: sealed::StackTraceMap> StackTraceMap for T {}

macro_rules! impl_stack_id_context {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::StackIdContext for $ty {}
        )+
    };
}

impl_stack_id_context!(
    crate::programs::probe::ProbeContext,
    crate::programs::retprobe::RetProbeContext,
    crate::programs::tracepoint::TracePointContext,
    crate::programs::raw_tracepoint::RawTracePointContext,
    crate::programs::tp_btf::BtfTracePointContext,
    crate::programs::perf_event::PerfEventContext,
    crate::programs::fentry::FEntryContext,
    crate::programs::fexit::FExitContext,
    crate::programs::lsm::LsmContext,
);
