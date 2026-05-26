use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::raw_tracepoint_arg, bindings::bpf_raw_tracepoint_args};

pub struct RawTracePointContext {
    ctx: *mut bpf_raw_tracepoint_args,
}

impl RawTracePointContext {
    pub const fn new(ctx: *mut c_void) -> Self {
        Self { ctx: ctx.cast() }
    }

    /// Returns the raw tracepoint argument at index `n`.
    ///
    /// Raw tracepoint arguments are the tracepoint's `TP_PROTO` arguments, not
    /// fields from the `trace_event_raw_*` record used by regular tracepoints.
    /// Their meaning and type depend on the tracepoint this program is attached
    /// to.
    ///
    /// The kernel passes these values in [`bpf_raw_tracepoint_args`][bpf]:
    /// `args[0]` is the first argument declared by the tracepoint's
    /// `TP_PROTO`, `args[1]` is the second, and so on.
    ///
    /// For example, the [`sys_enter` tracepoint][sys] passes
    /// `struct pt_regs *regs` as arg(0) and the syscall id as arg(1).
    ///
    /// [bpf]: https://github.com/torvalds/linux/blob/v6.15/include/uapi/linux/bpf.h#L7181-L7183
    /// [sys]: https://github.com/torvalds/linux/blob/v6.15/include/trace/events/syscalls.h#L20
    pub fn arg<T: Argument>(&self, n: usize) -> T {
        raw_tracepoint_arg(unsafe { &*self.ctx }, n)
    }
}

impl EbpfContext for RawTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx.cast()
    }
}
