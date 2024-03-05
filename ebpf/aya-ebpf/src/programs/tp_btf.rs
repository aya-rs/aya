use core::ffi::c_void;

use crate::{args::FromBtfArgument, EbpfContext};

pub struct BtfTracePointContext {
    ctx: *mut c_void,
}

impl BtfTracePointContext {
    pub fn new(ctx: *mut c_void) -> BtfTracePointContext {
        BtfTracePointContext { ctx }
    }

    /// Returns the `n`th argument of the BTF tracepoint, starting from 0.
    ///
    /// You can use the tplist tool provided by bcc to get a list of tracepoints and their
    /// arguments. TODO: document this better, possibly add a tplist alternative to aya.
    ///
    /// SAFETY: This function is deeply unsafe, as we are reading raw pointers into kernel memory.
    /// In particular, the value of `n` must not exceed the number of function arguments.
    /// Luckily, the BPF verifier will catch this for us.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #![allow(dead_code)]
    /// # use aya_ebpf::{programs::BtfTracePointContext, cty::{c_int, c_ulong, c_char}};
    /// unsafe fn try_tp_btf_sched_process_fork(ctx: BtfTracePointContext) -> Result<u32, u32> {
    ///     // Grab arguments
    ///     let parent_comm: *const c_char = ctx.arg(0);
    ///     let parent_pid: c_int = ctx.arg(1);
    ///     let child_comm: *const c_char = ctx.arg(2);
    ///     let child_pid: c_int = ctx.arg(3);
    ///
    ///     // You can then do stuff with parent_pidm parent_comm, child_pid, and
    ///     // child_comm down here.
    ///
    ///     Ok(0)
    /// }
    /// ```
    ///
    /// [1]: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h
    pub unsafe fn arg<T: FromBtfArgument>(&self, n: usize) -> T {
        T::from_argument(self.ctx as *const _, n)
    }
}

impl EbpfContext for BtfTracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
