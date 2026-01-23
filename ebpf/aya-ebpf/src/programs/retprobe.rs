use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::ret, bindings::pt_regs};

pub struct RetProbeContext {
    pub regs: *mut pt_regs,
}

impl RetProbeContext {
    pub const fn new(ctx: *mut c_void) -> Self {
        Self { regs: ctx.cast() }
    }

    /// Returns the return value of the probed function.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::{programs::RetProbeContext, cty::c_int};
    /// unsafe fn try_kretprobe_try_to_wake_up(ctx: RetProbeContext) -> Result<u32, u32> {
    ///     let retval: c_int = ctx.ret();
    ///
    ///     // Do something with retval
    ///
    ///     Ok(0)
    /// }
    /// ```
    pub fn ret<T: Argument>(&self) -> T {
        ret(unsafe { &*self.regs })
    }
}

impl EbpfContext for RetProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs.cast()
    }
}
