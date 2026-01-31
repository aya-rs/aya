use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::arg, bindings::pt_regs};

pub struct ProbeContext {
    pub regs: *mut pt_regs,
}

impl ProbeContext {
    pub const fn new(ctx: *mut c_void) -> Self {
        Self { regs: ctx.cast() }
    }

    /// Returns the `n`th argument to passed to the probe function, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::{programs::ProbeContext, cty::c_int, helpers::bpf_probe_read};
    /// # #[expect(non_camel_case_types)]
    /// # type pid_t = c_int;
    /// # #[expect(non_camel_case_types)]
    /// # struct task_struct {
    /// #     pid: pid_t,
    /// # }
    /// unsafe fn try_kprobe_try_to_wake_up(ctx: ProbeContext) -> Result<u32, u32> {
    ///     let tp: *const task_struct = ctx.arg(0).ok_or(1u32)?;
    ///     let pid = unsafe {
    ///         bpf_probe_read(core::ptr::addr_of!((*tp).pid))
    ///     }.map_err(|err| err as u32)?;
    ///
    ///     // Do something with pid or something else with tp
    ///
    ///     Ok(0)
    /// }
    /// ```
    pub fn arg<T: Argument>(&self, n: usize) -> Option<T> {
        arg(unsafe { &*self.regs }, n)
    }
}

impl EbpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs.cast()
    }
}
