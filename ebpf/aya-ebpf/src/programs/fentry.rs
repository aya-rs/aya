use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::btf_arg};

pub struct FEntryContext {
    ctx: *mut c_void,
}

impl FEntryContext {
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }

    /// Returns the `n`th argument to passed to the probe function, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::{cty::c_int, programs::FEntryContext};
    /// # #[expect(non_camel_case_types)]
    /// # type pid_t = c_int;
    /// # #[expect(non_camel_case_types)]
    /// # struct task_struct {
    /// #     pid: pid_t,
    /// # }
    /// unsafe fn try_fentry_try_to_wake_up(ctx: FEntryContext) -> Result<u32, u32> {
    ///     let tp: *const task_struct = ctx.arg(0);
    ///
    ///     // Do something with tp
    ///
    ///     Ok(0)
    /// }
    /// ```
    pub fn arg<T: Argument>(&self, n: usize) -> T {
        btf_arg(self, n)
    }
}

impl EbpfContext for FEntryContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
