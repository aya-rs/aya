use core::ffi::c_void;

use crate::{args::FromBtfArgument, BpfContext};

pub struct FEntryContext {
    ctx: *mut c_void,
}

impl FEntryContext {
    pub fn new(ctx: *mut c_void) -> FEntryContext {
        FEntryContext { ctx }
    }

    /// Returns the `n`th argument to passed to the probe function, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #![allow(non_camel_case_types)]
    /// # #![allow(dead_code)]
    /// # use aya_bpf::{cty::c_int, programs::FEntryContext};
    /// # type pid_t = c_int;
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
    pub unsafe fn arg<T: FromBtfArgument>(&self, n: usize) -> T {
        T::from_argument(self.ctx as *const _, n)
    }
}

impl BpfContext for FEntryContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
