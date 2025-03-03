use core::ffi::c_void;

use crate::{EbpfContext, args::FromBtfArgument};

pub struct FExitContext {
    ctx: *mut c_void,
}

impl FExitContext {
    pub fn new(ctx: *mut c_void) -> FExitContext {
        FExitContext { ctx }
    }

    /// Returns the `n`th argument to passed to the probe function, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #![expect(non_camel_case_types)]
    /// # #![expect(dead_code)]
    /// # use aya_ebpf::{cty::c_int, programs::FExitContext};
    /// # type pid_t = c_int;
    /// # struct task_struct {
    /// #     pid: pid_t,
    /// # }
    /// unsafe fn try_filename_lookup(ctx: FExitContext) -> Result<u32, u32> {
    ///     let tp: *const task_struct = ctx.arg(0);
    ///
    ///     // Do something with tp
    ///
    ///     Ok(0)
    /// }
    /// ```
    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn arg<T: FromBtfArgument>(&self, n: usize) -> T {
        unsafe { T::from_argument(self.ctx.cast(), n) }
    }
}

impl EbpfContext for FExitContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
