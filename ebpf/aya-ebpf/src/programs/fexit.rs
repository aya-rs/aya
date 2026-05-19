use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::btf_arg, helpers::bpf_get_func_ret};

pub struct FExitContext {
    ctx: *mut c_void,
}

impl FExitContext {
    pub const fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }

    /// Returns the `n`th argument passed to the probed function, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::{cty::c_int, programs::FExitContext};
    /// # #[expect(non_camel_case_types)]
    /// # type pid_t = c_int;
    /// # #[expect(non_camel_case_types)]
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
    pub fn arg<T: Argument>(&self, n: usize) -> T {
        btf_arg(self, n)
    }

    /// Returns the value returned by the probed function.
    ///
    /// This uses the [`bpf_get_func_ret`] helper, so programs that call this
    /// method require Linux 5.17 or later. On unsupported tracing attach types
    /// the helper returns `-EOPNOTSUPP`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::{cty::c_int, programs::FExitContext};
    /// unsafe fn try_filename_lookup(ctx: FExitContext) -> Result<u32, i32> {
    ///     let retval: c_int = ctx.ret()?;
    ///
    ///     // Do something with retval
    ///
    ///     Ok(0)
    /// }
    /// ```
    ///
    /// [`bpf_get_func_ret`]: crate::helpers::bpf_get_func_ret
    pub fn ret<T: Argument>(&self) -> Result<T, i32> {
        let mut value = 0;
        let ret = unsafe { bpf_get_func_ret(self.as_ptr(), &raw mut value) };
        if ret == 0 {
            Ok(T::from_register(value))
        } else {
            Err(ret as i32)
        }
    }
}

impl EbpfContext for FExitContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
