use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::btf_arg};

pub struct LsmContext {
    ctx: *mut c_void,
}

impl LsmContext {
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }

    /// Returns the `n`th argument passed to the LSM hook, starting from 0.
    ///
    /// You can refer to [the kernel's list of LSM hook definitions][1] to find the
    /// appropriate argument list for your LSM hook, where the argument list starts
    /// _after_ the third parameter to the kernel's `LSM_HOOK` macro.
    ///
    /// LSM probes specifically have access to an additional argument `retval: int`
    /// which provides the return value of the previous LSM program that was called on
    /// this code path, or 0 if this is the first LSM program to be called. This phony
    /// argument is always last in the argument list.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::{programs::LsmContext, cty::{c_int, c_ulong}};
    /// unsafe fn try_lsm_mmap_addr(ctx: LsmContext) -> Result<i32, i32> {
    ///     // In the kernel, this hook is defined as:
    ///     //   LSM_HOOK(int, 0, mmap_addr, unsigned long addr)
    ///     let addr: c_ulong = ctx.arg(0);
    ///     let retval: c_int = ctx.arg(1);
    ///
    ///     // You can then do stuff with addr and retval down here.
    ///
    ///     // To practice good LSM hygiene, let's defer to a previous retval
    ///     // if available:
    ///     if (retval != 0) {
    ///         return Ok(retval);
    ///     }
    ///
    ///     Ok(0)
    /// }
    /// ```
    ///
    /// [1]: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h
    pub fn arg<T: Argument>(&self, n: usize) -> T {
        btf_arg(self, n)
    }
}

impl EbpfContext for LsmContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
