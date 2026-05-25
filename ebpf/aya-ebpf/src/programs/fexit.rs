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
        let mut ret_val = 0;
        let err = unsafe { bpf_get_func_ret(self.as_ptr(), &raw mut ret_val) };

        // Keep the helper status from becoming linked with the traced function
        // return value in the verifier's scalar tracking.
        //
        // `bpf_get_func_ret` follows the normal BPF helper ABI: the helper
        // status is returned in R0, while the traced function return value is
        // written through `ret_val`. Kernels v5.10 through v6.7 can mishandle
        // precision tracking for linked scalar registers. For this helper, the
        // affected range starts at v5.17, when `bpf_get_func_ret` was added. If
        // LLVM emits a phi merge that shares a scalar id between the helper
        // status and `ret_val`, and the caller then narrows `ret_val` to `T`,
        // the verifier can incorrectly conclude that the traced return value is
        // zero and prune the caller's success branch.
        //
        // Rust makes this easy to trigger because `Result<T, i32>` keeps the
        // helper status and the traced return value live across the same match.
        // For integer-like `T`, both arms have similar scalar shapes and LLVM
        // may reuse registers around the merge, followed by a narrowing
        // sequence that the affected verifier mishandles.
        //
        // Passing the helper status through `black_box` forces a stack
        // spill/reload, breaking that verifier-side scalar relationship without
        // changing runtime semantics.
        //
        // See also:
        // https://github.com/torvalds/linux/commit/d028f87517d6775dccff4ddbca2740826f9e53f1
        // fixes this verifier bug by tracking BPF_JNE "not equal" constraints.
        // https://github.com/torvalds/linux/commit/9e314f5d8682e1fe6ac214fb34580a238b6fd3c4
        // is also a prerequisite, because it preserves 32/64-bit bounds
        // across reg_set_min_max().
        let err = core::hint::black_box(err);
        if err == 0 {
            Ok(T::from_register(ret_val))
        } else {
            Err(err as i32)
        }
    }
}

impl EbpfContext for FExitContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
