use core::ffi::c_void;

use crate::{args::FromPtRegs, BpfContext};

#[cfg(not(any(bpf_target_arch = "aarch64", bpf_target_arch = "riscv64")))]
use crate::bindings::pt_regs;

#[cfg(bpf_target_arch = "aarch64")]
use crate::bindings::user_pt_regs as pt_regs;

#[cfg(bpf_target_arch = "riscv64")]
use crate::bindings::user_regs_struct as pt_regs;

pub struct ProbeContext {
    pub regs: *mut pt_regs,
}

impl ProbeContext {
    pub fn new(ctx: *mut c_void) -> ProbeContext {
        ProbeContext {
            regs: ctx as *mut pt_regs,
        }
    }

    /// Returns the `n`th argument to passed to the probe function, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #![allow(non_camel_case_types)]
    /// # #![allow(dead_code)]
    /// # use aya_bpf::{programs::ProbeContext, cty::c_int, helpers::bpf_probe_read};
    /// # type pid_t = c_int;
    /// # struct task_struct {
    /// #     pid: pid_t,
    /// # }
    /// unsafe fn try_kprobe_try_to_wake_up(ctx: ProbeContext) -> Result<u32, u32> {
    ///     let tp: *const task_struct = ctx.arg(0).ok_or(1u32)?;
    ///     let pid = bpf_probe_read(&(*tp).pid as *const pid_t).map_err(|_| 1u32)?;
    ///
    ///     // Do something with pid or something else with tp
    ///
    ///     Ok(0)
    /// }
    /// ```
    pub fn arg<T: FromPtRegs>(&self, n: usize) -> Option<T> {
        T::from_argument(unsafe { &*self.regs }, n)
    }

    /// Returns the `n`th stack argument to passed to the probe function, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # # for c-function in x86_64 platform like:
    /// # # void function_with_many_args(int64 a0, int64 a1, int64 a2,
    /// # #      int64 a3, int64 a4, int64 a5, int64 a6)
    /// # #![allow(non_camel_case_types)]
    /// # #![allow(dead_code)]
    /// unsafe fn try_print_args(ctx: ProbeContext) -> Result<u32, u32> {
    ///     let a_0: i64 = ctx.arg(0).ok_or(1u32)?;
    ///     let a_1: i64 = ctx.arg(1).ok_or(1u32)?;
    ///     let a_2: i64 = ctx.arg(2).ok_or(1u32)?;
    ///     let a_3: i64 = ctx.arg(3).ok_or(1u32)?;
    ///     let a_4: i64 = ctx.arg(4).ok_or(1u32)?;
    ///     let a_5: i64 = ctx.arg(5).ok_or(1u32)?;
    ///     let a_6: i64 = ctx.stack_arg(0).ok_or(1u32)?;
    ///     info!(
    ///         &ctx,
    ///         "arg 0-6: {}, {}, {}, {}, {}, {}, {}",
    ///         a_0,
    ///         a_1,
    ///         a_2,
    ///         a_3,
    ///         a_4,
    ///         a_5,
    ///         a_6
    ///     );
    ///
    ///     // Do something with args
    ///
    ///     Ok(0)
    /// }
    /// ```
    pub fn stack_arg<T: FromPtRegs>(&self, n: usize) -> Option<T> {
        T::from_stack_argument(unsafe { &*self.regs }, n)
    }

    /// Returns the return value of the probed function.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #![allow(dead_code)]
    /// # use aya_bpf::{programs::ProbeContext, cty::c_int};
    /// unsafe fn try_kretprobe_try_to_wake_up(ctx: ProbeContext) -> Result<u32, u32> {
    ///     let retval: c_int = ctx.ret().ok_or(1u32)?;
    ///
    ///     // Do something with retval
    ///
    ///     Ok(0)
    /// }
    /// ```
    pub fn ret<T: FromPtRegs>(&self) -> Option<T> {
        T::from_retval(unsafe { &*self.regs })
    }
}

impl BpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs as *mut c_void
    }
}
