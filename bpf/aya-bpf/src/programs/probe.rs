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
