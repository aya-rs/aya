use core::ffi::c_void;

#[cfg(any(
    bpf_target_arch = "x86_64",
    bpf_target_arch = "arm",
    bpf_target_arch = "powerpc64"
))]
use crate::bindings::pt_regs;
// aarch64 uses user_pt_regs instead of pt_regs
#[cfg(any(bpf_target_arch = "aarch64", bpf_target_arch = "s390x"))]
use crate::bindings::user_pt_regs as pt_regs;
// riscv64 uses user_regs_struct instead of pt_regs
#[cfg(bpf_target_arch = "riscv64")]
use crate::bindings::user_regs_struct as pt_regs;
use crate::{args::FromPtRegs, EbpfContext};

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
    /// # use aya_ebpf::{programs::ProbeContext, cty::c_int, helpers::bpf_probe_read};
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
}

impl EbpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs as *mut c_void
    }
}
