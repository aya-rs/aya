use core::ffi::c_void;

#[cfg(any(
    bpf_target_arch = "x86_64",
    bpf_target_arch = "arm",
    bpf_target_arch = "powerpc64",
    bpf_target_arch = "mips"
))]
use crate::bindings::pt_regs;
// aarch64 uses user_pt_regs instead of pt_regs
#[cfg(any(
    bpf_target_arch = "aarch64",
    bpf_target_arch = "loongarch64",
    bpf_target_arch = "s390x",
))]
use crate::bindings::user_pt_regs as pt_regs;
// riscv64 uses user_regs_struct instead of pt_regs
#[cfg(bpf_target_arch = "riscv64")]
use crate::bindings::user_regs_struct as pt_regs;
use crate::{EbpfContext, args::FromPtRegs};

pub struct RetProbeContext {
    pub regs: *mut pt_regs,
}

impl RetProbeContext {
    pub fn new(ctx: *mut c_void) -> Self {
        Self { regs: ctx.cast() }
    }

    /// Returns the return value of the probed function.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #![expect(dead_code)]
    /// # use aya_ebpf::{programs::RetProbeContext, cty::c_int};
    /// unsafe fn try_kretprobe_try_to_wake_up(ctx: RetProbeContext) -> Result<u32, u32> {
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

impl EbpfContext for RetProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs.cast()
    }
}
