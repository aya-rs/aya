use core::ffi::c_void;

use crate::{
    Argument, EbpfContext,
    args::{PtRegsLayout as _, arg, syscall_read_arg},
    bindings::pt_regs,
};

pub struct ProbeContext {
    pub regs: *mut pt_regs,
}

impl ProbeContext {
    pub const fn new(ctx: *mut c_void) -> Self {
        Self { regs: ctx.cast() }
    }

    /// Returns the `n`th argument to passed to the probe function, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::{programs::ProbeContext, cty::c_int, helpers::bpf_probe_read};
    /// # #[expect(non_camel_case_types)]
    /// # type pid_t = c_int;
    /// # #[expect(non_camel_case_types)]
    /// # struct task_struct {
    /// #     pid: pid_t,
    /// # }
    /// unsafe fn try_kprobe_try_to_wake_up(ctx: ProbeContext) -> Result<u32, u32> {
    ///     let tp: *const task_struct = ctx.arg(0).ok_or(1u32)?;
    ///     let pid = unsafe {
    ///         bpf_probe_read(&raw const (*tp).pid)
    ///     }.map_err(|err| err as u32)?;
    ///
    ///     // Do something with pid or something else with tp
    ///
    ///     Ok(0)
    /// }
    /// ```
    pub fn arg<T: Argument>(&self, n: usize) -> Option<T> {
        arg(unsafe { &*self.regs }, n)
    }

    /// Returns the `n`th syscall argument, accounting for architecture-specific
    /// conventions that differ from the function-call ABI.
    ///
    /// On architectures with `ARCH_HAS_SYSCALL_WRAPPER` (aarch64, s390x, x86_64),
    /// the real `pt_regs` that holds the syscall arguments is obtained by
    /// dereferencing the first function-call argument. On aarch64, the first
    /// syscall argument is read from `orig_x0` (past `user_pt_regs`) rather
    /// than `regs[0]`/`x0`.
    ///
    /// On architectures where the syscall and function-call conventions
    /// coincide (arm, riscv64, mips, loongarch64), this is equivalent to
    /// [`arg`](Self::arg).
    pub fn syscall_arg<T: Argument>(&self, n: usize) -> Option<T> {
        let layout = unsafe { &*self.regs };
        let real_regs = layout.syscall_regs_ptr().unwrap_or(self.regs);
        syscall_read_arg(real_regs, n)
    }
}

/// Reads the `n`th syscall argument from the `pt_regs` pointed to by `regs`.
///
/// This is the building block for reading syscall arguments from contexts that
/// provide a raw `pt_regs` pointer (for example, the `sys_enter` raw
/// tracepoint passes a `struct pt_regs *` as its first argument).
pub fn syscall_arg<T: Argument>(regs: *const pt_regs, n: usize) -> Option<T> {
    syscall_read_arg(regs, n)
}

impl EbpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs.cast()
    }
}
