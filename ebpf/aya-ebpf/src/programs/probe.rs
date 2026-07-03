use core::ffi::c_void;

use crate::{
    Argument, EbpfContext,
    args::{arg, syscall_arg},
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

    /// Returns the `n`th syscall argument passed to the probed function,
    /// starting from 0.
    ///
    /// This is intended for use with kprobes attached to syscall wrapper
    /// functions (e.g., `__arm64_sys_*` on `AArch64` or `__x64_sys_*` on
    /// `x86-64`), which are present on kernels built with
    /// `CONFIG_ARCH_HAS_SYSCALL_WRAPPER`. Such wrappers take a single
    /// `const struct pt_regs *` argument; retrieve that pointer with
    /// [`Self::arg`] passing `0` as the index, then this method dereferences it
    /// and extracts the syscall arguments using the syscall calling convention
    /// rather than the regular call convention.
    ///
    /// Currently this is implemented only for `AArch64` and `x86-64`; on other
    /// architectures this method will return `None`.
    /// On some architectures the syscall register layout differs from the
    /// regular call convention:
    ///
    /// - `AArch64`: the first syscall argument lives in `orig_x0`, not
    ///   `regs[0]` (which is overwritten with the return value).
    /// - `x86-64`: the 4th syscall argument (index 3) is passed in `r10`
    ///   rather than `rcx` (which is clobbered by the `syscall` instruction).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::programs::ProbeContext;
    /// unsafe fn try_kprobe_sys_kill(ctx: ProbeContext) -> Result<u32, u32> {
    ///     // `__arm64_sys_kill` / `__x64_sys_kill` take a single
    ///     // `const struct pt_regs *` argument.
    ///     let pid: i32 = ctx.syscall_arg(0).ok_or(1u32)?;
    ///     let sig: i32 = ctx.syscall_arg(1).ok_or(1u32)?;
    ///     Ok(0)
    /// }
    /// ```
    pub fn syscall_arg<T: Argument>(&self, n: usize) -> Option<T> {
        // With CONFIG_ARCH_HAS_SYSCALL_WRAPPER, the probed function's only
        // argument is `const struct pt_regs *regs`.
        let regs: *const pt_regs = self.arg(0)?;
        unsafe { syscall_arg(regs, n) }
    }
}

impl EbpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs.cast()
    }
}
