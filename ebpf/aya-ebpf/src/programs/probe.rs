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
    /// Only the **native** syscall ABI is supported. On `x86-64`, compat
    /// wrappers such as `__ia32_sys_*` also take a `pt_regs *`, but their
    /// arguments are in the 32-bit register set (`EBX, ECX, EDX, ESI, EDI,
    /// EBP`), not the native registers selected here. A caller probing one of
    /// those wrappers will get unrelated register values rather than `None`.
    /// This matches libbpf's `BPF_KSYSCALL` limitation; see
    /// <https://github.com/torvalds/linux/blob/e5f0a698b/tools/lib/bpf/bpf_tracing.h#L885-L895>.
    ///
    /// On some architectures the syscall register layout differs from the
    /// regular call convention; see the per-architecture details on the
    /// `syscall_arg_reg_offset` impl in `aya_ebpf::args`.
    ///
    /// Currently this is implemented only for `AArch64` and `x86-64`; on other
    /// architectures this method will return `None`.
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
        // argument is `const struct pt_regs *regs`. On x86-64 and AArch64 the
        // kernel selects this config automatically, but on other architectures
        // (e.g. powerpc) it is user-configurable; libbpf auto-detects the
        // absence of a wrapper at runtime (see
        // https://github.com/torvalds/linux/blob/e5f0a698b/tools/lib/bpf/bpf_tracing.h#L906).
        // TODO: auto-detect non-wrapper kernels when support expands beyond
        // x86-64 and AArch64.
        let regs: *const pt_regs = self.arg(0)?;
        unsafe { syscall_arg(regs, n) }
    }
}

impl EbpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs.cast()
    }
}
