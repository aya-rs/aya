use core::ffi::c_void;

use crate::{bindings::pt_regs, BpfContext};

pub struct ProbeContext {
    pub regs: Regs,
}

impl ProbeContext {
    pub fn new(ctx: *mut c_void) -> ProbeContext {
        ProbeContext {
            regs: Regs::from(ctx as *mut pt_regs)
        }
    }
}

impl BpfContext for ProbeContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs.as_raw_ptr()
    }
}

pub struct Regs {
    regs: *mut pt_regs,
}

impl From<*mut pt_regs> for Regs {
    fn from(ctx: *mut pt_regs) -> Self {
        Regs { regs: ctx }
    }
}

/// This struct allow to generate the macros we have in C as PT_REGS_*
/// as simple method calls.
impl Regs {
    /// Utility to know if the context is valid
    pub fn is_null(&self) -> bool {
        self.regs.is_null()
    }

    /// Utility to get the underlying regs, useful for advanced users to access the
    /// underlying bindings.
    pub fn as_mut_ptr(&self) -> *mut pt_regs {
        self.regs
    }

    #[doc(hidden)]
    /// Utility to get the raw ptr, useful to interact with the context directly.
    pub(crate) fn as_raw_ptr(&self) -> *mut c_void {
        self.regs as *mut c_void
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_PARM1")]
    /// Utility to get the First Parameter
    pub fn parm1(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { &*(self.regs) }.rdi()
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_PARM2")]
    /// Utility to get the Second Parameter
    pub fn parm2(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { &*(self.regs) }.rsi()
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_PARM3")]
    /// Utility to get the Third Parameter
    pub fn parm3(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { &*(self.regs) }.rdx()
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_PARM4")]
    /// Utility to get the Fourth Parameter
    pub fn parm4(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { &*(self.regs) }.rcx()
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_PARM5")]
    /// Utility to get the Fifth Parameter
    pub fn parm5(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { &*(self.regs) }.r8()
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_PARM6")]
    /// Utility to get the Sixth Parameter (not available for s390x)
    pub fn parm6(&self) -> Option<::aya_bpf_cty::c_ulong> {
        unsafe { &*(self.regs) }.r9()
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_RET")]
    /// Utility to get the Stack Pointer
    pub fn ret(&self) -> *const c_void {
        unsafe { &*(self.regs) }.rsp as *const c_void
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_FP")]
    /// Utility to get the Frame Pointer
    /// Only available with CONFIG_FRAME_POINTER enabled on kernel.
    pub fn fp(&self) -> *const c_void {
        unsafe { &*(self.regs) }.rbp as *const c_void
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_RC")]
    /// Utility to get the Return Register
    pub fn rc(&self) -> *const c_void {
        unsafe { &*(self.regs) }.rax as *const c_void
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_IP")]
    /// Utility to get the Instruction Pointer register
    pub fn ip(&self) -> *const c_void {
        unsafe { &*(self.regs) }.rip as *const c_void
    }

    #[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
    #[doc(alias = "PT_REGS_SP")]
    /// Utility to get the Stack Pointer
    pub fn sp(&self) -> *const c_void {
        unsafe { &*(self.regs) }.rsp as *const c_void
    }
}


