use core::ffi::c_void;
use crate::{bindings::pt_regs, BpfContext};

pub struct ProbeContext {
    pub regs: Regs,
}

impl ProbeContext {
    pub fn new(ctx: *mut c_void) -> ProbeContext {
        ProbeContext {
            regs: Regs { regs: ctx as *mut pt_regs },
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

impl From<*mut c_void> for Regs {
    fn from(ctx: *mut c_void) -> Self {
        Regs { regs: ctx as *mut pt_regs }
    }
}

/// This struct allow to generate the macros we have in C as PT_REGS_*
/// as simple method calls.
impl Regs {
    /// Utility to know if the context is valid
    pub fn is_null(&self) -> bool {
        self.regs.is_null()
    }

    /// Utility to get the raw ptr, useful to interact with the context directly.
    pub fn as_raw_ptr(&self) -> *mut c_void {
        self.regs as *mut c_void
    }

    /// Utility to get the underlying regs, useful for advanced users to access the
    /// underlying binding without having to recast.
    pub fn as_regs(&self) -> *mut pt_regs {
        self.regs
    }

    #[doc(alias = "PT_REGS_PARM1")]
    /// Utility to get the First Parameter
    pub unsafe fn parm1(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rdi as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_PARM2")]
    /// Utility to get the Second Parameter
    pub unsafe fn parm2(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rsi as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_PARM3")]
    /// Utility to get the Third Parameter
    pub unsafe fn parm3(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rdx as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_PARM4")]
    /// Utility to get the Fourth Parameter
    pub unsafe fn parm4(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rcx as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_PARM5")]
    /// Utility to get the Fifth Parameter
    pub unsafe fn parm5(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.r8 as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_PARM6")]
    /// Utility to get the Sixth Parameter (not available for s390x)
    pub unsafe fn parm6(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.r9 as *const c_void;
        #[cfg(target_arch = "s390x")]
            // panic!("Sixth parameter does not exists for s390x.")
            return 0 as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_RET")]
    /// Utility to get the Stack Pointer
    pub unsafe fn ret(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rsp as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_FP")]
    /// Utility to get the Frame Pointer
    /// Only available with CONFIG_FRAME_POINTER enabled on kernel.
    pub unsafe fn fp(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rbp as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }


    #[doc(alias = "PT_REGS_RC")]
    /// Utility to get the Return Register
    pub fn rc(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rax as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_IP")]
    /// Utility to get the Instruction Pointer register
    pub unsafe fn ip(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rip as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }

    #[doc(alias = "PT_REGS_SP")]
    /// Utility to get the Stack Pointer
    pub unsafe fn sp(&self) -> *const c_void {
        // assert!(self.regs.is_null(),"You should ensure that the registers are not null");
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            return unsafe { &*(self.regs) }.rsp as *const c_void;
        // unreachable!();
        // panic!("Aya does not support this platform yet.");
        return 0 as *const c_void;
    }
}


