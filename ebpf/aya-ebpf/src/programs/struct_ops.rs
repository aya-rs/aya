use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::btf_arg};

/// Context provided to struct_ops programs.
///
/// Struct ops programs implement kernel interfaces and receive context
/// appropriate to the specific callback being invoked.
pub struct StructOpsContext {
    ctx: *mut c_void,
}

impl StructOpsContext {
    /// Creates a new context from a raw pointer.
    pub fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }

    /// Returns the `n`th argument passed to the struct_ops callback, starting from 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::programs::StructOpsContext;
    /// unsafe fn my_struct_ops_callback(ctx: StructOpsContext) -> i32 {
    ///     let arg0: u64 = ctx.arg(0);
    ///     // Process the argument...
    ///     0
    /// }
    /// ```
    pub fn arg<T: Argument>(&self, n: usize) -> T {
        btf_arg(self, n)
    }
}

impl EbpfContext for StructOpsContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
