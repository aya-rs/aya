use core::ffi::c_void;

use crate::{Argument, EbpfContext, programs::FExitContext};

/// The arguments and incoming return value of a function return modifier.
pub struct FModRetContext {
    inner: FExitContext,
}

impl FModRetContext {
    /// Creates a context from the pointer supplied to the program.
    pub const fn new(ctx: *mut c_void) -> Self {
        Self {
            inner: FExitContext::new(ctx),
        }
    }

    /// Returns the `n`th target argument, starting from zero.
    pub fn arg<T: Argument>(&self, n: usize) -> T {
        self.inner.arg(n)
    }

    /// Returns the incoming modifier result, initially zero.
    ///
    /// This is not the target function's result: the target has not run yet.
    /// The helper requires Linux 5.17 or later, as with [`FExitContext::ret`].
    pub fn ret<T: Argument>(&self) -> Result<T, i32> {
        self.inner.ret()
    }
}

impl EbpfContext for FModRetContext {
    fn as_ptr(&self) -> *mut c_void {
        self.inner.as_ptr()
    }
}
