use crate::cty::c_void;

// aarch64 uses user_pt_regs instead of pt_regs
#[cfg(not(bpf_target_arch = "aarch64"))]
use crate::bindings::pt_regs;
#[cfg(bpf_target_arch = "aarch64")]
use crate::bindings::user_pt_regs as pt_regs;

/// A trait that indicates a valid type for an argument which can be coerced from a BTF
/// context.
///
/// Users should not implement this trait.
///
/// SAFETY: This trait is _only_ safe to implement on primitive types that can fit into
/// a `u64`. For example, integers and raw pointers may be coerced from a BTF context.
pub unsafe trait FromBtfArgument: Sized {
    /// Coerces a `T` from the `n`th argument from a BTF context where `n` starts
    /// at 0 and increases by 1 for each successive argument.
    ///
    /// SAFETY: This function is deeply unsafe, as we are reading raw pointers into kernel
    /// memory. In particular, the value of `n` must not exceed the number of function
    /// arguments. Moreover, `ctx` must be a valid pointer to a BTF context, and `T` must
    /// be the right type for the given argument.
    unsafe fn from_argument(ctx: *const c_void, n: usize) -> Self;
}

unsafe impl<T> FromBtfArgument for *const T {
    unsafe fn from_argument(ctx: *const c_void, n: usize) -> *const T {
        // BTF arguments are exposed as an array of `usize` where `usize` can
        // either be treated as a pointer or a primitive type
        *(ctx as *const usize).add(n) as _
    }
}

/// Helper macro to implement [`FromBtfArgument`] for a primitive type.
macro_rules! unsafe_impl_from_btf_argument {
    ($type:ident) => {
        unsafe impl FromBtfArgument for $type {
            unsafe fn from_argument(ctx: *const c_void, n: usize) -> Self {
                // BTF arguments are exposed as an array of `usize` where `usize` can
                // either be treated as a pointer or a primitive type
                *(ctx as *const usize).add(n) as _
            }
        }
    };
}

unsafe_impl_from_btf_argument!(u8);
unsafe_impl_from_btf_argument!(u16);
unsafe_impl_from_btf_argument!(u32);
unsafe_impl_from_btf_argument!(u64);
unsafe_impl_from_btf_argument!(i8);
unsafe_impl_from_btf_argument!(i16);
unsafe_impl_from_btf_argument!(i32);
unsafe_impl_from_btf_argument!(i64);
unsafe_impl_from_btf_argument!(usize);
unsafe_impl_from_btf_argument!(isize);

/// A trait that indicates a valid type for an argument which can be coerced from
/// a pt_regs context.
///
/// Any implementation of this trait is strictly architecture-specific and depends on the
/// layout of the underlying pt_regs struct and the target processor's calling
/// conventions. Users should not implement this trait.
pub trait FromPtRegs: Sized {
    /// Coerces a `T` from the `n`th argument of a pt_regs context where `n` starts
    /// at 0 and increases by 1 for each successive argument.
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self>;

    /// Coerces a `T` from the return value of a pt_regs context.
    fn from_retval(ctx: &pt_regs) -> Option<Self>;
}

#[cfg(bpf_target_arch = "x86_64")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        match n {
            0 => ctx.rdi().map(|v| v as _),
            1 => ctx.rsi().map(|v| v as _),
            2 => ctx.rdx().map(|v| v as _),
            3 => ctx.rcx().map(|v| v as _),
            4 => ctx.r8().map(|v| v as _),
            5 => ctx.r9().map(|v| v as _),
            _ => None,
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        ctx.rax().map(|v| v as _)
    }
}

#[cfg(bpf_target_arch = "armv7")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 6 {
            ctx.uregs().map(|regs| regs[n] as _)
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        ctx.uregs().map(|regs| regs[0] as _)
    }
}

#[cfg(bpf_target_arch = "aarch64")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 7 {
            ctx.regs().map(|regs| regs[n] as _)
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        ctx.regs().map(|regs| regs[0] as _)
    }
}

#[cfg(bpf_target_arch = "x86_64")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        match n {
            0 => ctx.rdi().map(|v| v as _),
            1 => ctx.rsi().map(|v| v as _),
            2 => ctx.rdx().map(|v| v as _),
            3 => ctx.rcx().map(|v| v as _),
            4 => ctx.r8().map(|v| v as _),
            5 => ctx.r9().map(|v| v as _),
            _ => None,
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        ctx.rax().map(|v| v as _)
    }
}

#[cfg(bpf_target_arch = "armv7")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 6 {
            ctx.uregs().map(|regs| regs[n] as _)
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        ctx.uregs().map(|regs| regs[0] as _)
    }
}

#[cfg(bpf_target_arch = "aarch64")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 7 {
            ctx.regs().map(|regs| regs[n] as _)
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        ctx.regs().map(|regs| regs[0] as _)
    }
}

/// Helper macro to implement [`FromPtRegs`] for a primitive type.
macro_rules! impl_from_pt_regs {
    ($type:ident) => {
        #[cfg(bpf_target_arch = "x86_64")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                match n {
                    0 => ctx.rdi().map(|v| v as _),
                    1 => ctx.rsi().map(|v| v as _),
                    2 => ctx.rdx().map(|v| v as _),
                    3 => ctx.rcx().map(|v| v as _),
                    4 => ctx.r8().map(|v| v as _),
                    5 => ctx.r9().map(|v| v as _),
                    _ => None,
                }
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                ctx.rax().map(|v| v as _)
            }
        }

        #[cfg(bpf_target_arch = "armv7")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                if n <= 6 {
                    ctx.uregs().map(|regs| regs[n] as _)
                } else {
                    None
                }
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                ctx.uregs().map(|regs| regs[0] as _)
            }
        }

        #[cfg(bpf_target_arch = "aarch64")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                if n <= 7 {
                    ctx.regs().map(|regs| regs[n] as _)
                } else {
                    None
                }
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                ctx.regs().map(|regs| regs[0] as _)
            }
        }
    };
}

impl_from_pt_regs!(u8);
impl_from_pt_regs!(u16);
impl_from_pt_regs!(u32);
impl_from_pt_regs!(u64);
impl_from_pt_regs!(i8);
impl_from_pt_regs!(i16);
impl_from_pt_regs!(i32);
impl_from_pt_regs!(i64);
impl_from_pt_regs!(usize);
impl_from_pt_regs!(isize);
