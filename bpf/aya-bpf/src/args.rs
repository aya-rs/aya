use aya_bpf_bindings::bindings::__u64;

use crate::{cty::c_void, helpers::bpf_probe_read};

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

pub struct PtRegs {
    regs: *mut pt_regs,
}

/// A portable wrapper around pt_regs and user_pt_regs.
impl PtRegs {
    pub fn new(regs: *mut pt_regs) -> Self {
        PtRegs { regs }
    }

    /// Returns the value of the register used to pass arg `n`.
    pub fn arg<T: FromPtRegs>(&self, n: usize) -> Option<T> {
        T::from_argument(unsafe { &*self.regs }, n)
    }

    /// Returns the value of the stack argument used to parss arg `n`.
    pub fn stack_arg<T: FromPtRegs>(&self, n: usize) -> Option<T> {
        T::from_stack_argument(unsafe { &*self.regs }, n)
    }

    /// Returns the value of the register used to pass the return value.
    pub fn ret<T: FromPtRegs>(&self) -> Option<T> {
        T::from_retval(unsafe { &*self.regs })
    }

    /// Returns a pointer to the wrapped value.
    pub fn as_ptr(&self) -> *mut pt_regs {
        self.regs
    }
}

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

    /// Coerces a `T` from the `n`th stack argument of a pt_regs context where `n`
    /// starts at 0 and increases by 1 for each successive argument.
    fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self>;

    /// Coerces a `T` from the return value of a pt_regs context.
    fn from_retval(ctx: &pt_regs) -> Option<Self>;
}

#[cfg(bpf_target_arch = "x86_64")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        match n {
            0 => unsafe { bpf_probe_read(&ctx.rdi).map(|v| v as *const _).ok() },
            1 => unsafe { bpf_probe_read(&ctx.rsi).map(|v| v as *const _).ok() },
            2 => unsafe { bpf_probe_read(&ctx.rdx).map(|v| v as *const _).ok() },
            3 => unsafe { bpf_probe_read(&ctx.rcx).map(|v| v as *const _).ok() },
            4 => unsafe { bpf_probe_read(&ctx.r8).map(|v| v as *const _).ok() },
            5 => unsafe { bpf_probe_read(&ctx.r9).map(|v| v as *const _).ok() },
            _ => None,
        }
    }

    fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        unsafe {
            let addr: __u64 = ctx.rsp + 8 * (n + 1) as __u64;
            bpf_probe_read(addr as *const T)
                .map(|v| v as *const _)
                .ok()
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.rax).map(|v| v as *const _).ok() }
    }
}

#[cfg(bpf_target_arch = "arm")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 6 {
            unsafe { bpf_probe_read(&ctx.uregs[n]).map(|v| v as *const _).ok() }
        } else {
            None
        }
    }

    fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        unsafe {
            let addr: __u64 = &ctx.uregs[13] + 8 * (n + 1) as __u64;
            bpf_probe_read(addr as *const T)
                .map(|v| v as *const _)
                .ok()
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.uregs[0]).map(|v| v as *const _).ok() }
    }
}

#[cfg(bpf_target_arch = "aarch64")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 7 {
            unsafe { bpf_probe_read(&ctx.regs[n]).map(|v| v as *const _).ok() }
        } else {
            None
        }
    }

    fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        unsafe {
            let addr: __u64 = ctx.sp + 8 * (n + 1) as __u64;
            bpf_probe_read(addr as *const T)
                .map(|v| &v as *const _)
                .ok()
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.regs[0]).map(|v| v as *const _).ok() }
    }
}

#[cfg(bpf_target_arch = "x86_64")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        match n {
            0 => unsafe { bpf_probe_read(&ctx.rdi).map(|v| v as *mut _).ok() },
            1 => unsafe { bpf_probe_read(&ctx.rsi).map(|v| v as *mut _).ok() },
            2 => unsafe { bpf_probe_read(&ctx.rdx).map(|v| v as *mut _).ok() },
            3 => unsafe { bpf_probe_read(&ctx.rcx).map(|v| v as *mut _).ok() },
            4 => unsafe { bpf_probe_read(&ctx.r8).map(|v| v as *mut _).ok() },
            5 => unsafe { bpf_probe_read(&ctx.r9).map(|v| v as *mut _).ok() },
            _ => None,
        }
    }

    fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        unsafe {
            let addr: __u64 = ctx.rsp + 8 * (n + 1) as __u64;
            bpf_probe_read(addr as *mut T)
                .map(|mut v| &mut v as *mut _)
                .ok()
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.rax).map(|v| v as *mut _).ok() }
    }
}

#[cfg(bpf_target_arch = "arm")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 6 {
            unsafe { bpf_probe_read(&ctx.uregs[n]).map(|v| v as *mut _).ok() }
        } else {
            None
        }
    }

    fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        unsafe {
            let addr: __u64 = ctx.uregs[13] + 8 * (n + 1) as __u64;
            bpf_probe_read(addr as *mut T)
                .map(|mut v| &mut v as *mut _)
                .ok()
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.uregs[0]).map(|v| v as *mut _).ok() }
    }
}

#[cfg(bpf_target_arch = "aarch64")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 7 {
            unsafe { bpf_probe_read(&ctx.regs[n]).map(|v| v as *mut _).ok() }
        } else {
            None
        }
    }

    fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        unsafe {
            let addr: __u64 = ctx.sp + 8 * (n + 1) as __u64;
            bpf_probe_read(addr as *mut T)
                .map(|mut v| &mut v as *mut T)
                .ok()
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.regs[0]).map(|v| v as *mut _).ok() }
    }
}

/// Helper macro to implement [`FromPtRegs`] for a primitive type.
macro_rules! impl_from_pt_regs {
    ($type:ident) => {
        #[cfg(bpf_target_arch = "x86_64")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                match n {
                    0 => Some(ctx.rdi as *const $type as _),
                    1 => Some(ctx.rsi as *const $type as _),
                    2 => Some(ctx.rdx as *const $type as _),
                    3 => Some(ctx.rcx as *const $type as _),
                    4 => Some(ctx.r8 as *const $type as _),
                    5 => Some(ctx.r9 as *const $type as _),
                    _ => None,
                }
            }

            fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                let addr = ctx.rsp + 8 * (n + 1) as __u64;
                Some(addr as *const $type as _)
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                Some(ctx.rax as *const $type as _)
            }
        }

        #[cfg(bpf_target_arch = "arm")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                if n <= 6 {
                    Some(ctx.uregs[n] as *const $type as _)
                } else {
                    None
                }
            }

            fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                let addr = ctx.uregs[13] + 8 * (n + 1) as __u64;
                Some(addr as *const $type as _)
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                Some(ctx.uregs[0] as *const $type as _)
            }
        }

        #[cfg(bpf_target_arch = "aarch64")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                if n <= 7 {
                    Some(ctx.regs[n] as *const $type as _)
                } else {
                    None
                }
            }

            fn from_stack_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                let addr = ctx.sp + 8 * (n + 1) as __u64;
                Some(addr as *const $type as _)
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                Some(ctx.regs[0] as *const $type as _)
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
