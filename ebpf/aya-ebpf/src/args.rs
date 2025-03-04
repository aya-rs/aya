#[cfg(any(
    bpf_target_arch = "arm",
    bpf_target_arch = "mips",
    bpf_target_arch = "powerpc64",
    bpf_target_arch = "x86_64",
))]
use crate::bindings::pt_regs;
#[cfg(any(
    bpf_target_arch = "aarch64",
    bpf_target_arch = "loongarch64",
    bpf_target_arch = "s390x",
))]
use crate::bindings::user_pt_regs as pt_regs;
#[cfg(bpf_target_arch = "riscv64")]
use crate::bindings::user_regs_struct as pt_regs;
use crate::{bindings::bpf_raw_tracepoint_args, cty::c_void, helpers::bpf_probe_read};

/// A trait that indicates a valid type for an argument which can be coerced from a BTF
/// context.
///
/// Users should not implement this trait.
///
/// # Safety
///
/// This trait is _only_ safe to implement on primitive types that can fit into
/// a `u64`. For example, integers and raw pointers may be coerced from a BTF context.
pub unsafe trait FromBtfArgument: Sized {
    /// Coerces a `T` from the `n`th argument from a BTF context where `n` starts
    /// at 0 and increases by 1 for each successive argument.
    ///
    /// # Safety
    ///
    /// This function is deeply unsafe, as we are reading raw pointers into kernel
    /// memory. In particular, the value of `n` must not exceed the number of function
    /// arguments. Moreover, `ctx` must be a valid pointer to a BTF context, and `T` must
    /// be the right type for the given argument.
    unsafe fn from_argument(ctx: *const c_void, n: usize) -> Self;
}

unsafe impl<T> FromBtfArgument for *const T {
    unsafe fn from_argument(ctx: *const c_void, n: usize) -> *const T {
        // BTF arguments are exposed as an array of `usize` where `usize` can
        // either be treated as a pointer or a primitive type
        let ctx: *const usize = ctx.cast();
        (unsafe { *ctx.add(n) }) as _
    }
}

/// Helper macro to implement [`FromBtfArgument`] for a primitive type.
macro_rules! unsafe_impl_from_btf_argument {
    ($type:ident) => {
        unsafe impl FromBtfArgument for $type {
            unsafe fn from_argument(ctx: *const c_void, n: usize) -> Self {
                // BTF arguments are exposed as an array of `usize` where `usize` can
                // either be treated as a pointer or a primitive type
                let ctx: *const usize = ctx.cast();
                (unsafe { *ctx.add(n) }) as _
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

/// A portable wrapper around pt_regs, user_pt_regs and user_regs_struct.
impl PtRegs {
    pub fn new(regs: *mut pt_regs) -> Self {
        PtRegs { regs }
    }

    /// Returns the value of the register used to pass arg `n`.
    pub fn arg<T: FromPtRegs>(&self, n: usize) -> Option<T> {
        T::from_argument(unsafe { &*self.regs }, n)
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

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.regs[0]).map(|v| v as *const _).ok() }
    }
}

#[cfg(bpf_target_arch = "riscv64")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        match n {
            0 => unsafe { bpf_probe_read(&ctx.a0).map(|v| v as *const _).ok() },
            1 => unsafe { bpf_probe_read(&ctx.a1).map(|v| v as *const _).ok() },
            2 => unsafe { bpf_probe_read(&ctx.a2).map(|v| v as *const _).ok() },
            3 => unsafe { bpf_probe_read(&ctx.a3).map(|v| v as *const _).ok() },
            4 => unsafe { bpf_probe_read(&ctx.a4).map(|v| v as *const _).ok() },
            5 => unsafe { bpf_probe_read(&ctx.a5).map(|v| v as *const _).ok() },
            6 => unsafe { bpf_probe_read(&ctx.a6).map(|v| v as *const _).ok() },
            7 => unsafe { bpf_probe_read(&ctx.a7).map(|v| v as *const _).ok() },
            _ => None,
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.ra).map(|v| v as *const _).ok() }
    }
}

#[cfg(bpf_target_arch = "powerpc64")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 7 {
            unsafe { bpf_probe_read(&ctx.gpr[3 + n]).map(|v| v as *const _).ok() }
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.gpr[3]).map(|v| v as *const _).ok() }
    }
}

#[cfg(bpf_target_arch = "s390x")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 4 {
            unsafe { bpf_probe_read(&ctx.gprs[2 + n]).map(|v| v as *const _).ok() }
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.gprs[2]).map(|v| v as *const _).ok() }
    }
}

#[cfg(bpf_target_arch = "mips")]
impl<T> FromPtRegs for *const T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        // Assume N64 ABI like libbpf does.
        if n <= 7 {
            unsafe { bpf_probe_read(&ctx.regs[n + 4]).map(|v| v as *const _).ok() }
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.regs[31]).map(|v| v as *const _).ok() }
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

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.regs[0]).map(|v| v as *mut _).ok() }
    }
}

#[cfg(bpf_target_arch = "riscv64")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        match n {
            0 => unsafe { bpf_probe_read(&ctx.a0).map(|v| v as *mut _).ok() },
            1 => unsafe { bpf_probe_read(&ctx.a1).map(|v| v as *mut _).ok() },
            2 => unsafe { bpf_probe_read(&ctx.a2).map(|v| v as *mut _).ok() },
            3 => unsafe { bpf_probe_read(&ctx.a3).map(|v| v as *mut _).ok() },
            4 => unsafe { bpf_probe_read(&ctx.a4).map(|v| v as *mut _).ok() },
            5 => unsafe { bpf_probe_read(&ctx.a5).map(|v| v as *mut _).ok() },
            6 => unsafe { bpf_probe_read(&ctx.a6).map(|v| v as *mut _).ok() },
            7 => unsafe { bpf_probe_read(&ctx.a7).map(|v| v as *mut _).ok() },
            _ => None,
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.ra).map(|v| v as *mut _).ok() }
    }
}

#[cfg(bpf_target_arch = "powerpc64")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 7 {
            unsafe { bpf_probe_read(&ctx.gpr[3 + n]).map(|v| v as *mut _).ok() }
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.gpr[3]).map(|v| v as *mut _).ok() }
    }
}

#[cfg(bpf_target_arch = "s390x")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        if n <= 4 {
            unsafe { bpf_probe_read(&ctx.gprs[2 + n]).map(|v| v as *mut _).ok() }
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.gprs[2]).map(|v| v as *mut _).ok() }
    }
}

#[cfg(bpf_target_arch = "mips")]
impl<T> FromPtRegs for *mut T {
    fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
        // Assume N64 ABI like libbpf does.
        if n <= 7 {
            unsafe { bpf_probe_read(&ctx.regs[n + 4]).map(|v| v as *mut _).ok() }
        } else {
            None
        }
    }

    fn from_retval(ctx: &pt_regs) -> Option<Self> {
        unsafe { bpf_probe_read(&ctx.regs[31]).map(|v| v as *mut _).ok() }
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

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                Some(ctx.regs[0] as *const $type as _)
            }
        }

        #[cfg(bpf_target_arch = "riscv64")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                match n {
                    0 => Some(ctx.a0 as *const $type as _),
                    1 => Some(ctx.a1 as *const $type as _),
                    2 => Some(ctx.a2 as *const $type as _),
                    3 => Some(ctx.a3 as *const $type as _),
                    4 => Some(ctx.a4 as *const $type as _),
                    5 => Some(ctx.a5 as *const $type as _),
                    6 => Some(ctx.a6 as *const $type as _),
                    7 => Some(ctx.a7 as *const $type as _),
                    _ => None,
                }
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                Some(ctx.ra as *const $type as _)
            }
        }

        #[cfg(bpf_target_arch = "powerpc64")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                if n <= 7 {
                    Some(ctx.gpr[3 + n] as *const $type as _)
                } else {
                    None
                }
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                Some(ctx.gpr[3] as *const $type as _)
            }
        }

        #[cfg(bpf_target_arch = "s390x")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                if n <= 4 {
                    Some(ctx.gprs[2 + n] as *const $type as _)
                } else {
                    None
                }
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                Some(ctx.gprs[2] as *const $type as _)
            }
        }

        #[cfg(bpf_target_arch = "mips")]
        impl FromPtRegs for $type {
            fn from_argument(ctx: &pt_regs, n: usize) -> Option<Self> {
                if n <= 7 {
                    Some(ctx.regs[n + 4] as *const $type as _)
                } else {
                    None
                }
            }

            fn from_retval(ctx: &pt_regs) -> Option<Self> {
                Some(ctx.regs[31] as *const $type as _)
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

/// A Rust wrapper on `bpf_raw_tracepoint_args`.
pub struct RawTracepointArgs {
    args: *mut bpf_raw_tracepoint_args,
}

impl RawTracepointArgs {
    /// Creates a new instance of `RawTracepointArgs` from the given
    /// `bpf_raw_tracepoint_args` raw pointer to allow easier access
    /// to raw tracepoint argumetns.
    pub fn new(args: *mut bpf_raw_tracepoint_args) -> Self {
        RawTracepointArgs { args }
    }

    /// Returns the n-th argument of the raw tracepoint.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it performs raw pointer conversion and makes assumptions
    /// about the structure of the `bpf_raw_tracepoint_args` type. The tracepoint arguments are
    /// represented as an array of `__u64` values. To be precise, the wrapped
    /// `bpf_raw_tracepoint_args` binding defines it as `__IncompleteArrayField<__u64>` and the
    /// original C type as `__u64 args[0]`. This method provides a way to access these arguments
    /// conveniently in Rust using `__IncompleteArrayField<T>::as_slice` to represent that array
    /// as a slice of length n and then retrieve the n-th element of it.
    ///
    /// However, the method does not check the total number of available arguments for a given
    /// tracepoint and assumes that the slice has at least `n` elements, leading to undefined
    /// behavior if this condition is not met. Such check is impossible to do, because the
    /// tracepoint context doesn't contain any information about number of arguments.
    ///
    /// This method also cannot guarantee that the requested type matches the actual value type.
    /// Wrong assumptions about types can lead to undefined behavior. The tracepoint context
    /// doesn't provide any type information.
    ///
    /// The caller is responsible for ensuring they have accurate knowledge of the arguments
    /// and their respective types for the accessed tracepoint context.
    pub unsafe fn arg<T: FromRawTracepointArgs>(&self, n: usize) -> T {
        unsafe { T::from_argument(&*self.args, n) }
    }
}

#[expect(clippy::missing_safety_doc)]
pub unsafe trait FromRawTracepointArgs: Sized {
    /// Returns the n-th argument of the raw tracepoint.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it performs raw pointer conversion and makes assumptions
    /// about the structure of the `bpf_raw_tracepoint_args` type. The tracepoint arguments are
    /// represented as an array of `__u64` values. To be precise, the wrapped
    /// `bpf_raw_tracepoint_args` binding defines it as `__IncompleteArrayField<__u64>` and the
    /// original C type as `__u64 args[0]`. This method provides a way to access these arguments
    /// conveniently in Rust using `__IncompleteArrayField<T>::as_slice` to represent that array
    /// as a slice of length n and then retrieve the n-th element of it.
    ///
    /// However, the method does not check the total number of available arguments for a given
    /// tracepoint and assumes that the slice has at least `n` elements, leading to undefined
    /// behavior if this condition is not met. Such check is impossible to do, because the
    /// tracepoint context doesn't contain any information about number of arguments.
    ///
    /// This method also cannot guarantee that the requested type matches the actual value type.
    /// Wrong assumptions about types can lead to undefined behavior. The tracepoint context
    /// doesn't provide any type information.
    ///
    /// The caller is responsible for ensuring they have accurate knowledge of the arguments
    /// and their respective types for the accessed tracepoint context.
    unsafe fn from_argument(ctx: &bpf_raw_tracepoint_args, n: usize) -> Self;
}

unsafe impl<T> FromRawTracepointArgs for *const T {
    unsafe fn from_argument(ctx: &bpf_raw_tracepoint_args, n: usize) -> *const T {
        // Raw tracepoint arguments are exposed as `__u64 args[0]`.
        // https://elixir.bootlin.com/linux/v6.5.5/source/include/uapi/linux/bpf.h#L6829
        // They are represented as `__IncompleteArrayField<T>` in the Rust
        // wraapper.
        //
        // The most convenient way of accessing such type in Rust is to use
        // `__IncompleteArrayField<T>::as_slice` to represent that array as a
        // slice of length n and then retrieve the n-th element of it.
        //
        // We don't know how many arguments are there for the given tracepoint,
        // so we just assume that the slice has at least n elements. The whole
        // assumntion and implementation is unsafe.
        (unsafe { ctx.args.as_slice(n + 1) })[n] as _
    }
}

macro_rules! unsafe_impl_from_raw_tracepoint_args {
    ($type:ident) => {
        unsafe impl FromRawTracepointArgs for $type {
            unsafe fn from_argument(ctx: &bpf_raw_tracepoint_args, n: usize) -> Self {
                (unsafe { ctx.args.as_slice(n + 1) })[n] as _
            }
        }
    };
}

unsafe_impl_from_raw_tracepoint_args!(u8);
unsafe_impl_from_raw_tracepoint_args!(u16);
unsafe_impl_from_raw_tracepoint_args!(u32);
unsafe_impl_from_raw_tracepoint_args!(u64);
unsafe_impl_from_raw_tracepoint_args!(i8);
unsafe_impl_from_raw_tracepoint_args!(i16);
unsafe_impl_from_raw_tracepoint_args!(i32);
unsafe_impl_from_raw_tracepoint_args!(i64);
unsafe_impl_from_raw_tracepoint_args!(usize);
unsafe_impl_from_raw_tracepoint_args!(isize);
