use crate::bindings::{bpf_raw_tracepoint_args, pt_regs};

mod sealed {
    #[expect(unnameable_types, reason = "this is the sealed trait pattern")]
    pub trait Argument {
        fn from_register(value: u64) -> Self;
    }

    macro_rules! impl_argument {
        ($($( { $($generics:tt)* } )? $ty:ty $( { where $($where:tt)* } )?),+ $(,)?) => {
            $(
                #[expect(clippy::allow_attributes, reason = "macro")]
                #[allow(clippy::cast_lossless, trivial_numeric_casts, reason = "macro")]
                impl$($($generics)*)? Argument for $ty $(where $($where)*)? {
                    fn from_register(value: u64) -> Self {
                        value as Self
                    }
                }
            )+
        }
    }

    impl_argument!(
        i8,
        u8,
        i16,
        u16,
        i32,
        u32,
        i64,
        u64,
        i128,
        u128,
        isize,
        usize,
        {<T>} *const T {where T: 'static},
        {<T>} *mut T {where T: 'static},
    );
}

pub trait Argument: sealed::Argument {}

impl<T: sealed::Argument> Argument for T {}

/// Coerces a `T` from the `n`th argument from a BTF context where `n` starts
/// at 0 and increases by 1 for each successive argument.
pub(crate) fn btf_arg<T: Argument>(ctx: &impl crate::EbpfContext, n: usize) -> T {
    // BTF arguments are exposed as an array of `usize` where `usize` can
    // either be treated as a pointer or a primitive type
    let ptr: *const usize = ctx.as_ptr().cast();
    let ptr = unsafe { ptr.add(n) };
    T::from_register(unsafe { *ptr as u64 })
}

trait PtRegsLayout {
    type Reg;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg>;
    fn rc_reg(&self) -> &Self::Reg;
}

#[cfg(bpf_target_arch = "aarch64")]
impl PtRegsLayout for pt_regs {
    type Reg = crate::bindings::__u64;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg> {
        // AArch64 arguments align with libbpf's __PT_PARM{1..8}_REG (regs[0..7]).
        // https://github.com/torvalds/linux/blob/v6.17/arch/arm64/include/uapi/asm/ptrace.h#L88-L93
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L229-L244
        match index {
            0..=7 => Some(&self.regs[index]),
            _ => None,
        }
    }

    fn rc_reg(&self) -> &Self::Reg {
        // Return codes use libbpf's __PT_RC_REG (regs[0]/x0).
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L248-L251
        &self.regs[0]
    }
}

#[cfg(bpf_target_arch = "arm")]
impl PtRegsLayout for pt_regs {
    type Reg = crate::cty::c_long;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg> {
        // ARM arguments follow libbpf's __PT_PARM{1..7}_REG mapping (uregs[0..6]).
        // https://github.com/torvalds/linux/blob/v6.17/arch/arm/include/uapi/asm/ptrace.h#L124-L152
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L198-L210
        match index {
            0..=6 => Some(&self.uregs[index]),
            _ => None,
        }
    }

    fn rc_reg(&self) -> &Self::Reg {
        // Return codes use libbpf's __PT_RC_REG (uregs[0]).
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L211-L214
        &self.uregs[0]
    }
}

#[cfg(bpf_target_arch = "loongarch64")]
impl PtRegsLayout for pt_regs {
    type Reg = crate::cty::c_ulong;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg> {
        // LoongArch arguments correspond to libbpf's __PT_PARM{1..8}_REG (regs[4..11]).
        // https://github.com/torvalds/linux/blob/v6.17/arch/loongarch/include/asm/ptrace.h#L20-L33
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L427-L444
        match index {
            0..=7 => Some(&self.regs[4 + index]),
            _ => None,
        }
    }

    fn rc_reg(&self) -> &Self::Reg {
        // Return codes use libbpf's __PT_RC_REG (regs[4], a0).
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L445-L447
        &self.regs[4]
    }
}

#[cfg(bpf_target_arch = "mips")]
impl PtRegsLayout for pt_regs {
    type Reg = crate::bindings::__u64;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg> {
        // MIPS N64 arguments correspond to libbpf's __PT_PARM{1..8}_REG (regs[4..11]).
        // https://github.com/torvalds/linux/blob/v6.17/arch/mips/include/asm/ptrace.h#L28-L52
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L261-L275
        match index {
            0..=7 => Some(&self.regs[4 + index]),
            _ => None,
        }
    }

    fn rc_reg(&self) -> &Self::Reg {
        // Return codes use libbpf's __PT_RC_REG (regs[2], which aliases MIPS $v0).
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L277-L279
        &self.regs[2]
    }
}

#[cfg(bpf_target_arch = "powerpc64")]
impl PtRegsLayout for pt_regs {
    type Reg = crate::cty::c_ulong;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg> {
        // PowerPC64 arguments follow libbpf's __PT_PARM{1..8}_REG (gpr[3..10]).
        // https://github.com/torvalds/linux/blob/v6.17/arch/powerpc/include/asm/ptrace.h#L28-L56
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L290-L308
        match index {
            0..=7 => Some(&self.gpr[3 + index]),
            _ => None,
        }
    }

    fn rc_reg(&self) -> &Self::Reg {
        // Return codes use libbpf's __PT_RC_REG (gpr[3]).
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L311-L314
        &self.gpr[3]
    }
}

#[cfg(bpf_target_arch = "riscv64")]
impl PtRegsLayout for pt_regs {
    type Reg = crate::cty::c_ulong;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg> {
        // RISC-V arguments track libbpf's __PT_PARM{1..8}_REG (a0-a7).
        // https://github.com/torvalds/linux/blob/v6.17/arch/riscv/include/asm/ptrace.h#L15-L55
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L360-L376
        match index {
            0 => Some(&self.a0),
            1 => Some(&self.a1),
            2 => Some(&self.a2),
            3 => Some(&self.a3),
            4 => Some(&self.a4),
            5 => Some(&self.a5),
            6 => Some(&self.a6),
            7 => Some(&self.a7),
            _ => None,
        }
    }

    fn rc_reg(&self) -> &Self::Reg {
        // Return codes use libbpf's __PT_RC_REG (a0).
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L379-L382
        &self.a0
    }
}

#[cfg(bpf_target_arch = "s390x")]
impl PtRegsLayout for pt_regs {
    type Reg = crate::cty::c_ulong;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg> {
        // s390 arguments match libbpf's __PT_PARM{1..5}_REG (gprs[2..6]).
        // https://github.com/torvalds/linux/blob/v6.17/arch/s390/include/asm/ptrace.h#L111-L131
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L170-L181
        match index {
            0..=4 => Some(&self.gprs[2 + index]),
            _ => None,
        }
    }

    fn rc_reg(&self) -> &Self::Reg {
        // Return codes use libbpf's __PT_RC_REG (gprs[2]).
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L186-L188
        &self.gprs[2]
    }
}

#[cfg(bpf_target_arch = "x86_64")]
impl PtRegsLayout for pt_regs {
    type Reg = crate::cty::c_ulong;

    fn arg_reg(&self, index: usize) -> Option<&Self::Reg> {
        // x86-64 arguments mirror libbpf's __PT_PARM{1..6}_REG mapping (rdi, rsi, rdx, rcx, r8, r9).
        // https://github.com/torvalds/linux/blob/v6.17/arch/x86/include/asm/ptrace.h#L103-L155
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L134-L152
        match index {
            0 => Some(&self.rdi),
            1 => Some(&self.rsi),
            2 => Some(&self.rdx),
            3 => Some(&self.rcx),
            4 => Some(&self.r8),
            5 => Some(&self.r9),
            _ => None,
        }
    }

    fn rc_reg(&self) -> &Self::Reg {
        // Return codes use libbpf's __PT_RC_REG (rax).
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L148-L152
        &self.rax
    }
}

/// Coerces a `T` from the `n`th argument of a `pt_regs` context where `n` starts
/// at 0 and increases by 1 for each successive argument.
pub(crate) fn arg<T: Argument>(ctx: &pt_regs, n: usize) -> Option<T> {
    let reg = ctx.arg_reg(n)?;
    #[expect(clippy::allow_attributes, reason = "architecture-specific")]
    #[allow(
        clippy::cast_sign_loss,
        clippy::unnecessary_cast,
        trivial_numeric_casts,
        reason = "architecture-specific"
    )]
    Some(T::from_register((*reg) as u64))
}

/// Coerces a `T` from the return value of a `pt_regs` context.
pub(crate) fn ret<T: Argument>(ctx: &pt_regs) -> T {
    let reg = ctx.rc_reg();
    #[expect(clippy::allow_attributes, reason = "architecture-specific")]
    #[allow(
        clippy::cast_sign_loss,
        clippy::unnecessary_cast,
        trivial_numeric_casts,
        reason = "architecture-specific"
    )]
    T::from_register((*reg) as u64)
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
pub(crate) fn raw_tracepoint_arg<T: Argument>(ctx: &bpf_raw_tracepoint_args, n: usize) -> T {
    // Raw tracepoint arguments are exposed as `__u64 args[0]`.
    // https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/bpf.h#L7231-L7233
    // They are represented as `__IncompleteArrayField<T>` in the Rust
    // wrapper.
    //
    // The most convenient way of accessing such type in Rust is to use
    // `__IncompleteArrayField<T>::as_slice` to represent that array as a
    // slice of length n and then retrieve the n-th element of it.
    //
    // We don't know how many arguments are there for the given tracepoint,
    // so we just assume that the slice has at least n elements. The whole
    // assumption and implementation is unsafe.
    let ptr = ctx.args.as_ptr();
    let ptr = unsafe { ptr.add(n) };
    T::from_register(unsafe { *ptr })
}
