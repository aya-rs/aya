//! Syscall programs.
//!
//! BPF_PROG_TYPE_SYSCALL programs can be invoked directly via the bpf() syscall.
//! They are used for various purposes including HID-BPF probe functions.

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_SYSCALL;

use crate::programs::{ProgramData, ProgramError, ProgramType, load_program};

/// A BPF program that can be invoked directly via the bpf() syscall.
///
/// Syscall programs are typically used for:
/// - HID-BPF probe functions that determine whether to attach to a device
/// - General-purpose programs invoked via BPF_PROG_RUN
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.14.
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::Syscall;
///
/// let prog: &mut Syscall = bpf.program_mut("probe").unwrap().try_into()?;
/// prog.load()?;
/// // The program can now be invoked via bpf(BPF_PROG_RUN, ...)
/// // For HID-BPF, the kernel invokes the probe automatically during struct_ops attachment
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SYSCALL")]
pub struct Syscall {
    pub(crate) data: ProgramData<SyscallLink>,
}

impl Syscall {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::Syscall;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SYSCALL, &mut self.data)
    }
}

/// A link for syscall programs.
///
/// Syscall programs don't attach to anything in the traditional sense,
/// they are invoked directly. This is a placeholder for API consistency.
#[derive(Debug)]
pub struct SyscallLink {
    _private: (),
}

/// The type returned when detaching syscall links. Syscall programs don't
/// actually attach, so this is a no-op placeholder.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct SyscallLinkId(());

impl crate::programs::Link for SyscallLink {
    type Id = SyscallLinkId;

    fn id(&self) -> Self::Id {
        SyscallLinkId(())
    }

    fn detach(self) -> Result<(), ProgramError> {
        // Syscall programs don't attach to anything
        Ok(())
    }
}

crate::programs::id_as_key!(SyscallLink, SyscallLinkId);
