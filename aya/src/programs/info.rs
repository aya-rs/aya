//! Metadata information about an eBPF program.

use std::{
    ffi::CString,
    num::{NonZeroU32, NonZeroU64},
    os::fd::{AsFd as _, BorrowedFd},
    path::Path,
    time::{Duration, SystemTime},
};

use aya_obj::generated::{bpf_prog_info, bpf_prog_type};

use super::{
    utils::{boot_time, get_fdinfo},
    ProgramError, ProgramFd,
};
use crate::{
    sys::{
        bpf_get_object, bpf_prog_get_fd_by_id, bpf_prog_get_info_by_fd, iter_prog_ids, SyscallError,
    },
    util::bytes_of_bpf_name,
    FEATURES,
};

/// Provides information about a loaded program, like name, id and statistics
#[doc(alias = "bpf_prog_info")]
#[derive(Debug)]
pub struct ProgramInfo(pub(crate) bpf_prog_info);

impl ProgramInfo {
    pub(crate) fn new_from_fd(fd: BorrowedFd<'_>) -> Result<Self, ProgramError> {
        let info = bpf_prog_get_info_by_fd(fd, &mut [])?;
        Ok(Self(info))
    }

    /// The program type as defined by the linux kernel enum [`bpf_prog_type`].
    ///
    /// Introduced in kernel v4.13.
    pub fn program_type(&self) -> bpf_prog_type {
        bpf_prog_type::from(self.0.type_)
    }

    /// The unique ID for this program.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.13.
    pub fn id(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.id)
    }

    /// The program tag.
    ///
    /// The program tag is a SHA sum of the program's instructions which be used as an alternative to
    /// [`Self::id()`]". A program's id can vary every time it's loaded or unloaded, but the tag
    /// will remain the same.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.13.
    pub fn tag(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(u64::from_be_bytes(self.0.tag))
    }

    /// The size in bytes of the program's JIT-compiled machine code.
    ///
    /// Note that this requires the BPF JIT compiler to be enabled.
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.13.
    pub fn size_jitted(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.jited_prog_len)
    }

    /// The size in bytes of the program's translated eBPF bytecode, which is
    /// the bytecode after it has been passed though the verifier where it was
    /// possibly modified by the kernel.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn size_translated(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.xlated_prog_len)
    }

    /// The time of when the program was loaded.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn loaded_at(&self) -> Option<SystemTime> {
        if self.0.load_time > 0 {
            Some(boot_time() + Duration::from_nanos(self.0.load_time))
        } else {
            None
        }
    }

    /// The user ID of the process who loaded the program.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn created_by_uid(&self) -> Option<u32> {
        // This field was introduced in the same commit as `load_time`.
        if self.0.load_time > 0 {
            Some(self.0.created_by_uid)
        } else {
            None
        }
    }

    /// The IDs of the maps used by the program.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn map_ids(&self) -> Result<Option<Vec<NonZeroU32>>, ProgramError> {
        if FEATURES.prog_info_map_ids() {
            let mut map_ids = vec![0u32; self.0.nr_map_ids as usize];
            bpf_prog_get_info_by_fd(self.fd()?.as_fd(), &mut map_ids)?;

            Ok(Some(
                map_ids
                    .into_iter()
                    .map(|id| NonZeroU32::new(id).unwrap())
                    .collect(),
            ))
        } else {
            Ok(None)
        }
    }

    /// The name of the program as was provided when it was load. This is limited to 16 bytes.
    ///
    /// Introduced in kernel v4.15.
    pub fn name(&self) -> &[u8] {
        bytes_of_bpf_name(&self.0.name)
    }

    /// The name of the program as a &str.
    ///
    /// `None` is returned if the name was not valid unicode or if field is not available.
    ///
    /// Introduced in kernel v4.15.
    pub fn name_as_str(&self) -> Option<&str> {
        let name = std::str::from_utf8(self.name()).ok();
        if let Some(name_str) = name {
            if FEATURES.bpf_name() || !name_str.is_empty() {
                return name;
            }
        }
        None
    }

    /// Returns true if the program is defined with a GPL-compatible license.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v4.18.
    pub fn gpl_compatible(&self) -> Option<bool> {
        if FEATURES.prog_info_gpl_compatible() {
            Some(self.0.gpl_compatible() != 0)
        } else {
            None
        }
    }

    /// The BTF ID for the program.
    ///
    /// Introduced in kernel v5.0.
    pub fn btf_id(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.btf_id)
    }

    /// The number of verified instructions in the program.
    ///
    /// This may be less than the total number of instructions in the compiled
    /// program due to dead code elimination in the verifier.
    ///
    /// `None` is returned if the field is not available.
    ///
    /// Introduced in kernel v5.16.
    pub fn verified_instruction_count(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.0.verified_insns)
    }

    /// How much memory in bytes has been allocated and locked for the program.
    pub fn memory_locked(&self) -> Result<u32, ProgramError> {
        get_fdinfo(self.fd()?.as_fd(), "memlock")
    }

    /// Returns a file descriptor referencing the program.
    ///
    /// The returned file descriptor can be closed at any time and doing so does
    /// not influence the life cycle of the program.
    ///
    /// Uses kernel v4.13 features.
    pub fn fd(&self) -> Result<ProgramFd, ProgramError> {
        let Self(info) = self;
        let fd = bpf_prog_get_fd_by_id(info.id)?;
        Ok(ProgramFd(fd))
    }

    /// Loads a program from a pinned path in bpffs.
    ///
    /// Uses kernel v4.4 and v4.13 features.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
        use std::os::unix::ffi::OsStrExt as _;

        // TODO: avoid this unwrap by adding a new error variant.
        let path_string = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();
        let fd = bpf_get_object(&path_string).map_err(|(_, io_error)| SyscallError {
            call: "BPF_OBJ_GET",
            io_error,
        })?;

        Self::new_from_fd(fd.as_fd())
    }
}

/// Returns information about a loaded program with the [`ProgramInfo`] structure.
///
/// This information is populated at load time by the kernel and can be used
/// to correlate a given [`crate::programs::Program`] to it's corresponding [`ProgramInfo`]
/// metadata.
macro_rules! impl_info {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl $struct_name {
                /// Returns metadata information of this program.
                ///
                /// Uses kernel v4.13 features.
                pub fn info(&self) -> Result<ProgramInfo, ProgramError> {
                    let ProgramFd(fd) = self.fd()?;
                    ProgramInfo::new_from_fd(fd.as_fd())
                }
            }
        )+
    }
}

pub(crate) use impl_info;

/// Returns an iterator over all loaded bpf programs.
///
/// This differs from [`crate::Ebpf::programs`] since it will return all programs
/// listed on the host system and not only programs a specific [`crate::Ebpf`] instance.
///
/// Uses kernel v4.13 features.
///
/// # Example
/// ```
/// # use aya::programs::loaded_programs;
///
/// for p in loaded_programs() {
///     match p {
///         Ok(program) => println!("{}", String::from_utf8_lossy(program.name())),
///         Err(e) => println!("Error iterating programs: {:?}", e),
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns [`ProgramError::SyscallError`] if any of the syscalls required to either get
/// next program id, get the program fd, or the [`ProgramInfo`] fail. In cases where
/// iteration can't be performed, for example the caller does not have the necessary privileges,
/// a single item will be yielded containing the error that occurred.
pub fn loaded_programs() -> impl Iterator<Item = Result<ProgramInfo, ProgramError>> {
    iter_prog_ids()
        .map(|id| {
            let id = id?;
            bpf_prog_get_fd_by_id(id)
        })
        .map(|fd| {
            let fd = fd?;
            bpf_prog_get_info_by_fd(fd.as_fd(), &mut [])
        })
        .map(|result| result.map(ProgramInfo).map_err(Into::into))
}
