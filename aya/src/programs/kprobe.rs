//! Kernel space probes.
use std::{
    ffi::OsStr,
    io,
    os::fd::AsFd as _,
    path::{Path, PathBuf},
};

use aya_obj::generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_KPROBE};
use thiserror::Error;

use crate::{
    VerifierLogLevel,
    programs::{
        FdLink, LinkError, ProgramData, ProgramError, ProgramType, define_link_wrapper,
        impl_try_into_fdlink, load_program,
        perf_attach::{PerfLinkIdInner, PerfLinkInner},
        probe::{ProbeKind, attach},
    },
    sys::bpf_link_get_info_by_fd,
};

/// A kernel probe.
///
/// Kernel probes are eBPF programs that can be attached to almost any function inside
/// the kernel. They can be of two kinds:
///
/// - `kprobe`: get attached to the *start* of the target functions
/// - `kretprobe`: get attached to the *return address* of the target functions
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.1.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::KProbe};
///
/// let program: &mut KProbe = bpf.program_mut("intercept_wakeups").unwrap().try_into()?;
/// program.load()?;
/// program.attach("try_to_wake_up", 0)?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_KPROBE")]
pub struct KProbe {
    pub(crate) data: ProgramData<KProbeLink>,
    pub(crate) kind: ProbeKind,
}

impl KProbe {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::KProbe;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    /// Returns `KProbe` if the program is a `kprobe`, or `KRetProbe` if the
    /// program is a `kretprobe`.
    pub fn kind(&self) -> ProbeKind {
        self.kind
    }

    /// Attaches the program.
    ///
    /// Attaches the probe to the given function name inside the kernel. If
    /// `offset` is non-zero, it is added to the address of the target
    /// function.
    ///
    /// If the program is a `kprobe`, it is attached to the *start* address of the target function.
    /// Conversely if the program is a `kretprobe`, it is attached to the return address of the
    /// target function.
    ///
    /// The returned value can be used to detach from the given function, see [KProbe::detach].
    pub fn attach<T: AsRef<OsStr>>(
        &mut self,
        fn_name: T,
        offset: u64,
    ) -> Result<KProbeLinkId, ProgramError> {
        attach(
            &mut self.data,
            self.kind,
            fn_name.as_ref(),
            offset,
            None, // pid
            None, // cookie
        )
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P, kind: ProbeKind) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, kind })
    }
}

define_link_wrapper!(
    /// The link used by [KProbe] programs.
    KProbeLink,
    /// The type returned by [KProbe::attach]. Can be passed to [KProbe::detach].
    KProbeLinkId,
    PerfLinkInner,
    PerfLinkIdInner,
    KProbe,
);

/// The type returned when attaching a [`KProbe`] fails.
#[derive(Debug, Error)]
pub enum KProbeError {
    /// Error detaching from debugfs
    #[error("`{filename}`")]
    FileError {
        /// The file name
        filename: PathBuf,
        /// The [`io::Error`] returned from the file operation
        #[source]
        io_error: io::Error,
    },
}

impl_try_into_fdlink!(KProbeLink, PerfLinkInner);

impl TryFrom<FdLink> for KProbeLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_KPROBE_MULTI as u32) {
            return Ok(Self::new(PerfLinkInner::Fd(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}
