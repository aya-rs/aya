//! Kernel space probes.
use std::{
    ffi::OsStr,
    fmt::{self, Write},
    io,
    path::{Path, PathBuf},
};

use aya_obj::generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_KPROBE};
use thiserror::Error;

use crate::{
    VerifierLogLevel,
    programs::{
        ProgramData, ProgramError, ProgramType, define_link_wrapper, impl_try_from_fdlink,
        impl_try_into_fdlink, load_program_without_attach_type,
        perf_attach::{PerfLinkIdInner, PerfLinkInner},
        probe::{Probe, ProbeEventArgs, ProbeKind, attach},
    },
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
/// program.attach("try_to_wake_up")?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_KPROBE")]
pub struct KProbe {
    pub(crate) data: ProgramData<KProbeLink>,
    pub(crate) kind: ProbeKind,
}

/// A kernel function location accepted by [`KProbe::attach`].
#[derive(Debug, Clone, Copy)]
pub enum KProbeAttachLocation<'a> {
    /// The entry or return of a kernel function.
    Function(&'a OsStr),
    /// A byte offset relative to a kernel function.
    FunctionOffset(&'a OsStr, u64),
}

impl<'a> KProbeAttachLocation<'a> {
    /// Creates a location at `offset` bytes from the start of `function`.
    ///
    /// Function-relative offsets require the legacy attachment path and cannot
    /// be used by programs loaded from `kprobe.multi` or `kretprobe.multi`
    /// sections.
    pub fn with_offset<T: AsRef<OsStr> + ?Sized>(function: &'a T, offset: u64) -> Self {
        Self::FunctionOffset(function.as_ref(), offset)
    }

    const fn function(&self) -> &OsStr {
        match self {
            Self::Function(function) | Self::FunctionOffset(function, _) => function,
        }
    }

    const fn function_offset(&self) -> Option<u64> {
        match self {
            Self::Function(_) => None,
            Self::FunctionOffset(_, offset) => Some(*offset),
        }
    }
}

impl<'a, T: AsRef<OsStr> + ?Sized> From<&'a T> for KProbeAttachLocation<'a> {
    fn from(function: &'a T) -> Self {
        Self::Function(function.as_ref())
    }
}

impl From<&Self> for KProbeAttachLocation<'_> {
    fn from(location: &Self) -> Self {
        *location
    }
}

/// Describes one kernel attachment point and its optional cookie.
#[derive(Debug, Clone, Copy)]
pub struct KProbeAttachPoint<'a> {
    /// The location to attach to.
    pub location: KProbeAttachLocation<'a>,
    /// Optional value exposed to eBPF through `bpf_get_attach_cookie()`.
    pub cookie: Option<u64>,
}

impl<'a, L: Into<KProbeAttachLocation<'a>>> From<L> for KProbeAttachPoint<'a> {
    fn from(location: L) -> Self {
        Self {
            location: location.into(),
            cookie: None,
        }
    }
}

impl From<&Self> for KProbeAttachPoint<'_> {
    fn from(point: &Self) -> Self {
        *point
    }
}

pub(crate) struct KProbeAttachTarget<'a> {
    function: &'a OsStr,
    offset: u64,
}

impl KProbe {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::KProbe;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, kind: _ } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_KPROBE, data)
    }

    /// Returns [`ProbeKind::Entry`] if the program is a `kprobe`, or
    /// [`ProbeKind::Return`] if the program is a `kretprobe`.
    pub const fn kind(&self) -> ProbeKind {
        self.kind
    }

    /// Attaches the program to a kernel function.
    ///
    /// `point` may be a function name, a [`KProbeAttachLocation`], or a
    /// [`KProbeAttachPoint`] pairing a location with a cookie exposed to eBPF
    /// through `bpf_get_attach_cookie()`.
    ///
    /// If the program is a `kprobe`, it is attached to the *start* address of the target
    /// function. Conversely, if the program is a `kretprobe`, it is attached to the return
    /// address of the target function.
    ///
    /// The returned value can be used to detach from the given function, see [`KProbe::detach`].
    pub fn attach<'a, P>(&mut self, point: P) -> Result<KProbeLinkId, ProgramError>
    where
        P: Into<KProbeAttachPoint<'a>>,
    {
        let point = point.into();
        let Self { data, kind } = self;
        attach::<Self, _>(
            data,
            ProbeEventArgs {
                target: KProbeAttachTarget {
                    function: point.location.function(),
                    offset: point.location.function_offset().unwrap_or_default(),
                },
                kind: *kind,
            },
            point.cookie,
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

impl Probe for KProbe {
    type AttachTarget<'a> = KProbeAttachTarget<'a>;

    const PMU: &'static str = "kprobe";

    type Error = KProbeError;

    fn into_common_target(target: Self::AttachTarget<'_>) -> (&OsStr, u64, Option<u32>) {
        let KProbeAttachTarget { function, offset } = target;
        (function, offset, None)
    }

    fn file_error(filename: PathBuf, io_error: io::Error) -> Self::Error {
        KProbeError::FileError { filename, io_error }
    }

    fn write_offset<W: Write>(w: &mut W, kind: ProbeKind, offset: u64) -> fmt::Result {
        match kind {
            ProbeKind::Entry => write!(w, "+{offset}"),
            ProbeKind::Return => Ok(()),
        }
    }
}

define_link_wrapper!(
    KProbeLink,
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
impl_try_from_fdlink!(
    KProbeLink,
    PerfLinkInner,
    bpf_link_type::BPF_LINK_TYPE_PERF_EVENT
);
