//! Kernel space probes.
use std::{
    ffi::{CString, NulError, OsStr, OsString},
    fmt::{self, Write},
    io, iter,
    os::{
        fd::{AsFd as _, BorrowedFd},
        unix::ffi::OsStrExt as _,
    },
    path::{Path, PathBuf},
    slice,
};

use aya_obj::generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_KPROBE};
use libc::{EINVAL, ENOTSUP, EOPNOTSUPP};
use thiserror::Error;

use crate::{
    VerifierLogLevel,
    programs::{
        FdLink, LinkError, PerfLinkInner, ProgramData, ProgramError, ProgramType,
        define_link_wrapper, load_program_without_attach_type,
        probe::{
            self, AttachMode, ManyProbeLinks, Probe, ProbeEventArgs, ProbeKind, ProbeLinkIdInner,
            ProbeLinkInner,
        },
    },
    sys::{SyscallError, bpf_link_create_kprobe_multi},
    util::KernelVersion,
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
/// The minimum kernel version required to use this feature is 4.1. Native
/// multi-kprobe links require a 64-bit kernel 5.18 or later built with
/// `CONFIG_FPROBE`.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::KProbe};
///
/// let program: &mut KProbe = bpf.program_mut("intercept_wakeups").unwrap().try_into()?;
/// program.load()?;
/// program.attach(["try_to_wake_up"])?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_KPROBE")]
pub struct KProbe {
    pub(crate) data: ProgramData<KProbeLink>,
    pub(crate) kind: ProbeKind,
    pub(crate) attach_mode: AttachMode,
}

/// A kernel function location accepted by [`KProbe::attach`].
#[derive(Debug, Clone, Copy)]
pub enum KProbeAttachLocation<'a> {
    /// The entry or return of a kernel function.
    Function(&'a OsStr),
    /// A byte offset relative to a kernel function.
    ///
    /// Function-relative offsets require the legacy attachment path and cannot
    /// be used by programs loaded from `kprobe.multi` or `kretprobe.multi`
    /// sections.
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

impl KProbeAttachPoint<'_> {
    #[inline]
    fn probe_target(&self) -> KProbeAttachTarget<'_> {
        KProbeAttachTarget {
            function: self.location.function(),
            offset: self.location.function_offset().unwrap_or_default(),
        }
    }
}

enum KProbePoints<'a> {
    One(KProbeAttachPoint<'a>),
    Many(Vec<KProbeAttachPoint<'a>>),
}

impl KProbe {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::KProbe;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self {
            data,
            kind: _,
            attach_mode: _,
        } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_KPROBE, data)
    }

    /// Returns [`ProbeKind::Entry`] if the program is a `kprobe`, or
    /// [`ProbeKind::Return`] if the program is a `kretprobe`.
    pub const fn kind(&self) -> ProbeKind {
        self.kind
    }

    /// Attaches the program to one or more kernel functions.
    ///
    /// `points` accepts any `IntoIterator` of attachment points. For a single
    /// point, pass a one-element array such as `["try_to_wake_up"]` or
    /// `[KProbeAttachPoint { .. }]`. Function-only and function-offset
    /// locations can be mixed when attaching a program loaded from a legacy
    /// `kprobe` or `kretprobe` section. Programs loaded from `kprobe.multi` and
    /// `kretprobe.multi` sections accept only function-only locations. Empty
    /// input is rejected with [`KProbeError::EmptyPoints`].
    ///
    /// Programs loaded from `kprobe.multi` and `kretprobe.multi` sections use
    /// one native multi-kprobe link. Programs loaded from legacy sections use
    /// one perf attachment per point, managed through one logical link id.
    ///
    /// The returned value can be used to detach, see [`KProbe::detach`].
    pub fn attach<'a, I>(&mut self, points: I) -> Result<KProbeLinkId, ProgramError>
    where
        I: IntoIterator,
        I::Item: Into<KProbeAttachPoint<'a>>,
    {
        let mut points = points.into_iter().map(Into::into);
        match self.attach_mode {
            AttachMode::Single => self.attach_single_impl(points),
            AttachMode::Multi => self.attach_multi_impl(points),
            AttachMode::Unknown => {
                let Some(first) = points.next() else {
                    return Err(KProbeError::EmptyPoints.into());
                };
                // Retain the points so fallback can reuse the same input after a failed native
                // multi attach. The caller's iterator may not be replayable.
                let points = if let Some(second) = points.next() {
                    let mut collected = Vec::with_capacity(points.size_hint().0.saturating_add(2));
                    collected.extend([first, second]);
                    collected.extend(points);
                    KProbePoints::Many(collected)
                } else {
                    KProbePoints::One(first)
                };
                let points = match &points {
                    KProbePoints::One(point) => slice::from_ref(point),
                    KProbePoints::Many(points) => points,
                };
                // The native multi ABI has no per-symbol offset field. This API treats
                // FunctionOffset as requiring legacy attachment, even for zero offsets,
                // so skip native multi attach for the whole batch if any point uses one.
                if points
                    .iter()
                    .any(|point| point.location.function_offset().is_some())
                {
                    return match self.attach_single_impl(points.iter().copied()) {
                        Ok(link_id) => {
                            self.attach_mode = AttachMode::Single;
                            Ok(link_id)
                        }
                        Err(error) => Err(error),
                    };
                }

                let multi_result = self.attach_multi_impl(points.iter().copied());
                match multi_result {
                    Ok(link_id) => {
                        self.attach_mode = AttachMode::Multi;
                        Ok(link_id)
                    }
                    Err(multi_error) if should_fallback_to_single(&multi_error) => {
                        match self.attach_single_impl(points.iter().copied()) {
                            Ok(link_id) => {
                                self.attach_mode = AttachMode::Single;
                                Ok(link_id)
                            }
                            Err(single_error) => Err(KProbeError::AttachModeSelectionFailed {
                                multi_error: Box::new(multi_error),
                                single_error: Box::new(single_error),
                            }
                            .into()),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// This constructor starts in unknown mode because it cannot determine
    /// whether the original program was loaded for a legacy or multi-kprobe
    /// attachment. The first attachment selects a mode and remembers it.
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P, kind: ProbeKind) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self {
            data,
            kind,
            attach_mode: AttachMode::Unknown,
        })
    }

    fn attach_single_impl<'a, I>(&mut self, points: I) -> Result<KProbeLinkId, ProgramError>
    where
        I: IntoIterator<Item = KProbeAttachPoint<'a>>,
    {
        let Self {
            data,
            kind,
            attach_mode: _,
        } = self;
        let mut points = points.into_iter();
        let Some(first) = points.next() else {
            return Err(KProbeError::EmptyPoints.into());
        };

        let Some(second) = points.next() else {
            return probe::attach::<Self, KProbeLink>(
                data,
                ProbeEventArgs {
                    target: first.probe_target(),
                    kind: *kind,
                },
                first.cookie,
            );
        };

        let capacity = points.size_hint().0.saturating_add(2);
        let prog_fd = data.fd()?;
        let prog_fd = prog_fd.as_fd();
        let attach_error =
            |index: usize, point: &KProbeAttachPoint<'_>, attach_error: ProgramError| {
                let KProbeAttachTarget { function, offset } = point.probe_target();
                ProgramError::from(KProbeError::LegacyPerfAttachPointError {
                    index,
                    function: function.to_owned(),
                    offset,
                    attach_error: Box::new(attach_error),
                })
            };
        let first_link = probe::attach_impl::<Self>(
            prog_fd,
            ProbeEventArgs {
                target: first.probe_target(),
                kind: *kind,
            },
            first.cookie,
        )
        .map_err(|error| attach_error(0, &first, error))?;
        let mut links = ManyProbeLinks::from_first_link(first_link, capacity);

        for (index, point) in iter::once(second).chain(points).enumerate() {
            match links.attach_point::<Self>(
                prog_fd,
                ProbeEventArgs {
                    target: point.probe_target(),
                    kind: *kind,
                },
                point.cookie,
            ) {
                Ok(()) => {}
                Err(error) => {
                    // Explicitly detach links attached before this failure.
                    links.detach();
                    return Err(attach_error(index + 1, &point, error));
                }
            }
        }

        data.links
            .insert(KProbeLink::from(ProbeLinkInner::Many(links)))
    }

    fn attach_multi_impl<'a, I>(&mut self, points: I) -> Result<KProbeLinkId, ProgramError>
    where
        I: IntoIterator<Item = KProbeAttachPoint<'a>>,
    {
        let Self {
            data,
            kind,
            attach_mode: _,
        } = self;
        let mut points = points.into_iter();
        let mut functions = Vec::with_capacity(points.size_hint().0);
        let mut cookies: Option<Vec<u64>> = None;
        while let Some(point) = points.next() {
            if point.location.function_offset().is_some() {
                return Err(KProbeError::FunctionOffsetRequiresSingleMode.into());
            }
            let function = point.location.function();
            let function = CString::new(function.as_bytes()).map_err(|source| {
                // Offset validation takes precedence even when a preceding name contains NUL.
                if points.any(|point| point.location.function_offset().is_some()) {
                    KProbeError::FunctionOffsetRequiresSingleMode
                } else {
                    KProbeError::InvalidFunctionName {
                        function: function.to_owned(),
                        source,
                    }
                }
            })?;
            functions.push(function);

            // The kernel ABI takes parallel symbol and cookie arrays. Allocate cookies only
            // when needed, filling preceding entries with zero to preserve their alignment.
            match (&mut cookies, point.cookie) {
                (Some(values), cookie) => values.push(cookie.unwrap_or_default()),
                (slot @ None, Some(cookie)) => {
                    let mut values = Vec::with_capacity(functions.capacity());
                    values.resize(functions.len() - 1, 0);
                    values.push(cookie);
                    *slot = Some(values);
                }
                (None, None) => {}
            }
        }
        if functions.is_empty() {
            return Err(KProbeError::EmptyPoints.into());
        }

        let prog_fd = data.fd()?;
        let link =
            try_attach_kprobe_multi_link(prog_fd.as_fd(), &functions, *kind, cookies.as_deref())?;
        data.links
            .insert(KProbeLink::from(ProbeLinkInner::from(link)))
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
    ProbeLinkInner,
    ProbeLinkIdInner,
    KProbe,
);

impl From<PerfLinkInner> for KProbeLink {
    fn from(link: PerfLinkInner) -> Self {
        Self::from(ProbeLinkInner::from(link))
    }
}

impl TryFrom<KProbeLink> for FdLink {
    type Error = LinkError;

    fn try_from(value: KProbeLink) -> Result<Self, Self::Error> {
        match value.into_inner() {
            ProbeLinkInner::One(PerfLinkInner::Fd(link)) => Ok(link),
            inner => {
                // The wrapper owns detachment, including for legacy links.
                drop(KProbeLink::new(inner));
                Err(LinkError::InvalidLink)
            }
        }
    }
}

impl TryFrom<FdLink> for KProbeLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = crate::sys::bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32
            || info.type_ == bpf_link_type::BPF_LINK_TYPE_KPROBE_MULTI as u32
        {
            return Ok(Self::new(ProbeLinkInner::from(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

impl KProbeLink {
    /// Returns the underlying fd-backed links when available.
    ///
    /// A single [`KProbeLink`] may correspond to multiple [`FdLink`] values
    /// when a legacy program is attached to multiple points.
    ///
    /// If the underlying link representation is not fd-backed, the original
    /// [`KProbeLink`] is returned.
    pub fn into_fd_links(self) -> Result<Vec<FdLink>, Self> {
        self.into_inner().into_fd_links().map_err(Self::from)
    }
}

fn try_attach_kprobe_multi_link(
    prog_fd: BorrowedFd<'_>,
    names: &[CString],
    kind: ProbeKind,
    cookies: Option<&[u64]>,
) -> Result<FdLink, ProgramError> {
    let link_fd =
        bpf_link_create_kprobe_multi(prog_fd, names, cookies, matches!(kind, ProbeKind::Return))
            .map_err(|io_error| {
                let errno = io_error.raw_os_error();
                let is_unsupported = match errno {
                    Some(code) if code == ENOTSUP || code == EOPNOTSUPP => true,
                    // Multi-kprobe landed in Linux 5.18. Older kernels can report
                    // EINVAL for the unknown BPF_TRACE_KPROBE_MULTI attach type (see
                    // https://github.com/torvalds/linux/blob/4b0986a3/include/uapi/linux/bpf.h#L1000).
                    Some(code) if code == EINVAL => {
                        KernelVersion::current().is_ok_and(|kv| kv < KernelVersion::new(5, 18, 0))
                    }
                    _ => false,
                };

                if is_unsupported {
                    ProgramError::KProbeError(KProbeError::MultiLinkNotSupported)
                } else {
                    ProgramError::SyscallError(SyscallError {
                        call: "bpf_link_create",
                        io_error,
                    })
                }
            })?;
    Ok(FdLink::new(link_fd))
}

// In AttachMode::Unknown we probe whether the loaded program should attach via
// BPF_TRACE_KPROBE_MULTI or the legacy single-point perf path.
//
// Fallback is appropriate in two cases:
// - MultiLinkNotSupported: try_attach_kprobe_multi_link() uses this for
//   kernels that do not implement multi-kprobe links, including older kernels
//   (< 5.18) that may report the unknown attach type as EINVAL.
// - bpf_link_create(...)=EINVAL: on kernels that do support multi-kprobe links,
//   a handle loaded from pin/program info can still hit EINVAL when the loaded
//   program expects the legacy per-point attach path rather than the multi
//   attach type. In that case we intentionally retry via the per-point path
//   instead of surfacing the mode-probing error.
//
// Other errors indicate a real multi-attach failure and are propagated.
fn should_fallback_to_single(error: &ProgramError) -> bool {
    match error {
        ProgramError::KProbeError(KProbeError::MultiLinkNotSupported) => true,
        ProgramError::SyscallError(SyscallError {
            call: "bpf_link_create",
            io_error,
        }) => io_error.raw_os_error() == Some(EINVAL),
        _ => false,
    }
}

/// The type returned when attaching a [`KProbe`] fails.
#[derive(Debug, Error)]
pub enum KProbeError {
    /// Automatic attach-mode selection failed in both multi and legacy paths.
    #[error(
        "automatic kprobe attach-mode selection failed: multi={multi_error}; \
         legacy perf={single_error}"
    )]
    // Box the nested ProgramError values to avoid the recursive
    // `ProgramError -> KProbeError -> ProgramError` type.
    AttachModeSelectionFailed {
        /// Error returned by the native multi-kprobe path.
        multi_error: Box<ProgramError>,
        /// Error returned by the legacy per-point path.
        single_error: Box<ProgramError>,
    },

    /// Error detaching from debugfs
    #[error("`{filename}`")]
    FileError {
        /// The file name
        filename: PathBuf,
        /// The [`io::Error`] returned from the file operation
        #[source]
        io_error: io::Error,
    },

    /// The kernel does not support native multi-kprobe links.
    #[error("native multi-kprobe links are not supported by the running kernel")]
    MultiLinkNotSupported,

    /// No attach points were provided.
    #[error("no kprobe attach points provided")]
    EmptyPoints,

    /// The kernel function name contains a NUL byte.
    #[error("invalid kernel function name `{function:?}`")]
    InvalidFunctionName {
        /// The kernel function name.
        function: OsString,
        /// The error caused by the NUL byte.
        #[source]
        source: NulError,
    },

    /// Function-offset locations were passed to a native multi-kprobe program.
    #[error("function-offset attachments require a legacy kprobe program")]
    FunctionOffsetRequiresSingleMode,

    /// The legacy perf attach path failed for a specific point.
    #[error(
        "legacy perf attach failed at point #{index} for `{function:?}` + {offset:#x}: \
         {attach_error}"
    )]
    // Box the nested ProgramError value to avoid the recursive
    // `ProgramError -> KProbeError -> ProgramError` type.
    LegacyPerfAttachPointError {
        /// Index of the attach point within the caller input.
        index: usize,
        /// Kernel function name provided by the caller.
        function: OsString,
        /// Function offset used by the failing perf attachment.
        offset: u64,
        /// Original error returned by the attach syscall path.
        #[source]
        attach_error: Box<ProgramError>,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        ffi::{CStr, c_char},
        os::fd::FromRawFd as _,
    };

    use assert_matches::assert_matches;
    use aya_obj::generated::{bpf_attach_type::BPF_TRACE_KPROBE_MULTI, bpf_cmd};
    use rstest::rstest;

    use super::*;
    use crate::{
        programs::{ProgramFd, links::Links},
        sys::{Syscall, override_syscall},
    };

    fn test_program(attach_mode: AttachMode) -> KProbe {
        KProbe {
            data: ProgramData {
                name: None,
                obj: None,
                fd: None,
                links: Links::new(),
                attach_btf_obj_fd: None,
                attach_btf_id: None,
                attach_prog_fd: None,
                btf_fd: None,
                verifier_log_level: VerifierLogLevel::default(),
                path: None,
                flags: 0,
            },
            kind: ProbeKind::Entry,
            attach_mode,
        }
    }

    #[rstest]
    #[case::multi(AttachMode::Multi)]
    #[case::unknown(AttachMode::Unknown)]
    fn attach_rejects_nul_in_function_name(#[case] attach_mode: AttachMode) {
        let function = OsStr::from_bytes(b"foo\0\xffbar");
        let mut program = test_program(attach_mode);

        assert_matches!(
            program.attach([function]),
            Err(ProgramError::KProbeError(KProbeError::InvalidFunctionName {
                function: invalid_function,
                source,
            })) => {
                assert_eq!(invalid_function, function);
                assert_eq!(source.nul_position(), 3);
                assert_eq!(source.into_vec(), function.as_bytes());
            }
        );
    }

    #[rstest]
    #[case::single(AttachMode::Single)]
    #[case::multi(AttachMode::Multi)]
    #[case::unknown(AttachMode::Unknown)]
    fn attach_rejects_empty_input(#[case] attach_mode: AttachMode) {
        assert_matches!(
            test_program(attach_mode).attach(iter::empty::<KProbeAttachPoint<'_>>()),
            Err(ProgramError::KProbeError(KProbeError::EmptyPoints))
        );
    }

    #[rstest]
    #[case::multi_without_cookies(AttachMode::Multi, None)]
    #[case::multi_zero_cookie(AttachMode::Multi, Some(0))]
    #[case::multi_cookie_after_none(AttachMode::Multi, Some(17))]
    #[case::unknown_without_cookies(AttachMode::Unknown, None)]
    #[case::unknown_zero_cookie(AttachMode::Unknown, Some(0))]
    #[case::unknown_cookie_after_none(AttachMode::Unknown, Some(17))]
    fn multi_attach_preserves_symbol_cookie_order(
        #[case] attach_mode: AttachMode,
        #[case] cookie: Option<u64>,
    ) {
        thread_local! {
            static COOKIE: Cell<Option<u64>> = const { Cell::new(None) };
        }
        COOKIE.set(cookie);
        override_syscall(|call| {
            assert_matches!(call, Syscall::Ebpf { cmd: bpf_cmd::BPF_LINK_CREATE, attr } => {
                let link = unsafe { &attr.link_create };
                assert_eq!(link.attach_type, BPF_TRACE_KPROBE_MULTI as u32);
                let multi = unsafe { &link.__bindgen_anon_3.kprobe_multi };
                assert_eq!(multi.cnt, 3);
                assert_ne!(multi.syms, 0);
                let symbols = unsafe { slice::from_raw_parts(multi.syms as *const u64, 3) };
                for (&symbol, expected) in symbols.iter().zip([c"first", c"second", c"third"]) {
                    assert_eq!(unsafe { CStr::from_ptr(symbol as *const c_char) }, expected);
                }
                if let Some(cookie) = COOKIE.get() {
                    assert_ne!(multi.cookies, 0);
                    let cookies = unsafe { slice::from_raw_parts(multi.cookies as *const u64, 3) };
                    assert_eq!(cookies, [0, cookie, 0]);
                } else {
                    assert_eq!(multi.cookies, 0);
                }
            });
            Ok(crate::MockableFd::mock_signed_fd().into())
        });

        let mut program = test_program(attach_mode);
        program.data.fd = Some(ProgramFd(unsafe {
            crate::MockableFd::from_raw_fd(crate::MockableFd::mock_signed_fd())
        }));
        let mut points = [
            KProbeAttachPoint::from("first"),
            KProbeAttachPoint {
                location: KProbeAttachLocation::from("second"),
                cookie,
            },
            KProbeAttachPoint::from("third"),
        ]
        .into_iter();
        // Exercise an iterator without an exact length, including a cookie after a None entry.
        let link_id = program
            .attach(iter::from_fn(move || points.next()))
            .unwrap();
        assert_matches!(link_id, KProbeLinkId(ProbeLinkIdInner::One(_)));
        assert_matches!(program.attach_mode, AttachMode::Multi);
        program.detach(link_id).unwrap();
    }
}
