use std::{
    convert::Infallible,
    ffi::{OsStr, OsString},
    fmt::{self, Write},
    fs::{self, OpenOptions},
    io::{self, Write as _},
    os::fd::{AsFd as _, BorrowedFd},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    kernel_features::FEATURES,
    programs::{
        FdLink, Link, PerfLink, PerfLinkIdInner, PerfLinkInner, ProgramData, ProgramError,
        attach_bpf_link, attach_perf_event, id_as_key, trace_point::read_sys_fs_trace_point_id,
        utils::find_tracefs_path,
    },
    sys::{SyscallError, perf_event_open_probe, perf_event_open_trace_point},
    util::KernelVersion,
};

static PROBE_NAME_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Kind of probe program
#[derive(Debug, Copy, Clone)]
pub enum ProbeKind {
    /// Probe the entry of the function
    Entry,
    /// Probe the return of the function
    Return,
}

/// Internal identifier for [`ProbeLinkInner`].
#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum ProbeLinkIdInner {
    // One underlying link, which may represent one or multiple attachment points.
    One(PerfLinkIdInner),
    // Multiple underlying links, one per attachment point, created in single mode
    // or after unknown-mode fallback.
    Many(Vec<PerfLinkIdInner>),
}

/// Homogeneous per-point links created by an explicit single-mode attach or an
/// unknown-mode fallback.
///
/// The first attached point selects the variant, making mixed fd-backed and
/// perf-backed collections unrepresentable.
#[derive(Debug)]
pub(crate) enum ManyProbeLinks {
    Fd(Vec<FdLink>),
    PerfLink(Vec<PerfLink>),
}

impl ManyProbeLinks {
    pub(crate) fn from_first_link(first: PerfLinkInner, capacity: usize) -> Self {
        match first {
            PerfLinkInner::Fd(link) => {
                let mut links = Vec::with_capacity(capacity);
                links.push(link);
                Self::Fd(links)
            }
            PerfLinkInner::PerfLink(link) => {
                let mut links = Vec::with_capacity(capacity);
                links.push(link);
                Self::PerfLink(links)
            }
        }
    }

    pub(crate) fn attach_point<P: Probe>(
        &mut self,
        prog_fd: BorrowedFd<'_>,
        args: ProbeEventArgs<P::AttachTarget<'_>>,
        cookie: Option<u64>,
    ) -> Result<(), ProgramError> {
        // The first attached point selected this variant, so subsequent points can use the same
        // fd-backed or perf-backed path directly without repeating backend selection.
        match self {
            Self::Fd(links) => {
                let link = attach_bpf_probe::<P>(prog_fd, args, cookie)?;
                links.push(link);
            }
            Self::PerfLink(links) => {
                let link = attach_perf_event_probe::<P>(prog_fd, args, cookie)?;
                links.push(link);
            }
        }
        Ok(())
    }

    fn ids(&self) -> Vec<PerfLinkIdInner> {
        match self {
            Self::Fd(links) => links
                .iter()
                .map(|link| PerfLinkIdInner::FdLinkId(link.id()))
                .collect(),
            Self::PerfLink(links) => links
                .iter()
                .map(|link| PerfLinkIdInner::PerfLinkId(link.id()))
                .collect(),
        }
    }

    pub(crate) fn detach(self) {
        match self {
            Self::Fd(links) => {
                for link in links {
                    let Ok(()) = link.detach();
                }
            }
            Self::PerfLink(links) => {
                for link in links {
                    let Ok(()) = link.detach();
                }
            }
        }
    }
}

/// Internal representation shared by probe programs whose logical attachment
/// may be backed by one native link or several per-point links.
#[derive(Debug)]
pub(crate) enum ProbeLinkInner {
    // One underlying link, which may represent one or multiple attachment points.
    One(PerfLinkInner),
    // Multiple underlying links, one per attachment point, created in single mode
    // or after unknown-mode fallback.
    Many(ManyProbeLinks),
}

impl ProbeLinkInner {
    pub(crate) fn into_fd_links(self) -> Result<Vec<FdLink>, Self> {
        match self {
            Self::One(link) => match link {
                PerfLinkInner::Fd(link) => Ok(vec![link]),
                link @ PerfLinkInner::PerfLink(_) => Err(Self::One(link)),
            },
            Self::Many(ManyProbeLinks::Fd(links)) => Ok(links),
            Self::Many(links @ ManyProbeLinks::PerfLink(_)) => Err(Self::Many(links)),
        }
    }
}

impl From<PerfLinkInner> for ProbeLinkInner {
    fn from(link: PerfLinkInner) -> Self {
        Self::One(link)
    }
}

impl From<FdLink> for ProbeLinkInner {
    fn from(link: FdLink) -> Self {
        Self::One(PerfLinkInner::Fd(link))
    }
}

impl Link for ProbeLinkInner {
    type Id = ProbeLinkIdInner;
    type Error = Infallible;

    fn id(&self) -> Self::Id {
        match self {
            Self::One(link) => ProbeLinkIdInner::One(link.id()),
            Self::Many(links) => ProbeLinkIdInner::Many(links.ids()),
        }
    }

    fn detach(self) -> Result<(), Self::Error> {
        match self {
            Self::One(link) => {
                let Ok(()) = link.detach();
            }
            Self::Many(links) => links.detach(),
        }
        Ok(())
    }
}

id_as_key!(ProbeLinkInner, ProbeLinkIdInner);

/// Arguments used to create a perf event for a probe family's target.
pub(crate) struct ProbeEventArgs<T> {
    pub(crate) target: T,
    pub(crate) kind: ProbeKind,
}

pub(crate) trait Probe {
    type AttachTarget<'a>;

    const PMU: &'static str;

    type Error: Into<ProgramError>;

    fn into_common_target(target: Self::AttachTarget<'_>) -> (&OsStr, u64, Option<u32>);

    fn file_error(filename: PathBuf, io_error: io::Error) -> Self::Error;

    fn write_offset<W: Write>(w: &mut W, kind: ProbeKind, offset: u64) -> fmt::Result;
}

pub(crate) fn lines(bytes: &[u8]) -> impl Iterator<Item = &OsStr> {
    use std::os::unix::ffi::OsStrExt as _;

    bytes.as_ref().split(|b| b == &b'\n').map(|mut line| {
        while let [stripped @ .., c] = line {
            if c.is_ascii_whitespace() {
                line = stripped;
                continue;
            }
            break;
        }
        OsStr::from_bytes(line)
    })
}

pub(crate) trait OsStringExt {
    fn starts_with(&self, needle: &OsStr) -> bool;
    #[expect(dead_code, reason = "kept for symmetry with the other helpers")]
    fn ends_with(&self, needle: &OsStr) -> bool;
    fn strip_prefix(&self, prefix: &OsStr) -> Option<&OsStr>;
    fn strip_suffix(&self, suffix: &OsStr) -> Option<&OsStr>;
}

impl OsStringExt for OsStr {
    fn starts_with(&self, needle: &OsStr) -> bool {
        use std::os::unix::ffi::OsStrExt as _;
        self.as_bytes().starts_with(needle.as_bytes())
    }

    fn ends_with(&self, needle: &OsStr) -> bool {
        use std::os::unix::ffi::OsStrExt as _;
        self.as_bytes().ends_with(needle.as_bytes())
    }

    fn strip_prefix(&self, prefix: &OsStr) -> Option<&OsStr> {
        use std::os::unix::ffi::OsStrExt as _;
        self.as_bytes()
            .strip_prefix(prefix.as_bytes())
            .map(Self::from_bytes)
    }

    fn strip_suffix(&self, suffix: &OsStr) -> Option<&OsStr> {
        use std::os::unix::ffi::OsStrExt as _;
        self.as_bytes()
            .strip_suffix(suffix.as_bytes())
            .map(Self::from_bytes)
    }
}

type DetachDebugFs = fn(&OsStr) -> Result<(), ProgramError>;

#[derive(Debug)]
pub(crate) struct ProbeEvent {
    event_alias: OsString,
    detach_debug_fs: Option<(DetachDebugFs, bool)>,
}

impl ProbeEvent {
    pub(crate) fn disarm(&mut self) {
        let Self {
            event_alias: _,
            detach_debug_fs,
        } = self;
        if let Some((_detach_debug_fs, is_guard)) = detach_debug_fs {
            *is_guard = false;
        }
    }

    pub(crate) fn detach(mut self) -> Result<(), ProgramError> {
        let Self {
            event_alias,
            detach_debug_fs,
        } = &mut self;
        detach_debug_fs
            .take()
            .map(|(detach_debug_fs, _is_guard)| detach_debug_fs(event_alias))
            .transpose()?;
        Ok(())
    }
}

impl Drop for ProbeEvent {
    fn drop(&mut self) {
        let Self {
            event_alias,
            detach_debug_fs,
        } = self;
        if let Some((detach_debug_fs, is_guard)) = detach_debug_fs {
            if *is_guard {
                let _unused: Result<(), ProgramError> = detach_debug_fs(event_alias);
            }
        }
    }
}

pub(crate) fn attach<P: Probe, T: Link + From<PerfLinkInner>>(
    program_data: &mut ProgramData<T>,
    args: ProbeEventArgs<P::AttachTarget<'_>>,
    cookie: Option<u64>,
) -> Result<T::Id, ProgramError> {
    // https://github.com/torvalds/linux/commit/e12f03d7031a977356e3d7b75a68c2185ff8d155
    // Use debugfs to create probe
    let prog_fd = program_data.fd()?;
    let prog_fd = prog_fd.as_fd();
    let link = attach_impl::<P>(prog_fd, args, cookie)?;
    program_data.links.insert(T::from(link))
}

pub(crate) fn attach_impl<P: Probe>(
    prog_fd: BorrowedFd<'_>,
    args: ProbeEventArgs<P::AttachTarget<'_>>,
    cookie: Option<u64>,
) -> Result<PerfLinkInner, ProgramError> {
    if probe_pmu_supported() && FEATURES.bpf_perf_link.get() {
        attach_bpf_probe::<P>(prog_fd, args, cookie).map(PerfLinkInner::Fd)
    } else {
        attach_perf_event_probe::<P>(prog_fd, args, cookie).map(PerfLinkInner::PerfLink)
    }
}

fn attach_bpf_probe<P: Probe>(
    prog_fd: BorrowedFd<'_>,
    args: ProbeEventArgs<P::AttachTarget<'_>>,
    cookie: Option<u64>,
) -> Result<FdLink, ProgramError> {
    let perf_fd = create_as_probe::<P>(args)?;
    attach_bpf_link(prog_fd, perf_fd, cookie)
}

fn attach_perf_event_probe<P: Probe>(
    prog_fd: BorrowedFd<'_>,
    args: ProbeEventArgs<P::AttachTarget<'_>>,
    cookie: Option<u64>,
) -> Result<PerfLink, ProgramError> {
    if cookie.is_some() {
        return Err(ProgramError::AttachCookieNotSupported);
    }

    let (perf_fd, event) = if probe_pmu_supported() {
        (create_as_probe::<P>(args)?, None)
    } else {
        let (perf_fd, event) = create_as_trace_point::<P>(args)?;
        (perf_fd, Some(event))
    };
    attach_perf_event(prog_fd, perf_fd, event)
}

fn probe_pmu_supported() -> bool {
    KernelVersion::at_least(4, 17, 0)
}

fn detach_debug_fs<P: Probe>(event_alias: &OsStr) -> Result<(), ProgramError> {
    let tracefs = find_tracefs_path()?;

    delete_probe_event(tracefs, P::PMU, event_alias)
        .map_err(|(filename, io_error)| P::file_error(filename, io_error).into())
}

fn create_as_probe<P: Probe>(
    ProbeEventArgs { target, kind }: ProbeEventArgs<P::AttachTarget<'_>>,
) -> Result<crate::MockableFd, ProgramError> {
    let (target, offset, pid) = P::into_common_target(target);
    let perf_ty = read_sys_fs_perf_type(P::PMU)
        .map_err(|(filename, io_error)| P::file_error(filename, io_error).into())?;

    let ret_bit = match kind {
        ProbeKind::Return => Some(
            read_sys_fs_perf_ret_probe(P::PMU)
                .map_err(|(filename, io_error)| P::file_error(filename, io_error).into())?,
        ),
        ProbeKind::Entry => None,
    };

    perf_event_open_probe(perf_ty, ret_bit, target, offset, pid)
        .map_err(|io_error| SyscallError {
            call: "perf_event_open",
            io_error,
        })
        .map_err(Into::into)
}

fn create_as_trace_point<P: Probe>(
    ProbeEventArgs { target, kind }: ProbeEventArgs<P::AttachTarget<'_>>,
) -> Result<(crate::MockableFd, ProbeEvent), ProgramError> {
    let tracefs = find_tracefs_path()?;
    let (target, offset, pid) = P::into_common_target(target);

    let event = create_probe_event::<P>(tracefs, kind, target, offset)
        .map_err(|(filename, io_error)| P::file_error(filename, io_error).into())?;

    let ProbeEvent {
        event_alias,
        detach_debug_fs: _,
    } = &event;
    let category = format!("{}s", P::PMU);
    let tpid = read_sys_fs_trace_point_id(tracefs, &category, event_alias.as_ref())?;
    let perf_fd = perf_event_open_trace_point(tpid, pid).map_err(|io_error| SyscallError {
        call: "perf_event_open",
        io_error,
    })?;

    Ok((perf_fd, event))
}

fn create_probe_event<P: Probe>(
    tracefs: &Path,
    kind: ProbeKind,
    target: &OsStr,
    offset: u64,
) -> Result<ProbeEvent, (PathBuf, io::Error)> {
    use std::os::unix::ffi::OsStrExt as _;

    let probe_type_prefix = match kind {
        ProbeKind::Entry => 'p',
        ProbeKind::Return => 'r',
    };

    let mut event_alias = OsString::new();
    write!(
        &mut event_alias,
        "aya_{}_{}_",
        process::id(),
        probe_type_prefix,
    )
    .unwrap();
    for b in target.as_bytes() {
        let b = match *b {
            b'.' | b'/' | b'-' => b'_',
            b => b,
        };
        event_alias.push(OsStr::from_bytes(&[b]));
    }
    write!(
        &mut event_alias,
        "_{:#x}_{}",
        offset,
        PROBE_NAME_INDEX.fetch_add(1, Ordering::AcqRel)
    )
    .unwrap();

    let mut probe = OsString::new();
    write!(&mut probe, "{}:{}s/", probe_type_prefix, P::PMU).unwrap();
    probe.push(&event_alias);
    probe.push(" ");
    probe.push(target);
    P::write_offset(&mut probe, kind, offset).unwrap();
    probe.push("\n");

    let events_file_name = tracefs.join(format!("{}_events", P::PMU));
    OpenOptions::new()
        .append(true)
        .open(&events_file_name)
        .and_then(|mut events_file| events_file.write_all(probe.as_bytes()))
        .map_err(|e| (events_file_name, e))?;

    Ok(ProbeEvent {
        event_alias,
        detach_debug_fs: Some((detach_debug_fs::<P>, true)),
    })
}

fn delete_probe_event(
    tracefs: &Path,
    pmu: &str,
    event_alias: &OsStr,
) -> Result<(), (PathBuf, io::Error)> {
    use std::os::unix::ffi::OsStrExt as _;

    let events_file_name = tracefs.join(format!("{pmu}_events"));

    fs::read(&events_file_name)
        .and_then(|events| {
            let found = lines(&events).any(|line| {
                let mut line = line.as_bytes();
                // See [`create_probe_event`] and the documentation:
                //
                // https://docs.kernel.org/trace/kprobetrace.html
                //
                // https://docs.kernel.org/trace/uprobetracer.html
                loop {
                    match line.split_first() {
                        None => break false,
                        Some((b, rest)) => {
                            line = rest;
                            if *b == b'/' {
                                break line.starts_with(event_alias.as_bytes());
                            }
                        }
                    }
                }
            });

            if found {
                let mut events_file = OpenOptions::new().append(true).open(&events_file_name)?;
                let mut rm = OsString::new();
                rm.push("-:");
                rm.push(event_alias);
                rm.push("\n");

                events_file.write_all(rm.as_bytes())
            } else {
                Ok(())
            }
        })
        .map_err(|e| (events_file_name, e))
}

fn read_sys_fs_perf_type(pmu: &str) -> Result<u32, (PathBuf, io::Error)> {
    let file = Path::new("/sys/bus/event_source/devices")
        .join(pmu)
        .join("type");

    fs::read_to_string(&file)
        .and_then(|perf_ty| perf_ty.trim().parse().map_err(io::Error::other))
        .map_err(|e| (file, e))
}

fn read_sys_fs_perf_ret_probe(pmu: &str) -> Result<u32, (PathBuf, io::Error)> {
    let file = Path::new("/sys/bus/event_source/devices")
        .join(pmu)
        .join("format/retprobe");

    fs::read_to_string(&file)
        .and_then(|data| {
            let mut parts = data.trim().splitn(2, ':').skip(1);
            let config = parts
                .next()
                .ok_or_else(|| io::Error::other("invalid format"))?;

            config.parse().map_err(io::Error::other)
        })
        .map_err(|e| (file, e))
}
