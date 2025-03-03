use std::{
    ffi::{OsStr, OsString},
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::fd::AsFd as _,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicUsize, Ordering},
};

use libc::pid_t;

use crate::{
    programs::{
        kprobe::KProbeError, perf_attach, perf_attach::PerfLinkInner, perf_attach_debugfs,
        trace_point::read_sys_fs_trace_point_id, uprobe::UProbeError, utils::find_tracefs_path,
        Link, ProgramData, ProgramError,
    },
    sys::{perf_event_open_probe, perf_event_open_trace_point, SyscallError},
    util::KernelVersion,
};

static PROBE_NAME_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Kind of probe program
#[derive(Debug, Copy, Clone)]
pub enum ProbeKind {
    /// Kernel probe
    KProbe,
    /// Kernel return probe
    KRetProbe,
    /// User space probe
    UProbe,
    /// User space return probe
    URetProbe,
}

impl ProbeKind {
    fn pmu(&self) -> &'static str {
        match *self {
            Self::KProbe | Self::KRetProbe => "kprobe",
            Self::UProbe | Self::URetProbe => "uprobe",
        }
    }
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
    #[allow(dead_code)] // Would be odd to have the others without this one.
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

#[derive(Debug)]
pub(crate) struct ProbeEvent {
    kind: ProbeKind,
    event_alias: OsString,
}

pub(crate) fn attach<T: Link + From<PerfLinkInner>>(
    program_data: &mut ProgramData<T>,
    kind: ProbeKind,
    // NB: the meaning of this argument is different for kprobe/kretprobe and uprobe/uretprobe; in
    // the kprobe case it is the name of the function to attach to, in the uprobe case it is a path
    // to the binary or library.
    //
    // TODO: consider encoding the type and the argument in the [`ProbeKind`] enum instead of a
    // separate argument.
    fn_name: &OsStr,
    offset: u64,
    pid: Option<pid_t>,
    cookie: Option<u64>,
) -> Result<T::Id, ProgramError> {
    // https://github.com/torvalds/linux/commit/e12f03d7031a977356e3d7b75a68c2185ff8d155
    // Use debugfs to create probe
    let prog_fd = program_data.fd()?;
    let prog_fd = prog_fd.as_fd();
    let link = if !KernelVersion::at_least(4, 17, 0) {
        if cookie.is_some() {
            return Err(ProgramError::AttachCookieNotSupported);
        }
        let (fd, event_alias) = create_as_trace_point(kind, fn_name, offset, pid)?;
        perf_attach_debugfs(prog_fd, fd, ProbeEvent { kind, event_alias })
    } else {
        let fd = create_as_probe(kind, fn_name, offset, pid)?;
        perf_attach(prog_fd, fd, cookie)
    }?;
    program_data.links.insert(T::from(link))
}

pub(crate) fn detach_debug_fs(event: ProbeEvent) -> Result<(), ProgramError> {
    use ProbeKind::*;

    let tracefs = find_tracefs_path()?;

    let ProbeEvent {
        kind,
        event_alias: _,
    } = &event;
    let kind = *kind;
    let result = delete_probe_event(tracefs, event);

    result.map_err(|(filename, io_error)| match kind {
        KProbe | KRetProbe => KProbeError::FileError { filename, io_error }.into(),
        UProbe | URetProbe => UProbeError::FileError { filename, io_error }.into(),
    })
}

fn create_as_probe(
    kind: ProbeKind,
    fn_name: &OsStr,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<crate::MockableFd, ProgramError> {
    use ProbeKind::*;

    let perf_ty = match kind {
        KProbe | KRetProbe => read_sys_fs_perf_type(kind.pmu())
            .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        UProbe | URetProbe => read_sys_fs_perf_type(kind.pmu())
            .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
    };

    let ret_bit = match kind {
        KRetProbe => Some(
            read_sys_fs_perf_ret_probe(kind.pmu())
                .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        ),
        URetProbe => Some(
            read_sys_fs_perf_ret_probe(kind.pmu())
                .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
        ),
        _ => None,
    };

    perf_event_open_probe(perf_ty, ret_bit, fn_name, offset, pid)
        .map_err(|io_error| SyscallError {
            call: "perf_event_open",
            io_error,
        })
        .map_err(Into::into)
}

fn create_as_trace_point(
    kind: ProbeKind,
    name: &OsStr,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<(crate::MockableFd, OsString), ProgramError> {
    use ProbeKind::*;

    let tracefs = find_tracefs_path()?;

    let event_alias = match kind {
        KProbe | KRetProbe => create_probe_event(tracefs, kind, name, offset)
            .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        UProbe | URetProbe => create_probe_event(tracefs, kind, name, offset)
            .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
    };

    let category = format!("{}s", kind.pmu());
    let tpid = read_sys_fs_trace_point_id(tracefs, &category, event_alias.as_ref())?;
    let fd = perf_event_open_trace_point(tpid, pid).map_err(|io_error| SyscallError {
        call: "perf_event_open",
        io_error,
    })?;

    Ok((fd, event_alias))
}

fn create_probe_event(
    tracefs: &Path,
    kind: ProbeKind,
    fn_name: &OsStr,
    offset: u64,
) -> Result<OsString, (PathBuf, io::Error)> {
    use std::os::unix::ffi::OsStrExt as _;

    use ProbeKind::*;

    let events_file_name = tracefs.join(format!("{}_events", kind.pmu()));
    let probe_type_prefix = match kind {
        KProbe | UProbe => 'p',
        KRetProbe | URetProbe => 'r',
    };

    let mut event_alias = OsString::new();
    write!(
        &mut event_alias,
        "aya_{}_{}_",
        process::id(),
        probe_type_prefix,
    )
    .unwrap();
    for b in fn_name.as_bytes() {
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
    write!(&mut probe, "{}:{}s/", probe_type_prefix, kind.pmu(),).unwrap();
    probe.push(&event_alias);
    probe.push(" ");
    probe.push(fn_name);
    match kind {
        KProbe => write!(&mut probe, "+{offset}").unwrap(),
        UProbe | URetProbe => write!(&mut probe, ":{offset:#x}").unwrap(),
        _ => {}
    };
    probe.push("\n");

    OpenOptions::new()
        .append(true)
        .open(&events_file_name)
        .and_then(|mut events_file| events_file.write_all(probe.as_bytes()))
        .map_err(|e| (events_file_name, e))?;

    Ok(event_alias)
}

fn delete_probe_event(tracefs: &Path, event: ProbeEvent) -> Result<(), (PathBuf, io::Error)> {
    use std::os::unix::ffi::OsStrExt as _;

    let ProbeEvent { kind, event_alias } = event;
    let events_file_name = tracefs.join(format!("{}_events", kind.pmu()));

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
                OpenOptions::new()
                    .append(true)
                    .open(&events_file_name)
                    .and_then(|mut events_file| {
                        let mut rm = OsString::new();
                        rm.push("-:");
                        rm.push(event_alias);
                        rm.push("\n");

                        events_file.write_all(rm.as_bytes())
                    })
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
        .and_then(|perf_ty| perf_ty.trim().parse::<u32>().map_err(io::Error::other))
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

            config.parse::<u32>().map_err(io::Error::other)
        })
        .map_err(|e| (file, e))
}
