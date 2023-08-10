use crate::util::KernelVersion;
use libc::pid_t;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::fd::{AsRawFd as _, OwnedFd},
    path::Path,
    process,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    programs::{
        kprobe::KProbeError, perf_attach, perf_attach::PerfLinkInner, perf_attach_debugfs,
        trace_point::read_sys_fs_trace_point_id, uprobe::UProbeError, utils::find_tracefs_path,
        Link, ProgramData, ProgramError,
    },
    sys::{perf_event_open_probe, perf_event_open_trace_point, SyscallError},
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
            ProbeKind::KProbe | ProbeKind::KRetProbe => "kprobe",
            ProbeKind::UProbe | ProbeKind::URetProbe => "uprobe",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProbeEvent {
    kind: ProbeKind,
    event_alias: String,
}

pub(crate) fn attach<T: Link + From<PerfLinkInner>>(
    program_data: &mut ProgramData<T>,
    kind: ProbeKind,
    fn_name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<T::Id, ProgramError> {
    // https://github.com/torvalds/linux/commit/e12f03d7031a977356e3d7b75a68c2185ff8d155
    // Use debugfs to create probe
    let prog_fd = program_data.fd_or_err()?;
    let prog_fd = prog_fd.as_raw_fd();
    let link = if KernelVersion::current().unwrap() < KernelVersion::new(4, 17, 0) {
        let (fd, event_alias) = create_as_trace_point(kind, fn_name, offset, pid)?;
        perf_attach_debugfs(prog_fd, fd, ProbeEvent { kind, event_alias })
    } else {
        let fd = create_as_probe(kind, fn_name, offset, pid)?;
        perf_attach(prog_fd, fd)
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
    fn_name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<OwnedFd, ProgramError> {
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

    perf_event_open_probe(perf_ty, ret_bit, fn_name, offset, pid).map_err(|(_code, io_error)| {
        SyscallError {
            call: "perf_event_open",
            io_error,
        }
        .into()
    })
}

fn create_as_trace_point(
    kind: ProbeKind,
    name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<(OwnedFd, String), ProgramError> {
    use ProbeKind::*;

    let tracefs = find_tracefs_path()?;

    let event_alias = match kind {
        KProbe | KRetProbe => create_probe_event(tracefs, kind, name, offset)
            .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        UProbe | URetProbe => create_probe_event(tracefs, kind, name, offset)
            .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
    };

    let category = format!("{}s", kind.pmu());
    let tpid = read_sys_fs_trace_point_id(tracefs, &category, &event_alias)?;
    let fd = perf_event_open_trace_point(tpid, pid).map_err(|(_code, io_error)| SyscallError {
        call: "perf_event_open",
        io_error,
    })?;

    Ok((fd, event_alias))
}

fn create_probe_event(
    tracefs: &Path,
    kind: ProbeKind,
    fn_name: &str,
    offset: u64,
) -> Result<String, (String, io::Error)> {
    use ProbeKind::*;

    let events_file_name = tracefs.join(format!("{}_events", kind.pmu()));
    let probe_type_prefix = match kind {
        KProbe | UProbe => 'p',
        KRetProbe | URetProbe => 'r',
    };

    let fixed_fn_name = fn_name.replace(['.', '/', '-'], "_");

    let event_alias = format!(
        "aya_{}_{}_{}_{:#x}_{}",
        process::id(),
        probe_type_prefix,
        fixed_fn_name,
        offset,
        PROBE_NAME_INDEX.fetch_add(1, Ordering::AcqRel)
    );
    let offset_suffix = match kind {
        KProbe => format!("+{offset}"),
        UProbe | URetProbe => format!(":{offset:#x}"),
        _ => String::new(),
    };
    let probe = format!(
        "{}:{}s/{} {}{}\n",
        probe_type_prefix,
        kind.pmu(),
        event_alias,
        fn_name,
        offset_suffix
    );

    let mut events_file = OpenOptions::new()
        .append(true)
        .open(&events_file_name)
        .map_err(|e| (events_file_name.display().to_string(), e))?;

    events_file
        .write_all(probe.as_bytes())
        .map_err(|e| (events_file_name.display().to_string(), e))?;

    Ok(event_alias)
}

fn delete_probe_event(tracefs: &Path, event: ProbeEvent) -> Result<(), (String, io::Error)> {
    let ProbeEvent { kind, event_alias } = event;
    let events_file_name = tracefs.join(format!("{}_events", kind.pmu()));

    let events = fs::read_to_string(&events_file_name)
        .map_err(|e| (events_file_name.display().to_string(), e))?;

    let found = events.lines().any(|line| line.contains(&event_alias));

    if found {
        let mut events_file = OpenOptions::new()
            .append(true)
            .open(&events_file_name)
            .map_err(|e| (events_file_name.display().to_string(), e))?;

        let rm = format!("-:{event_alias}\n");

        events_file
            .write_all(rm.as_bytes())
            .map_err(|e| (events_file_name.display().to_string(), e))?;
    }

    Ok(())
}

fn read_sys_fs_perf_type(pmu: &str) -> Result<u32, (String, io::Error)> {
    let file = format!("/sys/bus/event_source/devices/{pmu}/type");

    let perf_ty = fs::read_to_string(&file).map_err(|e| (file.clone(), e))?;
    let perf_ty = perf_ty
        .trim()
        .parse::<u32>()
        .map_err(|e| (file, io::Error::new(io::ErrorKind::Other, e)))?;

    Ok(perf_ty)
}

fn read_sys_fs_perf_ret_probe(pmu: &str) -> Result<u32, (String, io::Error)> {
    let file = format!("/sys/bus/event_source/devices/{pmu}/format/retprobe");

    let data = fs::read_to_string(&file).map_err(|e| (file.clone(), e))?;

    let mut parts = data.trim().splitn(2, ':').skip(1);
    let config = parts.next().ok_or_else(|| {
        (
            file.clone(),
            io::Error::new(io::ErrorKind::Other, "invalid format"),
        )
    })?;

    config
        .parse::<u32>()
        .map_err(|e| (file, io::Error::new(io::ErrorKind::Other, e)))
}
