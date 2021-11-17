use libc::pid_t;
use std::{
    fs,
    io::{self, Write},
    process,
};

use crate::{
    programs::{
        kprobe::KProbeError, perf_attach, perf_attach_debugfs,
        trace_point::read_sys_fs_trace_point_id, uprobe::UProbeError, LinkRef, ProgramData,
        ProgramError,
    },
    sys::{kernel_version, perf_event_open_probe, perf_event_open_trace_point},
};

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

pub(crate) fn attach(
    program_data: &mut ProgramData,
    kind: ProbeKind,
    fn_name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<LinkRef, ProgramError> {
    // https://github.com/torvalds/linux/commit/e12f03d7031a977356e3d7b75a68c2185ff8d155
    // Use debugfs to create probe
    let k_ver = kernel_version().unwrap();
    if k_ver < (4, 17, 0) {
        let (fd, event_alias) = create_as_trace_point(kind, fn_name, offset, pid)?;

        return perf_attach_debugfs(program_data, fd, kind, event_alias);
    };

    let fd = create_as_probe(kind, fn_name, offset, pid)?;

    perf_attach(program_data, fd)
}

pub(crate) fn detach_debug_fs(kind: ProbeKind, event_alias: &str) -> Result<(), ProgramError> {
    use ProbeKind::*;

    /*
     * Taken from https://github.com/iovisor/bcc/blob/67f59ee80fcf5deedaacba1436d9fa09d32a16a0/src/cc/libbpf.c#L1173
     *
     * For [k,u]probe created with perf_event_open (on newer kernel), it is
     * not necessary to clean it up in [k,u]probe_events. We first look up
     * the %s_bcc_%d line in [k,u]probe_events. If the event is not found,
     * it is safe to skip the cleaning up process (write -:... to the file).
     */

    let event_type = match kind {
        KProbe | KRetProbe => "kprobe",
        UProbe | URetProbe => "uprobe",
    };

    let events_file_name = format!("/sys/kernel/debug/tracing/{}_events", event_type);

    let found = match kind {
        KProbe | KRetProbe => {
            find_in_sys_kernel_debug_tracing_events(&events_file_name, event_alias)
                .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?
        }
        UProbe | URetProbe => {
            find_in_sys_kernel_debug_tracing_events(&events_file_name, event_alias)
                .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?
        }
    };

    if found {
        match kind {
            KProbe | KRetProbe => {
                delete_in_sys_kernel_debug_tracing_events(&events_file_name, event_alias)
                    .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?
            }
            UProbe | URetProbe => {
                delete_in_sys_kernel_debug_tracing_events(&events_file_name, event_alias)
                    .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?
            }
        };
    }

    Ok(())
}

fn create_as_probe(
    kind: ProbeKind,
    fn_name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<i32, ProgramError> {
    use ProbeKind::*;

    let perf_ty = match kind {
        KProbe | KRetProbe => read_sys_fs_perf_type("kprobe")
            .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        UProbe | URetProbe => read_sys_fs_perf_type("uprobe")
            .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
    };

    let ret_bit = match kind {
        KRetProbe => Some(
            read_sys_fs_perf_ret_probe("kprobe")
                .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        ),
        URetProbe => Some(
            read_sys_fs_perf_ret_probe("uprobe")
                .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
        ),
        _ => None,
    };

    let fd = perf_event_open_probe(perf_ty, ret_bit, fn_name, offset, pid).map_err(
        |(_code, io_error)| ProgramError::SyscallError {
            call: "perf_event_open".to_owned(),
            io_error,
        },
    )? as i32;

    Ok(fd)
}

fn create_as_trace_point(
    kind: ProbeKind,
    name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<(i32, String), ProgramError> {
    use ProbeKind::*;

    let (event_type, event_alias) = match kind {
        KProbe | KRetProbe => (
            "kprobes",
            create_probe_event(kind, "kprobe", name, offset)
                .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        ),
        UProbe | URetProbe => (
            "uprobes",
            create_probe_event(kind, "uprobe", name, offset)
                .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
        ),
    };

    // TODO: pid and cpu handling
    let tpid = read_sys_fs_trace_point_id(event_type, &event_alias)?;
    let fd = perf_event_open_trace_point(tpid).map_err(|(_code, io_error)| {
        ProgramError::SyscallError {
            call: "perf_event_open".to_owned(),
            io_error,
        }
    })? as i32;

    Ok((fd, event_alias))
}

fn create_probe_event(
    kind: ProbeKind,
    event_type: &str,
    fn_name: &str,
    offset: u64,
) -> Result<String, (String, io::Error)> {
    use ProbeKind::*;

    let events_file_name = format!("/sys/kernel/debug/tracing/{}_events", event_type);
    let probe_type_prefix = match kind {
        KProbe | UProbe => 'p',
        KRetProbe | URetProbe => 'r',
    };
    let event_alias = format!("{}_{}_aya_{}", probe_type_prefix, fn_name, process::id());

    let mut events_file = fs::OpenOptions::new()
        .append(true)
        .open(&events_file_name)
        .map_err(|e| (events_file_name.clone(), e))?;

    // FIXME: add offset
    let p = match kind {
        KProbe => format!(
            "{}:{}s/{} {}",
            probe_type_prefix, event_type, event_alias, fn_name
        ),
        KRetProbe => format!(
            "{}:{}s/{} {}",
            probe_type_prefix, event_type, event_alias, fn_name
        ),
        UProbe => format!(
            "{}:{}s/{} {}",
            probe_type_prefix, event_type, event_alias, fn_name
        ),
        URetProbe => format!(
            "{}:{}s/{} {}",
            probe_type_prefix, event_type, event_alias, fn_name
        ),
    };

    events_file
        .write_all(p.as_bytes())
        .map_err(|e| (events_file_name.clone(), e))?;

    Ok(event_alias)
}

fn find_in_sys_kernel_debug_tracing_events(
    events_file_name: &str,
    event_name: &str,
) -> Result<bool, (String, io::Error)> {
    use std::io::BufRead;

    let events_file =
        fs::File::open(events_file_name).map_err(|e| (events_file_name.to_string(), e))?;

    Ok(io::BufReader::new(events_file)
        .lines()
        .map(|line| line.unwrap())
        .any(|line| line == event_name))
}

fn delete_in_sys_kernel_debug_tracing_events(
    events_file_name: &str,
    event_name: &str,
) -> Result<(), (String, io::Error)> {
    let mut events_file = fs::OpenOptions::new()
        .append(true)
        .open(events_file_name)
        .map_err(|e| (events_file_name.to_string(), e))?;

    events_file
        .write_fmt(format_args!("-:{}", event_name))
        .map_err(|e| (events_file_name.to_string(), e))?;

    Ok(())
}

fn read_sys_fs_perf_type(pmu: &str) -> Result<u32, (String, io::Error)> {
    let file = format!("/sys/bus/event_source/devices/{}/type", pmu);

    let perf_ty = fs::read_to_string(&file).map_err(|e| (file.clone(), e))?;
    let perf_ty = perf_ty
        .trim()
        .parse::<u32>()
        .map_err(|e| (file, io::Error::new(io::ErrorKind::Other, e)))?;

    Ok(perf_ty)
}

fn read_sys_fs_perf_ret_probe(pmu: &str) -> Result<u32, (String, io::Error)> {
    let file = format!("/sys/bus/event_source/devices/{}/format/retprobe", pmu);

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
