use libc::pid_t;
use std::{fs, io};

use crate::{
    programs::{
        kprobe::KProbeError, perf_attach, uprobe::UProbeError, LinkRef, ProgramData, ProgramError,
    },
    sys::perf_event_open_probe,
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
    name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<LinkRef, ProgramError> {
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

    let fd = perf_event_open_probe(perf_ty, ret_bit, name, offset, pid).map_err(
        |(_code, io_error)| ProgramError::SyscallError {
            call: "perf_event_open".to_owned(),
            io_error,
        },
    )? as i32;

    perf_attach(program_data, fd)
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
