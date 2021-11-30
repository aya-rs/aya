use libc::close;
use std::os::unix::io::RawFd;

use crate::{
    programs::{probe::detach_debug_fs, ProbeKind},
    sys::perf_event_ioctl,
    PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF,
};

use super::{InnerLink, OwnedLink, ProgramData, ProgramError};

#[derive(Debug)]
struct PerfLinkInfo {
    probe_kind: ProbeKind,
    event_alias: String,
}

#[derive(Debug)]
pub(crate) struct PerfLink {
    perf_fd: RawFd,
    info: Option<PerfLinkInfo>,
}

impl InnerLink for PerfLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        let _ = perf_event_ioctl(self.perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        unsafe { close(self.perf_fd) };

        if let Some(info) = self.info.take() {
            let _ = detach_debug_fs(info.probe_kind, &info.event_alias);
        }

        Ok(())
    }
}

pub(crate) fn perf_attach(data: &mut ProgramData, fd: RawFd) -> Result<OwnedLink, ProgramError> {
    perf_attach_either(data, fd, None)
}

pub(crate) fn perf_attach_debugfs(
    data: &mut ProgramData,
    fd: RawFd,
    probe_kind: ProbeKind,
    event_alias: String,
) -> Result<OwnedLink, ProgramError> {
    let info = PerfLinkInfo {
        probe_kind,
        event_alias,
    };
    perf_attach_either(data, fd, Some(info))
}

fn perf_attach_either(
    data: &mut ProgramData,
    fd: RawFd,
    info: Option<PerfLinkInfo>,
) -> Result<OwnedLink, ProgramError> {
    let prog_fd = data.fd_or_err()?;
    perf_event_ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd).map_err(|(_, io_error)| {
        ProgramError::SyscallError {
            call: "PERF_EVENT_IOC_SET_BPF".to_owned(),
            io_error,
        }
    })?;
    perf_event_ioctl(fd, PERF_EVENT_IOC_ENABLE, 0).map_err(|(_, io_error)| {
        ProgramError::SyscallError {
            call: "PERF_EVENT_IOC_ENABLE".to_owned(),
            io_error,
        }
    })?;

    Ok(PerfLink { perf_fd: fd, info }.into())
}
