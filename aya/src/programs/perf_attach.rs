use libc::close;
use std::os::unix::io::RawFd;

use crate::{
    programs::{probe::detach_debug_fs, ProbeKind},
    sys::perf_event_ioctl,
    PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF,
};

use super::{Link, OwnedLink, ProgramData, ProgramError};

#[derive(Debug)]
pub(crate) struct PerfLink {
    perf_fd: Option<RawFd>,
    probe_kind: Option<ProbeKind>,
    event_alias: Option<String>,
}

impl Link for PerfLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(fd) = self.perf_fd.take() {
            let _ = perf_event_ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
            unsafe { close(fd) };

            if let Some(probe_kind) = self.probe_kind.take() {
                if let Some(event_alias) = self.event_alias.take() {
                    let _ = detach_debug_fs(probe_kind, &event_alias);
                }
            }

            Ok(())
        } else {
            Err(ProgramError::AlreadyDetached)
        }
    }
}

impl Drop for PerfLink {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

pub(crate) fn perf_attach(data: &mut ProgramData, fd: RawFd) -> Result<OwnedLink, ProgramError> {
    perf_attach_either(data, fd, None, None)
}

pub(crate) fn perf_attach_debugfs(
    data: &mut ProgramData,
    fd: RawFd,
    probe_kind: ProbeKind,
    event_alias: String,
) -> Result<OwnedLink, ProgramError> {
    perf_attach_either(data, fd, Some(probe_kind), Some(event_alias))
}

fn perf_attach_either(
    data: &mut ProgramData,
    fd: RawFd,
    probe_kind: Option<ProbeKind>,
    event_alias: Option<String>,
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

    Ok(PerfLink {
        perf_fd: Some(fd),
        probe_kind,
        event_alias,
    }
    .into())
}
