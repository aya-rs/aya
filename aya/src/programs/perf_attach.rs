use libc::close;
use std::os::unix::io::RawFd;

use crate::{
    sys::perf_event_ioctl, PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF,
};

use super::{Link, LinkRef, ProgramData, ProgramError};

#[derive(Debug)]
struct PerfLink {
    perf_fd: Option<RawFd>,
}

impl Link for PerfLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(fd) = self.perf_fd.take() {
            let _ = perf_event_ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
            unsafe { close(fd) };
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

pub(crate) fn perf_attach(data: &mut ProgramData, fd: RawFd) -> Result<LinkRef, ProgramError> {
    let prog_fd = data.fd_or_err()?;
    perf_event_ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd)
        .map_err(|(_, io_error)| ProgramError::PerfEventAttachError { io_error })?;
    perf_event_ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)
        .map_err(|(_, io_error)| ProgramError::PerfEventAttachError { io_error })?;

    Ok(data.link(PerfLink { perf_fd: Some(fd) }))
}
