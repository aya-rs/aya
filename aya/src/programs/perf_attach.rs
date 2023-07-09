//! Perf attach links.
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use crate::{
    generated::bpf_attach_type::BPF_PERF_EVENT,
    programs::{probe::detach_debug_fs, FdLink, Link, ProbeKind, ProgramError},
    sys::{bpf_link_create, perf_event_ioctl},
    FEATURES, PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF,
};

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum PerfLinkIdInner {
    FdLinkId(<FdLink as Link>::Id),
    PerfLinkId(<PerfLink as Link>::Id),
}

#[derive(Debug)]
pub(crate) enum PerfLinkInner {
    FdLink(FdLink),
    PerfLink(PerfLink),
}

impl Link for PerfLinkInner {
    type Id = PerfLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            PerfLinkInner::FdLink(link) => PerfLinkIdInner::FdLinkId(link.id()),
            PerfLinkInner::PerfLink(link) => PerfLinkIdInner::PerfLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            PerfLinkInner::FdLink(link) => link.detach(),
            PerfLinkInner::PerfLink(link) => link.detach(),
        }
    }
}

/// The identifer of a PerfLink.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct PerfLinkId(RawFd);

/// The attachment type of PerfEvent programs.
#[derive(Debug)]
pub struct PerfLink {
    perf_fd: OwnedFd,
    probe_kind: Option<ProbeKind>,
    event_alias: Option<String>,
}

impl Link for PerfLink {
    type Id = PerfLinkId;

    fn id(&self) -> Self::Id {
        // TODO (AM)
        PerfLinkId(self.perf_fd.as_raw_fd())
    }

    fn detach(mut self) -> Result<(), ProgramError> {
        let _ = perf_event_ioctl(self.perf_fd.as_fd(), PERF_EVENT_IOC_DISABLE, 0);

        if let Some(probe_kind) = self.probe_kind.take() {
            if let Some(event_alias) = self.event_alias.take() {
                let _ = detach_debug_fs(probe_kind, &event_alias);
            }
        }

        Ok(())
    }
}

pub(crate) fn perf_attach(
    prog_fd: BorrowedFd<'_>,
    fd: OwnedFd,
) -> Result<PerfLinkInner, ProgramError> {
    if FEATURES.bpf_perf_link() {
        let link_fd = bpf_link_create(prog_fd, fd.as_raw_fd(), BPF_PERF_EVENT, None, 0).map_err(
            |(_, io_error)| ProgramError::SyscallError {
                call: "bpf_link_create".to_owned(),
                io_error,
            },
        )?;
        Ok(PerfLinkInner::FdLink(FdLink::new(link_fd)))
    } else {
        perf_attach_either(prog_fd, fd, None, None)
    }
}

pub(crate) fn perf_attach_debugfs(
    prog_fd: BorrowedFd<'_>,
    fd: OwnedFd,
    probe_kind: ProbeKind,
    event_alias: String,
) -> Result<PerfLinkInner, ProgramError> {
    perf_attach_either(prog_fd, fd, Some(probe_kind), Some(event_alias))
}

fn perf_attach_either(
    prog_fd: BorrowedFd<'_>,
    fd: OwnedFd,
    probe_kind: Option<ProbeKind>,
    event_alias: Option<String>,
) -> Result<PerfLinkInner, ProgramError> {
    perf_event_ioctl(fd.as_fd(), PERF_EVENT_IOC_SET_BPF, prog_fd.as_raw_fd()).map_err(
        |(_, io_error)| ProgramError::SyscallError {
            call: "PERF_EVENT_IOC_SET_BPF".to_owned(),
            io_error,
        },
    )?;
    perf_event_ioctl(fd.as_fd(), PERF_EVENT_IOC_ENABLE, 0).map_err(|(_, io_error)| {
        ProgramError::SyscallError {
            call: "PERF_EVENT_IOC_ENABLE".to_owned(),
            io_error,
        }
    })?;

    Ok(PerfLinkInner::PerfLink(PerfLink {
        perf_fd: fd,
        probe_kind,
        event_alias,
    }))
}
