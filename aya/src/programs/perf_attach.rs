//! Perf attach links.
use std::{
    io,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, RawFd},
};

use aya_obj::generated::bpf_attach_type::BPF_PERF_EVENT;

use crate::{
    FEATURES,
    programs::{FdLink, Link, ProgramError, id_as_key, probe::ProbeEvent},
    sys::{
        BpfLinkCreateArgs, LinkTarget, PerfEventIoctlRequest, SyscallError, bpf_link_create,
        is_bpf_cookie_supported, perf_event_ioctl,
    },
};

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum PerfLinkIdInner {
    FdLinkId(<FdLink as Link>::Id),
    PerfLinkId(<PerfLink as Link>::Id),
}

#[derive(Debug)]
pub(crate) enum PerfLinkInner {
    Fd(FdLink),
    PerfLink(PerfLink),
}

impl Link for PerfLinkInner {
    type Id = PerfLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(link) => PerfLinkIdInner::FdLinkId(link.id()),
            Self::PerfLink(link) => PerfLinkIdInner::PerfLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(link) => link.detach(),
            Self::PerfLink(link) => link.detach(),
        }
    }
}

id_as_key!(PerfLinkInner, PerfLinkIdInner);

/// The identifier of a `PerfLink`.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct PerfLinkId(RawFd);

/// The attachment type of [`PerfEvent`] programs.
///
/// [`PerfEvent`]: crate::programs::PerfEvent
#[derive(Debug)]
pub(crate) struct PerfLink {
    perf_fd: crate::MockableFd,
    event: Option<ProbeEvent>,
}

impl Link for PerfLink {
    type Id = PerfLinkId;

    fn id(&self) -> Self::Id {
        PerfLinkId(self.perf_fd.as_raw_fd())
    }

    fn detach(self) -> Result<(), ProgramError> {
        let Self { perf_fd, event } = self;
        let _unused: io::Result<()> =
            perf_event_ioctl(perf_fd.as_fd(), PerfEventIoctlRequest::Disable);
        if let Some(event) = event {
            let _unused: Result<(), ProgramError> = event.detach();
        }

        Ok(())
    }
}

id_as_key!(PerfLink, PerfLinkId);

pub(crate) fn perf_attach(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    cookie: Option<u64>,
) -> Result<PerfLinkInner, ProgramError> {
    if cookie.is_some() && (!is_bpf_cookie_supported() || !FEATURES.bpf_perf_link()) {
        return Err(ProgramError::AttachCookieNotSupported);
    }
    if FEATURES.bpf_perf_link() {
        let link_fd = bpf_link_create(
            prog_fd,
            LinkTarget::Fd(perf_fd.as_fd()),
            BPF_PERF_EVENT,
            0,
            cookie.map(|bpf_cookie| BpfLinkCreateArgs::PerfEvent { bpf_cookie }),
        )
        .map_err(|io_error| SyscallError {
            call: "bpf_link_create",
            io_error,
        })?;
        Ok(PerfLinkInner::Fd(FdLink::new(link_fd)))
    } else {
        perf_attach_either(prog_fd, perf_fd, None)
    }
}

pub(crate) fn perf_attach_debugfs(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    event: ProbeEvent,
) -> Result<PerfLinkInner, ProgramError> {
    perf_attach_either(prog_fd, perf_fd, Some(event))
}

fn perf_attach_either(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    mut event: Option<ProbeEvent>,
) -> Result<PerfLinkInner, ProgramError> {
    perf_event_ioctl(perf_fd.as_fd(), PerfEventIoctlRequest::SetBpf(prog_fd)).map_err(
        |io_error| SyscallError {
            call: "PERF_EVENT_IOC_SET_BPF",
            io_error,
        },
    )?;
    perf_event_ioctl(perf_fd.as_fd(), PerfEventIoctlRequest::Enable).map_err(|io_error| {
        SyscallError {
            call: "PERF_EVENT_IOC_ENABLE",
            io_error,
        }
    })?;

    if let Some(event) = event.as_mut() {
        event.disarm();
    }

    Ok(PerfLinkInner::PerfLink(PerfLink { perf_fd, event }))
}
