//! Perf attach links.
use std::{
    convert::Infallible,
    io,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, RawFd},
};

use aya_obj::generated::bpf_attach_type::BPF_PERF_EVENT;

use crate::{
    kernel_features::FEATURES,
    programs::{FdLink, Link, ProgramError, id_as_key, probe::ProbeEvent},
    sys::{
        BpfLinkCreateArgs, LinkTarget, PerfEventIoctlRequest, SyscallError, bpf_link_create,
        perf_event_ioctl,
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
    type Error = Infallible;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(link) => PerfLinkIdInner::FdLinkId(link.id()),
            Self::PerfLink(link) => PerfLinkIdInner::PerfLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), Self::Error> {
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
    type Error = Infallible;

    fn id(&self) -> Self::Id {
        PerfLinkId(self.perf_fd.as_raw_fd())
    }

    fn detach(self) -> Result<(), Self::Error> {
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
    if FEATURES.bpf_perf_link() {
        attach_bpf_link(prog_fd, perf_fd, cookie).map(PerfLinkInner::Fd)
    } else {
        if cookie.is_some() {
            return Err(ProgramError::AttachCookieNotSupported);
        }
        attach_perf_event(prog_fd, perf_fd, None).map(PerfLinkInner::PerfLink)
    }
}

pub(crate) fn attach_bpf_link(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    cookie: Option<u64>,
) -> Result<FdLink, ProgramError> {
    if cookie.is_some() && !FEATURES.bpf_cookie() {
        return Err(ProgramError::AttachCookieNotSupported);
    }
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
    Ok(FdLink::new(link_fd))
}

pub(crate) fn attach_perf_event(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    mut event: Option<ProbeEvent>,
) -> Result<PerfLink, ProgramError> {
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

    Ok(PerfLink { perf_fd, event })
}
