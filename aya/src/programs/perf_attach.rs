//! Perf attach links.
use std::{
    io,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, RawFd},
};

use aya_obj::generated::bpf_attach_type::BPF_PERF_EVENT;

use crate::{
    FEATURES,
    programs::{
        FdLink, Link, ProgramError, id_as_key,
        probe::ProbeEvent,
        uprobe::{UProbeError, UProbeLinkDetachErrors},
    },
    sys::{
        BpfLinkCreateArgs, LinkTarget, PerfEventIoctlRequest, SyscallError, bpf_link_create,
        is_bpf_cookie_supported, perf_event_ioctl,
    },
};

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum PerfLinkIdInner {
    Single(PerfLinkIdInnerInner),
    Multi(Vec<PerfLinkIdInnerInner>),
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum PerfLinkIdInnerInner {
    FdLinkId(<FdLink as Link>::Id),
    PerfLinkId(<PerfLink as Link>::Id),
}

#[derive(Debug)]
pub(crate) enum PerfLinkLeaf {
    Fd(FdLink),
    PerfLink(PerfLink),
}

impl PerfLinkLeaf {
    pub(crate) fn into_fd_link(self) -> Result<FdLink, Self> {
        match self {
            Self::Fd(link) => Ok(link),
            Self::PerfLink(link) => Err(Self::PerfLink(link)),
        }
    }
}

impl Link for PerfLinkLeaf {
    type Id = PerfLinkIdInnerInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(link) => PerfLinkIdInnerInner::FdLinkId(link.id()),
            Self::PerfLink(link) => PerfLinkIdInnerInner::PerfLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(link) => link.detach(),
            Self::PerfLink(link) => link.detach(),
        }
    }
}

id_as_key!(PerfLinkLeaf, PerfLinkIdInnerInner);

#[derive(Debug)]
pub(crate) enum PerfLinkInner {
    Single(PerfLinkLeaf),
    Multi(Vec<PerfLinkLeaf>),
}

impl PerfLinkInner {
    pub(crate) fn into_fd_link(self) -> Result<FdLink, Self> {
        match self {
            Self::Single(PerfLinkLeaf::Fd(link)) => Ok(link),
            Self::Single(link) => Err(Self::Single(link)),
            Self::Multi(links) => Err(Self::Multi(links)),
        }
    }

    pub(crate) fn into_fd_links(self) -> Result<Vec<FdLink>, Self> {
        match self {
            Self::Single(link) => link
                .into_fd_link()
                .map(|link| vec![link])
                .map_err(Self::Single),
            Self::Multi(links) => {
                let mut fd_links = Vec::with_capacity(links.len());
                let mut pending = links.into_iter();

                while let Some(link) = pending.next() {
                    match link.into_fd_link() {
                        Ok(link) => fd_links.push(link),
                        Err(link) => {
                            let mut links = fd_links
                                .into_iter()
                                .map(PerfLinkLeaf::from)
                                .collect::<Vec<_>>();
                            links.push(link);
                            links.extend(pending);
                            return Err(Self::Multi(links));
                        }
                    }
                }

                Ok(fd_links)
            }
        }
    }
}

impl From<PerfLinkIdInnerInner> for PerfLinkIdInner {
    fn from(link_id: PerfLinkIdInnerInner) -> Self {
        Self::Single(link_id)
    }
}

impl From<FdLink> for PerfLinkLeaf {
    fn from(link: FdLink) -> Self {
        Self::Fd(link)
    }
}

impl From<PerfLinkLeaf> for PerfLinkInner {
    fn from(link: PerfLinkLeaf) -> Self {
        Self::Single(link)
    }
}

impl From<FdLink> for PerfLinkInner {
    fn from(link: FdLink) -> Self {
        PerfLinkLeaf::from(link).into()
    }
}

impl Link for PerfLinkInner {
    type Id = PerfLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Single(link) => link.id().into(),
            Self::Multi(links) => PerfLinkIdInner::Multi(links.iter().map(Link::id).collect()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Single(link) => link.detach(),
            Self::Multi(links) => {
                // Best-effort cleanup: keep detaching remaining links even if one fails.
                let mut errors = Vec::new();
                for link in links {
                    if let Err(error) = link.detach() {
                        errors.push(error);
                    }
                }
                collect_link_detach_errors(errors)
            }
        }
    }
}

id_as_key!(PerfLinkInner, PerfLinkIdInner);

pub(crate) fn collect_link_detach_errors(errors: Vec<ProgramError>) -> Result<(), ProgramError> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(UProbeError::CompositeLinkDetachFailed {
            error: UProbeLinkDetachErrors::new(errors),
        }
        .into())
    }
}

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

impl From<PerfLink> for PerfLinkLeaf {
    fn from(link: PerfLink) -> Self {
        Self::PerfLink(link)
    }
}

impl From<PerfLink> for PerfLinkInner {
    fn from(link: PerfLink) -> Self {
        PerfLinkLeaf::from(link).into()
    }
}

pub(crate) fn perf_attach(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    cookie: Option<u64>,
) -> Result<PerfLinkLeaf, ProgramError> {
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
        Ok(FdLink::new(link_fd).into())
    } else {
        perf_attach_either(prog_fd, perf_fd, None)
    }
}

pub(crate) fn perf_attach_debugfs(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    event: ProbeEvent,
) -> Result<PerfLinkLeaf, ProgramError> {
    perf_attach_either(prog_fd, perf_fd, Some(event))
}

fn perf_attach_either(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    mut event: Option<ProbeEvent>,
) -> Result<PerfLinkLeaf, ProgramError> {
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

    Ok(PerfLink { perf_fd, event }.into())
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_collect_link_detach_errors_empty_ok() {
        collect_link_detach_errors(Vec::new()).unwrap();
    }

    #[test]
    fn test_collect_link_detach_errors_single_error() {
        let error = collect_link_detach_errors(vec![ProgramError::AlreadyLoaded]).unwrap_err();

        assert_matches!(
            error,
            ProgramError::UProbeError(UProbeError::CompositeLinkDetachFailed { error })
                if matches!(error.as_slice(), [ProgramError::AlreadyLoaded])
        );
    }

    #[test]
    fn test_collect_link_detach_errors_multiple_errors() {
        let error = collect_link_detach_errors(vec![
            ProgramError::AlreadyAttached,
            ProgramError::NotAttached,
        ])
        .unwrap_err();

        assert_matches!(
            error,
            ProgramError::UProbeError(UProbeError::CompositeLinkDetachFailed { error })
                if matches!(
                    error.as_slice(),
                    [ProgramError::AlreadyAttached, ProgramError::NotAttached]
                )
        );
    }
}
