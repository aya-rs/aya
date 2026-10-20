//! Cgroup socket address programs.

use std::{hash::Hash, os::fd::AsFd, path::Path};

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
pub use aya_obj::programs::CgroupSockAddrAttachType;

use crate::{
    VerifierLogLevel,
    programs::{
        CgroupAttachMode, FdLink, Link, LinkError, ProgAttachLink, ProgramData, ProgramError,
        ProgramType, define_link_wrapper, id_as_key, impl_program_adopt_link, impl_try_into_fdlink,
        links::{CgroupFdLink, cgroup_fd_link_supported},
        load_program_with_attach_type,
    },
    sys::{LinkTarget, SyscallError, bpf_link_create},
};

/// A program that can be used to inspect or modify socket addresses (`struct sockaddr`).
///
/// [`CgroupSockAddr`] programs can be used to inspect or modify socket addresses passed to
/// various syscalls within a [cgroup]. They can be attached to a number of different
/// places as described in [`CgroupSockAddrAttachType`].
///
/// [cgroup]: https://man7.org/linux/man-pages/man7/cgroups.7.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.17.
///
/// On kernels before 5.7, [`Self::attach`] creates legacy `BPF_PROG_ATTACH` links,
/// which [`Self::adopt_link`] rejects with [`crate::programs::LinkError::InvalidLink`].
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::{CgroupAttachMode, CgroupSockAddr, CgroupSockAddrAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let egress: &mut CgroupSockAddr = bpf.program_mut("connect4").unwrap().try_into()?;
/// egress.load()?;
/// egress.attach(file, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCK_ADDR")]
pub struct CgroupSockAddr {
    pub(crate) data: ProgramData<CgroupSockAddrLink>,
    pub(crate) attach_type: CgroupSockAddrAttachType,
}

impl CgroupSockAddr {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::CgroupSockAddr;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, attach_type } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, *attach_type, data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [`CgroupSockAddr::detach`].
    pub fn attach<T: AsFd>(
        &mut self,
        cgroup: T,
        mode: CgroupAttachMode,
    ) -> Result<CgroupSockAddrLinkId, ProgramError> {
        let Self { data, attach_type } = self;
        let prog_fd = data.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();
        if cgroup_fd_link_supported() {
            let link_fd = bpf_link_create(
                prog_fd,
                LinkTarget::Fd(cgroup_fd),
                *attach_type,
                mode.into(),
                None,
            )
            .map_err(|io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
            data.links
                .insert(CgroupSockAddrLink::new(CgroupSockAddrLinkInner::Fd(
                    CgroupFdLink::new(link_fd, (*attach_type).into()),
                )))
        } else {
            let link = ProgAttachLink::attach(prog_fd, cgroup_fd, *attach_type, mode)?;

            data.links.insert(CgroupSockAddrLink::new(
                CgroupSockAddrLinkInner::ProgAttach(link),
            ))
        }
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        attach_type: CgroupSockAddrAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupSockAddrLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupSockAddrLinkInner {
    Fd(CgroupFdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSockAddrLinkInner {
    type Id = CgroupSockAddrLinkIdInner;
    type Error = ProgramError;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => CgroupSockAddrLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => CgroupSockAddrLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), Self::Error> {
        match self {
            Self::Fd(fd) => fd.detach().map_err(Into::into),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(CgroupSockAddrLinkInner, CgroupSockAddrLinkIdInner);

define_link_wrapper!(
    CgroupSockAddrLink,
    CgroupSockAddrLinkId,
    CgroupSockAddrLinkInner,
    CgroupSockAddrLinkIdInner,
    CgroupSockAddr,
);

impl_program_adopt_link!(
    CgroupSockAddr,
    CgroupSockAddrLink,
    CgroupSockAddrLinkId,
    CgroupSockAddrLinkInner,
    |program: &CgroupSockAddr| Some(program.attach_type.into()),
);

impl_try_into_fdlink!(CgroupSockAddrLink, CgroupSockAddrLinkInner, link);

impl TryFrom<FdLink> for CgroupSockAddrLink {
    type Error = LinkError;

    fn try_from(link: FdLink) -> Result<Self, Self::Error> {
        Ok(Self::new(CgroupSockAddrLinkInner::Fd(link.try_into()?)))
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io, mem, os::fd::FromRawFd as _, path::Path};

    use assert_matches::assert_matches;
    use aya_obj::generated::{
        bpf_attach_type::{self, BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET4_CONNECT},
        bpf_cmd, bpf_prog_info,
    };
    use rstest::rstest;

    use super::{
        CgroupSockAddr, CgroupSockAddrAttachType, CgroupSockAddrLink, CgroupSockAddrLinkInner,
    };
    use crate::{
        MockableFd, VerifierLogLevel,
        programs::{
            Link as _, ProgramData, ProgramError,
            links::{CgroupFdLink, LinkError},
        },
        sys::{Syscall, override_syscall},
    };

    thread_local! {
        static UPDATED: Cell<bool> = const { Cell::new(false) };
        static INFO_QUERIED: Cell<bool> = const { Cell::new(false) };
    }

    // CI does not run Linux 5.7. Simulate its syscall behavior: link updates
    // succeed, but link info queries fail with EINVAL. Adoption must use the
    // cached attach type without querying link info, even for mismatched hooks.
    #[rstest]
    #[case::matching(BPF_CGROUP_INET4_CONNECT, true)]
    #[case::mismatched(BPF_CGROUP_INET4_BIND, false)]
    fn adopt_link_does_not_query_link_info(
        #[case] attach_type: bpf_attach_type,
        #[case] compatible: bool,
    ) {
        let fd = MockableFd::mock_signed_fd();
        // Adoption does not use kernel program metadata. Zero BTF IDs also keep
        // from_bpf_prog_info from issuing extra BTF lookups during test setup.
        // SAFETY: bpf_prog_info contains only integers and byte arrays,
        // including its bitfield storage, so all-zero bytes are valid.
        let program_info: bpf_prog_info = unsafe { mem::zeroed() };
        let mut program = CgroupSockAddr {
            data: ProgramData::from_bpf_prog_info(
                None,
                // SAFETY: This synthetic FD is only used by mocked syscalls.
                // MockableFd's test Drop skips closing FDs at or above mock_signed_fd().
                unsafe { MockableFd::from_raw_fd(fd) },
                Path::new(""),
                program_info,
                VerifierLogLevel::default(),
            )
            .unwrap(),
            attach_type: CgroupSockAddrAttachType::Connect4,
        };
        let link = CgroupSockAddrLink::new(CgroupSockAddrLinkInner::Fd(CgroupFdLink::new(
            // SAFETY: This synthetic FD is only used by mocked syscalls.
            // MockableFd's test Drop skips closing FDs at or above mock_signed_fd().
            unsafe { MockableFd::from_raw_fd(fd + 1) },
            attach_type,
        )));
        let link_id = link.id();
        UPDATED.set(false);
        INFO_QUERIED.set(false);
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_LINK_UPDATE,
                attr,
            } => {
                // SAFETY: bpf_link_update initialized the link_update union member
                // before invoking this BPF_LINK_UPDATE syscall mock.
                let attr = unsafe { attr.link_update };
                assert_eq!(attr.link_fd, MockableFd::mock_unsigned_fd() + 1);
                assert_eq!(
                    // SAFETY: bpf_link_update initialized the new_prog_fd union member.
                    unsafe { attr.__bindgen_anon_1.new_prog_fd },
                    MockableFd::mock_unsigned_fd()
                );
                assert_eq!(attr.flags, 0);
                UPDATED.set(true);
                Ok(0)
            }
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_OBJ_GET_INFO_BY_FD,
                ..
            } => {
                INFO_QUERIED.set(true);
                Err((-1, io::Error::from_raw_os_error(libc::EINVAL)))
            }
            call => panic!("unexpected syscall: {call:?}"),
        });

        let result = program.adopt_link(link);
        assert!(!INFO_QUERIED.get());
        assert_eq!(UPDATED.get(), compatible);
        if compatible {
            let adopted_link_id = result.unwrap();
            assert_eq!(adopted_link_id, link_id);
            assert_eq!(program.take_link(adopted_link_id).unwrap().id(), link_id);
        } else {
            let (error, link) = result.unwrap_err();
            assert_matches!(error, ProgramError::LinkError(LinkError::InvalidLink));
            assert_eq!(link.id(), link_id);
        }
    }
}
