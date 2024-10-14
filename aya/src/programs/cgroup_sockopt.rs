//! Cgroup socket option programs.

use std::{hash::Hash, os::fd::AsFd, path::Path};

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCKOPT;
pub use aya_obj::programs::CgroupSockoptAttachType;

use crate::{
    programs::{
        define_link_wrapper, id_as_key, load_program, CgroupAttachMode, FdLink, Link,
        ProgAttachLink, ProgramData, ProgramError,
    },
    sys::{bpf_link_create, LinkTarget, SyscallError},
    util::KernelVersion,
    VerifierLogLevel,
};

/// A program that can be used to get or set options on sockets.
///
/// [`CgroupSockopt`] programs can be attached to a cgroup and will be called every
/// time a process executes getsockopt or setsockopt system call.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.3.
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
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
/// use aya::programs::{CgroupAttachMode, CgroupSockopt};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let program: &mut CgroupSockopt = bpf.program_mut("cgroup_sockopt").unwrap().try_into()?;
/// program.load()?;
/// program.attach(file, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCKOPT")]
pub struct CgroupSockopt {
    pub(crate) data: ProgramData<CgroupSockoptLink>,
    pub(crate) attach_type: CgroupSockoptAttachType,
}

impl CgroupSockopt {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(self.attach_type.into());
        load_program(BPF_PROG_TYPE_CGROUP_SOCKOPT, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [CgroupSockopt::detach].
    pub fn attach<T: AsFd>(
        &mut self,
        cgroup: T,
        mode: CgroupAttachMode,
    ) -> Result<CgroupSockoptLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();
        let attach_type = self.data.expected_attach_type.unwrap();
        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            let link_fd = bpf_link_create(
                prog_fd,
                LinkTarget::Fd(cgroup_fd),
                attach_type,
                mode.into(),
                None,
            )
            .map_err(|(_, io_error)| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
            self.data
                .links
                .insert(CgroupSockoptLink::new(CgroupSockoptLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            let link = ProgAttachLink::attach(prog_fd, cgroup_fd, attach_type, mode)?;

            self.data
                .links
                .insert(CgroupSockoptLink::new(CgroupSockoptLinkInner::ProgAttach(
                    link,
                )))
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
        attach_type: CgroupSockoptAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupSockoptLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupSockoptLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSockoptLinkInner {
    type Id = CgroupSockoptLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => CgroupSockoptLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => CgroupSockoptLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(fd) => fd.detach(),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(CgroupSockoptLinkInner, CgroupSockoptLinkIdInner);

define_link_wrapper!(
    /// The link used by [CgroupSockopt] programs.
    CgroupSockoptLink,
    /// The type returned by [CgroupSockopt::attach]. Can be passed to [CgroupSockopt::detach].
    CgroupSockoptLinkId,
    CgroupSockoptLinkInner,
    CgroupSockoptLinkIdInner,
    CgroupSockopt,
);
