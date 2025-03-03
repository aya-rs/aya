//! Socket option programs.
use std::os::fd::AsFd;

use aya_obj::generated::{
    bpf_attach_type::BPF_CGROUP_SOCK_OPS, bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS,
};

use crate::{
    programs::{
        CgroupAttachMode, FdLink, Link, ProgAttachLink, ProgramData, ProgramError,
        define_link_wrapper, id_as_key, load_program,
    },
    sys::{LinkTarget, SyscallError, bpf_link_create},
    util::KernelVersion,
};

/// A program used to work with sockets.
///
/// [`SockOps`] programs can access or set socket options, connection
/// parameters, watch connection state changes and more. They are attached to
/// cgroups.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.13.
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
/// use aya::programs::{CgroupAttachMode, SockOps};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let prog: &mut SockOps = bpf.program_mut("intercept_active_sockets").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(file, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SOCK_OPS")]
pub struct SockOps {
    pub(crate) data: ProgramData<SockOpsLink>,
}

impl SockOps {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCK_OPS, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [SockOps::detach].
    pub fn attach<T: AsFd>(
        &mut self,
        cgroup: T,
        mode: CgroupAttachMode,
    ) -> Result<SockOpsLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();
        let attach_type = BPF_CGROUP_SOCK_OPS;
        if KernelVersion::at_least(5, 7, 0) {
            let link_fd = bpf_link_create(
                prog_fd,
                LinkTarget::Fd(cgroup_fd),
                attach_type,
                mode.into(),
                None,
            )
            .map_err(|io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
            self.data
                .links
                .insert(SockOpsLink::new(SockOpsLinkInner::Fd(FdLink::new(link_fd))))
        } else {
            let link = ProgAttachLink::attach(prog_fd, cgroup_fd, attach_type, mode)?;

            self.data
                .links
                .insert(SockOpsLink::new(SockOpsLinkInner::ProgAttach(link)))
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum SockOpsLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum SockOpsLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for SockOpsLinkInner {
    type Id = SockOpsLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => SockOpsLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => SockOpsLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(fd) => fd.detach(),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(SockOpsLinkInner, SockOpsLinkIdInner);

define_link_wrapper!(
    /// The link used by [SockOps] programs.
    SockOpsLink,
    /// The type returned by [SockOps::attach]. Can be passed to [SockOps::detach].
    SockOpsLinkId,
    SockOpsLinkInner,
    SockOpsLinkIdInner,
    SockOps,
);
