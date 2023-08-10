//! Socket option programs.
use std::os::fd::AsRawFd;

use crate::{
    generated::{bpf_attach_type::BPF_CGROUP_SOCK_OPS, bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS},
    programs::{
        define_link_wrapper, load_program, ProgAttachLink, ProgAttachLinkId, ProgramData,
        ProgramError,
    },
    sys::{bpf_prog_attach, SyscallError},
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::SockOps;
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let prog: &mut SockOps = bpf.program_mut("intercept_active_sockets").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(file)?;
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
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<SockOpsLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let prog_fd = prog_fd.as_raw_fd();
        let cgroup_fd = cgroup.as_raw_fd();

        bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS).map_err(|(_, io_error)| {
            SyscallError {
                call: "bpf_prog_attach",
                io_error,
            }
        })?;
        self.data.links.insert(SockOpsLink::new(ProgAttachLink::new(
            prog_fd,
            cgroup_fd,
            BPF_CGROUP_SOCK_OPS,
        )))
    }

    /// Detaches the program.
    ///
    /// See [SockOps::attach].
    pub fn detach(&mut self, link_id: SockOpsLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: SockOpsLinkId) -> Result<SockOpsLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

define_link_wrapper!(
    /// The link used by [SockOps] programs.
    SockOpsLink,
    /// The type returned by [SockOps::attach]. Can be passed to [SockOps::detach].
    SockOpsLinkId,
    ProgAttachLink,
    ProgAttachLinkId
);
