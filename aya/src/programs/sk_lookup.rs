use std::os::fd::AsRawFd;

use crate::{
    generated::{bpf_attach_type::BPF_SK_LOOKUP, bpf_prog_type::BPF_PROG_TYPE_SK_LOOKUP},
    programs::{define_link_wrapper, load_program, FdLinkId, ProgramData, ProgramError},
    sys::{bpf_link_create, SyscallError},
};

use super::links::FdLink;

/// A program used to redirect incoming packets to a local socket.
///
/// [`SkLookup`] programs are attached to network namespaces to provide programmable
/// socket lookup for TCP/UDP when a packet is to be delievered locally.
///
/// You may attach multiple programs to the same namespace and they are executed
/// in the order they were attached.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.9.
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::SkLookup;
///
/// let file = File::open("/var/run/netns/test")?;
/// let program: &mut SkLookup = bpf.program_mut("sk_lookup").unwrap().try_into()?;
/// program.load()?;
/// program.attach(file)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SK_LOOKUP")]
pub struct SkLookup {
    pub(crate) data: ProgramData<SkLookupLink>,
}

impl SkLookup {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_SK_LOOKUP);
        load_program(BPF_PROG_TYPE_SK_LOOKUP, &mut self.data)
    }

    /// Attaches the program to the given network namespace.
    ///
    /// The returned value can be used to detach, see [SkLookup::detach].
    pub fn attach<T: AsRawFd>(&mut self, netns: T) -> Result<SkLookupLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let prog_fd = prog_fd.as_raw_fd();
        let netns_fd = netns.as_raw_fd();

        let link_fd = bpf_link_create(prog_fd, netns_fd, BPF_SK_LOOKUP, None, 0).map_err(
            |(_, io_error)| SyscallError {
                call: "bpf_link_create",
                io_error,
            },
        )?;
        self.data
            .links
            .insert(SkLookupLink::new(FdLink::new(link_fd)))
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: SkLookupLinkId) -> Result<SkLookupLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Detaches the program.
    ///
    /// See [SkLookup::attach].
    pub fn detach(&mut self, link_id: SkLookupLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

define_link_wrapper!(
    /// The link used by [SkLookup] programs.
    SkLookupLink,
    /// The type returned by [SkLookup::attach]. Can be passed to [SkLookup::detach].
    SkLookupLinkId,
    FdLink,
    FdLinkId
);
