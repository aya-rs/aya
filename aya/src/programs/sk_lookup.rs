//! Programmable socket lookup.
use std::os::fd::AsFd;

use aya_obj::generated::{bpf_attach_type::BPF_SK_LOOKUP, bpf_prog_type::BPF_PROG_TYPE_SK_LOOKUP};

use super::links::FdLink;
use crate::{
    programs::{define_link_wrapper, load_program, FdLinkId, ProgramData, ProgramError},
    sys::{bpf_link_create, LinkTarget, SyscallError},
};

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
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
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
    pub fn attach<T: AsFd>(&mut self, netns: T) -> Result<SkLookupLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let netns_fd = netns.as_fd();

        let link_fd = bpf_link_create(prog_fd, LinkTarget::Fd(netns_fd), BPF_SK_LOOKUP, 0, None)
            .map_err(|io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
        self.data
            .links
            .insert(SkLookupLink::new(FdLink::new(link_fd)))
    }
}

define_link_wrapper!(
    /// The link used by [SkLookup] programs.
    SkLookupLink,
    /// The type returned by [SkLookup::attach]. Can be passed to [SkLookup::detach].
    SkLookupLinkId,
    FdLink,
    FdLinkId,
    SkLookup,
);
