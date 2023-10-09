//! Flow dissector programs.

use std::os::fd::AsFd;

use crate::{
    generated::{bpf_attach_type::BPF_FLOW_DISSECTOR, bpf_prog_type::BPF_PROG_TYPE_FLOW_DISSECTOR},
    programs::{define_link_wrapper, load_program, FdLink, FdLinkId, ProgramData, ProgramError},
    sys::{bpf_link_create, LinkTarget, SyscallError},
};

/// A program that can be attached as a Flow Dissector routine
///
/// ['FlowDissector'] programs operate on an __sk_buff.
/// However, only the limited set of fields is allowed: data, data_end and flow_keys.
/// flow_keys is struct bpf_flow_keys and contains flow dissector input and output arguments.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.2.
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
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::FlowDissector};
/// use std::fs::File;
///
/// let program: &mut FlowDissector = bpf.program_mut("filename_lookup").unwrap().try_into()?;
/// program.load()?;
///
/// let net_ns = File::open("/proc/self/ns/net")?;
/// program.attach(net_ns)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_FLOW_DISSECTOR")]
pub struct FlowDissector {
    pub(crate) data: ProgramData<FlowDissectorLink>,
}

impl FlowDissector {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_FLOW_DISSECTOR);
        load_program(BPF_PROG_TYPE_FLOW_DISSECTOR, &mut self.data)
    }

    /// Attaches the program to the given network namespace.
    ///
    /// The returned value can be used to detach, see [FlowDissector::detach].
    pub fn attach<T: AsFd>(&mut self, netns: T) -> Result<FlowDissectorLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let netns_fd = netns.as_fd();

        let link_fd = bpf_link_create(
            prog_fd,
            LinkTarget::Fd(netns_fd),
            BPF_FLOW_DISSECTOR,
            None,
            0,
        )
        .map_err(|(_, io_error)| SyscallError {
            call: "bpf_link_create",
            io_error,
        })?;
        self.data
            .links
            .insert(FlowDissectorLink::new(FdLink::new(link_fd)))
    }

    /// Detaches the program.
    ///
    /// See [FlowDissector::attach].
    pub fn detach(&mut self, link_id: FlowDissectorLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(
        &mut self,
        link_id: FlowDissectorLinkId,
    ) -> Result<FlowDissectorLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

define_link_wrapper!(
    /// The link used by [FlowDissector] programs.
    FlowDissectorLink,
    /// The type returned by [FlowDissector::attach]. Can be passed to [FlowDissector::detach].
    FlowDissectorLinkId,
    FdLink,
    FdLinkId
);
