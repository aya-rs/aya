//! Flow dissector programs.

use std::os::fd::AsFd;

use aya_obj::generated::{
    bpf_attach_type::BPF_FLOW_DISSECTOR, bpf_prog_type::BPF_PROG_TYPE_FLOW_DISSECTOR,
};

use crate::{
    programs::{FdLink, FdLinkId, ProgramData, ProgramError, define_link_wrapper, load_program},
    sys::{LinkTarget, SyscallError, bpf_link_create},
};

/// A program that can be attached as a Flow Dissector routine
///
/// ['FlowDissector'] programs operate on an __sk_buff.
/// However, only the limited set of fields is allowed: data, data_end and flow_keys.
/// flow_keys is struct bpf_flow_keys and contains flow dissector input and output arguments.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.20.
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
/// use aya::programs::FlowDissector;
///
/// let program: &mut FlowDissector = bpf.program_mut("filename_lookup").unwrap().try_into()?;
/// program.load()?;
///
/// let net_ns = std::fs::File::open("/proc/self/ns/net")?;
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
            0,
            None,
        )
        .map_err(|io_error| SyscallError {
            call: "bpf_link_create",
            io_error,
        })?;
        self.data
            .links
            .insert(FlowDissectorLink::new(FdLink::new(link_fd)))
    }
}

define_link_wrapper!(
    /// The link used by [FlowDissector] programs.
    FlowDissectorLink,
    /// The type returned by [FlowDissector::attach]. Can be passed to [FlowDissector::detach].
    FlowDissectorLinkId,
    FdLink,
    FdLinkId,
    FlowDissector,
);
