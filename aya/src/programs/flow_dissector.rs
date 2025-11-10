//! Flow dissector programs.

use std::os::fd::AsFd;

use aya_obj::generated::{
    bpf_attach_type::BPF_FLOW_DISSECTOR, bpf_prog_type::BPF_PROG_TYPE_FLOW_DISSECTOR,
};

use crate::{
    programs::{
        CgroupAttachMode, FdLink, Link, ProgAttachLink, ProgramData, ProgramError, ProgramType,
        define_link_wrapper, id_as_key, impl_try_into_fdlink, load_program,
    },
    sys::{LinkTarget, SyscallError, bpf_link_create},
    util::KernelVersion,
};

/// Flow dissector is a program type that parses metadata out of the packets.
///
/// BPF flow dissectors can be attached per network namespace. These programs
/// are given a packet and expected to populate the fields of
/// `FlowDissectorContext::flow_keys`. The return code of the BPF program is
/// either [`BPF_OK`] to indicate successful dissection, [`BPF_DROP`] to
/// indicate parsing error, or [`BPF_FLOW_DISSECTOR_CONTINUE`] to indicate that
/// no custom dissection was performed, and fallback to standard dissector is
/// requested.
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
///
/// [`FlowDissectorContext::flow_keys`]: ../../../aya-ebpf/programs/flow_dissector/struct.FlowDissectorContext.html#method.flow_keys
/// [`BPF_OK`]: ../../../aya-ebpf/bindings/bpf_ret_code/constant.bpf_ok
/// [`BPF_DROP`]: ../../../aya-ebpf/bindings/bpf_ret_code/constant.bpf_drop
/// [`BPF_FLOW_DISSECTOR_CONTINUE`]: ../../../aya-ebpf/bindings/bpf_ret_code/constant.bpf_flow_dissector_continue
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_FLOW_DISSECTOR")]
pub struct FlowDissector {
    pub(crate) data: ProgramData<FlowDissectorLink>,
}

impl FlowDissector {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::FlowDissector;

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

        if KernelVersion::at_least(5, 7, 0) {
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
                .insert(FlowDissectorLink::new(FlowDissectorLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            let link = ProgAttachLink::attach(
                prog_fd,
                netns_fd,
                BPF_FLOW_DISSECTOR,
                CgroupAttachMode::default(),
            )?;

            self.data
                .links
                .insert(FlowDissectorLink::new(FlowDissectorLinkInner::ProgAttach(
                    link,
                )))
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum FlowDissectorLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum FlowDissectorLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for FlowDissectorLinkInner {
    type Id = FlowDissectorLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => FlowDissectorLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => FlowDissectorLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(fd) => fd.detach(),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(FlowDissectorLinkInner, FlowDissectorLinkIdInner);

define_link_wrapper!(
    FlowDissectorLink,
    FlowDissectorLinkId,
    FlowDissectorLinkInner,
    FlowDissectorLinkIdInner,
    FlowDissector,
);

impl_try_into_fdlink!(FlowDissectorLink, FlowDissectorLinkInner);
