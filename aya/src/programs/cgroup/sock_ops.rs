//! Socket option programs.

use aya_obj::generated::{
    bpf_attach_type::BPF_CGROUP_SOCK_OPS, bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS,
};

use crate::programs::{
    ProgramData, ProgramError, ProgramType,
    cgroup::{define_cgroup_link, impl_cgroup_attach},
    impl_try_into_fdlink, load_program_with_attach_type,
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
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SockOps;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_SOCK_OPS, BPF_CGROUP_SOCK_OPS, data)
    }

    impl_cgroup_attach!(SockOpsLinkId, SockOpsLinkInner, BPF_CGROUP_SOCK_OPS);
}

define_cgroup_link!(
    SockOpsLink,
    SockOpsLinkId,
    SockOpsLinkInner,
    SockOpsLinkIdInner,
    SockOps,
);

impl_try_into_fdlink!(SockOpsLink, SockOpsLinkInner);
