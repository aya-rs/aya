//! Cgroup socket option programs.

use std::path::Path;

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCKOPT;
pub use aya_obj::programs::CgroupSockoptAttachType;

use crate::{
    VerifierLogLevel,
    programs::{
        ProgramData, ProgramError, ProgramType,
        cgroup::{define_cgroup_link, impl_cgroup_attach},
        load_program_with_attach_type,
    },
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
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::CgroupSockopt;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, attach_type } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_CGROUP_SOCKOPT, *attach_type, data)
    }

    impl_cgroup_attach!(
        CgroupSockoptLinkId,
        CgroupSockoptLinkInner,
        self.attach_type
    );

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

define_cgroup_link!(
    CgroupSockoptLink,
    CgroupSockoptLinkId,
    CgroupSockoptLinkInner,
    CgroupSockoptLinkIdInner,
    CgroupSockopt,
);
