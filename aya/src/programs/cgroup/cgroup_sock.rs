//! Cgroup socket programs.

use std::path::Path;

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK;
pub use aya_obj::programs::CgroupSockAttachType;

use crate::{
    VerifierLogLevel,
    programs::{
        ProgramData, ProgramError, ProgramType,
        cgroup::{define_cgroup_link, impl_cgroup_attach},
        impl_try_into_fdlink, load_program_with_attach_type,
    },
};

/// A program that is called on socket creation, bind and release.
///
/// [`CgroupSock`] programs can be used to allow or deny socket creation from
/// within a [cgroup], or they can be used to monitor and gather statistics.
///
/// [cgroup]: https://man7.org/linux/man-pages/man7/cgroups.7.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.10.
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
/// use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let bind: &mut CgroupSock = bpf.program_mut("bind").unwrap().try_into()?;
/// bind.load()?;
/// bind.attach(file, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCK")]
pub struct CgroupSock {
    pub(crate) data: ProgramData<CgroupSockLink>,
    pub(crate) attach_type: CgroupSockAttachType,
}

impl CgroupSock {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::CgroupSock;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, attach_type } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_CGROUP_SOCK, *attach_type, data)
    }

    impl_cgroup_attach!(CgroupSockLinkId, CgroupSockLinkInner, self.attach_type);

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        attach_type: CgroupSockAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}

define_cgroup_link!(
    CgroupSockLink,
    CgroupSockLinkId,
    CgroupSockLinkInner,
    CgroupSockLinkIdInner,
    CgroupSock,
);

impl_try_into_fdlink!(CgroupSockLink, CgroupSockLinkInner);
