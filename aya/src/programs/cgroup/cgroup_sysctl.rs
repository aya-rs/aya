//! Cgroup sysctl programs.

use aya_obj::generated::{
    bpf_attach_type::BPF_CGROUP_SYSCTL, bpf_prog_type::BPF_PROG_TYPE_CGROUP_SYSCTL,
};

use crate::programs::{
    ProgramData, ProgramError, ProgramType,
    cgroup::{define_cgroup_link, impl_cgroup_attach},
    load_program_with_attach_type,
};

/// A program used to watch for sysctl changes.
///
/// [`CgroupSysctl`] programs can be attached to a cgroup and will be called every
/// time a process inside that cgroup tries to read from or write to a sysctl knob in proc.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.2.
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
/// use aya::programs::{CgroupAttachMode, CgroupSysctl};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let program: &mut CgroupSysctl = bpf.program_mut("cgroup_sysctl").unwrap().try_into()?;
/// program.load()?;
/// program.attach(file, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SYSCTL")]
pub struct CgroupSysctl {
    pub(crate) data: ProgramData<CgroupSysctlLink>,
}

impl CgroupSysctl {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::CgroupSysctl;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_CGROUP_SYSCTL, BPF_CGROUP_SYSCTL, data)
    }

    impl_cgroup_attach!(CgroupSysctlLinkId, CgroupSysctlLinkInner, BPF_CGROUP_SYSCTL);
}

define_cgroup_link!(
    CgroupSysctlLink,
    CgroupSysctlLinkId,
    CgroupSysctlLinkInner,
    CgroupSysctlLinkIdInner,
    CgroupSysctl,
);
