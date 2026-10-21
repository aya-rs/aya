//! Cgroup device programs.

use std::os::fd::AsFd;

use aya_obj::generated::{
    bpf_attach_type::BPF_CGROUP_DEVICE, bpf_prog_type::BPF_PROG_TYPE_CGROUP_DEVICE,
};

use crate::{
    programs::{
        ProgAttachLink, ProgramData, ProgramError, ProgramFd, ProgramType, bpf_prog_get_fd_by_id,
        cgroup::{define_cgroup_link, impl_cgroup_attach},
        load_program_with_attach_type, query,
    },
    sys::ProgQueryTarget,
};

/// A program used to watch or prevent device interaction from a cgroup.
///
/// [`CgroupDevice`] programs can be attached to a cgroup and will be called every
/// time a process inside that cgroup tries to access (e.g. read, write, mknod)
/// a device (identified through its major and minor number). See
/// [mknod](https://man7.org/linux/man-pages/man2/mknod.2.html) as a starting point.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is [4.15](https://github.com/torvalds/linux/commit/ebc614f68).
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
/// use aya::programs::{CgroupAttachMode, CgroupDevice};
///
/// let cgroup = std::fs::File::open("/sys/fs/cgroup/unified")?;
/// let program: &mut CgroupDevice = bpf.program_mut("cgroup_dev").unwrap().try_into()?;
/// program.load()?;
/// program.attach(cgroup, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_DEVICE")]
pub struct CgroupDevice {
    pub(crate) data: ProgramData<CgroupDeviceLink>,
}

impl CgroupDevice {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::CgroupDevice;

    /// Loads the program inside the kernel
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_CGROUP_DEVICE, BPF_CGROUP_DEVICE, data)
    }

    impl_cgroup_attach!(CgroupDeviceLinkId, CgroupDeviceLinkInner, BPF_CGROUP_DEVICE);

    /// Queries the cgroup for attached programs.
    pub fn query<T: AsFd>(target_fd: T) -> Result<Vec<CgroupDeviceLink>, ProgramError> {
        let target_fd = target_fd.as_fd();
        let (_, prog_ids) = query(
            ProgQueryTarget::Fd(target_fd),
            BPF_CGROUP_DEVICE,
            0,
            &mut None,
        )?;

        prog_ids
            .into_iter()
            .map(|prog_id| {
                let prog_fd = bpf_prog_get_fd_by_id(prog_id)?;
                let target_fd = target_fd.try_clone_to_owned()?;
                let target_fd = crate::MockableFd::from_fd(target_fd);
                let prog_fd = ProgramFd(prog_fd);
                Ok(CgroupDeviceLink::new(CgroupDeviceLinkInner::ProgAttach(
                    ProgAttachLink::new(prog_fd, target_fd, BPF_CGROUP_DEVICE),
                )))
            })
            .collect()
    }
}

define_cgroup_link!(
    CgroupDeviceLink,
    CgroupDeviceLinkId,
    CgroupDeviceLinkInner,
    CgroupDeviceLinkIdInner,
    CgroupDevice,
);
