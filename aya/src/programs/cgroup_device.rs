//! Cgroup device programs.

use std::os::fd::AsFd;

use aya_obj::generated::{
    bpf_attach_type::BPF_CGROUP_DEVICE, bpf_prog_type::BPF_PROG_TYPE_CGROUP_DEVICE,
};

use crate::{
    programs::{
        bpf_prog_get_fd_by_id, define_link_wrapper, id_as_key, load_program, query,
        CgroupAttachMode, FdLink, Link, ProgAttachLink, ProgramData, ProgramError, ProgramFd,
    },
    sys::{bpf_link_create, LinkTarget, ProgQueryTarget, SyscallError},
    util::KernelVersion,
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
/// The minimum kernel version required to use this feature is [4.15](https://github.com/torvalds/linux/commit/ebc614f687369f9df99828572b1d85a7c2de3d92).
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
    /// Loads the program inside the kernel
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_CGROUP_DEVICE, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [CgroupDevice::detach]
    pub fn attach<T: AsFd>(
        &mut self,
        cgroup: T,
        mode: CgroupAttachMode,
    ) -> Result<CgroupDeviceLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();

        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            let link_fd = bpf_link_create(
                prog_fd,
                LinkTarget::Fd(cgroup_fd),
                BPF_CGROUP_DEVICE,
                mode.into(),
                None,
            )
            .map_err(|io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
            self.data
                .links
                .insert(CgroupDeviceLink::new(CgroupDeviceLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            let link = ProgAttachLink::attach(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE, mode)?;

            self.data
                .links
                .insert(CgroupDeviceLink::new(CgroupDeviceLinkInner::ProgAttach(
                    link,
                )))
        }
    }

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

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupDeviceLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupDeviceLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupDeviceLinkInner {
    type Id = CgroupDeviceLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => CgroupDeviceLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => CgroupDeviceLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(fd) => fd.detach(),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(CgroupDeviceLinkInner, CgroupDeviceLinkIdInner);

define_link_wrapper!(
    /// The link used by [CgroupDevice] programs.
    CgroupDeviceLink,
    /// The type returned by [CgroupDevice::attach]. Can be passed to [CgroupDevice::detach].
    CgroupDeviceLinkId,
    CgroupDeviceLinkInner,
    CgroupDeviceLinkIdInner,
    CgroupDevice,
);
