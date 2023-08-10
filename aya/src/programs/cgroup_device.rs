//! Cgroup device programs.

use crate::util::KernelVersion;
use std::os::fd::AsRawFd;

use crate::{
    generated::{bpf_attach_type::BPF_CGROUP_DEVICE, bpf_prog_type::BPF_PROG_TYPE_CGROUP_DEVICE},
    programs::{
        define_link_wrapper, load_program, FdLink, Link, ProgAttachLink, ProgramData, ProgramError,
    },
    sys::{bpf_link_create, bpf_prog_attach, SyscallError},
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::programs::CgroupDevice;
///
/// let cgroup = std::fs::File::open("/sys/fs/cgroup/unified")?;
/// let program: &mut CgroupDevice = bpf.program_mut("cgroup_dev").unwrap().try_into()?;
/// program.load()?;
/// program.attach(cgroup)?;
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
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<CgroupDeviceLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let prog_fd = prog_fd.as_raw_fd();
        let cgroup_fd = cgroup.as_raw_fd();

        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            let link_fd = bpf_link_create(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE, None, 0).map_err(
                |(_, io_error)| SyscallError {
                    call: "bpf_link_create",
                    io_error,
                },
            )?;
            self.data
                .links
                .insert(CgroupDeviceLink::new(CgroupDeviceLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE).map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_prog_attach",
                    io_error,
                }
            })?;
            self.data
                .links
                .insert(CgroupDeviceLink::new(CgroupDeviceLinkInner::ProgAttach(
                    ProgAttachLink::new(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE),
                )))
        }
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(
        &mut self,
        link_id: CgroupDeviceLinkId,
    ) -> Result<CgroupDeviceLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Detaches the program
    ///
    /// See [CgroupDevice::attach].
    pub fn detach(&mut self, link_id: CgroupDeviceLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
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
            CgroupDeviceLinkInner::Fd(fd) => CgroupDeviceLinkIdInner::Fd(fd.id()),
            CgroupDeviceLinkInner::ProgAttach(p) => CgroupDeviceLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            CgroupDeviceLinkInner::Fd(fd) => fd.detach(),
            CgroupDeviceLinkInner::ProgAttach(p) => p.detach(),
        }
    }
}

define_link_wrapper!(
    /// The link used by [CgroupDevice] programs.
    CgroupDeviceLink,
    /// The type returned by [CgroupDevice::attach]. Can be passed to [CgroupDevice::detach].
    CgroupDeviceLinkId,
    CgroupDeviceLinkInner,
    CgroupDeviceLinkIdInner
);
