use std::os::unix::prelude::{AsRawFd, RawFd};

use crate::{
    generated::{
        bpf_attach_type::{BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS},
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB,
    },
    programs::{load_program, LinkRef, ProgAttachLink, ProgramData, ProgramError},
    sys::{bpf_link_create, bpf_prog_attach, kernel_version},
};

use super::FdLink;

/// A program used to inspect or filter network activity for a given cgroup.
///
/// [`CgroupSkb`] programs can be used to inspect or filter network activity
/// generated on all the sockets belonging to a given [cgroup]. They can be
/// attached to both _ingress_ and _egress_.
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::fs::File;
/// use std::convert::TryInto;
/// use aya::programs::{CgroupSkb, CgroupSkbAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let egress: &mut CgroupSkb = bpf.program_mut("egress_filter")?.try_into()?;
/// egress.load()?;
/// egress.attach(file, CgroupSkbAttachType::Egress)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SKB")]
pub struct CgroupSkb {
    pub(crate) data: ProgramData,
    pub(crate) expected_attach_type: Option<CgroupSkbAttachType>,
}

impl CgroupSkb {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_CGROUP_SKB, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    /// Returns the expected attach type of the program.
    ///
    /// [`CgroupSkb`] programs can specify the expected attach type in their ELF
    /// section name, eg `cgroup_skb/ingress` or `cgroup_skb/egress`. This
    /// method returns `None` for programs defined with the generic section
    /// `cgroup/skb`.
    pub fn expected_attach_type(&self) -> &Option<CgroupSkbAttachType> {
        &self.expected_attach_type
    }

    /// Attaches the program to the given cgroup.
    pub fn attach<T: AsRawFd>(
        &mut self,
        cgroup: T,
        attach_type: CgroupSkbAttachType,
    ) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let cgroup_fd = cgroup.as_raw_fd();

        let attach_type = match attach_type {
            CgroupSkbAttachType::Ingress => BPF_CGROUP_INET_INGRESS,
            CgroupSkbAttachType::Egress => BPF_CGROUP_INET_EGRESS,
        };
        let k_ver = kernel_version().unwrap();
        if k_ver >= (5, 7, 0) {
            let link_fd =
                bpf_link_create(prog_fd, cgroup_fd, attach_type, 0).map_err(|(_, io_error)| {
                    ProgramError::SyscallError {
                        call: "bpf_link_create".to_owned(),
                        io_error,
                    }
                })? as RawFd;
            Ok(self.data.link(FdLink { fd: Some(link_fd) }))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, attach_type).map_err(|(_, io_error)| {
                ProgramError::SyscallError {
                    call: "bpf_prog_attach".to_owned(),
                    io_error,
                }
            })?;

            Ok(self
                .data
                .link(ProgAttachLink::new(prog_fd, cgroup_fd, attach_type)))
        }
    }
}

/// Defines where to attach a [`CgroupSkb`] program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSkbAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
}
