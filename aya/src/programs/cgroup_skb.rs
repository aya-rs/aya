//! Cgroup skb programs.

use crate::util::KernelVersion;
use std::{hash::Hash, os::fd::AsRawFd, path::Path};

use crate::{
    generated::{
        bpf_attach_type::{BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS},
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB,
    },
    programs::{
        define_link_wrapper, load_program, FdLink, Link, ProgAttachLink, ProgramData, ProgramError,
    },
    sys::{bpf_link_create, bpf_prog_attach, SyscallError},
    VerifierLogLevel,
};

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
/// use aya::programs::{CgroupSkb, CgroupSkbAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let egress: &mut CgroupSkb = bpf.program_mut("egress_filter").unwrap().try_into()?;
/// egress.load()?;
/// egress.attach(file, CgroupSkbAttachType::Egress)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SKB")]
pub struct CgroupSkb {
    pub(crate) data: ProgramData<CgroupSkbLink>,
    pub(crate) expected_attach_type: Option<CgroupSkbAttachType>,
}

impl CgroupSkb {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type =
            self.expected_attach_type
                .map(|attach_type| match attach_type {
                    CgroupSkbAttachType::Ingress => BPF_CGROUP_INET_INGRESS,
                    CgroupSkbAttachType::Egress => BPF_CGROUP_INET_EGRESS,
                });
        load_program(BPF_PROG_TYPE_CGROUP_SKB, &mut self.data)
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
    ///
    /// The returned value can be used to detach, see [CgroupSkb::detach].
    pub fn attach<T: AsRawFd>(
        &mut self,
        cgroup: T,
        attach_type: CgroupSkbAttachType,
    ) -> Result<CgroupSkbLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let prog_fd = prog_fd.as_raw_fd();
        let cgroup_fd = cgroup.as_raw_fd();

        let attach_type = match attach_type {
            CgroupSkbAttachType::Ingress => BPF_CGROUP_INET_INGRESS,
            CgroupSkbAttachType::Egress => BPF_CGROUP_INET_EGRESS,
        };
        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            let link_fd = bpf_link_create(prog_fd, cgroup_fd, attach_type, None, 0).map_err(
                |(_, io_error)| SyscallError {
                    call: "bpf_link_create",
                    io_error,
                },
            )?;
            self.data
                .links
                .insert(CgroupSkbLink::new(CgroupSkbLinkInner::Fd(FdLink::new(
                    link_fd,
                ))))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, attach_type).map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_prog_attach",
                    io_error,
                }
            })?;

            self.data
                .links
                .insert(CgroupSkbLink::new(CgroupSkbLinkInner::ProgAttach(
                    ProgAttachLink::new(prog_fd, cgroup_fd, attach_type),
                )))
        }
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: CgroupSkbLinkId) -> Result<CgroupSkbLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Detaches the program.
    ///
    /// See [CgroupSkb::attach].
    pub fn detach(&mut self, link_id: CgroupSkbLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        expected_attach_type: CgroupSkbAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self {
            data,
            expected_attach_type: Some(expected_attach_type),
        })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupSkbLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupSkbLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSkbLinkInner {
    type Id = CgroupSkbLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            CgroupSkbLinkInner::Fd(fd) => CgroupSkbLinkIdInner::Fd(fd.id()),
            CgroupSkbLinkInner::ProgAttach(p) => CgroupSkbLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            CgroupSkbLinkInner::Fd(fd) => fd.detach(),
            CgroupSkbLinkInner::ProgAttach(p) => p.detach(),
        }
    }
}

define_link_wrapper!(
    /// The link used by [CgroupSkb] programs.
    CgroupSkbLink,
    /// The type returned by [CgroupSkb::attach]. Can be passed to [CgroupSkb::detach].
    CgroupSkbLinkId,
    CgroupSkbLinkInner,
    CgroupSkbLinkIdInner
);

/// Defines where to attach a [`CgroupSkb`] program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSkbAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
}
