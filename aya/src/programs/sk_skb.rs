//! Skskb programs.

use std::{os::fd::AsFd as _, path::Path};

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_SK_SKB;
pub use aya_obj::programs::SkSkbKind;

use crate::{
    VerifierLogLevel,
    maps::sock::SockMapFd,
    programs::{
        CgroupAttachMode, FdLink, Link, ProgAttachLink, ProgramData, ProgramError, ProgramType,
        define_link_wrapper, id_as_key, impl_try_into_fdlink, load_program_without_attach_type,
    },
    sys::{LinkTarget, SyscallError, bpf_link_create},
    util::KernelVersion,
};

/// A program used to intercept ingress socket buffers.
///
/// [`SkSkb`] programs are attached to [socket maps], and can be used to
/// inspect, redirect or filter incoming packet. See also [`SockMap`] and
/// [`SockHash`].
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
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
/// use aya::maps::SockMap;
/// use aya::programs::SkSkb;
///
/// let intercept_ingress: SockMap<_> = bpf.map("INTERCEPT_INGRESS").unwrap().try_into()?;
/// let map_fd = intercept_ingress.fd().try_clone()?;
///
/// let prog: &mut SkSkb = bpf.program_mut("intercept_ingress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&map_fd)?;
///
/// # Ok::<(), Error>(())
/// ```
///
/// [socket maps]: crate::maps::sock
/// [`SockMap`]: crate::maps::SockMap
/// [`SockHash`]: crate::maps::SockHash
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SK_SKB")]
pub struct SkSkb {
    pub(crate) data: ProgramData<SkSkbLink>,
    pub(crate) kind: SkSkbKind,
}

impl SkSkb {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SkSkb;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, kind: _ } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_SK_SKB, data)
    }

    /// Attaches the program to the given socket map.
    ///
    /// The returned value can be used to detach, see [`SkSkb::detach`].
    pub fn attach(&mut self, map: &SockMapFd) -> Result<SkSkbLinkId, ProgramError> {
        let Self { data, kind } = self;
        let prog_fd = data.fd()?;
        let prog_fd = prog_fd.as_fd();
        let attach_type = *kind;
        if KernelVersion::at_least(5, 7, 0) {
            let link_fd = bpf_link_create(
                prog_fd,
                LinkTarget::Fd(map.as_fd()),
                attach_type,
                CgroupAttachMode::Single.into(),
                None,
            )
            .map_err(|io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
            data.links
                .insert(SkSkbLink::new(SkSkbLinkInner::Fd(FdLink::new(link_fd))))
        } else {
            let link = ProgAttachLink::attach(
                prog_fd,
                map.as_fd(),
                attach_type,
                CgroupAttachMode::Single,
            )?;
            data.links
                .insert(SkSkbLink::new(SkSkbLinkInner::ProgAttach(link)))
        }
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P, kind: SkSkbKind) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, kind })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum SkSkbLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum SkSkbLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for SkSkbLinkInner {
    type Id = SkSkbLinkIdInner;
    type Error = ProgramError;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => SkSkbLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => SkSkbLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), Self::Error> {
        match self {
            Self::Fd(fd) => fd.detach().map_err(Into::into),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(SkSkbLinkInner, SkSkbLinkIdInner);

define_link_wrapper!(
    SkSkbLink,
    SkSkbLinkId,
    SkSkbLinkInner,
    SkSkbLinkIdInner,
    SkSkb,
);

impl_try_into_fdlink!(SkSkbLink, SkSkbLinkInner);
