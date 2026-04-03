//! Skskb programs.

use std::{os::fd::AsFd as _, path::Path};

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_SK_SKB;
pub use aya_obj::programs::SkSkbKind;

use crate::{
    VerifierLogLevel,
    maps::sock::SockMapFd,
    programs::{
        CgroupAttachMode, ProgAttachLink, ProgAttachLinkId, ProgramData, ProgramError, ProgramType,
        define_link_wrapper, load_program_without_attach_type,
    },
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
        let link = ProgAttachLink::attach(prog_fd, map.as_fd(), *kind, CgroupAttachMode::Single)?;

        data.links.insert(SkSkbLink::new(link))
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

define_link_wrapper!(
    SkSkbLink,
    SkSkbLinkId,
    ProgAttachLink,
    ProgAttachLinkId,
    SkSkb,
);
