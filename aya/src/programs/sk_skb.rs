//! Skskb programs.

use std::{
    os::fd::{AsFd as _, OwnedFd},
    path::Path,
    sync::Arc,
};

use aya_obj::Features;

use crate::{
    generated::{
        bpf_attach_type::{BPF_SK_SKB_STREAM_PARSER, BPF_SK_SKB_STREAM_VERDICT},
        bpf_prog_type::BPF_PROG_TYPE_SK_SKB,
    },
    maps::sock::SockMapFd,
    programs::{
        define_link_wrapper, load_program, ProgAttachLink, ProgAttachLinkId, ProgramData,
        ProgramError,
    },
    VerifierLogLevel,
};

/// The kind of [`SkSkb`] program.
#[derive(Copy, Clone, Debug)]
pub enum SkSkbKind {
    /// A Stream Parser
    StreamParser,
    /// A Stream Verdict
    StreamVerdict,
}

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
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SK_SKB, &mut self.data)
    }

    /// Attaches the program to the given socket map.
    ///
    /// The returned value can be used to detach, see [SkSkb::detach].
    pub fn attach(&mut self, map: &SockMapFd) -> Result<SkSkbLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();

        let attach_type = match self.kind {
            SkSkbKind::StreamParser => BPF_SK_SKB_STREAM_PARSER,
            SkSkbKind::StreamVerdict => BPF_SK_SKB_STREAM_VERDICT,
        };

        let link = ProgAttachLink::attach(prog_fd, map.as_fd(), attach_type)?;

        self.data.links.insert(SkSkbLink::new(link))
    }

    /// Detaches the program.
    ///
    /// See [SkSkb::attach].
    pub fn detach(&mut self, link_id: SkSkbLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: SkSkbLinkId) -> Result<SkSkbLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        kind: SkSkbKind,
        token_fd: Option<Arc<OwnedFd>>,
        features: Features,
    ) -> Result<Self, ProgramError> {
        let data =
            ProgramData::from_pinned_path(path, VerifierLogLevel::default(), token_fd, features)?;
        Ok(Self { data, kind })
    }
}

define_link_wrapper!(
    /// The link used by [SkSkb] programs.
    SkSkbLink,
    /// The type returned by [SkSkb::attach]. Can be passed to [SkSkb::detach].
    SkSkbLinkId,
    ProgAttachLink,
    ProgAttachLinkId
);
