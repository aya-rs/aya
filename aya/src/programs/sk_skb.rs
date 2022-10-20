//! Skskb programs.

use std::os::unix::io::AsRawFd;

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
    sys::bpf_prog_attach,
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
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::SockMap;
/// use aya::programs::SkSkb;
///
/// let intercept_ingress: SockMap<_> = bpf.map("INTERCEPT_INGRESS").unwrap().try_into()?;
/// let map_fd = intercept_ingress.fd()?;
///
/// let prog: &mut SkSkb = bpf.program_mut("intercept_ingress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(map_fd)?;
///
/// # Ok::<(), aya::BpfError>(())
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
    pub fn attach(&mut self, map: SockMapFd) -> Result<SkSkbLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let map_fd = map.as_raw_fd();

        let attach_type = match self.kind {
            SkSkbKind::StreamParser => BPF_SK_SKB_STREAM_PARSER,
            SkSkbKind::StreamVerdict => BPF_SK_SKB_STREAM_VERDICT,
        };
        bpf_prog_attach(prog_fd, map_fd, attach_type).map_err(|(_, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_prog_attach".to_owned(),
                io_error,
            }
        })?;
        self.data
            .links
            .insert(SkSkbLink(ProgAttachLink::new(prog_fd, map_fd, attach_type)))
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
}

define_link_wrapper!(
    /// The link used by [SkSkb] programs.
    SkSkbLink,
    /// The type returned by [SkSkb::attach]. Can be passed to [SkSkb::detach].
    SkSkbLinkId,
    ProgAttachLink,
    ProgAttachLinkId
);
