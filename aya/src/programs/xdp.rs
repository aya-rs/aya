//! eXpress Data Path (XDP) programs.

use std::{
    ffi::CString,
    hash::Hash,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, RawFd},
    path::Path,
};

use aya_obj::{
    generated::{
        XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_SKB_MODE, bpf_link_type,
        bpf_prog_type::BPF_PROG_TYPE_XDP,
    },
    programs::XdpAttachType,
};
use thiserror::Error;

use crate::{
    VerifierLogLevel,
    programs::{
        FdLink, Link, ProgramData, ProgramError, ProgramType, define_link_wrapper, id_as_key,
        impl_try_from_fdlink, impl_try_into_fdlink, load_program_with_attach_type,
    },
    sys::{
        LinkTarget, NetlinkError, SyscallError, bpf_link_create, bpf_link_update,
        netlink_set_xdp_fd,
    },
};

/// An error that occurred while working with an XDP program.
#[derive(Debug, Error)]
pub enum XdpError {
    /// A netlink error occurred.
    #[error(transparent)]
    NetlinkError(#[from] NetlinkError),
}

/// XDP attachment mode.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum XdpMode {
    /// Let the kernel choose the mode.
    #[default]
    Default,
    /// Generic XDP, executed by the kernel network stack.
    Skb,
    /// Native XDP, executed by the network driver.
    Driver,
    /// Hardware offload, executed by the network device.
    Hardware,
}

impl XdpMode {
    pub(crate) const fn flags(self) -> u32 {
        match self {
            Self::Default => 0,
            Self::Skb => XDP_FLAGS_SKB_MODE,
            Self::Driver => XDP_FLAGS_DRV_MODE,
            Self::Hardware => XDP_FLAGS_HW_MODE,
        }
    }
}

/// An XDP program.
///
/// eXpress Data Path (XDP) programs can be attached to the very early stages of network
/// processing, where they can apply custom packet processing logic.  When supported by the
/// underlying network driver, XDP programs can execute directly on network cards, greatly
/// reducing CPU load.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.8.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::{Xdp, XdpMode}};
///
/// let program: &mut Xdp = bpf.program_mut("intercept_packets").unwrap().try_into()?;
/// program.attach("eth0", XdpMode::default())?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_XDP")]
pub struct Xdp {
    pub(crate) data: ProgramData<XdpLink>,
    pub(crate) attach_type: XdpAttachType,
}

impl Xdp {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::Xdp;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, attach_type } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_XDP, *attach_type, data)
    }

    /// Attaches the program to the given `interface`.
    ///
    /// The returned value can be used to detach, see [`Xdp::detach`].
    ///
    /// # Errors
    ///
    /// If the given `interface` does not exist
    /// [`ProgramError::UnknownInterface`] is returned.
    ///
    /// When `bpf_link_create` is unavailable or rejects the request, the call
    /// transparently falls back to the legacy netlink-based attach path.
    pub fn attach(&mut self, interface: &str, mode: XdpMode) -> Result<XdpLinkId, ProgramError> {
        // TODO: avoid this unwrap by adding a new error variant.
        let c_interface = CString::new(interface).unwrap();
        let if_index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if if_index == 0 {
            return Err(ProgramError::UnknownInterface {
                name: interface.to_string(),
            });
        }
        self.attach_to_if_index(if_index, mode)
    }

    /// Attaches the program to the given interface index.
    ///
    /// The returned value can be used to detach, see [`Xdp::detach`].
    ///
    /// # Errors
    ///
    /// When `bpf_link_create` is unavailable or rejects the request, the call
    /// transparently falls back to the legacy netlink-based attach path.
    pub fn attach_to_if_index(
        &mut self,
        if_index: u32,
        mode: XdpMode,
    ) -> Result<XdpLinkId, ProgramError> {
        let Self { data, attach_type } = self;
        let prog_fd = data.fd()?;
        let prog_fd = prog_fd.as_fd();
        let flags = mode.flags();
        let link = match bpf_link_create(
            prog_fd,
            LinkTarget::IfIndex(if_index),
            *attach_type,
            flags,
            None,
        ) {
            Ok(link_fd) => XdpLinkInner::Fd(FdLink::new(link_fd)),
            Err(io_error) => {
                if io_error.raw_os_error() != Some(libc::EINVAL) {
                    return Err(ProgramError::SyscallError(SyscallError {
                        call: "bpf_link_create",
                        io_error,
                    }));
                }

                // Fall back to netlink-based attachment.

                let if_index = if_index as i32;
                unsafe { netlink_set_xdp_fd(if_index, Some(prog_fd), None, mode) }
                    .map_err(XdpError::NetlinkError)?;

                let prog_fd = prog_fd.as_raw_fd();
                XdpLinkInner::NlLink(NlLink {
                    if_index,
                    prog_fd,
                    mode,
                })
            }
        };
        data.links.insert(XdpLink::new(link))
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        attach_type: XdpAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }

    /// Atomically replaces the program referenced by the provided link.
    ///
    /// Ownership of the link will transfer to this program.
    pub fn attach_to_link(&mut self, link: XdpLink) -> Result<XdpLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        match link.into_inner() {
            XdpLinkInner::Fd(fd_link) => {
                let link_fd = fd_link.fd;
                bpf_link_update(link_fd.as_fd(), prog_fd, None, 0).map_err(|io_error| {
                    SyscallError {
                        call: "bpf_link_update",
                        io_error,
                    }
                })?;

                self.data
                    .links
                    .insert(XdpLink::new(XdpLinkInner::Fd(FdLink::new(link_fd))))
            }
            XdpLinkInner::NlLink(NlLink {
                if_index,
                prog_fd: old_prog_fd,
                mode,
            }) => {
                // SAFETY: TODO(https://github.com/aya-rs/aya/issues/612): make this safe by not holding `RawFd`s.
                let old_prog_fd = unsafe { BorrowedFd::borrow_raw(old_prog_fd) };
                unsafe {
                    netlink_set_xdp_fd(if_index, Some(prog_fd), Some(old_prog_fd), mode)
                        .map_err(XdpError::NetlinkError)?;
                }

                let prog_fd = prog_fd.as_raw_fd();
                self.data
                    .links
                    .insert(XdpLink::new(XdpLinkInner::NlLink(NlLink {
                        if_index,
                        prog_fd,
                        mode,
                    })))
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct NlLink {
    if_index: i32,
    prog_fd: RawFd,
    mode: XdpMode,
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) struct NlLinkId(i32, RawFd);

impl Link for NlLink {
    type Id = NlLinkId;

    fn id(&self) -> Self::Id {
        let Self {
            if_index,
            prog_fd,
            mode: _,
        } = self;
        NlLinkId(*if_index, *prog_fd)
    }

    fn detach(self) -> Result<(), ProgramError> {
        let Self {
            if_index,
            prog_fd,
            mode,
        } = self;
        // SAFETY: TODO(https://github.com/aya-rs/aya/issues/612): make this safe by not holding `RawFd`s.
        let prog_fd = unsafe { BorrowedFd::borrow_raw(prog_fd) };
        let _unused: Result<(), NetlinkError> =
            unsafe { netlink_set_xdp_fd(if_index, None, Some(prog_fd), mode) };
        Ok(())
    }
}

id_as_key!(NlLink, NlLinkId);

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum XdpLinkIdInner {
    FdLinkId(<FdLink as Link>::Id),
    NlLinkId(<NlLink as Link>::Id),
}

#[derive(Debug)]
pub(crate) enum XdpLinkInner {
    Fd(FdLink),
    NlLink(NlLink),
}

impl Link for XdpLinkInner {
    type Id = XdpLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(link) => XdpLinkIdInner::FdLinkId(link.id()),
            Self::NlLink(link) => XdpLinkIdInner::NlLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(link) => link.detach(),
            Self::NlLink(link) => link.detach(),
        }
    }
}

id_as_key!(XdpLinkInner, XdpLinkIdInner);

impl_try_into_fdlink!(XdpLink, XdpLinkInner);
impl_try_from_fdlink!(XdpLink, XdpLinkInner, bpf_link_type::BPF_LINK_TYPE_XDP);

define_link_wrapper!(XdpLink, XdpLinkId, XdpLinkInner, XdpLinkIdInner, Xdp);
