//! eXpress Data Path (XDP) programs.

use crate::{sys::NetlinkError, util::KernelVersion};
use bitflags;
use libc::if_nametoindex;
use std::{convert::TryFrom, ffi::CString, hash::Hash, mem, os::unix::io::RawFd};
use thiserror::Error;

use crate::{
    generated::{
        bpf_attach_type::{self, BPF_XDP},
        bpf_link_type,
        bpf_prog_type::BPF_PROG_TYPE_XDP,
        XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_REPLACE, XDP_FLAGS_SKB_MODE,
        XDP_FLAGS_UPDATE_IF_NOEXIST,
    },
    programs::{
        define_link_wrapper, load_program, FdLink, Link, LinkError, ProgramData, ProgramError,
    },
    sys::{bpf_link_create, bpf_link_get_info_by_fd, bpf_link_update, netlink_set_xdp_fd},
};

/// The type returned when attaching an [`Xdp`] program fails on kernels `< 5.9`.
#[derive(Debug, Error)]
pub enum XdpError {
    /// netlink error while attaching XDP program
    #[error("netlink error while attaching XDP program")]
    NetlinkError {
        /// the [`io::Error`] from the netlink call
        #[source]
        io_error: NetlinkError,
    },
}

bitflags! {
    /// Flags passed to [`Xdp::attach()`].
    #[derive(Clone, Copy, Debug, Default)]
    pub struct XdpFlags: u32 {
        /// Skb mode.
        const SKB_MODE = XDP_FLAGS_SKB_MODE;
        /// Driver mode.
        const DRV_MODE = XDP_FLAGS_DRV_MODE;
        /// Hardware mode.
        const HW_MODE = XDP_FLAGS_HW_MODE;
        /// Replace a previously attached XDP program.
        const REPLACE = XDP_FLAGS_REPLACE;
        /// Only attach if there isn't another XDP program already attached.
        const UPDATE_IF_NOEXIST = XDP_FLAGS_UPDATE_IF_NOEXIST;
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
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::{Xdp, XdpFlags}};
///
/// let program: &mut Xdp = bpf.program_mut("intercept_packets").unwrap().try_into()?;
/// program.attach("eth0", XdpFlags::default())?;
/// # Ok::<(), aya::BpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_XDP")]
pub struct Xdp {
    pub(crate) data: ProgramData<XdpLink>,
}

impl Xdp {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(bpf_attach_type::BPF_XDP);
        load_program(BPF_PROG_TYPE_XDP, &mut self.data)
    }

    /// Attaches the program to the given `interface`.
    ///
    /// The returned value can be used to detach, see [Xdp::detach].
    ///
    /// # Errors
    ///
    /// If the given `interface` does not exist
    /// [`ProgramError::UnknownInterface`] is returned.
    ///
    /// When attaching fails, [`ProgramError::SyscallError`] is returned for
    /// kernels `>= 5.9.0`, and instead
    /// [`XdpError::NetlinkError`] is returned for older
    /// kernels.
    pub fn attach(&mut self, interface: &str, flags: XdpFlags) -> Result<XdpLinkId, ProgramError> {
        let c_interface = CString::new(interface).unwrap();
        let if_index = unsafe { if_nametoindex(c_interface.as_ptr()) };
        if if_index == 0 {
            return Err(ProgramError::UnknownInterface {
                name: interface.to_string(),
            });
        }
        self.attach_to_if_index(if_index, flags)
    }

    /// Attaches the program to the given interface index.
    ///
    /// The returned value can be used to detach, see [Xdp::detach].
    ///
    /// # Errors
    ///
    /// When attaching fails, [`ProgramError::SyscallError`] is returned for
    /// kernels `>= 5.9.0`, and instead
    /// [`XdpError::NetlinkError`] is returned for older
    /// kernels.
    pub fn attach_to_if_index(
        &mut self,
        if_index: u32,
        flags: XdpFlags,
    ) -> Result<XdpLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let if_index = if_index as RawFd;

        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 9, 0) {
            let link_fd = bpf_link_create(prog_fd, if_index, BPF_XDP, None, flags.bits()).map_err(
                |(_, io_error)| ProgramError::SyscallError {
                    call: "bpf_link_create",
                    io_error,
                },
            )? as RawFd;
            self.data
                .links
                .insert(XdpLink::new(XdpLinkInner::FdLink(FdLink::new(link_fd))))
        } else {
            unsafe { netlink_set_xdp_fd(if_index, prog_fd, None, flags.bits()) }
                .map_err(|io_error| XdpError::NetlinkError { io_error })?;

            self.data
                .links
                .insert(XdpLink::new(XdpLinkInner::NlLink(NlLink {
                    if_index,
                    prog_fd,
                    flags,
                })))
        }
    }

    /// Detaches the program.
    ///
    /// See [Xdp::attach].
    pub fn detach(&mut self, link_id: XdpLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: XdpLinkId) -> Result<XdpLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Atomically replaces the program referenced by the provided link.
    ///
    /// Ownership of the link will transfer to this program.
    pub fn attach_to_link(&mut self, link: XdpLink) -> Result<XdpLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        match link.inner() {
            XdpLinkInner::FdLink(fd_link) => {
                let link_fd = fd_link.fd;
                bpf_link_update(link_fd, prog_fd, None, 0).map_err(|(_, io_error)| {
                    ProgramError::SyscallError {
                        call: "bpf_link_update",
                        io_error,
                    }
                })?;
                // dispose of link and avoid detach on drop
                mem::forget(link);
                self.data
                    .links
                    .insert(XdpLink::new(XdpLinkInner::FdLink(FdLink::new(link_fd))))
            }
            XdpLinkInner::NlLink(nl_link) => {
                let if_index = nl_link.if_index;
                let old_prog_fd = nl_link.prog_fd;
                let flags = nl_link.flags;
                let replace_flags = flags | XdpFlags::REPLACE;
                unsafe {
                    netlink_set_xdp_fd(if_index, prog_fd, Some(old_prog_fd), replace_flags.bits())
                        .map_err(|io_error| XdpError::NetlinkError { io_error })?;
                }
                // dispose of link and avoid detach on drop
                mem::forget(link);
                self.data
                    .links
                    .insert(XdpLink::new(XdpLinkInner::NlLink(NlLink {
                        if_index,
                        prog_fd,
                        flags,
                    })))
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct NlLink {
    if_index: i32,
    prog_fd: RawFd,
    flags: XdpFlags,
}

impl Link for NlLink {
    type Id = (i32, RawFd);

    fn id(&self) -> Self::Id {
        (self.if_index, self.prog_fd)
    }

    fn detach(self) -> Result<(), ProgramError> {
        let flags = if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            self.flags.bits() | XDP_FLAGS_REPLACE
        } else {
            self.flags.bits()
        };
        let _ = unsafe { netlink_set_xdp_fd(self.if_index, -1, Some(self.prog_fd), flags) };
        Ok(())
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum XdpLinkIdInner {
    FdLinkId(<FdLink as Link>::Id),
    NlLinkId(<NlLink as Link>::Id),
}

#[derive(Debug)]
pub(crate) enum XdpLinkInner {
    FdLink(FdLink),
    NlLink(NlLink),
}

impl Link for XdpLinkInner {
    type Id = XdpLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            XdpLinkInner::FdLink(link) => XdpLinkIdInner::FdLinkId(link.id()),
            XdpLinkInner::NlLink(link) => XdpLinkIdInner::NlLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            XdpLinkInner::FdLink(link) => link.detach(),
            XdpLinkInner::NlLink(link) => link.detach(),
        }
    }
}

impl TryFrom<XdpLink> for FdLink {
    type Error = LinkError;

    fn try_from(value: XdpLink) -> Result<Self, Self::Error> {
        if let XdpLinkInner::FdLink(fd) = value.into_inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl TryFrom<FdLink> for XdpLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        // unwrap of fd_link.fd will not panic since it's only None when being dropped.
        let info =
            bpf_link_get_info_by_fd(fd_link.fd).map_err(|io_error| LinkError::SyscallError {
                call: "BPF_OBJ_GET_INFO_BY_FD",
                code: 0,
                io_error,
            })?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_XDP as u32) {
            return Ok(XdpLink::new(XdpLinkInner::FdLink(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

define_link_wrapper!(
    /// The link used by [Xdp] programs.
    XdpLink,
    /// The type returned by [Xdp::attach]. Can be passed to [Xdp::detach].
    XdpLinkId,
    XdpLinkInner,
    XdpLinkIdInner
);
