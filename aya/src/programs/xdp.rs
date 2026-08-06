//! eXpress Data Path (XDP) programs.

use std::{
    convert::Infallible,
    ffi::CString,
    hash::Hash,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, RawFd},
    path::Path,
};

use aya_obj::{
    generated::{
        BPF_F_XDP_DEV_BOUND_ONLY, XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_SKB_MODE,
        bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_XDP,
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
    util::KernelVersion,
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

    /// Binds the program to `interface` at load time so it can call XDP
    /// metadata kfuncs (e.g. `bpf_xdp_metadata_rx_timestamp`).
    ///
    /// Must be called before [`Xdp::load`]. The program remains executed by
    /// the kernel — this only associates it with a device so the verifier
    /// permits device-bound kfuncs. To offload the program to the device
    /// instead, attach with [`XdpMode::Hardware`].
    ///
    /// # Errors
    ///
    /// If the given `interface` does not exist
    /// [`ProgramError::UnknownInterface`] is returned. If the program has
    /// already been loaded [`ProgramError::AlreadyLoaded`] is returned.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 6.3.
    pub fn set_dev_bound(&mut self, interface: &str) -> Result<(), ProgramError> {
        // TODO: avoid this unwrap by adding a new error variant.
        let c_interface = CString::new(interface).unwrap();
        let if_index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if if_index == 0 {
            return Err(ProgramError::UnknownInterface {
                name: interface.to_string(),
            });
        }
        self.set_dev_bound_by_if_index(if_index)
    }

    /// Binds the program to the interface identified by `if_index` at load
    /// time so it can call XDP metadata kfuncs
    /// (e.g. `bpf_xdp_metadata_rx_timestamp`).
    ///
    /// Must be called before [`Xdp::load`]. See [`Xdp::set_dev_bound`] for
    /// details.
    ///
    /// # Errors
    ///
    /// If the program has already been loaded
    /// [`ProgramError::AlreadyLoaded`] is returned.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 6.3.
    pub const fn set_dev_bound_by_if_index(&mut self, if_index: u32) -> Result<(), ProgramError> {
        if self.data.fd.is_some() {
            return Err(ProgramError::AlreadyLoaded);
        }
        self.data.prog_ifindex = if_index;
        self.data.flags |= BPF_F_XDP_DEV_BOUND_ONLY;
        Ok(())
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
                    // Preserve the atomic replacement contract for netlink
                    // links: only replace the current XDP program if it still
                    // matches the program fd recorded in this link. The
                    // netlink API expresses that compare-and-replace operation
                    // with XDP_FLAGS_REPLACE and IFLA_XDP_EXPECTED_FD, which
                    // were added in Linux 5.7. On older kernels this request
                    // is expected to fail in the kernel instead of degrading to
                    // an unconditional replacement.
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
    type Error = Infallible;

    fn id(&self) -> Self::Id {
        let Self {
            if_index,
            prog_fd,
            mode: _,
        } = self;
        NlLinkId(*if_index, *prog_fd)
    }

    fn detach(self) -> Result<(), Self::Error> {
        let Self {
            if_index,
            prog_fd,
            mode,
        } = self;
        // IFLA_XDP_EXPECTED_FD and XDP_FLAGS_REPLACE were added in Linux 5.7;
        // see https://github.com/torvalds/linux/commit/92234c8f. Use them
        // when available so detach only clears the program represented by this
        // link. On older kernels, skip the expected fd so detach keeps the
        // legacy best-effort behavior instead of failing because the kernel
        // does not understand the replacement attributes.
        let prog_fd = KernelVersion::at_least(5, 7, 0).then(|| {
            // SAFETY: TODO(https://github.com/aya-rs/aya/issues/612): make this safe by not holding `RawFd`s.
            unsafe { BorrowedFd::borrow_raw(prog_fd) }
        });
        let _unused: Result<(), NetlinkError> =
            unsafe { netlink_set_xdp_fd(if_index, None, prog_fd, mode) };
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
    type Error = Infallible;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(link) => XdpLinkIdInner::FdLinkId(link.id()),
            Self::NlLink(link) => XdpLinkIdInner::NlLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), Self::Error> {
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

#[cfg(test)]
mod tests {
    use std::os::fd::FromRawFd as _;

    use assert_matches::assert_matches;

    use super::*;
    use crate::programs::{ProgramFd, links::Links};

    fn new_xdp() -> Xdp {
        Xdp {
            data: ProgramData {
                name: None,
                obj: None,
                fd: None,
                links: Links::new(),
                attach_btf_obj_fd: None,
                attach_btf_id: None,
                attach_prog_fd: None,
                btf_fd: None,
                verifier_log_level: VerifierLogLevel::default(),
                path: None,
                flags: 0,
                prog_ifindex: 0,
            },
            attach_type: XdpAttachType::Interface,
        }
    }

    #[test]
    fn set_dev_bound_by_if_index_records_index_and_flag() {
        let mut xdp = new_xdp();
        xdp.set_dev_bound_by_if_index(7).unwrap();
        assert_eq!(xdp.data.prog_ifindex, 7);
        assert_eq!(
            xdp.data.flags & BPF_F_XDP_DEV_BOUND_ONLY,
            BPF_F_XDP_DEV_BOUND_ONLY
        );
    }

    #[test]
    fn set_dev_bound_by_if_index_preserves_existing_flags() {
        let mut xdp = new_xdp();
        // Simulate an unrelated flag such as BPF_F_XDP_HAS_FRAGS that a caller
        // may have set before opting into device binding.
        let preexisting = 0x1234_0000;
        xdp.data.flags = preexisting;

        xdp.set_dev_bound_by_if_index(3).unwrap();

        assert_eq!(xdp.data.prog_ifindex, 3);
        assert_eq!(xdp.data.flags, preexisting | BPF_F_XDP_DEV_BOUND_ONLY);
    }

    #[test]
    fn set_dev_bound_by_if_index_is_idempotent() {
        let mut xdp = new_xdp();
        xdp.set_dev_bound_by_if_index(9).unwrap();
        // A second call with a different index overrides the recorded index
        // but keeps the flag set (verifies `|=` rather than `=`).
        xdp.set_dev_bound_by_if_index(11).unwrap();
        assert_eq!(xdp.data.prog_ifindex, 11);
        assert_eq!(
            xdp.data.flags & BPF_F_XDP_DEV_BOUND_ONLY,
            BPF_F_XDP_DEV_BOUND_ONLY
        );
    }

    #[test]
    fn set_dev_bound_by_if_index_after_load_returns_already_loaded() {
        let mut xdp = new_xdp();
        let fd = unsafe { crate::MockableFd::from_raw_fd(crate::MockableFd::mock_signed_fd()) };
        xdp.data.fd = Some(ProgramFd(fd));

        assert_matches!(
            xdp.set_dev_bound_by_if_index(1),
            Err(ProgramError::AlreadyLoaded)
        );
        // Nothing must be mutated when the program is already loaded.
        assert_eq!(xdp.data.prog_ifindex, 0);
        assert_eq!(xdp.data.flags, 0);
    }
}
