//! Network traffic control programs.
use std::{ffi::CString, io, os::fd::AsFd as _, path::Path};

use aya_obj::generated::{
    TC_H_CLSACT, TC_H_MIN_EGRESS, TC_H_MIN_INGRESS,
    bpf_attach_type::{self, BPF_NETKIT_PEER, BPF_NETKIT_PRIMARY, BPF_TCX_EGRESS, BPF_TCX_INGRESS},
    bpf_link_type,
    bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS,
};
use thiserror::Error;

use super::{FdLink, ProgramInfo};
use crate::{
    VerifierLogLevel,
    programs::{
        Link, LinkError, LinkOrder, ProgramData, ProgramError, ProgramType, define_link_wrapper,
        id_as_key, impl_try_into_fdlink, load_program_without_attach_type, query,
    },
    sys::{
        BpfLinkCreateArgs, LinkTarget, NetlinkError, NetlinkSocket, ProgQueryTarget, SyscallError,
        bpf_link_create, bpf_link_update, bpf_prog_get_fd_by_id, netlink_find_filter_with_name,
        netlink_qdisc_add_clsact, netlink_qdisc_attach, netlink_qdisc_detach,
    },
    util::{ifindex_from_ifname, tc_handler_make},
};

/// Attachment configuration for [`SchedClassifier`] programs.
pub enum SchedClassifierAttachment {
    /// Attach as a legacy TC filter using netlink.
    Tc {
        /// The legacy TC hook to attach to.
        attach_type: TcAttachType,
        /// Netlink attach options.
        options: NlOptions,
    },
    /// Attach to TCX using the eBPF link interface.
    Tcx {
        /// The TCX hook to attach to.
        attach_type: TcxAttachType,
        /// Multi-prog link ordering.
        link_order: LinkOrder,
    },
    /// Attach to a Netkit device using the eBPF link interface.
    Netkit {
        /// The Netkit hook to attach to.
        attach_type: NetkitAttachType,
        /// Multi-prog link ordering.
        link_order: LinkOrder,
    },
}

/// Traffic control attach type using netlink.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TcAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
    /// Attach to custom parent.
    Custom(u32),
}

/// Traffic control attach type using eBPF link interface.
/// Requires kernels >= 6.6.0.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TcxAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
}

impl TcxAttachType {
    pub(crate) const fn bpf_attach_type(self) -> bpf_attach_type {
        match self {
            Self::Ingress => BPF_TCX_INGRESS,
            Self::Egress => BPF_TCX_EGRESS,
        }
    }
}

/// Netkit attach type using eBPF link interface.
/// Requires kernels >= 6.7.0.
/// Can only be attached to netkit devices.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum NetkitAttachType {
    /// Attach to primary.
    Primary,
    /// Attach to peer.
    Peer,
}

impl NetkitAttachType {
    pub(crate) const fn bpf_attach_type(self) -> bpf_attach_type {
        match self {
            Self::Primary => BPF_NETKIT_PRIMARY,
            Self::Peer => BPF_NETKIT_PEER,
        }
    }
}

/// A network traffic control classifier.
///
/// [`SchedClassifier`] programs can be used to inspect, filter or redirect
/// network packets in both ingress and egress. They are executed as part of the
/// linux network traffic control system. See
/// [https://man7.org/linux/man-pages/man8/tc-bpf.8.html](https://man7.org/linux/man-pages/man8/tc-bpf.8.html).
///
/// # Examples
///
/// # Minimum kernel version
///
/// Legacy TC attachments require kernel 4.1 or later. TCX attachments require
/// kernel 6.6 or later. Netkit attachments require kernel 6.7 or later and a
/// netkit device.
///
/// # Legacy TC attachment
///
/// Legacy TC attachments use netlink and require the `clsact` qdisc.
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
/// #     Tc(#[from] aya::programs::tc::TcError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::{tc::{self, NlOptions}, SchedClassifier, SchedClassifierAttachment, TcAttachType};
///
/// // the clsact qdisc needs to be added before SchedClassifier programs can be
/// // attached with legacy TC
/// tc::qdisc_add_clsact("eth0")?;
///
/// let prog: &mut SchedClassifier = bpf.program_mut("redirect_ingress").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(
///     "eth0",
///     SchedClassifierAttachment::Tc {
///         attach_type: TcAttachType::Ingress,
///         options: NlOptions::default(),
///     },
/// )?;
///
/// # Ok::<(), Error>(())
/// ```
///
/// # TCX attachment
///
/// TCX attachments use eBPF links and support multi-prog ordering.
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
/// #     Tc(#[from] aya::programs::tc::TcError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::{LinkOrder, SchedClassifier, SchedClassifierAttachment, TcxAttachType};
///
/// let prog: &mut SchedClassifier = bpf.program_mut("redirect_ingress").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(
///     "eth0",
///     SchedClassifierAttachment::Tcx {
///         attach_type: TcxAttachType::Ingress,
///         link_order: LinkOrder::default(),
///     },
/// )?;
///
/// # Ok::<(), Error>(())
/// ```
///
/// # Netkit attachment
///
/// Netkit attachments use eBPF links and support multi-prog ordering. The
/// interface must be a netkit device.
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
/// #     Tc(#[from] aya::programs::tc::TcError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::{LinkOrder, NetkitAttachType, SchedClassifier, SchedClassifierAttachment};
///
/// let primary_prog: &mut SchedClassifier = bpf.program_mut("primary").unwrap().try_into()?;
/// primary_prog.load()?;
/// primary_prog.attach(
///     "nk0",
///     SchedClassifierAttachment::Netkit {
///         attach_type: NetkitAttachType::Primary,
///         link_order: LinkOrder::default(),
///     },
/// )?;
/// let peer_prog: &mut SchedClassifier = bpf.program_mut("peer").unwrap().try_into()?;
/// peer_prog.load()?;
/// // Peer attachment still occurs on the primary interface
/// peer_prog.attach(
///     "nk0",
///     SchedClassifierAttachment::Netkit {
///         attach_type: NetkitAttachType::Peer,
///         link_order: LinkOrder::default(),
///     },
/// )?;
///
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SCHED_CLS")]
pub struct SchedClassifier {
    pub(crate) data: ProgramData<SchedClassifierLink>,
}

/// Errors from TC programs
#[derive(Debug, Error)]
pub enum TcError {
    /// a netlink error occurred.
    #[error(transparent)]
    NetlinkError(#[from] NetlinkError),
    /// the provided string contains a nul byte.
    #[error(transparent)]
    NulError(#[from] std::ffi::NulError),
    /// an IO error occurred.
    #[error(transparent)]
    IoError(#[from] io::Error),
    /// the clsact qdisc is already attached.
    #[error("the clsact qdisc is already attached")]
    AlreadyAttached,
    /// operation not supported for programs loaded via tcx or netkit.
    #[error("operation not supported for fd-backed TC links")]
    InvalidLinkOperation,
}

impl TcAttachType {
    pub(crate) const fn tc_parent(self) -> u32 {
        match self {
            Self::Custom(parent) => parent,
            Self::Ingress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_INGRESS),
            Self::Egress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_EGRESS),
        }
    }
}

/// Options for [`SchedClassifier`] attach via netlink.
#[derive(Debug, Default, Hash, Eq, PartialEq)]
pub struct NlOptions {
    /// Priority assigned to tc program with lower number = higher priority.
    /// If set to default (0), the system chooses the next highest priority or 49152 if no filters exist yet
    pub priority: u16,
    /// Handle used to uniquely identify a program at a given priority level.
    /// If set to default (0), the system chooses a handle.
    pub handle: u32,
}

impl SchedClassifier {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SchedClassifier;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_SCHED_CLS, data)
    }

    /// Attaches the program to the given `interface`.
    ///
    /// The returned value can be used to detach, see [`SchedClassifier::detach`].
    ///
    /// # Errors
    ///
    /// When attaching fails, [`ProgramError::SyscallError`] is returned for
    /// kernels `>= 6.6.0`, and [`TcError::NetlinkError`] is returned for
    /// older kernels. A common cause of netlink attachment failure is not having added
    /// the `clsact` qdisc to the given interface, see [`qdisc_add_clsact`]
    ///
    pub fn attach(
        &mut self,
        interface: &str,
        attachment: SchedClassifierAttachment,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let if_index = ifindex_from_ifname(interface).map_err(TcError::IoError)?;
        match attachment {
            SchedClassifierAttachment::Tc {
                attach_type,
                options,
            } => self.do_netlink_attach(if_index, attach_type, options, true),
            SchedClassifierAttachment::Tcx {
                attach_type,
                link_order,
            } => self.do_bpf_link_attach(
                if_index,
                attach_type.bpf_attach_type(),
                &link_order,
                Some(BpfLinkCreateArgs::Tcx(&link_order.link_ref)),
            ),
            SchedClassifierAttachment::Netkit {
                attach_type,
                link_order,
            } => self.do_bpf_link_attach(
                if_index,
                attach_type.bpf_attach_type(),
                &link_order,
                Some(BpfLinkCreateArgs::Netkit(&link_order.link_ref)),
            ),
        }
    }

    /// Atomically replaces the program referenced by the provided link.
    ///
    /// Ownership of the link will transfer to this program.
    pub fn attach_to_link(
        &mut self,
        link: SchedClassifierLink,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        match link.into_inner() {
            TcLinkInner::Fd(link) => {
                let fd = link.fd;
                let link_fd = fd.as_fd();

                bpf_link_update(link_fd.as_fd(), prog_fd, None, 0).map_err(|io_error| {
                    SyscallError {
                        call: "bpf_link_update",
                        io_error,
                    }
                })?;

                self.data
                    .links
                    .insert(SchedClassifierLink::new(TcLinkInner::Fd(FdLink::new(fd))))
            }
            TcLinkInner::NlLink(NlLink {
                if_index,
                attach_type,
                priority,
                handle,
            }) => {
                self.do_netlink_attach(if_index, attach_type, NlOptions { priority, handle }, false)
            }
        }
    }

    fn do_bpf_link_attach(
        &mut self,
        if_index: u32,
        attach_type: bpf_attach_type,
        link_order: &LinkOrder,
        bpf_link_create_args: Option<BpfLinkCreateArgs<'_>>,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();

        let link_fd = bpf_link_create(
            prog_fd,
            LinkTarget::IfIndex(if_index),
            attach_type,
            link_order.flags.bits(),
            bpf_link_create_args,
        )
        .map_err(|io_error| SyscallError {
            call: "bpf_mprog_attach",
            io_error,
        })?;

        self.data
            .links
            .insert(SchedClassifierLink::new(TcLinkInner::Fd(FdLink::new(
                link_fd,
            ))))
    }

    fn do_netlink_attach(
        &mut self,
        if_index: u32,
        attach_type: TcAttachType,
        options: NlOptions,
        create: bool,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();

        let name = self.data.name.as_deref().unwrap_or_default();
        // TODO: avoid this unwrap by adding a new error variant.
        let name = CString::new(name).unwrap();
        let (priority, handle) = unsafe {
            netlink_qdisc_attach(
                if_index as i32,
                &attach_type,
                prog_fd,
                &name,
                options.priority,
                options.handle,
                create,
            )
        }
        .map_err(TcError::NetlinkError)?;

        self.data
            .links
            .insert(SchedClassifierLink::new(TcLinkInner::NlLink(NlLink {
                if_index,
                attach_type,
                priority,
                handle,
            })))
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data })
    }

    /// Queries a given interface for attached TCX programs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use aya::programs::tc::{TcxAttachType, SchedClassifier};
    /// # #[derive(Debug, thiserror::Error)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     Program(#[from] aya::programs::ProgramError),
    /// # }
    /// let (revision, programs) = SchedClassifier::query_tcx("eth0", TcxAttachType::Ingress)?;
    /// # Ok::<(), Error>(())
    /// ```
    pub fn query_tcx(
        interface: &str,
        attach_type: TcxAttachType,
    ) -> Result<(u64, Vec<ProgramInfo>), ProgramError> {
        let if_index = ifindex_from_ifname(interface).map_err(TcError::IoError)?;

        let (revision, prog_ids) = query(
            ProgQueryTarget::IfIndex(if_index),
            attach_type.bpf_attach_type(),
            0,
            &mut None,
        )?;

        let prog_infos = prog_ids
            .into_iter()
            .map(|prog_id| {
                let prog_fd = bpf_prog_get_fd_by_id(prog_id)?;
                let prog_info = ProgramInfo::new_from_fd(prog_fd.as_fd())?;
                Ok::<ProgramInfo, ProgramError>(prog_info)
            })
            .collect::<Result<_, _>>()?;

        Ok((revision, prog_infos))
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) struct NlLinkId(u32, TcAttachType, u16, u32);

#[derive(Debug)]
pub(crate) struct NlLink {
    if_index: u32,
    attach_type: TcAttachType,
    priority: u16,
    handle: u32,
}

impl Link for NlLink {
    type Id = NlLinkId;

    fn id(&self) -> Self::Id {
        NlLinkId(self.if_index, self.attach_type, self.priority, self.handle)
    }

    fn detach(self) -> Result<(), ProgramError> {
        unsafe {
            netlink_qdisc_detach(
                self.if_index as i32,
                self.attach_type,
                self.priority,
                self.handle,
            )
        }
        .map_err(ProgramError::NetlinkError)?;
        Ok(())
    }
}

id_as_key!(NlLink, NlLinkId);

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum TcLinkIdInner {
    FdLinkId(<FdLink as Link>::Id),
    NlLinkId(<NlLink as Link>::Id),
}

#[derive(Debug)]
pub(crate) enum TcLinkInner {
    Fd(FdLink),
    NlLink(NlLink),
}

impl Link for TcLinkInner {
    type Id = TcLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(link) => TcLinkIdInner::FdLinkId(link.id()),
            Self::NlLink(link) => TcLinkIdInner::NlLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(link) => link.detach(),
            Self::NlLink(link) => link.detach(),
        }
    }
}

id_as_key!(TcLinkInner, TcLinkIdInner);

impl<'a> TryFrom<&'a SchedClassifierLink> for &'a FdLink {
    type Error = LinkError;

    fn try_from(value: &'a SchedClassifierLink) -> Result<Self, Self::Error> {
        if let TcLinkInner::Fd(fd) = value.inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl_try_into_fdlink!(SchedClassifierLink, TcLinkInner);

impl TryFrom<FdLink> for SchedClassifierLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = crate::sys::bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;

        match info.type_ {
            link_type
                if link_type == bpf_link_type::BPF_LINK_TYPE_TCX as u32
                    || link_type == bpf_link_type::BPF_LINK_TYPE_NETKIT as u32 =>
            {
                Ok(Self::new(TcLinkInner::Fd(fd_link)))
            }
            _ => Err(LinkError::InvalidLink),
        }
    }
}

define_link_wrapper!(
    SchedClassifierLink,
    SchedClassifierLinkId,
    TcLinkInner,
    TcLinkIdInner,
    SchedClassifier,
);

impl SchedClassifierLink {
    /// Constructs a [`SchedClassifierLink`] where the `if_name`, `attach_type`,
    /// `priority` and `handle` are already known. This may have been found from a link created by
    /// [`SchedClassifier::attach`], the output of the `tc filter` command or from the output of
    /// another BPF loader.
    ///
    /// Note: If you create a link for a program that you do not own, detaching it may have
    /// unintended consequences.
    ///
    /// # Errors
    /// Returns [`io::Error`] if `if_name` is invalid. If the other parameters are invalid this call
    /// will succeed, but calling [`SchedClassifierLink::detach`] will return [`TcError::NetlinkError`].
    ///
    /// # Examples
    /// ```no_run
    /// # use aya::programs::tc::SchedClassifierLink;
    /// # use aya::programs::TcAttachType;
    /// # #[derive(Debug, thiserror::Error)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     IO(#[from] std::io::Error),
    /// # }
    /// # fn read_persisted_link_details() -> (&'static str, TcAttachType, u16, u32) {
    /// #     ("eth0", TcAttachType::Ingress, 50, 1)
    /// # }
    /// // Get the link parameters from some external source. Where and how the parameters are
    /// // persisted is up to your application.
    /// let (if_name, attach_type, priority, handle) = read_persisted_link_details();
    /// let new_tc_link = SchedClassifierLink::attached(if_name, attach_type, priority, handle)?;
    ///
    /// # Ok::<(), Error>(())
    /// ```
    pub fn attached(
        if_name: &str,
        attach_type: TcAttachType,
        priority: u16,
        handle: u32,
    ) -> Result<Self, io::Error> {
        let if_index = ifindex_from_ifname(if_name)?;
        Ok(Self(Some(TcLinkInner::NlLink(NlLink {
            if_index,
            attach_type,
            priority,
            handle,
        }))))
    }

    /// Returns the attach type.
    pub fn attach_type(&self) -> Result<TcAttachType, ProgramError> {
        if let TcLinkInner::NlLink(n) = self.inner() {
            Ok(n.attach_type)
        } else {
            Err(TcError::InvalidLinkOperation.into())
        }
    }

    /// Returns the allocated priority. If none was provided at attach time, this was allocated for you.
    pub fn priority(&self) -> Result<u16, ProgramError> {
        if let TcLinkInner::NlLink(n) = self.inner() {
            Ok(n.priority)
        } else {
            Err(TcError::InvalidLinkOperation.into())
        }
    }

    /// Returns the assigned handle. If none was provided at attach time, this was allocated for you.
    pub fn handle(&self) -> Result<u32, ProgramError> {
        if let TcLinkInner::NlLink(n) = self.inner() {
            Ok(n.handle)
        } else {
            Err(TcError::InvalidLinkOperation.into())
        }
    }
}

/// Add the `clsact` qdisc to the given interface.
///
/// The `clsact` qdisc must be added to an interface before [`SchedClassifier`]
/// programs can be attached.
pub fn qdisc_add_clsact(if_name: &str) -> Result<(), TcError> {
    let if_index = ifindex_from_ifname(if_name)?;
    unsafe { netlink_qdisc_add_clsact(if_index as i32).map_err(TcError::NetlinkError) }
}

/// Detaches the programs with the given name.
///
/// # Errors
///
/// Returns [`io::ErrorKind::NotFound`] to indicate that no programs with the
/// given name were found, so nothing was detached. Other error kinds indicate
/// an actual failure while detaching a program.
pub fn qdisc_detach_program(
    if_name: &str,
    attach_type: TcAttachType,
    name: &str,
) -> Result<(), TcError> {
    let cstr = CString::new(name).map_err(TcError::NulError)?;
    let if_index = ifindex_from_ifname(if_name)? as i32;

    let sock = NetlinkSocket::open().map_err(NetlinkError::from)?;
    let filter_info = netlink_find_filter_with_name(&sock, if_index, attach_type, &cstr)?;
    // Check for errors before detaching any programs.
    let filter_info: Vec<_> = filter_info.collect::<Result<_, _>>()?;
    if filter_info.is_empty() {
        return Err(TcError::IoError(io::Error::new(
            io::ErrorKind::NotFound,
            name.to_owned(),
        )));
    }

    for (prio, handle) in filter_info {
        unsafe { netlink_qdisc_detach(if_index, attach_type, prio, handle)? }
    }

    Ok(())
}
