//! Network traffic control programs.
use std::{
    ffi::CString,
    io,
    os::fd::{AsFd as _, BorrowedFd},
    path::Path,
};

use aya_obj::generated::{
    TC_H_CLSACT, TC_H_MIN_EGRESS, TC_H_MIN_INGRESS,
    bpf_attach_type::{self, BPF_TCX_EGRESS, BPF_TCX_INGRESS},
    bpf_link_type,
    bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS,
};
use thiserror::Error;

use super::{FdLink, ProgramInfo};
use crate::{
    VerifierLogLevel,
    programs::{
        Link, LinkError, LinkOrder, LinkUpdate, NetworkInterface, ProgramData, ProgramError,
        ProgramType, define_link_wrapper, id_as_key, impl_program_adopt_link, impl_try_from_fdlink,
        impl_try_into_fdlink, load_program_without_attach_type, query,
    },
    sys::{
        BpfLinkCreateArgs, LinkTarget, NetlinkError, NetlinkSocket, ProgQueryTarget, SyscallError,
        bpf_link_create, bpf_prog_get_fd_by_id, netlink_find_filter_with_name,
        netlink_qdisc_add_clsact, netlink_qdisc_attach, netlink_qdisc_detach,
    },
    util::{KernelVersion, tc_handler_make},
};

/// Traffic control attach type.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TcAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
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
/// The minimum kernel version required to use this feature is 4.1.
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
/// use aya::programs::{tc, SchedClassifier, TcAttachType};
///
/// // Prepare clsact for the netlink backend used on older kernels.
/// tc::qdisc_add_clsact("eth0")?;
///
/// let prog: &mut SchedClassifier = bpf.program_mut("redirect_ingress").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach("eth0", TcAttachType::Ingress)?;
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
    /// operation not supported for programs loaded via tcx.
    #[error("operation not supported for programs loaded via tcx")]
    InvalidLinkOperation,
}

impl TcAttachType {
    const fn bpf_attach_type(self) -> bpf_attach_type {
        match self {
            Self::Ingress => BPF_TCX_INGRESS,
            Self::Egress => BPF_TCX_EGRESS,
        }
    }
}

/// Attach point and backend for a [`SchedClassifier`] attach operation.
///
/// Select a backend explicitly, or let [`TcAttach::Auto`] choose based on the
/// kernel version and attach type. Passing a [`TcAttachType`] directly to
/// [`SchedClassifier::attach`] selects [`TcAttach::Auto`].
///
/// Custom parents are specified explicitly through [`TcAttach::Netlink`].
/// Automatic and TCX attachment only accept ingress or egress.
#[derive(Debug)]
pub enum TcAttach {
    /// Use TCX and attach as the last TCX program for ingress and egress on
    /// kernels >= 6.6.0, or use netlink with default options otherwise.
    Auto(TcAttachType),
    /// Use netlink at the given parent with the given options.
    Netlink {
        /// Parent identifying the qdisc or class at which to attach the filter.
        ///
        /// Convert a [`TcAttachType`] to select the corresponding clsact parent,
        /// or specify a [`TcHandle`] for a custom parent. The parent must already
        /// exist and support filters; this operation does not create it.
        parent: TcHandle,
        /// Options for the filter attached at this parent.
        options: NlOptions,
    },
    /// Use TCX at the given attach point with the given ordering. Requires
    /// kernel >= 6.6.0 and does not fall back to netlink if attachment fails.
    Tcx(TcAttachType, LinkOrder),
}

impl From<TcAttachType> for TcAttach {
    fn from(attach_type: TcAttachType) -> Self {
        Self::Auto(attach_type)
    }
}

/// A TC handle in `major:minor` form.
///
/// Matches the `M:N` syntax accepted by `tc(8)`. It can identify a filter,
/// class, or qdisc, including the parent passed to [`TcAttach::Netlink`].
/// Use [`TcHandle::AUTO_ASSIGN`] to ask the kernel to allocate a filter handle.
#[derive(Debug, Clone, Copy, Default, Hash, Eq, PartialEq)]
#[doc(alias = "tcm_handle")]
pub struct TcHandle {
    /// Upper 16 bits when encoded as a u32.
    major: u16,
    /// Lower 16 bits when encoded as a u32.
    minor: u16,
}

impl TcHandle {
    /// Sentinel that asks the kernel to allocate a handle at attach time.
    ///
    /// Equal to [`Default::default`]. The allocated value is exposed by
    /// [`SchedClassifierLink::handle`] after the program is attached.
    pub const AUTO_ASSIGN: Self = Self { major: 0, minor: 0 };

    /// Const equivalent of `Self { major, minor }`.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

impl From<TcHandle> for u32 {
    fn from(TcHandle { major, minor }: TcHandle) -> Self {
        (Self::from(major) << 16) | Self::from(minor)
    }
}

impl From<u32> for TcHandle {
    fn from(value: u32) -> Self {
        Self {
            major: (value >> 16) as u16,
            minor: value as u16,
        }
    }
}

impl From<TcAttachType> for TcHandle {
    /// Returns the clsact parent for ingress or egress.
    fn from(attach_type: TcAttachType) -> Self {
        let minor = match attach_type {
            TcAttachType::Ingress => TC_H_MIN_INGRESS,
            TcAttachType::Egress => TC_H_MIN_EGRESS,
        };
        tc_handler_make(TC_H_CLSACT, minor).into()
    }
}

/// Options for [`SchedClassifier`] attach via netlink.
#[derive(Debug, Default, Hash, Eq, PartialEq)]
pub struct NlOptions {
    /// Priority assigned to tc program with lower number = higher priority.
    /// If set to default (0), the system chooses the next highest priority or 49152 if no filters exist yet
    pub priority: u16,
    /// Handle used to uniquely identify a program at a given priority level.
    ///
    /// Defaults to [`TcHandle::AUTO_ASSIGN`], which lets the kernel pick one.
    pub handle: TcHandle,
    /// `classid` bound to this filter (also known as `flowid` in `tc(8)`).
    ///
    /// In direct-action mode the major 16 bits of the resulting class id come
    /// from this attribute and the minor 16 bits come from the program at run
    /// time via `__sk_buff::tc_classid`. This split requires Linux 4.6 (commit
    /// [`3a461da1d`]).
    ///
    /// When [`None`], no attribute is sent and the filter is not bound to a
    /// class.
    ///
    /// [`3a461da1d`]: https://github.com/torvalds/linux/commit/3a461da1d
    #[doc(alias = "TCA_BPF_CLASSID")]
    pub classid: Option<TcHandle>,
}

impl SchedClassifier {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SchedClassifier;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_SCHED_CLS, data)
    }

    /// Attaches the program to an interface specified by name or index.
    ///
    /// Pass a name such as `"eth0"`, an interface index, or a [`NetworkInterface`].
    ///
    /// Pass a [`TcAttachType`] or [`TcAttach::Auto`] to use TCX and attach as the
    /// last TCX program for ingress and egress on kernels >= 6.6.0, or use netlink
    /// with default options otherwise.
    ///
    /// Pass [`TcAttach::Netlink`] to explicitly select netlink, or [`TcAttach::Tcx`]
    /// to select TCX and control link ordering. TCX attachment failures are
    /// returned without falling back to netlink.
    ///
    /// Netlink attachment accepts a parent handle. Convert a [`TcAttachType`]
    /// for the corresponding clsact parent, or specify a custom [`TcHandle`].
    ///
    /// ```no_run
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// use aya::programs::{tc, SchedClassifier, TcAttach, TcAttachType};
    ///
    /// // Prepare clsact for netlink attachment.
    /// tc::qdisc_add_clsact("eth0")?;
    ///
    /// let prog: &mut SchedClassifier = bpf.program_mut("redirect_ingress").unwrap().try_into()?;
    /// prog.load()?;
    /// prog.attach("eth0", TcAttach::Netlink {
    ///     parent: TcAttachType::Ingress.into(),
    ///     options: tc::NlOptions::default(),
    /// })?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// The returned value can be used to detach, see [`SchedClassifier::detach`].
    ///
    /// # Link Pinning (TCX mode, kernel >= 6.6)
    ///
    /// Links can be pinned to bpffs for atomic replacement across process restarts.
    ///
    /// ```no_run
    /// # use std::{io, path::Path};
    ///
    /// # use aya::{
    /// #     programs::{
    /// #         LinkOrder, SchedClassifier, TcAttach, TcAttachType,
    /// #         links::{FdLink, LinkError, PinnedLink},
    /// #     },
    /// #     sys::SyscallError,
    /// # };
    ///
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// # let prog: &mut SchedClassifier = bpf.program_mut("prog").unwrap().try_into()?;
    /// # prog.load()?;
    /// let pin_path = "/sys/fs/bpf/my_link";
    ///
    /// let link_id = match PinnedLink::from_pin(pin_path) {
    ///     Ok(old) => {
    ///         let link = FdLink::from(old).try_into()?;
    ///         // This caller chooses to release its link reference if adoption fails.
    ///         prog.adopt_link(link).map_err(|(error, _link)| error)?
    ///     }
    ///     Err(LinkError::SyscallError(SyscallError { io_error, .. }))
    ///         if io_error.kind() == io::ErrorKind::NotFound =>
    ///     {
    ///         prog.attach(
    ///             "eth0",
    ///             TcAttach::Tcx(TcAttachType::Ingress, LinkOrder::default()),
    ///         )?
    ///     }
    ///     Err(e) => return Err(e.into()),
    /// };
    ///
    /// let link = prog.take_link(link_id)?;
    /// let fd_link: FdLink = link.try_into()?;
    /// fd_link.pin(pin_path)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// If no interface with the given name exists,
    /// [`ProgramError::UnknownInterface`] is returned.
    ///
    /// If the interface name contains an interior NUL byte,
    /// [`ProgramError::InvalidInterfaceName`] is returned.
    ///
    /// Other interface lookup failures return [`ProgramError::IOError`].
    ///
    /// Attachment failures return [`ProgramError::SyscallError`] for TCX or
    /// [`TcError::NetlinkError`] for netlink. A common cause of netlink failure is
    /// not having added the `clsact` qdisc to the interface, see [`qdisc_add_clsact`].
    pub fn attach<'a>(
        &mut self,
        interface: impl Into<NetworkInterface<'a>>,
        attach: impl Into<TcAttach>,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let if_index = interface.into().if_index_for_program()?;
        match attach.into() {
            TcAttach::Auto(attach_type) => {
                if KernelVersion::at_least(6, 6, 0) {
                    self.attach_tcx(if_index, attach_type, LinkOrder::default())
                } else {
                    self.attach_netlink(if_index, attach_type.into(), NlOptions::default())
                }
            }
            TcAttach::Netlink { parent, options } => self.attach_netlink(if_index, parent, options),
            TcAttach::Tcx(attach_type, order) => self.attach_tcx(if_index, attach_type, order),
        }
    }
}

impl LinkUpdate for TcLinkInner {
    fn update(&mut self, prog_fd: BorrowedFd<'_>, name: Option<&str>) -> Result<(), ProgramError> {
        match self {
            Self::Fd(link) => link.update(prog_fd, name),
            Self::NlLink(link) => link.update(prog_fd, name),
        }
    }
}

impl LinkUpdate for NlLink {
    fn update(&mut self, prog_fd: BorrowedFd<'_>, name: Option<&str>) -> Result<(), ProgramError> {
        let link = Self::attach(
            self.if_index,
            self.parent,
            NlOptions {
                priority: self.priority,
                handle: self.handle,
                classid: self.classid,
            },
            prog_fd,
            name,
            false, // Replace the existing filter.
        )?;
        // Preserve the old filter identity until replacement succeeds.
        *self = link;
        Ok(())
    }
}

impl NlLink {
    fn attach(
        if_index: u32,
        parent: TcHandle,
        options: NlOptions,
        prog_fd: BorrowedFd<'_>,
        name: Option<&str>,
        create: bool,
    ) -> Result<Self, ProgramError> {
        // TODO: avoid this unwrap by adding a new error variant.
        let name = CString::new(name.unwrap_or_default()).unwrap();
        let (priority, handle) = netlink_qdisc_attach(
            if_index as i32,
            parent,
            prog_fd,
            &name,
            options.priority,
            options.handle,
            options.classid,
            create,
        )
        .map_err(TcError::NetlinkError)?;

        Ok(Self {
            if_index,
            parent,
            priority,
            handle,
            classid: options.classid,
        })
    }
}

impl SchedClassifier {
    fn attach_netlink(
        &mut self,
        if_index: u32,
        parent: TcHandle,
        options: NlOptions,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let link = NlLink::attach(
            if_index,
            parent,
            options,
            prog_fd,
            self.data.name.as_deref(),
            true,
        )?;

        self.data
            .links
            .insert(SchedClassifierLink::new(TcLinkInner::NlLink(link)))
    }

    fn attach_tcx(
        &mut self,
        if_index: u32,
        attach_type: TcAttachType,
        order: LinkOrder,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let link_fd = bpf_link_create(
            prog_fd.as_fd(),
            LinkTarget::IfIndex(if_index),
            attach_type.bpf_attach_type(),
            order.flags.bits(),
            Some(BpfLinkCreateArgs::Tcx(&order.link_ref)),
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
    /// Pass a name such as `"eth0"`, an interface index, or a [`NetworkInterface`].
    /// Queries support ingress and egress TCX attach points.
    ///
    /// # Errors
    ///
    /// If no interface with the given name exists,
    /// [`ProgramError::UnknownInterface`] is returned.
    ///
    /// If the interface name contains an interior NUL byte,
    /// [`ProgramError::InvalidInterfaceName`] is returned.
    ///
    /// Other interface lookup failures return [`ProgramError::IOError`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use aya::programs::tc::{TcAttachType, SchedClassifier};
    /// # #[derive(Debug, thiserror::Error)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     Program(#[from] aya::programs::ProgramError),
    /// # }
    /// let (revision, programs) = SchedClassifier::query_tcx("eth0", TcAttachType::Ingress)?;
    /// # Ok::<(), Error>(())
    /// ```
    pub fn query_tcx<'a>(
        interface: impl Into<NetworkInterface<'a>>,
        attach_type: TcAttachType,
    ) -> Result<(u64, Vec<ProgramInfo>), ProgramError> {
        let if_index = interface.into().if_index_for_program()?;

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
pub(crate) struct NlLinkId(u32, TcHandle, u16, TcHandle);

#[derive(Debug)]
pub(crate) struct NlLink {
    if_index: u32,
    parent: TcHandle,
    priority: u16,
    handle: TcHandle,
    classid: Option<TcHandle>,
}

impl Link for NlLink {
    type Id = NlLinkId;
    type Error = ProgramError;

    fn id(&self) -> Self::Id {
        NlLinkId(self.if_index, self.parent, self.priority, self.handle)
    }

    fn detach(self) -> Result<(), Self::Error> {
        let Self {
            if_index,
            parent,
            priority,
            handle,
            classid: _classid,
        } = self;
        netlink_qdisc_detach(if_index as i32, parent, priority, handle)
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
    type Error = ProgramError;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(link) => TcLinkIdInner::FdLinkId(link.id()),
            Self::NlLink(link) => TcLinkIdInner::NlLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), Self::Error> {
        match self {
            Self::Fd(link) => link.detach().map_err(Into::into),
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
impl_try_from_fdlink!(
    SchedClassifierLink,
    TcLinkInner,
    bpf_link_type::BPF_LINK_TYPE_TCX
);

define_link_wrapper!(
    SchedClassifierLink,
    SchedClassifierLinkId,
    TcLinkInner,
    TcLinkIdInner,
    SchedClassifier,
);

impl_program_adopt_link!(SchedClassifier, SchedClassifierLink, SchedClassifierLinkId);

impl SchedClassifierLink {
    /// Reconstructs an owned link to an existing netlink TC filter from its known parts.
    ///
    /// The parts may come from a link created by [`SchedClassifier::attach`], the
    /// output of `tc filter`, or another BPF loader. This does not attach a program
    /// or query the kernel to check whether the filter exists.
    ///
    /// The returned link attempts to detach the filter when dropped or explicitly
    /// detached. Ensure the parts identify the intended filter and that no other
    /// owner will detach it independently. Incorrect parts may cause an unrelated
    /// filter to be detached.
    ///
    /// Pass a name such as `"eth0"`, an interface index, or a [`NetworkInterface`].
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the interface name is invalid or does not exist.
    /// Interface indices, parent handles, and the other parts are not validated
    /// by this call.
    ///
    /// # Examples
    /// ```no_run
    /// # use aya::programs::tc::{SchedClassifierLink, TcHandle};
    /// # use aya::programs::TcAttachType;
    /// # #[derive(Debug, thiserror::Error)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     IO(#[from] std::io::Error),
    /// # }
    /// # fn read_persisted_link_details() -> (&'static str, TcHandle, u16, TcHandle, Option<TcHandle>) {
    /// #     ("eth0", TcAttachType::Ingress.into(), 50, TcHandle::new(0, 1), None)
    /// # }
    /// // Get the link parameters from some external source. Where and how the parameters are
    /// // persisted is up to your application.
    /// let (if_name, parent, priority, handle, classid) = read_persisted_link_details();
    /// let new_tc_link =
    ///     SchedClassifierLink::from_netlink_parts(if_name, parent, priority, handle, classid)?;
    ///
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_netlink_parts<'a>(
        interface: impl Into<NetworkInterface<'a>>,
        parent: TcHandle,
        priority: u16,
        handle: TcHandle,
        classid: Option<TcHandle>,
    ) -> Result<Self, io::Error> {
        let if_index = interface.into().if_index()?;
        Ok(Self(Some(TcLinkInner::NlLink(NlLink {
            if_index,
            parent,
            priority,
            handle,
            classid,
        }))))
    }

    /// Returns the parent at which the netlink filter is attached.
    pub fn parent(&self) -> Result<TcHandle, ProgramError> {
        if let TcLinkInner::NlLink(n) = self.inner() {
            Ok(n.parent)
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
    pub fn handle(&self) -> Result<TcHandle, ProgramError> {
        if let TcLinkInner::NlLink(n) = self.inner() {
            Ok(n.handle)
        } else {
            Err(TcError::InvalidLinkOperation.into())
        }
    }

    /// Returns the `classid` bound to this filter, or [`None`] if the filter
    /// is not bound to a class. See [`NlOptions::classid`].
    pub fn classid(&self) -> Result<Option<TcHandle>, ProgramError> {
        if let TcLinkInner::NlLink(n) = self.inner() {
            Ok(n.classid)
        } else {
            Err(TcError::InvalidLinkOperation.into())
        }
    }
}

/// Add the `clsact` qdisc to the given interface.
///
/// The `clsact` qdisc must be added before attaching a [`SchedClassifier`]
/// through netlink at its ingress or egress parent. TCX does not require it.
///
/// Pass a name such as `"eth0"`, an interface index, or a [`NetworkInterface`].
pub fn qdisc_add_clsact<'a>(interface: impl Into<NetworkInterface<'a>>) -> Result<(), TcError> {
    let if_index = interface.into().if_index()?;
    netlink_qdisc_add_clsact(if_index as i32).map_err(TcError::NetlinkError)
}

/// Detaches the programs with the given name.
///
/// Pass an interface name such as `"eth0"`, an interface index, or a [`NetworkInterface`].
/// Convert a [`TcAttachType`] to select its clsact parent, or specify the custom
/// parent used for netlink attachment.
///
/// # Errors
///
/// Returns [`io::ErrorKind::NotFound`] to indicate that no programs with the
/// given name were found, so nothing was detached. Other error kinds indicate
/// an actual failure while detaching a program.
pub fn qdisc_detach_program<'a>(
    interface: impl Into<NetworkInterface<'a>>,
    parent: TcHandle,
    name: &str,
) -> Result<(), TcError> {
    let cstr = CString::new(name).map_err(TcError::NulError)?;
    let if_index = interface.into().if_index()? as i32;

    let sock = NetlinkSocket::open().map_err(NetlinkError::from)?;
    let filter_info = netlink_find_filter_with_name(&sock, if_index, parent, &cstr)?;
    // Check for errors before detaching any programs.
    let filter_info: Vec<_> = filter_info.collect::<Result<_, _>>()?;
    if filter_info.is_empty() {
        return Err(TcError::IoError(io::Error::new(
            io::ErrorKind::NotFound,
            name.to_owned(),
        )));
    }

    for (prio, handle) in filter_info {
        netlink_qdisc_detach(if_index, parent, prio, handle)?;
    }

    Ok(())
}
