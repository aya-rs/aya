//! Network traffic control programs.
use std::{
    ffi::{CStr, CString},
    io,
    os::fd::AsFd as _,
    path::Path,
};

use thiserror::Error;

use super::{FdLink, ProgramInfo};
use crate::{
    generated::{
        bpf_attach_type::{self, BPF_TCX_EGRESS, BPF_TCX_INGRESS},
        bpf_link_type,
        bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS,
        TC_H_CLSACT, TC_H_MIN_EGRESS, TC_H_MIN_INGRESS,
    },
    programs::{
        define_link_wrapper, id_as_key, load_program, query, Link, LinkError, LinkOrder,
        ProgramData, ProgramError,
    },
    sys::{
        bpf_link_create, bpf_link_get_info_by_fd, bpf_link_update, bpf_prog_get_fd_by_id,
        netlink_find_filter_with_name, netlink_qdisc_add_clsact, netlink_qdisc_attach,
        netlink_qdisc_detach, LinkTarget, ProgQueryTarget, SyscallError,
    },
    util::{ifindex_from_ifname, tc_handler_make, KernelVersion},
    VerifierLogLevel,
};

/// Traffic control attach type.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TcAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
    /// Attach to custom parent.
    Custom(u32),
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
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::{tc, SchedClassifier, TcAttachType};
///
/// // the clsact qdisc needs to be added before SchedClassifier programs can be
/// // attached
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
    /// netlink error while attaching ebpf program
    #[error("netlink error while attaching ebpf program to tc")]
    NetlinkError {
        /// the [`io::Error`] from the netlink call
        #[source]
        io_error: io::Error,
    },
    /// the clsact qdisc is already attached
    #[error("the clsact qdisc is already attached")]
    AlreadyAttached,
    /// tcx links can only be attached to ingress or egress, custom attachment is not supported
    #[error("tcx links can only be attached to ingress or egress, custom attachment: {0} is not supported")]
    InvalidTcxAttach(u32),
    /// operation not supported for programs loaded via tcx
    #[error("operation not supported for programs loaded via tcx")]
    InvalidLinkOperation,
}

impl TcAttachType {
    pub(crate) fn tc_parent(&self) -> u32 {
        match self {
            Self::Custom(parent) => *parent,
            Self::Ingress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_INGRESS),
            Self::Egress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_EGRESS),
        }
    }

    pub(crate) fn tcx_attach_type(&self) -> Result<bpf_attach_type, TcError> {
        match self {
            Self::Ingress => Ok(BPF_TCX_INGRESS),
            Self::Egress => Ok(BPF_TCX_EGRESS),
            Self::Custom(tcx_attach_type) => Err(TcError::InvalidTcxAttach(*tcx_attach_type)),
        }
    }
}

/// Options for a SchedClassifier attach operation.
///
/// The options vary based on what is supported by the current kernel. Kernels
/// older than 6.6.0 must utilize netlink for attachments, while newer kernels
/// can utilize the modern TCX eBPF link type which supports the kernel's
/// multi-prog API.
#[derive(Debug)]
pub enum TcAttachOptions {
    /// Netlink attach options.
    Netlink(NlOptions),
    /// Tcx attach options.
    TcxOrder(LinkOrder),
}

/// Options for SchedClassifier attach via netlink.
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
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SCHED_CLS, &mut self.data)
    }

    /// Attaches the program to the given `interface`.
    ///
    /// On kernels >= 6.6.0, it will attempt to use the TCX interface and attach as
    /// the last TCX program. On older kernels, it will fallback to using the
    /// legacy netlink interface.
    ///
    /// For finer grained control over link ordering use [`SchedClassifier::attach_with_options`].
    ///
    /// The returned value can be used to detach, see [SchedClassifier::detach].
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
        attach_type: TcAttachType,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        if !matches!(attach_type, TcAttachType::Custom(_))
            && KernelVersion::current().unwrap() >= KernelVersion::new(6, 6, 0)
        {
            self.attach_with_options(
                interface,
                attach_type,
                TcAttachOptions::TcxOrder(LinkOrder::default()),
            )
        } else {
            self.attach_with_options(
                interface,
                attach_type,
                TcAttachOptions::Netlink(NlOptions::default()),
            )
        }
    }

    /// Attaches the program to the given `interface` with options defined in [`TcAttachOptions`].
    ///
    /// The returned value can be used to detach, see [SchedClassifier::detach].
    ///
    /// # Errors
    ///
    /// [`TcError::NetlinkError`] is returned if attaching fails. A common cause
    /// of failure is not having added the `clsact` qdisc to the given
    /// interface, see [`qdisc_add_clsact`]
    ///
    pub fn attach_with_options(
        &mut self,
        interface: &str,
        attach_type: TcAttachType,
        options: TcAttachOptions,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let if_index = ifindex_from_ifname(interface)
            .map_err(|io_error| TcError::NetlinkError { io_error })?;
        self.do_attach(if_index, attach_type, options, true)
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
            TcLinkInner::FdLink(link) => {
                let fd = link.fd;
                let link_fd = fd.as_fd();

                bpf_link_update(link_fd.as_fd(), prog_fd, None, 0).map_err(|(_, io_error)| {
                    SyscallError {
                        call: "bpf_link_update",
                        io_error,
                    }
                })?;

                self.data
                    .links
                    .insert(SchedClassifierLink::new(TcLinkInner::FdLink(FdLink::new(
                        fd,
                    ))))
            }
            TcLinkInner::NlLink(NlLink {
                if_index,
                attach_type,
                priority,
                handle,
            }) => self.do_attach(
                if_index,
                attach_type,
                TcAttachOptions::Netlink(NlOptions { priority, handle }),
                false,
            ),
        }
    }

    fn do_attach(
        &mut self,
        if_index: u32,
        attach_type: TcAttachType,
        options: TcAttachOptions,
        create: bool,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();

        match options {
            TcAttachOptions::Netlink(options) => {
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
                .map_err(|io_error| TcError::NetlinkError { io_error })?;

                self.data
                    .links
                    .insert(SchedClassifierLink::new(TcLinkInner::NlLink(NlLink {
                        if_index,
                        attach_type,
                        priority,
                        handle,
                    })))
            }
            TcAttachOptions::TcxOrder(options) => {
                let link_fd = bpf_link_create(
                    prog_fd,
                    LinkTarget::IfIndex(if_index),
                    attach_type.tcx_attach_type()?,
                    None,
                    options.flags.bits(),
                    Some(&options.link_ref),
                )
                .map_err(|(_, io_error)| SyscallError {
                    call: "bpf_mprog_attach",
                    io_error,
                })?;

                self.data
                    .links
                    .insert(SchedClassifierLink::new(TcLinkInner::FdLink(FdLink::new(
                        link_fd,
                    ))))
            }
        }
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
    /// # use aya::programs::tc::{TcAttachType, SchedClassifier};
    /// # #[derive(Debug, thiserror::Error)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     Program(#[from] aya::programs::ProgramError),
    /// # }
    /// let (revision, programs) = SchedClassifier::query_tcx("eth0", TcAttachType::Ingress)?;
    /// # Ok::<(), Error>(())
    /// ```
    pub fn query_tcx(
        interface: &str,
        attach_type: TcAttachType,
    ) -> Result<(u64, Vec<ProgramInfo>), ProgramError> {
        let if_index = ifindex_from_ifname(interface)
            .map_err(|io_error| TcError::NetlinkError { io_error })?;

        let (revision, prog_ids) = query(
            ProgQueryTarget::IfIndex(if_index),
            attach_type.tcx_attach_type()?,
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
                &self.attach_type,
                self.priority,
                self.handle,
            )
        }
        .map_err(|io_error| TcError::NetlinkError { io_error })?;
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
    FdLink(FdLink),
    NlLink(NlLink),
}

impl Link for TcLinkInner {
    type Id = TcLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::FdLink(link) => TcLinkIdInner::FdLinkId(link.id()),
            Self::NlLink(link) => TcLinkIdInner::NlLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::FdLink(link) => link.detach(),
            Self::NlLink(link) => link.detach(),
        }
    }
}

id_as_key!(TcLinkInner, TcLinkIdInner);

impl<'a> TryFrom<&'a SchedClassifierLink> for &'a FdLink {
    type Error = LinkError;

    fn try_from(value: &'a SchedClassifierLink) -> Result<Self, Self::Error> {
        if let TcLinkInner::FdLink(fd) = value.inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl TryFrom<SchedClassifierLink> for FdLink {
    type Error = LinkError;

    fn try_from(value: SchedClassifierLink) -> Result<Self, Self::Error> {
        if let TcLinkInner::FdLink(fd) = value.into_inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl TryFrom<FdLink> for SchedClassifierLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_TCX as u32) {
            return Ok(Self::new(TcLinkInner::FdLink(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

define_link_wrapper!(
    /// The link used by [SchedClassifier] programs.
    SchedClassifierLink,
    /// The type returned by [SchedClassifier::attach]. Can be passed to [SchedClassifier::detach].
    SchedClassifierLinkId,
    TcLinkInner,
    TcLinkIdInner,
    SchedClassifier,
);

impl SchedClassifierLink {
    /// Constructs a [`SchedClassifierLink`] where the `if_name`, `attach_type`,
    /// `priority` and `handle` are already known. This may have been found from a link created by
    /// [SchedClassifier::attach], the output of the `tc filter` command or from the output of
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

/// Add the `clasct` qdisc to the given interface.
///
/// The `clsact` qdisc must be added to an interface before [`SchedClassifier`]
/// programs can be attached.
pub fn qdisc_add_clsact(if_name: &str) -> Result<(), io::Error> {
    let if_index = ifindex_from_ifname(if_name)?;
    unsafe { netlink_qdisc_add_clsact(if_index as i32) }
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
) -> Result<(), io::Error> {
    let cstr = CString::new(name)?;
    qdisc_detach_program_fast(if_name, attach_type, &cstr)
}

/// Detaches the programs with the given name as a C string.
/// Unlike qdisc_detach_program, this function does not allocate an additional
/// CString to.
///
/// # Errors
///
/// Returns [`io::ErrorKind::NotFound`] to indicate that no programs with the
/// given name were found, so nothing was detached. Other error kinds indicate
/// an actual failure while detaching a program.
fn qdisc_detach_program_fast(
    if_name: &str,
    attach_type: TcAttachType,
    name: &CStr,
) -> Result<(), io::Error> {
    let if_index = ifindex_from_ifname(if_name)? as i32;

    let filter_info = unsafe { netlink_find_filter_with_name(if_index, attach_type, name)? };
    if filter_info.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            name.to_string_lossy(),
        ));
    }

    for (prio, handle) in filter_info {
        unsafe { netlink_qdisc_detach(if_index, &attach_type, prio, handle)? };
    }

    Ok(())
}
