//! Network traffic control programs.
use thiserror::Error;

use std::{
    ffi::{CStr, CString},
    io,
    path::Path,
};

use crate::{
    generated::{
        bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS, TC_H_CLSACT, TC_H_MIN_EGRESS, TC_H_MIN_INGRESS,
    },
    programs::{define_link_wrapper, load_program, Link, ProgramData, ProgramError},
    sys::{
        netlink_find_filter_with_name, netlink_qdisc_add_clsact, netlink_qdisc_attach,
        netlink_qdisc_detach, NetlinkError,
    },
    util::{ifindex_from_ifname, tc_handler_make},
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
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
    pub(crate) name: Box<CStr>,
}

/// Errors from TC programs
#[derive(Debug, Error)]
pub enum TcError {
    /// netlink error while attaching ebpf program
    #[error(transparent)]
    NetlinkError(#[from] NetlinkError),

    /// the provided string contains a nul byte
    #[error(transparent)]
    NulError(#[from] std::ffi::NulError),

    #[error(transparent)]
    /// an IO error occurred
    IoError(#[from] io::Error),
    /// the clsact qdisc is already attached
    #[error("the clsact qdisc is already attached")]
    AlreadyAttached,
}

impl TcAttachType {
    pub(crate) fn parent(&self) -> u32 {
        match self {
            TcAttachType::Custom(parent) => *parent,
            TcAttachType::Ingress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_INGRESS),
            TcAttachType::Egress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_EGRESS),
        }
    }
}

/// Options for SchedClassifier attach
#[derive(Default)]
pub struct TcOptions {
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

    /// Attaches the program to the given `interface` using the default options.
    ///
    /// The returned value can be used to detach, see [SchedClassifier::detach].
    ///
    /// # Errors
    ///
    /// [`TcError::NetlinkError`] is returned if attaching fails. A common cause
    /// of failure is not having added the `clsact` qdisc to the given
    /// interface, see [`qdisc_add_clsact`]
    ///
    pub fn attach(
        &mut self,
        interface: &str,
        attach_type: TcAttachType,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        self.attach_with_options(interface, attach_type, TcOptions::default())
    }

    /// Attaches the program to the given `interface` with options defined in [`TcOptions`].
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
        options: TcOptions,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let if_index = ifindex_from_ifname(interface).map_err(TcError::IoError)?;
        let (priority, handle) = unsafe {
            netlink_qdisc_attach(
                if_index as i32,
                &attach_type,
                prog_fd,
                &self.name,
                options.priority,
                options.handle,
            )
        }
        .map_err(ProgramError::NetlinkError)?;

        self.data.links.insert(SchedClassifierLink::new(TcLink {
            if_index: if_index as i32,
            attach_type,
            priority,
            handle,
        }))
    }

    /// Detaches the program.
    ///
    /// See [SchedClassifier::attach].
    pub fn detach(&mut self, link_id: SchedClassifierLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(
        &mut self,
        link_id: SchedClassifierLinkId,
    ) -> Result<SchedClassifierLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        let cname = CString::new(data.name.clone().unwrap_or_default())
            .unwrap()
            .into_boxed_c_str();
        Ok(Self { data, name: cname })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) struct TcLinkId(i32, TcAttachType, u16, u32);

#[derive(Debug)]
struct TcLink {
    if_index: i32,
    attach_type: TcAttachType,
    priority: u16,
    handle: u32,
}

impl Link for TcLink {
    type Id = TcLinkId;

    fn id(&self) -> Self::Id {
        TcLinkId(self.if_index, self.attach_type, self.priority, self.handle)
    }

    fn detach(self) -> Result<(), ProgramError> {
        unsafe {
            netlink_qdisc_detach(self.if_index, &self.attach_type, self.priority, self.handle)
        }
        .map_err(ProgramError::NetlinkError)?;
        Ok(())
    }
}

define_link_wrapper!(
    /// The link used by [SchedClassifier] programs.
    SchedClassifierLink,
    /// The type returned by [SchedClassifier::attach]. Can be passed to [SchedClassifier::detach].
    SchedClassifierLinkId,
    TcLink,
    TcLinkId
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
    ) -> Result<SchedClassifierLink, io::Error> {
        let if_index = ifindex_from_ifname(if_name)?;
        Ok(SchedClassifierLink(Some(TcLink {
            if_index: if_index as i32,
            attach_type,
            priority,
            handle,
        })))
    }

    /// Returns the allocated priority. If none was provided at attach time, this was allocated for you.
    pub fn priority(&self) -> u16 {
        self.inner().priority
    }

    /// Returns the assigned handle. If none was provided at attach time, this was allocated for you.
    pub fn handle(&self) -> u32 {
        self.inner().handle
    }
}

/// Add the `clasct` qdisc to the given interface.
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
) -> Result<(), TcError> {
    let if_index = ifindex_from_ifname(if_name)? as i32;

    let filter_info = unsafe { netlink_find_filter_with_name(if_index, attach_type, name)? };
    if filter_info.is_empty() {
        return Err(TcError::IoError(io::Error::new(
            io::ErrorKind::NotFound,
            name.to_string_lossy(),
        )));
    }

    for (prio, handle) in filter_info {
        unsafe { netlink_qdisc_detach(if_index, &attach_type, prio, handle)? };
    }

    Ok(())
}
