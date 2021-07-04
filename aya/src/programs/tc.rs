//! Network traffic control programs.
use thiserror::Error;

use std::{ffi::CString, io, os::unix::io::RawFd};

use crate::{
    generated::{
        bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS, TC_H_CLSACT, TC_H_MIN_EGRESS, TC_H_MIN_INGRESS,
    },
    programs::{load_program, Link, LinkRef, ProgramData, ProgramError},
    sys::{netlink_qdisc_add_clsact, netlink_qdisc_attach, netlink_qdisc_detach},
    util::{ifindex_from_ifname, tc_handler_make},
};

/// Traffic control attach type.
#[derive(Debug, Clone, Copy)]
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
/// # let mut bpf = aya::Bpf::load(&[], None)?;
/// use std::convert::TryInto;
/// use aya::programs::{tc, SchedClassifier, TcAttachType};
///
/// // the clsact qdisc needs to be added before SchedClassifier programs can be
/// // attached
/// tc::qdisc_add_clsact("eth0")?;
///
/// let prog: &mut SchedClassifier = bpf.program_mut("redirect_ingress")?.try_into()?;
/// prog.load()?;
/// prog.attach("eth0", TcAttachType::Ingress)?;
///
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SCHED_CLS")]
pub struct SchedClassifier {
    pub(crate) data: ProgramData,
}

#[derive(Debug, Error)]
pub enum TcError {
    #[error("netlink error while attaching ebpf program to tc")]
    NetlinkError {
        #[source]
        io_error: io::Error,
    },
    #[error("the clsact qdisc is already attached")]
    AlreadyAttached,
}

#[derive(Debug)]
struct TcLink {
    if_index: i32,
    attach_type: TcAttachType,
    prog_fd: Option<RawFd>,
    priority: u32,
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

impl SchedClassifier {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SCHED_CLS, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    /// Attaches the program to the given `interface`.
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
    ) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let if_index = ifindex_from_ifname(interface)
            .map_err(|io_error| TcError::NetlinkError { io_error })?;
        let name = CString::new(self.name()).unwrap();
        let priority =
            unsafe { netlink_qdisc_attach(if_index as i32, &attach_type, prog_fd, &name) }
                .map_err(|io_error| TcError::NetlinkError { io_error })?;
        Ok(self.data.link(TcLink {
            if_index: if_index as i32,
            attach_type,
            prog_fd: Some(prog_fd),
            priority,
        }))
    }
}

impl Drop for TcLink {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

impl Link for TcLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if self.prog_fd.take().is_some() {
            unsafe { netlink_qdisc_detach(self.if_index, &self.attach_type, self.priority) }
                .map_err(|io_error| TcError::NetlinkError { io_error })?;
            Ok(())
        } else {
            Err(ProgramError::AlreadyDetached)
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
