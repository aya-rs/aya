use thiserror::Error;

use std::{io, os::unix::io::RawFd};

use crate::{
    generated::{
        TC_H_CLSACT, TC_H_MIN_INGRESS, TC_H_MIN_EGRESS,
        bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS,
    },
    programs::{Link, LinkRef, load_program, ProgramData, ProgramError},
    sys::{netlink_qdisc_add_clsact, netlink_qdisc_attach, netlink_qdisc_detach},
    util::{ifindex_from_ifname, tc_handler_make},
};

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum TcAttachPoint {
    Ingress = TC_H_MIN_INGRESS,
    Egress = TC_H_MIN_EGRESS,
    Custom,
}

#[derive(Debug)]
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
    attach_point: TcAttachPoint,
    prog_fd: Option<RawFd>,
    priority: u32,
}

impl TcAttachPoint {
    pub fn tcm_parent(&self, parent: u32) -> Result<u32, io::Error> {
        match *self {
            TcAttachPoint::Custom => {
                if parent == 0 {
                    return Err(io::Error::new(io::ErrorKind::Other, "Parent must be non-zero for Custom attach points"));
                }
                Ok(parent)
            }
            _ => Ok(tc_handler_make(TC_H_CLSACT, (*self).clone() as u32))
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

    /// Attaches the program to the given `interface` and `attach-point`
    pub fn attach(&mut self, interface: &str, attach_point: TcAttachPoint) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let if_index = unsafe { ifindex_from_ifname(interface) }
                         .map_err(|io_error| TcError::NetlinkError { io_error })?;
        let prog_name = self.name();
        let priority = unsafe { netlink_qdisc_attach(if_index as i32, &attach_point, prog_fd, &prog_name[..]) }
            .map_err(|io_error| TcError::NetlinkError { io_error })?;
        Ok(self.data.link(TcLink {
            if_index: if_index as i32,
            attach_point,
            prog_fd: Some(prog_fd),
            priority,
        }))
    }
    
    /// Add "clasct" qdisc to an interface
    pub fn qdisc_add_clsact_to_interface(if_name: &str) -> Result<(), ProgramError> {
        // unsafe wrapper
        let if_index = unsafe { ifindex_from_ifname(if_name) }
                           .map_err(|_| ProgramError::UnknownInterface {name: if_name.to_string()})?;
        unsafe { netlink_qdisc_add_clsact(if_index as i32) }
                           .map_err(|io_error| TcError::NetlinkError { io_error })?;
        Ok(())
    }
}

impl Drop for TcLink {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

impl Link for TcLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(_) = self.prog_fd.take() {
            unsafe { netlink_qdisc_detach(self.if_index, &self.attach_point, self.priority) }
                .map_err(|io_error| TcError::NetlinkError { io_error })?;
            Ok(())
        } else {
            Err(ProgramError::AlreadyDetached)
        }
    }
}

