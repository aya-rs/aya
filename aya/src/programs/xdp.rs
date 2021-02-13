use libc::if_nametoindex;
use std::{ffi::CString, io};
use thiserror::Error;

use crate::{
    generated::{bpf_attach_type::BPF_XDP, bpf_prog_type::BPF_PROG_TYPE_XDP, XDP_FLAGS_REPLACE},
    programs::{load_program, FdLink, Link, LinkRef, ProgramData, ProgramError},
    sys::bpf_link_create,
    sys::kernel_version,
    sys::netlink_set_xdp_fd,
    RawFd,
};

#[derive(Debug, Error)]
pub enum XdpError {
    #[error("netlink error while attaching XDP program")]
    NetlinkError {
        #[source]
        io_error: io::Error,
    },
}

#[derive(Debug)]
pub struct Xdp {
    pub(crate) data: ProgramData,
}

impl Xdp {
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_XDP, &mut self.data)
    }

    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    pub fn attach(&mut self, interface: &str) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;

        let c_interface = CString::new(interface).unwrap();
        let if_index = unsafe { if_nametoindex(c_interface.as_ptr()) } as RawFd;
        if if_index == 0 {
            return Err(ProgramError::UnknownInterface {
                name: interface.to_string(),
            })?;
        }

        let k_ver = kernel_version().unwrap();
        if k_ver >= (5, 7, 0) {
            let link_fd = bpf_link_create(prog_fd, if_index + 42, BPF_XDP, 0)
                .map_err(|(_, io_error)| ProgramError::BpfLinkCreateError { io_error })?
                as RawFd;
            Ok(self
                .data
                .link(XdpLink::FdLink(FdLink { fd: Some(link_fd) })))
        } else {
            unsafe { netlink_set_xdp_fd(if_index, prog_fd, None, 0) }
                .map_err(|io_error| XdpError::NetlinkError { io_error })?;

            Ok(self.data.link(XdpLink::NlLink(NlLink {
                if_index,
                prog_fd: Some(prog_fd),
            })))
        }
    }
}

#[derive(Debug)]
struct NlLink {
    if_index: i32,
    prog_fd: Option<RawFd>,
}

impl Link for NlLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(fd) = self.prog_fd.take() {
            let _ = unsafe { netlink_set_xdp_fd(self.if_index, -1, Some(fd), XDP_FLAGS_REPLACE) };
            Ok(())
        } else {
            Err(ProgramError::AlreadyDetached)
        }
    }
}

impl Drop for NlLink {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

#[derive(Debug)]
enum XdpLink {
    FdLink(FdLink),
    NlLink(NlLink),
}

impl Link for XdpLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        match self {
            XdpLink::FdLink(link) => link.detach(),
            XdpLink::NlLink(link) => link.detach(),
        }
    }
}
