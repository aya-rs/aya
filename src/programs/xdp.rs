use std::{cell::RefCell, ffi::CString, rc::Rc};

use libc::if_nametoindex;

use crate::RawFd;
use crate::{
    generated::{bpf_attach_type::BPF_XDP, bpf_prog_type::BPF_PROG_TYPE_XDP},
    programs::{load_program, FdLink, Link, LinkRef, ProgramData, ProgramError},
    syscalls::bpf_link_create,
};

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

    pub fn attach(&mut self, interface: &str) -> Result<impl Link, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;

        let c_interface = CString::new(interface).unwrap();
        let if_index = unsafe { if_nametoindex(c_interface.as_ptr()) } as RawFd;
        if if_index == 0 {
            return Err(ProgramError::UnkownInterface {
                name: interface.to_string(),
            })?;
        }

        let link_fd = bpf_link_create(prog_fd, if_index, BPF_XDP, 0).map_err(|(_, io_error)| {
            ProgramError::BpfLinkCreateFailed {
                program: self.name(),
                io_error,
            }
        })? as RawFd;
        let link = Rc::new(RefCell::new(FdLink { fd: Some(link_fd) }));
        self.data.links.push(link.clone());

        Ok(LinkRef::new(&link))
    }
}
