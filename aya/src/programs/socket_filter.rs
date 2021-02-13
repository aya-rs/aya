use libc::{setsockopt, SOL_SOCKET, SO_ATTACH_BPF, SO_DETACH_BPF};
use std::{io, mem, os::unix::prelude::RawFd};

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER,
    programs::{load_program, Link, LinkRef, ProgramData, ProgramError},
};

#[derive(Debug)]
pub struct SocketFilter {
    pub(crate) data: ProgramData,
}

impl SocketFilter {
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCKET_FILTER, &mut self.data)
    }

    pub fn attach(&mut self, socket: RawFd) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;

        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                SO_ATTACH_BPF,
                &prog_fd as *const _ as *const _,
                mem::size_of::<RawFd>() as u32,
            )
        };
        if ret < 0 {
            return Err(ProgramError::SocketFilterError {
                io_error: io::Error::last_os_error(),
            });
        }

        Ok(self.data.link(SocketFilterLink {
            socket,
            prog_fd: Some(prog_fd),
        }))
    }
}

#[derive(Debug)]
struct SocketFilterLink {
    socket: RawFd,
    prog_fd: Option<RawFd>,
}

impl Link for SocketFilterLink {
    fn detach(&mut self) -> Result<(), ProgramError> {
        if let Some(fd) = self.prog_fd.take() {
            unsafe {
                setsockopt(
                    self.socket,
                    SOL_SOCKET,
                    SO_DETACH_BPF,
                    &fd as *const _ as *const _,
                    mem::size_of::<RawFd>() as u32,
                );
            }
            Ok(())
        } else {
            Err(ProgramError::AlreadyDetached)
        }
    }
}

impl Drop for SocketFilterLink {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
