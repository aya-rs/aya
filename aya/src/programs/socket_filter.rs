use libc::{setsockopt, SOL_SOCKET};
use std::{io, mem, os::unix::prelude::RawFd};
use thiserror::Error;

use crate::{
    generated::{bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER, SO_ATTACH_BPF, SO_DETACH_BPF},
    programs::{load_program, Link, LinkRef, ProgramData, ProgramError},
};

#[derive(Debug, Error)]
pub enum SocketFilterError {
    #[error("setsockopt SO_ATTACH_BPF failed")]
    SoAttachBpfError {
        #[source]
        io_error: io::Error,
    },
}

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
                SO_ATTACH_BPF as i32,
                &prog_fd as *const _ as *const _,
                mem::size_of::<RawFd>() as u32,
            )
        };
        if ret < 0 {
            return Err(SocketFilterError::SoAttachBpfError {
                io_error: io::Error::last_os_error(),
            })?;
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
                    SO_DETACH_BPF as i32,
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
