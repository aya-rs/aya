use std::{io, mem, os::unix::prelude::RawFd};

use libc::{setsockopt, SOL_SOCKET, SO_ATTACH_BPF};

use crate::generated::bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER;

use super::{load_program, ProgramData, ProgramError};

#[derive(Debug)]
pub struct SocketFilter {
    pub(crate) data: ProgramData,
}

impl SocketFilter {
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCKET_FILTER, &mut self.data)
    }

    pub fn attach(&self, socket: RawFd) -> Result<(), ProgramError> {
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

        Ok(())
    }
}
