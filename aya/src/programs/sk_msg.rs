use std::ops::Deref;

use crate::{
    generated::{bpf_attach_type::BPF_SK_MSG_VERDICT, bpf_prog_type::BPF_PROG_TYPE_SK_MSG},
    maps::{sock::SocketMap, Map, SockMap},
    programs::{load_program, LinkRef, ProgAttachLink, ProgramData, ProgramError},
    sys::bpf_prog_attach,
};

/// A socket buffer program.
///
/// Socket buffer programs are attached to [sockmaps], and can be used to
/// redirect or drop packets. See the [`SockMap` documentation] for more info
/// and examples.
///
/// [sockmaps]: crate::maps::SockMap
/// [`SockMap` documentation]: crate::maps::SockMap
#[derive(Debug)]
pub struct SkMsg {
    pub(crate) data: ProgramData,
}

impl SkMsg {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SK_MSG, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    /// Attaches the program to the given sockmap.
    pub fn attach(&mut self, map: &dyn SocketMap) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let map_fd = map.fd_or_err()?;

        bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT).map_err(|(_, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_link_create".to_owned(),
                io_error,
            }
        })?;
        Ok(self.data.link(ProgAttachLink {
            prog_fd: Some(prog_fd),
            target_fd: Some(map_fd),
            attach_type: BPF_SK_MSG_VERDICT,
        }))
    }
}
