use std::os::unix::io::AsRawFd;

use crate::{
    generated::{bpf_attach_type::BPF_CGROUP_SOCK_OPS, bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS},
    programs::{load_program, LinkRef, ProgAttachLink, ProgramData, ProgramError},
    sys::bpf_prog_attach,
};

#[derive(Debug)]
pub struct SockOps {
    pub(crate) data: ProgramData,
}

impl SockOps {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCK_OPS, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    /// Attaches the program to the given sockmap.
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let cgroup_fd = cgroup.as_raw_fd();

        bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS).map_err(|(_, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_prog_attach".to_owned(),
                io_error,
            }
        })?;
        Ok(self.data.link(ProgAttachLink {
            prog_fd: Some(prog_fd),
            target_fd: Some(cgroup_fd),
            attach_type: BPF_CGROUP_SOCK_OPS,
        }))
    }
}
