//! Kernel space probes.
//!
//! Kernel probes are eBPF programs that can be attached to almost any function inside the kernel.
use libc::pid_t;
use std::io;
use thiserror::Error;

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_KPROBE,
    programs::{
        load_program,
        probe::{attach, ProbeKind},
        LinkRef, ProgramData, ProgramError,
    },
};

/// A `kprobe` program.
#[derive(Debug)]
pub struct KProbe {
    pub(crate) data: ProgramData,
    pub(crate) kind: ProbeKind,
}

impl KProbe {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    pub fn attach(
        &mut self,
        fn_name: &str,
        offset: u64,
        pid: Option<pid_t>,
    ) -> Result<LinkRef, ProgramError> {
        attach(&mut self.data, self.kind, fn_name, offset, pid)
    }
}

#[derive(Debug, Error)]
pub enum KProbeError {
    #[error("`{filename}`")]
    FileError {
        filename: String,
        #[source]
        io_error: io::Error,
    },
}
