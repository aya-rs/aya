use aya::{
    EbpfError,
    pin::PinError,
    programs::{ProgramError, links::LinkError},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Ebpf(#[from] EbpfError),
    #[error("maximum number of programs are already attached: {0}")]
    MaxPrograms(usize),
    #[error("failed to pin: {0}")]
    Pin(#[from] PinError),
    #[error("{0}")]
    Program(#[from] ProgramError),
    #[error("failed to create a bpf link {0}")]
    Link(#[from] LinkError),
    #[error("failed to acquire flock on XDP directory: {0}")]
    Lock(nix::errno::Errno),
    #[error("dispatcher config file is invalid")]
    InvalidConfig,
    #[error("concurrent modification detected, retry required")]
    ConcurrentModification,
    #[error("XDP link is not an fd-based link; cannot pin")]
    NoFdLink,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
