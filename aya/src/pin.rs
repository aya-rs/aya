//! Pinning BPF objects to the BPF filesystem.

use crate::sys::SyscallError;
use thiserror::Error;

/// An error ocurred working with a pinned BPF object.
#[derive(Error, Debug)]
pub enum PinError {
    /// The object has already been pinned.
    #[error("the BPF object `{name}` has already been pinned")]
    AlreadyPinned {
        /// Object name.
        name: String,
    },
    /// The object FD is not known by Aya.
    #[error("the BPF object `{name}`'s FD is not known")]
    NoFd {
        /// Object name.
        name: String,
    },
    /// The path for the BPF object is not valid.
    #[error("invalid pin path `{error}`")]
    InvalidPinPath {
        /// The error message.
        error: String,
    },
    /// An error ocurred making a syscall.
    #[error(transparent)]
    SyscallError(#[from] SyscallError),
}
