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
    #[error("invalid pin path `{}`", path.display())]
    InvalidPinPath {
        /// The path.
        path: std::path::PathBuf,

        #[source]
        /// The source error.
        error: std::ffi::NulError,
    },
    /// An error ocurred making a syscall.
    #[error(transparent)]
    SyscallError(#[from] SyscallError),

    /// An error occured unpinning an object.
    #[error("Failed to remove pins {paths:?} for object {name}")]
    UnpinError {
        /// Object name.
        name: String,

        /// The paths.
        paths: Vec<std::path::PathBuf>,

        /// The source error
        errors: Vec<std::io::Error>,
    },
}
