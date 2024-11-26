//! Rust idiomatic bindings for the AF_XDP socket interface.
//!
//! This module helps with creating suitable socket(s) from a memory allocation of chunks, sockets
//! for access to all four rings, binding to a specific `(ifname, queue_id)`, and for creating the
//! memory mapping to interact with all these queues directly.
//!
//! Please see https://docs.kernel.org/networking/af_xdp.html for a detailed explanation of AF_XDP.
//!
//! The entrypoint to the module is an instance of [`XdpSocketBuilder`], or for power users
//! the more low-level [`crate::Umem`].
//!
//! This module builds upon the `xdpilone` crate (https://crates.io/crates/xdpilone), with
//! some (optional) abstractions on top.

use std::{borrow::Cow, ffi::NulError, io::Error};

use thiserror::Error;

mod xsk;

pub use xsk::{
    BufIdx, DeviceQueue, IfInfo, ReadComplete, ReadRx, RingCons, RingProd, RingRx, RingTx, Socket,
    SocketConfig, Umem, UmemChunk, UmemConfig, User, WriteFill, WriteTx, XdpSocketBuilder,
};

/// Errors occuring from working with AF_XDP
#[derive(Error)]
pub enum XskError {
    /// Errno returned by the OS
    #[error("errno {errno}")]
    Errno {
        /// The errno
        errno: i32,
    },
    /// Error creating a [`CString`]
    #[error("nul error")]
    NulError(#[from] NulError),

    /// Invalid option in XskSocketBuilder
    #[error("invalid option: {0}")]
    SocketOptionError(String),

    /// Memory related errors
    #[error("memory error")]
    MemoryError(#[from] AllocationError),
}

/// Errors related to allocation of UMEM memory
#[derive(Error, Debug)]
pub enum AllocationError {
    /// The memory is not page aligned
    #[error("memory region not page aligned")]
    UmemUnaligned,
    /// The memory region is smaller than what's required by [`UmemConfig`]
    #[error("memory region too small")]
    UmemSize,
}

impl<'a> XskError {
    /// Create an error from the latest [`errno`].
    pub fn last_os_error() -> Self {
        Self::Errno {
            errno: Error::last_os_error().raw_os_error().unwrap_or(-1),
        }
    }

    /// Get the string that describes the error code in `errno`
    /// Returns [`None`] if the error type is any other than [`XskError::Errno`]
    pub fn get_strerror(&self) -> Option<Cow<'a, str>> {
        if let Self::Errno { errno } = self {
            unsafe {
                Some(Cow::Owned(
                    std::ffi::CStr::from_ptr(libc::strerror(*errno))
                        .to_string_lossy()
                        .into_owned(),
                ))
            }
        } else {
            None
        }
    }
}

impl std::fmt::Debug for XskError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Errno { errno } => {
                let description = self
                    .get_strerror()
                    .unwrap_or_else(|| Cow::Owned("Unknown error".to_string()));
                write!(f, "Errno({}: {})", errno, description)
            }
            Self::NulError(e) => {
                write!(f, "NulError {}", e)
            }
            Self::SocketOptionError(e) => {
                write!(f, "SocketOptionError {}", e)
            }
            Self::MemoryError(e) => {
                write!(f, "MemoryError {}", e)
            }
        }
    }
}
