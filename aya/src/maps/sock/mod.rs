//! Socket maps.
mod sock_hash;
mod sock_map;

pub use sock_hash::SockHash;
pub use sock_map::SockMap;

use std::os::unix::io::{AsRawFd, RawFd};

/// A socket map file descriptor.
#[derive(Copy, Clone)]
pub struct SockMapFd(RawFd);

impl AsRawFd for SockMapFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}
