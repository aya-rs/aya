//! Socket maps.
mod sock_hash;
mod sock_map;

pub use sock_hash::SockHash;
pub use sock_map::SockMap;

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

/// A socket map file descriptor.
#[derive(Copy, Clone)]
pub struct SockMapFd(RawFd);

impl AsRawFd for SockMapFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl AsFd for SockMapFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: This isn't necessarily safe, we need to find ways
        // to enforce that the file descriptor is still
        // valid. TODO(#612)
        unsafe { BorrowedFd::borrow_raw(self.0) }
    }
}
