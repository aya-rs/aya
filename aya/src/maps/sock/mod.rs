//! Socket maps.
mod sock_hash;
mod sock_map;

pub use sock_hash::SockHash;
pub use sock_map::SockMap;

use std::os::{
    fd::{AsFd, BorrowedFd},
    unix::io::{AsRawFd, RawFd},
};

/// A socket map file descriptor.
#[derive(Copy, Clone)]
pub struct SockMapFd<'f>(BorrowedFd<'f>);

impl AsRawFd for SockMapFd<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for SockMapFd<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
