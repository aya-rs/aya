//! Socket maps.
mod sock_hash;
mod sock_map;

use std::{
    io,
    os::fd::{AsFd, BorrowedFd},
};

pub use sock_hash::SockHash;
pub use sock_map::SockMap;

/// A socket map file descriptor.
#[repr(transparent)]
pub struct SockMapFd(super::MapFd);

impl SockMapFd {
    /// Creates a new instance that shares the same underlying file description as [`self`].
    pub fn try_clone(&self) -> io::Result<Self> {
        let Self(inner) = self;
        let super::MapFd(inner) = inner;
        let inner = inner.try_clone()?;
        let inner = super::MapFd(inner);
        Ok(Self(inner))
    }
}

impl AsFd for SockMapFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self(fd) = self;
        fd.as_fd()
    }
}
