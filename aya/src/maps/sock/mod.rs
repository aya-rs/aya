//! Socket maps.
mod sock_hash;
mod sock_map;

pub use sock_hash::SockHash;
pub use sock_map::SockMap;

use std::{
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::io::{AsRawFd, RawFd},
    },
    sync::Arc,
};

/// A socket map file descriptor.
#[derive(Clone)]
pub struct SockMapFd(Arc<OwnedFd>);

impl AsRawFd for SockMapFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for SockMapFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
