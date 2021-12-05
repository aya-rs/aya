//! Socket maps.
mod sock_hash;
mod sock_map;

use std::os::unix::io::RawFd;

use crate::maps::MapError;

pub use sock_hash::SockHash;
pub use sock_map::SockMap;
pub trait SocketMap {
    fn fd_or_err(&self) -> Result<RawFd, MapError>;
}

impl<'a, S: SocketMap> SocketMap for &'a S {
    fn fd_or_err(&self) -> Result<RawFd, MapError> {
        (*self).fd_or_err()
    }
}
