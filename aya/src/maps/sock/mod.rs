//! Socket maps.
mod sock_hash;
mod sock_map;

use std::os::unix::io::RawFd;

use crate::maps::MapError;

pub use sock_hash::SockHash;
pub use sock_map::SockMap;

/// Shared behaviour between [`SockHash`] and [`SockMap`]
pub trait SocketMap {
    /// Returns a [`Result`] containg the map fd or an error if there is none
    fn fd_or_err(&self) -> Result<RawFd, MapError>;
}
