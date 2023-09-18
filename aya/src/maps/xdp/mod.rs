//! XDP maps.
mod cpu_map;
mod dev_map;
mod dev_map_hash;
mod xsk_map;

pub use cpu_map::CpuMap;
pub use dev_map::DevMap;
pub use dev_map_hash::DevMapHash;
pub use xsk_map::XskMap;

use super::MapError;
use thiserror::Error;

#[derive(Error, Debug)]
/// Errors occuring from working with XDP Maps
pub enum XdpMapError {
    /// Chained programs are not supported.
    #[error("chained programs are not supported by the current kernel")]
    ChainedProgramNotSupported,

    /// Map operation failed.
    #[error(transparent)]
    MapError(#[from] MapError),
}
