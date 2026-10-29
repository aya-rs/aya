//! XDP maps.
mod cpu_map;
mod dev_map;
mod dev_map_hash;
mod xsk_map;

pub use cpu_map::CpuMap;
pub use dev_map::DevMap;
pub use dev_map_hash::DevMapHash;
use thiserror::Error;
pub use xsk_map::XskMap;

use super::MapError;

#[derive(Error, Debug)]
/// Errors occurring from working with XDP maps.
pub enum XdpMapError {
    /// Chained programs are not supported.
    ///
    /// This occurs either because the map was declared with a 4-byte value
    /// (no program-fd slot) or because the kernel does not support chained
    /// programs for this map type.
    #[error(
        "chained programs are not supported: either the map uses a 4-byte \
         value layout or the current kernel lacks the required feature"
    )]
    ChainedProgramNotSupported,

    /// Map operation failed.
    #[error(transparent)]
    MapError(#[from] MapError),
}
