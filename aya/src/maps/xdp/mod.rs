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

use super::{MapData, MapError};

/// Returns whether the values of a CPU or device map include a program, as
/// determined by the value size the map was created with.
///
/// Checking the map rather than probing the kernel keeps this consistent with
/// how the map was created, e.g. with a BPF token or by another process.
pub(crate) const fn has_prog_id<V>(map: &MapData) -> bool {
    map.obj.value_size() as usize == size_of::<V>()
}

#[derive(Error, Debug)]
/// Errors occurring from working with XDP maps.
pub enum XdpMapError {
    /// Chained programs are not supported.
    #[error("chained programs are not supported by the current kernel")]
    ChainedProgramNotSupported,

    /// Map operation failed.
    #[error(transparent)]
    MapError(#[from] MapError),
}
