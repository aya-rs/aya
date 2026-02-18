//! Support for BPF maps that contain references to other maps.
mod array;
mod hash_map;

pub use array::ArrayOfMaps;
pub use hash_map::HashOfMaps;

use super::{FromMapData, MapData, MapError};

/// Converts a map ID returned by the kernel into a typed map.
///
/// The kernel's map-of-maps API is asymmetric: update takes the FD of the inner map,
/// but lookup returns the ID. This helper converts the ID back to an FD and constructs
/// the typed map via [`FromMapData`].
fn map_from_id<M: FromMapData>(id: u32) -> Result<M, MapError> {
    let map_data = MapData::from_id(id)?;
    <M as FromMapData>::from_map_data(map_data)
}
