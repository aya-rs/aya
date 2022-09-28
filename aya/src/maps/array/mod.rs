//! Array types.
#[allow(clippy::module_inception)]
mod array;
mod per_cpu_array;
mod program_array;

pub use array::*;
pub use per_cpu_array::PerCpuArray;
pub use program_array::ProgramArray;

use crate::maps::{MapData, MapError};

pub(crate) fn check_bounds(map: &MapData, index: u32) -> Result<(), MapError> {
    let max_entries = map.obj.max_entries();
    if index >= map.obj.max_entries() {
        Err(MapError::OutOfBounds { index, max_entries })
    } else {
        Ok(())
    }
}
