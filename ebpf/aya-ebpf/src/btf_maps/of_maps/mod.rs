//! BTF-compatible BPF maps that contain references to other maps.
mod array;
mod hash_map;

pub use array::ArrayOfMaps;
pub use hash_map::HashOfMaps;
