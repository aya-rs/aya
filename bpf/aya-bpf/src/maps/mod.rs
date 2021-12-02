#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum PinningType {
    None = 0,
    ByName = 1,
}

pub mod array;
pub mod array_of_maps;
pub mod hash_map;
pub mod hash_of_maps;
pub mod per_cpu_array;
pub mod perf;
pub mod queue;
pub mod sock_hash;
pub mod sock_map;
pub mod stack_trace;

pub use array::Array;
pub use array_of_maps::ArrayOfMaps;
pub use hash_map::HashMap;
pub use hash_of_maps::HashOfMaps;
pub use per_cpu_array::PerCpuArray;
pub use perf::{PerfEventArray, PerfEventByteArray};
pub use queue::Queue;
pub use sock_hash::SockHash;
pub use sock_map::SockMap;
pub use stack_trace::StackTrace;
