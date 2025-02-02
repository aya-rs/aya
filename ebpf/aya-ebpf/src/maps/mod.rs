#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PinningType {
    None = 0,
    ByName = 1,
}

pub mod array;
pub mod array_of_maps;
pub mod bloom_filter;
pub mod hash_map;
pub mod hash_of_maps;
pub mod lpm_trie;
pub mod per_cpu_array;
pub mod perf;
pub mod program_array;
pub mod queue;
pub mod ring_buf;
pub mod sock_hash;
pub mod sock_map;
pub mod stack;
pub mod stack_trace;
pub mod xdp;

pub use array::Array;
pub use array_of_maps::ArrayOfMaps;
pub use bloom_filter::BloomFilter;
pub use hash_map::{HashMap, LruHashMap, LruPerCpuHashMap, PerCpuHashMap};
pub use hash_of_maps::HashOfMaps;
pub use lpm_trie::LpmTrie;
pub use per_cpu_array::PerCpuArray;
pub use perf::{PerfEventArray, PerfEventByteArray};
pub use program_array::ProgramArray;
pub use queue::Queue;
pub use ring_buf::RingBuf;
pub use sock_hash::SockHash;
pub use sock_map::SockMap;
pub use stack::Stack;
pub use stack_trace::StackTrace;
pub use xdp::{CpuMap, DevMap, DevMapHash, XskMap};

// Map is a marker trait for all eBPF maps that can be used in a map of maps.
pub unsafe trait InnerMap {}
