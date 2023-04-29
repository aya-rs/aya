#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PinningType {
    None = 0,
    ByName = 1,
}

pub mod array;
pub mod bloom_filter;
pub mod hash_map;
pub mod lpm_trie;
pub mod per_cpu_array;
pub mod perf;
pub mod program_array;
pub mod queue;
pub mod sock_hash;
pub mod sock_map;
pub mod stack;
pub mod stack_trace;

pub use array::Array;
pub use bloom_filter::BloomFilter;
pub use hash_map::{HashMap, LruHashMap, LruPerCpuHashMap, PerCpuHashMap};
pub use lpm_trie::LpmTrie;
pub use per_cpu_array::PerCpuArray;
pub use perf::{PerfEventArray, PerfEventByteArray};
pub use program_array::ProgramArray;
pub use queue::Queue;
pub use sock_hash::SockHash;
pub use sock_map::SockMap;
pub use stack::Stack;
pub use stack_trace::StackTrace;

#[cfg(feature = "btf-maps")]
mod btf_maps {
    #[repr(C)]
    pub(crate) struct MapDef<
        K,
        V,
        const MAP_TYPE: usize,
        const MAX_ENTRIES: usize,
        const FLAGS: usize = 0,
    > {
        r#type: *const [i32; MAP_TYPE],
        key: *const K,
        value: *const V,
        max_entries: *const [i32; MAX_ENTRIES],
        map_flags: *const [i32; FLAGS],
    }

    impl<K, V, const MAP_TYPE: usize, const MAX_ENTRIES: usize, const FLAGS: usize>
        MapDef<K, V, MAP_TYPE, MAX_ENTRIES, FLAGS>
    {
        pub const fn new() -> Self {
            Self {
                r#type: ::core::ptr::null(),
                key: ::core::ptr::null(),
                value: ::core::ptr::null(),
                max_entries: ::core::ptr::null(),
                map_flags: ::core::ptr::null(),
            }
        }
    }
}

#[cfg(feature = "btf-maps")]
pub(crate) use btf_maps::*;
