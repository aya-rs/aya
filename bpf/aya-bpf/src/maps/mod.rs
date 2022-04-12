//! Data structures used to store eBPF programs data and share them with the
//! user space.
//!
//! The eBPF platform provides data structures - maps in eBPF speak - that are
//! used store data and share it with the user space. When you define a static
//! variable of a map type (i.e. [`HashMap`](crate::maps::HashMap), that map gets
//! initialized during the eBPF object load into the kernel and is ready to
//! use by programs.
//!

//!
//! # Typed maps
//!
//! The eBPF API includes many map types each supporting different operations.
//!
//! Each type of map provides methods to access and modify the data in the map
//! (i.e. [`get`](crate::maps::HashMap::get), [`get_ptr_mut`](crate::maps::HashMap::get_ptr_mut),
//! [`insert`](crate::maps::HashMap::insert) and, [`remove`](crate::maps::HashMap::remove)).
//!
//! For example:
//!
//! ```no_run
//! # #![allow(dead_code)]
//! use aya_bpf::{macros::map, maps::HashMap};
//! # use aya_bpf::programs::TracePointContext;
//!
//! #[map]
//! static PID_TO_TGID: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
//!
//! # fn try_test(ctx: &TracePointContext) -> Result<i32, i32> {
//! let pid: u32 = ctx.pid();
//! let tgid: u32 = ctx.tgid();
//! PID_TO_TGID.insert(&pid, &tgid, 0).map_err(|e| e as i32)?;
//! # Ok(0)
//! # }
//! ```
//!
//! Please refer to documentation for each map type for more details.

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
