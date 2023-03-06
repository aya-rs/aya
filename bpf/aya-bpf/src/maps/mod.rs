//! Data structures used to setup and share data with eBPF programs.
//!
//! The eBPF platform provides data structures - maps in eBPF speak - that are
//! used to store data and share them with user-space.
//!
//! # Examples
//!
//! XDP program using a [`HashMap<u32, u32>`](HashMap) to block traffic from
//! IP addresses defined in it:
//!
//! ```no_run
//! # use core::ffi::c_long;
//! use aya_bpf::{bindings::xdp_action, macros::map, maps::HashMap};
//! # use aya_bpf::programs::XdpContext;
//!
//! /// A map which stores IP addresses to block.
//! #[map]
//! static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
//!
//! # fn parse_src_addr(ctx: &XdpContext) -> u32 { 0 }
//! # fn try_test(ctx: &XdpContext) -> Result<(), c_long> {
//! let src_addr = parse_src_addr(ctx);
//! if BLOCKLIST.get(&src_addr).is_some() {
//!     return Ok(xdp_action::XDP_DROP);
//! }
//! Ok(xdp_action::XDP_PASS)
//! # }
//! ```

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
