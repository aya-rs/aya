use core::{cell::UnsafeCell, marker::PhantomData, ptr::NonNull};

use aya_ebpf_cty::{c_long, c_void};

use crate::helpers::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem};

pub mod array;
pub mod bloom_filter;
pub mod hash_map;
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
pub use bloom_filter::BloomFilter;
pub use hash_map::{HashMap, LruHashMap, PerCpuHashMap};
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

/// A marker used to remove names of annotated types in LLVM debug info and
/// therefore also in BTF.
///
/// # Example
#[repr(transparent)]
pub(crate) struct AyaBtfMapMarker(PhantomData<()>);

impl AyaBtfMapMarker {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

#[macro_export]
macro_rules! btf_map_def {
    ($name:ident, $t:ident) => {
        #[allow(dead_code)]
        pub struct $name<K, V, const M: usize, const F: usize = 0> {
            r#type: *const [i32; $t as usize],
            key: *const K,
            value: *const V,
            max_entries: *const [i32; M],
            map_flags: *const [i32; F],

            // Anonymize the struct.
            _anon: $crate::btf_maps::AyaBtfMapMarker,
        }

        // Implementing `Default` makes no sense in this case. Maps are always
        // global variables, so they need to be instantiated with a `const`
        // method. `Default::default` method is not `const`.
        #[allow(clippy::new_without_default)]
        impl<K, V, const M: usize, const F: usize> $name<K, V, M, F> {
            pub const fn new() -> $name<K, V, M, F> {
                $name {
                    r#type: &[0i32; $t as usize],
                    key: ::core::ptr::null(),
                    value: ::core::ptr::null(),
                    max_entries: &[0i32; M],
                    map_flags: &[0i32; F],
                    _anon: $crate::btf_maps::AyaBtfMapMarker::new(),
                }
            }
        }
    };
}

#[inline]
fn insert<M, K, V>(def: &UnsafeCell<M>, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
    let key: *const _ = key;
    let value: *const _ = value;
    match unsafe { bpf_map_update_elem(def.get().cast(), key.cast(), value.cast(), flags) } {
        0 => Ok(()),
        ret => Err(ret),
    }
}

#[inline]
fn remove<M, K>(def: &UnsafeCell<M>, key: &K) -> Result<(), c_long> {
    let key: *const _ = key;
    match unsafe { bpf_map_delete_elem(def.get().cast(), key.cast()) } {
        0 => Ok(()),
        ret => Err(ret),
    }
}

#[inline]
fn lookup<M, K, V>(def: &UnsafeCell<M>, index: &K) -> Option<NonNull<V>> {
    let ptr = unsafe { bpf_map_lookup_elem(def.get().cast(), &index as *const _ as *const c_void) };
    NonNull::new(ptr as *mut V)
}
