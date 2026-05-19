//! BTF-compatible BPF hash map variants.

#![deny(missing_docs)]

use core::{borrow::Borrow, ptr::NonNull};

use aya_ebpf_bindings::bindings::{BPF_F_NO_COMMON_LRU, BPF_F_NO_PREALLOC};

use crate::{btf_maps::btf_map_def, insert, lookup, remove};

macro_rules! define_btf_hash_map {
    // Enforces kernel constraints from kernel/bpf/hashtab.c
    // htab_map_alloc_check. The 8-byte value-alignment ceiling applies to
    // all four variants: shared hashtab slots sit at
    // `htab_elem.key[__aligned(8)] + round_up(key_size, 8)`, and per-CPU
    // slots come from `bpf_map_alloc_percpu(..., 8, ...)`. Values with
    // stricter alignment would be under-aligned for `&V` returned by
    // `get`.
    (
        $(#[$top_attr:meta])*
        $name:ident,
        map_type: $map_type:ident,
        rejected_flag: ($rejected_flag:expr, $rejected_flag_msg:literal $(,)?),
        get_doc: { $(#[$get_attr:meta])+ } $(,)?
    ) => {
        btf_map_def!(
            $(#[$top_attr])*
            pub struct $name<K, V; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
            map_type: $map_type,
            max_entries: MAX_ENTRIES,
            map_flags: FLAGS,
            key_type: K,
            value_type: V,
        );

        impl<K, V, const MAX_ENTRIES: usize, const FLAGS: usize> $name<K, V, MAX_ENTRIES, FLAGS> {
            const _CHECK: () = {
                assert!(
                    size_of::<K>() > 0,
                    concat!(stringify!($name), " key must be non-zero sized."),
                );
                assert!(
                    size_of::<V>() > 0,
                    concat!(stringify!($name), " value must be non-zero sized."),
                );
                assert!(
                    MAX_ENTRIES > 0,
                    concat!(stringify!($name), " max_entries must be greater than zero."),
                );
                assert!(FLAGS & $rejected_flag as usize == 0, $rejected_flag_msg);
                assert!(
                    align_of::<V>() <= 8,
                    concat!(
                        stringify!($name),
                        " value alignment must be at most 8 bytes.",
                    ),
                );
            };

            $(#[$get_attr])+
            #[inline(always)]
            pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V> {
                let () = Self::_CHECK;
                // SAFETY: The caller upholds the aliasing invariants documented above.
                unsafe { self.lookup(key.borrow()).map(|p| p.as_ref()) }
            }

            /// Returns a `*const V` for the value associated with `key`.
            ///
            /// The same aliasing caveat as [`Self::get`] applies; it is the
            /// caller's responsibility to decide whether dereferencing the
            /// pointer is safe.
            #[inline(always)]
            pub fn get_ptr(&self, key: impl Borrow<K>) -> Option<*const V> {
                let () = Self::_CHECK;
                unsafe { self.lookup(key.borrow()).map(|p| p.as_ptr().cast_const()) }
            }

            /// Returns a `*mut V` for the value associated with `key`.
            ///
            /// The same aliasing caveat as [`Self::get`] applies, and the
            /// caller must additionally avoid concurrent writes.
            #[inline(always)]
            pub fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
                let () = Self::_CHECK;
                unsafe { self.lookup(key.borrow()).map(NonNull::as_ptr) }
            }

            #[inline(always)]
            unsafe fn lookup(&self, key: &K) -> Option<NonNull<V>> {
                lookup(self.as_ptr(), key)
            }

            /// Inserts `value` under `key`.
            ///
            /// `flags` is forwarded to `bpf_map_update_elem`; common choices
            /// are `BPF_ANY`, `BPF_NOEXIST`, and `BPF_EXIST`.
            #[inline(always)]
            pub fn insert(
                &self,
                key: impl Borrow<K>,
                value: impl Borrow<V>,
                flags: u64,
            ) -> Result<(), i32> {
                let () = Self::_CHECK;
                insert(self.as_ptr(), key.borrow(), value.borrow(), flags)
            }

            /// Removes the entry for `key`.
            #[inline(always)]
            pub fn remove(&self, key: impl Borrow<K>) -> Result<(), i32> {
                let () = Self::_CHECK;
                remove(self.as_ptr(), key.borrow())
            }
        }
    };
}

define_btf_hash_map!(
    /// A BTF-compatible BPF hash map.
    ///
    /// Stores values of type `V` keyed by `K` with kernel-managed collision
    /// chaining. Entries persist until explicitly removed or the map is
    /// dropped.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.19.
    ///
    /// # Flag and size restrictions
    ///
    /// `BPF_F_NO_COMMON_LRU` is rejected by the kernel on non-LRU hash maps
    /// and returns `EINVAL`. The key and value must both be non-zero sized
    /// and `max_entries` must be at least 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::HashMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static COUNTS: HashMap<u32, u64, 1024> = HashMap::new();
    /// ```
    HashMap,
    map_type: BPF_MAP_TYPE_HASH,
    rejected_flag: (
        BPF_F_NO_COMMON_LRU,
        "BPF_F_NO_COMMON_LRU is only valid on LRU hash variants.",
    ),
    get_doc: {
        /// Returns a reference to the value associated with `key`.
        ///
        /// # Safety
        ///
        /// The returned reference is only valid until the next `insert` or
        /// `remove` on this map. Unless the map was created with
        /// `BPF_F_NO_PREALLOC`, the kernel keeps a preallocated freelist
        /// and recycles a slot the moment its entry is removed; a
        /// subsequent `insert` into that slot reuses the bytes the
        /// reference points to, causing garbage to be read or corruption
        /// on write.
    },
);

define_btf_hash_map!(
    /// A BTF-compatible BPF LRU hash map.
    ///
    /// Stores values of type `V` keyed by `K`. When the map is full, the
    /// kernel evicts the least-recently-used entry on insert. Lookups from
    /// BPF context bump the LRU position; passing `BPF_F_NO_COMMON_LRU`
    /// switches bookkeeping to per-CPU LRU lists at the cost of rounding
    /// `max_entries` up to a multiple of `num_possible_cpus()`.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.19.
    /// `BPF_MAP_TYPE_LRU_HASH` itself dates back to 4.10, but BTF map
    /// definitions require the BTF pretty-print path for hashtab maps,
    /// which landed in 4.19.
    ///
    /// # Flag and size restrictions
    ///
    /// `BPF_F_NO_PREALLOC` is rejected by the kernel on LRU hash maps and
    /// returns `ENOTSUPP`. The key and value must both be non-zero sized
    /// and `max_entries` must be at least 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::LruHashMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static RECENT: LruHashMap<u32, u64, 1024> = LruHashMap::new();
    /// ```
    LruHashMap,
    map_type: BPF_MAP_TYPE_LRU_HASH,
    rejected_flag: (
        BPF_F_NO_PREALLOC,
        "BPF_F_NO_PREALLOC is rejected by LRU hash maps.",
    ),
    get_doc: {
        /// Returns a reference to the value associated with `key`, bumping
        /// its LRU position.
        ///
        /// # Safety
        ///
        /// The returned reference is only valid until the next `insert` or
        /// `remove` on this map. When the map is full, an `insert` evicts
        /// the least-recently-used entry and recycles its slot; if that
        /// slot held the borrowed entry, the reference now aliases the new
        /// value. A `remove` of the borrowed entry has the same effect.
    },
);

define_btf_hash_map!(
    /// A BTF-compatible BPF per-CPU hash map.
    ///
    /// Stores a distinct value of type `V` per CPU, keyed by `K`. Reads and
    /// writes from BPF context reference the slot belonging to the CPU that
    /// executes the program; other CPUs' slots are accessible only from
    /// user space via `bpf_map_lookup_elem` with a `num_possible_cpus()`-sized
    /// value buffer.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.19.
    /// `BPF_MAP_TYPE_PERCPU_HASH` itself dates back to 4.6, but BTF map
    /// definitions require the BTF pretty-print path for hashtab maps,
    /// which landed in 4.19.
    ///
    /// # Flag and size restrictions
    ///
    /// `BPF_F_NO_COMMON_LRU` is rejected by the kernel on non-LRU hash maps
    /// and returns `EINVAL`. Each per-CPU value must also satisfy
    /// `round_up(size_of::<V>(), 8) <= PCPU_MIN_UNIT_SIZE` (32 KiB on most
    /// kernel builds); violations fail with `E2BIG` at load time. The key
    /// and value must both be non-zero sized and `max_entries` must be at
    /// least 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::PerCpuHashMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static COUNTS: PerCpuHashMap<u32, u64, 1024> = PerCpuHashMap::new();
    /// ```
    PerCpuHashMap,
    map_type: BPF_MAP_TYPE_PERCPU_HASH,
    rejected_flag: (
        BPF_F_NO_COMMON_LRU,
        "BPF_F_NO_COMMON_LRU is only valid on LRU hash variants.",
    ),
    get_doc: {
        /// Returns a reference to the current CPU's value for `key`.
        ///
        /// # Safety
        ///
        /// The returned reference is only valid until the next `insert` or
        /// `remove` on this map. Unless the map was created with
        /// `BPF_F_NO_PREALLOC`, the kernel keeps a preallocated freelist
        /// and recycles a slot the moment its entry is removed; a
        /// subsequent `insert` into that slot reuses the bytes the
        /// reference points to, causing garbage to be read or corruption
        /// on write.
    },
);

define_btf_hash_map!(
    /// A BTF-compatible BPF LRU per-CPU hash map.
    ///
    /// Stores a distinct value of type `V` per CPU, keyed by `K`, with LRU
    /// eviction when the map fills. Reads and writes from BPF context
    /// reference the slot belonging to the CPU that executes the program;
    /// LRU bookkeeping defaults to a single shared list across CPUs and may
    /// be switched to per-CPU LRU lists with `BPF_F_NO_COMMON_LRU`, at the
    /// cost of rounding `max_entries` up to a multiple of
    /// `num_possible_cpus()`.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.19.
    /// `BPF_MAP_TYPE_LRU_PERCPU_HASH` itself dates back to 4.10, but BTF
    /// map definitions require the BTF pretty-print path for hashtab maps,
    /// which landed in 4.19.
    ///
    /// # Flag and size restrictions
    ///
    /// `BPF_F_NO_PREALLOC` is rejected by the kernel on LRU hash maps and
    /// returns `ENOTSUPP`. Each per-CPU value must also satisfy
    /// `round_up(size_of::<V>(), 8) <= PCPU_MIN_UNIT_SIZE` (32 KiB on most
    /// kernel builds); violations fail with `E2BIG` at load time. The key
    /// and value must both be non-zero sized and `max_entries` must be at
    /// least 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::LruPerCpuHashMap, macros::btf_map};
    ///
    /// #[btf_map]
    /// static RECENT: LruPerCpuHashMap<u32, u64, 1024> = LruPerCpuHashMap::new();
    /// ```
    LruPerCpuHashMap,
    map_type: BPF_MAP_TYPE_LRU_PERCPU_HASH,
    rejected_flag: (
        BPF_F_NO_PREALLOC,
        "BPF_F_NO_PREALLOC is rejected by LRU hash maps.",
    ),
    get_doc: {
        /// Returns a reference to the current CPU's value for `key`,
        /// bumping its LRU position.
        ///
        /// # Safety
        ///
        /// The returned reference is only valid until the next `insert` or
        /// `remove` on this map. When the map is full, an `insert` evicts
        /// the least-recently-used entry and recycles its slot; if that
        /// slot held the borrowed entry, the reference now aliases the new
        /// value. A `remove` of the borrowed entry has the same effect.
    },
);
