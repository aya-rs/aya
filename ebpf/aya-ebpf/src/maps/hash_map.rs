//! Hash map types that can be shared between eBPF programs and user-space.

#![deny(missing_docs)]

use core::{borrow::Borrow, cell::UnsafeCell, marker::PhantomData, mem};

use aya_ebpf_bindings::bindings::bpf_map_type::{
    BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH,
};
use aya_ebpf_cty::c_long;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_HASH},
    insert, lookup,
    maps::PinningType,
    remove,
};

/// Generates a hash map definition with common methods.
macro_rules! hash_map {
    (
        $map_doc:literal,
        $map_doc_examples:literal,
        $name:ident,
        $t:ident
        $(,)?
    ) => {
        #[doc = include_str!($map_doc)]
        #[doc = $map_doc_examples]
        #[repr(transparent)]
        pub struct $name<K, V> {
            def: UnsafeCell<bpf_map_def>,
            _k: PhantomData<K>,
            _v: PhantomData<V>,
        }

        unsafe impl<K: Sync, V: Sync> Sync for $name<K, V> {}

        impl<K, V> $name<K, V> {
            /// Creates a new map with the given `max_entries` and `flags`.
            pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
                Self {
                    def: UnsafeCell::new(build_def::<K, V>(
                        $t,
                        max_entries,
                        flags,
                        PinningType::None,
                    )),
                    _k: PhantomData,
                    _v: PhantomData,
                }
            }

            /// Creates a new map with the given `max_entries` and `flags` that
            /// is pinned in the BPF filesystem in the directory designated by
            /// [`EbpfLoader::map_pin_path`][map-pin-path].
            ///
            /// [map-pin-path]: https://docs.rs/aya/latest/aya/struct.EbpfLoader.html#method.map_pin_path
            pub const fn pinned(max_entries: u32, flags: u32) -> Self {
                Self {
                    def: UnsafeCell::new(build_def::<K, V>(
                        BPF_MAP_TYPE_HASH,
                        max_entries,
                        flags,
                        PinningType::ByName,
                    )),
                    _k: PhantomData,
                    _v: PhantomData,
                }
            }

            #[doc = "Retrieves the value associated with `key` from the map."]
            #[doc = include_str!("map_safety.md")]
            #[inline]
            pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V> {
                unsafe { get(self.def.get(), key.borrow()) }
            }

            #[doc = "Retrieves the pointer associated with `key` from the map."]
            #[doc = include_str!("map_safety.md")]
            #[inline]
            pub fn get_ptr(&self, key: impl Borrow<K>) -> Option<*const V> {
                get_ptr(self.def.get(), key.borrow())
            }

            #[doc = "Retrieves the mutable pointer associated with `key` from the map."]
            #[doc = include_str!("map_safety.md")]
            #[inline]
            pub fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
                get_ptr_mut(self.def.get(), key.borrow())
            }

            /// Inserts a key-value pair into the map.
            #[inline]
            pub fn insert(
                &self,
                key: impl Borrow<K>,
                value: impl Borrow<V>,
                flags: u64,
            ) -> Result<(), c_long> {
                insert(self.def.get().cast(), key.borrow(), value.borrow(), flags)
            }

            /// Removes a key from the map.
            #[inline]
            pub fn remove(&self, key: impl Borrow<K>) -> Result<(), c_long> {
                remove(self.def.get().cast(), key.borrow())
            }
        }
    };
}

hash_map!(
    "docs/hash_map.md",
    r#"# Examples

```rust,no_run
use aya_ebpf::{
    maps::HashMap,
    macros::{map, tracepoint},
    programs::TracePointContext,
    EbpfContext as _,
};

/// A hash map that counts syscalls issued by different processes.
#[map]
static COUNTER: HashMap<
    // PID.
    u32,
    // Count of syscalls issued by the given process.
    u32
> = HashMap::with_max_entries(
    // Maximum number of elements. Reaching this capacity triggers an error.
    10,
    // Optional flags.
    0
);

/// A simple program attached to the `sys_enter` tracepoint that counts
/// syscalls.
#[tracepoint]
fn sys_enter(ctx: TracePointContext) {
    let pid = ctx.pid();

    if let Some(mut count) = COUNTER.get_ptr_mut(pid) {
        unsafe { *count += 1 };
    } else {
        COUNTER.insert(
            pid,
            // New value.
            1,
            // Optional flags.
            0
        );
    }
}
```"#,
    HashMap,
    BPF_MAP_TYPE_HASH,
);
hash_map!(
    "docs/lru_hash_map.md",
    r#"# Examples

```rust,no_run
use aya_ebpf::{
    maps::LruHashMap,
    macros::{map, tracepoint},
    programs::TracePointContext,
    EbpfContext as _,
};

/// A hash map that counts syscalls issued by different processes.
#[map]
static COUNTER: LruHashMap<
    // PID.
    u32,
    // Count of syscalls issued by the given process.
    u32,

> = LruHashMap::with_max_entries(
    // Maximum number of elements. Reaching this capacity triggers eviction of
    // the least used elements.
    10,
    // Optional flags.
    0
);

/// A simple program attached to the `sys_enter` tracepoint that counts
/// syscalls.
#[tracepoint]
fn sys_enter(ctx: TracePointContext) {
    let pid = ctx.pid();

    if let Some(mut count) = COUNTER.get_ptr_mut(pid) {
        unsafe { *count += 1 };
    } else {
        COUNTER.insert(
            pid,
            // New value.
            1,
            // Optional flags.
            0
        );
    }
}
```"#,
    LruHashMap,
    BPF_MAP_TYPE_LRU_HASH,
);
hash_map!(
    "docs/per_cpu_hash_map.md",
    r#"# Examples

```rust,no_run
use aya_ebpf::{
    maps::PerCpuHashMap,
    macros::{map, tracepoint},
    programs::TracePointContext,
    EbpfContext as _,
};

/// A hash map that counts syscalls issued by different processes.
#[map]
static COUNTER: PerCpuHashMap<
    // PID.
    u32,
    // Count of syscalls issued by the given process.
    u32
> = PerCpuHashMap::with_max_entries(
    // Maximum number of elements. Reaching this capacity triggers an error.
    10,
    // Optional flags.
    0
);

/// A simple program attached to the `sys_enter` tracepoint that counts
/// syscalls.
#[tracepoint]
fn sys_enter(ctx: TracePointContext) {
    let pid = ctx.pid();

    if let Some(mut count) = COUNTER.get_ptr_mut(pid) {
        unsafe { *count += 1 };
    } else {
        COUNTER.insert(
            pid,
            // New value.
            1,
            // Optional flags.
            0
        );
    }
}
```"#,
    PerCpuHashMap,
    BPF_MAP_TYPE_PERCPU_HASH
);
hash_map!(
    "docs/lru_per_cpu_hash_map.md",
    r#"# Examples

```rust,no_run
use aya_ebpf::{
    maps::LruPerCpuHashMap,
    macros::{map, tracepoint},
    programs::TracePointContext,
    EbpfContext as _,
};

/// A hash map that counts syscalls issued by different processes.
#[map]
static COUNTER: LruPerCpuHashMap<
    // PID.
    u32,
    // Count of syscalls issued by the given process.
    u32,

> = LruPerCpuHashMap::with_max_entries(
    // Maximum number of elements. Reaching this capacity triggers eviction of
    // the least used elements.
    10,
    // Optional flags.
    0
);

/// A simple program attached to the `sys_enter` tracepoint that counts
/// syscalls.
#[tracepoint]
fn sys_enter(ctx: TracePointContext) {
    let pid = ctx.pid();

    if let Some(mut count) = COUNTER.get_ptr_mut(pid) {
        unsafe { *count += 1 };
    } else {
        COUNTER.insert(
            pid,
            // New value.
            1,
            // Optional flags.
            0
        );
    }
}
```"#,
    LruPerCpuHashMap,
    BPF_MAP_TYPE_LRU_PERCPU_HASH
);

const fn build_def<K, V>(ty: u32, max_entries: u32, flags: u32, pin: PinningType) -> bpf_map_def {
    bpf_map_def {
        type_: ty,
        key_size: mem::size_of::<K>() as u32,
        value_size: mem::size_of::<V>() as u32,
        max_entries,
        map_flags: flags,
        id: 0,
        pinning: pin as u32,
    }
}

#[inline]
unsafe fn get<'a, K, V>(def: *mut bpf_map_def, key: &K) -> Option<&'a V> {
    get_ptr(def, key).map(|p| unsafe { &*p })
}

#[inline]
fn get_ptr_mut<K, V>(def: *mut bpf_map_def, key: &K) -> Option<*mut V> {
    lookup(def.cast(), key).map(|p| p.as_ptr())
}

#[inline]
fn get_ptr<K, V>(def: *mut bpf_map_def, key: &K) -> Option<*const V> {
    lookup::<_, V>(def.cast(), key).map(|p| p.as_ptr().cast_const())
}
