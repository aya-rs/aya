use core::{borrow::Borrow, cell::UnsafeCell};

use crate::{
    bindings::bpf_map_type::{
        BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH,
        BPF_MAP_TYPE_PERCPU_HASH,
    },
    btf_map_def,
    cty::{c_long, c_void},
    insert, lookup, remove,
};

/// Generates a hash map definition with common methods.
macro_rules! hash_map {
    (
        $map_doc:literal,
        $map_doc_examples:literal,
        $name:ident,
        $def:ident
        $(,)?
    ) => {
        #[doc = include_str!($map_doc)]
        #[doc = include_str!($map_doc_examples)]
        #[repr(transparent)]
        pub struct $name<K, V, const M: usize, const F: usize = 0>(UnsafeCell<$def<K, V, M, F>>);

        unsafe impl<K: Sync, V: Sync, const M: usize, const F: usize> Sync for $name<K, V, M, F> {}

        impl<K, V, const M: usize, const F: usize> $name<K, V, M, F> {
            #[expect(
                clippy::new_without_default,
                reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
            )]
            pub const fn new() -> Self {
                Self(UnsafeCell::new($def::new()))
            }

            #[doc = "Retrieves the value associated with `key` from the map."]
            #[doc = include_str!("../maps/map_safety.md")]
            #[inline]
            pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V> {
                unsafe { get(self.0.get().cast(), key.borrow()) }
            }

            #[doc = "Retrieves the pointer associated with `key` from the map."]
            #[doc = include_str!("../maps/map_safety.md")]
            #[inline]
            pub fn get_ptr(&self, key: impl Borrow<K>) -> Option<*const V> {
                get_ptr(self.0.get().cast(), key.borrow())
            }

            #[doc = "Retrieves the mutable pointer associated with `key` from the map."]
            #[doc = include_str!("../maps/map_safety.md")]
            #[inline]
            pub fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
                get_ptr_mut(self.0.get().cast(), key.borrow())
            }

            #[inline]
            pub fn insert(
                &self,
                key: impl Borrow<K>,
                value: impl Borrow<V>,
                flags: u64,
            ) -> Result<(), c_long> {
                insert(self.0.get().cast(), key.borrow(), value.borrow(), flags)
            }

            #[inline]
            pub fn remove(&self, key: impl Borrow<K>) -> Result<(), c_long> {
                remove(self.0.get().cast(), key.borrow())
            }
        }
    };
}

btf_map_def!(HashMapDef, BPF_MAP_TYPE_HASH);
btf_map_def!(LruHashMapDef, BPF_MAP_TYPE_LRU_HASH);
btf_map_def!(PerCpuHashMapDef, BPF_MAP_TYPE_PERCPU_HASH);
btf_map_def!(LruPerCpuHashMapDef, BPF_MAP_TYPE_LRU_PERCPU_HASH);

hash_map!(
    "../maps/docs/hash_map.md",
    "docs/hash_map_examples.md",
    HashMap,
    HashMapDef,
);

hash_map!(
    "../maps/docs/lru_hash_map.md",
    "docs/lru_hash_map_examples.md",
    LruHashMap,
    LruHashMapDef,
);

hash_map!(
    "../maps/docs/per_cpu_hash_map.md",
    "docs/per_cpu_hash_map_examples.md",
    PerCpuHashMap,
    PerCpuHashMapDef,
);

hash_map!(
    "../maps/docs/lru_per_cpu_hash_map.md",
    "docs/lru_per_cpu_hash_map_examples.md",
    LruPerCpuHashMap,
    LruPerCpuHashMapDef,
);

#[inline]
unsafe fn get<'a, K, V>(def: *mut c_void, key: &K) -> Option<&'a V> {
    get_ptr(def, key).map(|p| unsafe { &*p })
}

#[inline]
fn get_ptr_mut<K, V>(def: *mut c_void, key: &K) -> Option<*mut V> {
    lookup(def, key).map(|p| p.as_ptr())
}

#[inline]
fn get_ptr<K, V>(def: *mut c_void, key: &K) -> Option<*const V> {
    lookup::<_, V>(def.cast(), key).map(|p| p.as_ptr().cast_const())
}
