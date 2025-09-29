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

btf_map_def!(HashMapDef, BPF_MAP_TYPE_HASH);

#[repr(transparent)]
pub struct HashMap<K, V, const M: usize, const F: usize = 0>(UnsafeCell<HashMapDef<K, V, M, F>>);

unsafe impl<K: Sync, V: Sync, const M: usize, const F: usize> Sync for HashMap<K, V, M, F> {}

impl<K, V, const M: usize, const F: usize> HashMap<K, V, M, F> {
    #[expect(
        clippy::new_without_default,
        reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
    )]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(HashMapDef::new()))
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

    /// Inserts a key-value pair into the map.
    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.0.get().cast(), key.borrow(), value.borrow(), flags)
    }

    /// Removes a key from the map.
    #[inline]
    pub fn remove(&self, key: impl Borrow<K>) -> Result<(), c_long> {
        remove(self.0.get().cast(), key.borrow())
    }
}

btf_map_def!(LruHashMapDef, BPF_MAP_TYPE_LRU_HASH);

#[repr(transparent)]
pub struct LruHashMap<K, V, const M: usize, const F: usize = 0>(
    UnsafeCell<LruHashMapDef<K, V, M, F>>,
);

unsafe impl<K: Sync, V: Sync, const M: usize, const F: usize> Sync for LruHashMap<K, V, M, F> {}

impl<K, V, const M: usize, const F: usize> LruHashMap<K, V, M, F> {
    #[expect(
        clippy::new_without_default,
        reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
    )]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(LruHashMapDef::new()))
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

    /// Inserts a key-value pair into the map.
    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.0.get().cast(), key.borrow(), value.borrow(), flags)
    }

    /// Removes a key from the map.
    #[inline]
    pub fn remove(&self, key: impl Borrow<K>) -> Result<(), c_long> {
        remove(self.0.get().cast(), key.borrow())
    }
}

btf_map_def!(PerCpuHashMapDef, BPF_MAP_TYPE_PERCPU_HASH);

#[repr(transparent)]
pub struct PerCpuHashMap<K, V, const M: usize, const F: usize>(
    UnsafeCell<PerCpuHashMapDef<K, V, M, F>>,
);

unsafe impl<K: Sync, V: Sync, const M: usize, const F: usize> Sync for PerCpuHashMap<K, V, M, F> {}

impl<K, V, const M: usize, const F: usize> PerCpuHashMap<K, V, M, F> {
    #[expect(
        clippy::new_without_default,
        reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
    )]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(PerCpuHashMapDef::new()))
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

    /// Inserts a key-value pair into the map.
    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.0.get().cast(), key.borrow(), value.borrow(), flags)
    }

    /// Removes a key from the map.
    #[inline]
    pub fn remove(&self, key: impl Borrow<K>) -> Result<(), c_long> {
        remove(self.0.get().cast(), key.borrow())
    }
}

btf_map_def!(LruPerCpuHashMapDef, BPF_MAP_TYPE_LRU_PERCPU_HASH);

#[repr(transparent)]
pub struct LruPerCpuHashMap<K, V, const M: usize, const F: usize = 0>(
    UnsafeCell<LruPerCpuHashMapDef<K, V, M, F>>,
);

unsafe impl<K: Sync, V: Sync, const M: usize, const F: usize> Sync
    for LruPerCpuHashMap<K, V, M, F>
{
}

impl<K, V, const M: usize, const F: usize> LruPerCpuHashMap<K, V, M, F> {
    #[expect(
        clippy::new_without_default,
        reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
    )]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(LruPerCpuHashMapDef::new()))
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

    /// Inserts a key-value pair into the map.
    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.0.get().cast(), key.borrow(), value.borrow(), flags)
    }

    /// Removes a key from the map.
    #[inline]
    pub fn remove(&self, key: impl Borrow<K>) -> Result<(), c_long> {
        remove(self.0.get().cast(), key.borrow())
    }
}

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
