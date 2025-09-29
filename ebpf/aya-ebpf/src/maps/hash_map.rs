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

#[repr(transparent)]
pub struct HashMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K: Sync, V: Sync> Sync for HashMap<K, V> {}

impl<K, V> HashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_HASH,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

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

#[repr(transparent)]
pub struct LruHashMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K: Sync, V: Sync> Sync for LruHashMap<K, V> {}

impl<K, V> LruHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LRU_HASH,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LRU_HASH,
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

#[repr(transparent)]
pub struct PerCpuHashMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K, V> Sync for PerCpuHashMap<K, V> {}

impl<K, V> PerCpuHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_PERCPU_HASH,
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

#[repr(transparent)]
pub struct LruPerCpuHashMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K, V> Sync for LruPerCpuHashMap<K, V> {}

impl<K, V> LruPerCpuHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
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
