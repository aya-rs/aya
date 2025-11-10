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

    /// Retrieve the value associate with `key` from the map.
    ///
    /// # Safety
    ///
    /// Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not guarantee the atomicity
    /// of `insert` or `remove`, and any element removed from the map might get aliased by another
    /// element in the map, causing garbage to be read, or corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V> {
        unsafe { get(self.def.get(), key.borrow()) }
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: impl Borrow<K>) -> Option<*const V> {
        get_ptr(self.def.get(), key.borrow())
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key.borrow())
    }

    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.def.get().cast(), key.borrow(), value.borrow(), flags)
    }

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

    /// Retrieve the value associate with `key` from the map.
    ///
    /// # Safety
    ///
    /// Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not guarantee the atomicity
    /// of `insert` or `remove`, and any element removed from the map might get aliased by another
    /// element in the map, causing garbage to be read, or corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V> {
        unsafe { get(self.def.get(), key.borrow()) }
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: impl Borrow<K>) -> Option<*const V> {
        get_ptr(self.def.get(), key.borrow())
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key.borrow())
    }

    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.def.get().cast(), key.borrow(), value.borrow(), flags)
    }

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

    /// Retrieve the value associate with `key` from the map.
    ///
    /// # Safety
    ///
    /// Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not guarantee the atomicity
    /// of `insert` or `remove`, and any element removed from the map might get aliased by another
    /// element in the map, causing garbage to be read, or corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V> {
        unsafe { get(self.def.get(), key.borrow()) }
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: impl Borrow<K>) -> Option<*const V> {
        get_ptr(self.def.get(), key.borrow())
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key.borrow())
    }

    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.def.get().cast(), key.borrow(), value.borrow(), flags)
    }

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

    /// Retrieve the value associate with `key` from the map.
    ///
    /// # Safety
    ///
    /// Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not guarantee the atomicity
    /// of `insert` or `remove`, and any element removed from the map might get aliased by another
    /// element in the map, causing garbage to be read, or corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V> {
        unsafe { get(self.def.get(), key.borrow()) }
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: impl Borrow<K>) -> Option<*const V> {
        get_ptr(self.def.get(), key.borrow())
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key.borrow())
    }

    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.def.get().cast(), key.borrow(), value.borrow(), flags)
    }

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
