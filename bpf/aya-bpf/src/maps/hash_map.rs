use core::{marker::PhantomData, mem};

use aya_bpf_bindings::bindings::bpf_map_type::{
    BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH,
};
use aya_bpf_cty::{c_long, c_void};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_HASH},
    helpers::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem},
    maps::PinningType,
};

#[repr(transparent)]
pub struct HashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> HashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> HashMap<K, V> {
        HashMap {
            def: build_def::<K, V>(BPF_MAP_TYPE_HASH, max_entries, flags, PinningType::None),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> HashMap<K, V> {
        HashMap {
            def: build_def::<K, V>(BPF_MAP_TYPE_HASH, max_entries, flags, PinningType::ByName),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    #[inline]
    pub unsafe fn get(&mut self, key: &K) -> Option<&V> {
        get(&mut self.def, key)
    }

    #[inline]
    pub unsafe fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(&mut self.def, key, value, flags)
    }

    #[inline]
    pub unsafe fn remove(&mut self, key: &K) -> Result<(), c_long> {
        remove(&mut self.def, key)
    }
}

#[repr(transparent)]
pub struct LruHashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> LruHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> LruHashMap<K, V> {
        LruHashMap {
            def: build_def::<K, V>(BPF_MAP_TYPE_LRU_HASH, max_entries, flags, PinningType::None),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> LruHashMap<K, V> {
        LruHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_LRU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    #[inline]
    pub unsafe fn get(&mut self, key: &K) -> Option<&V> {
        get(&mut self.def, key)
    }

    #[inline]
    pub unsafe fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(&mut self.def, key, value, flags)
    }

    #[inline]
    pub unsafe fn remove(&mut self, key: &K) -> Result<(), c_long> {
        remove(&mut self.def, key)
    }
}

#[repr(transparent)]
pub struct PerCpuHashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> PerCpuHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> PerCpuHashMap<K, V> {
        PerCpuHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::None,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> PerCpuHashMap<K, V> {
        PerCpuHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    #[inline]
    pub unsafe fn get(&mut self, key: &K) -> Option<&V> {
        get(&mut self.def, key)
    }

    #[inline]
    pub unsafe fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(&mut self.def, key, value, flags)
    }

    #[inline]
    pub unsafe fn remove(&mut self, key: &K) -> Result<(), c_long> {
        remove(&mut self.def, key)
    }
}

#[repr(transparent)]
pub struct LruPerCpuHashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> LruPerCpuHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> LruPerCpuHashMap<K, V> {
        LruPerCpuHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::None,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> LruPerCpuHashMap<K, V> {
        LruPerCpuHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    #[inline]
    pub unsafe fn get(&mut self, key: &K) -> Option<&V> {
        get(&mut self.def, key)
    }

    #[inline]
    pub unsafe fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(&mut self.def, key, value, flags)
    }

    #[inline]
    pub unsafe fn remove(&mut self, key: &K) -> Result<(), c_long> {
        remove(&mut self.def, key)
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
unsafe fn get<'a, K, V>(def: &mut bpf_map_def, key: &K) -> Option<&'a V> {
    let value = bpf_map_lookup_elem(def as *mut _ as *mut _, key as *const _ as *const c_void);
    if value.is_null() {
        None
    } else {
        // FIXME: alignment
        Some(&*(value as *const V))
    }
}

#[inline]
unsafe fn insert<K, V>(
    def: &mut bpf_map_def,
    key: &K,
    value: &V,
    flags: u64,
) -> Result<(), c_long> {
    let ret = bpf_map_update_elem(
        def as *mut _ as *mut _,
        key as *const _ as *const _,
        value as *const _ as *const _,
        flags,
    );
    if ret < 0 {
        return Err(ret);
    }

    Ok(())
}

#[inline]
unsafe fn remove<K>(def: &mut bpf_map_def, key: &K) -> Result<(), c_long> {
    let value = bpf_map_delete_elem(def as *mut _ as *mut _, key as *const _ as *const c_void);
    if value < 0 {
        Err(value)
    } else {
        Ok(())
    }
}
