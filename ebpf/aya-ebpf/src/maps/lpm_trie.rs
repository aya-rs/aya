use core::{cell::UnsafeCell, marker::PhantomData, mem};

use aya_ebpf_bindings::bindings::BPF_F_NO_PREALLOC;
use aya_ebpf_cty::c_long;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_LPM_TRIE},
    insert, lookup,
    maps::PinningType,
    remove,
};

#[repr(transparent)]
pub struct LpmTrie<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K: Sync, V: Sync> Sync for LpmTrie<K, V> {}

#[repr(C, packed)]
pub struct Key<K> {
    /// Represents the number of bits matched against.
    pub prefix_len: u32,
    /// Represents arbitrary data stored in the LpmTrie.
    pub data: K,
}

impl<K> Key<K> {
    pub fn new(prefix_len: u32, data: K) -> Self {
        Self { prefix_len, data }
    }
}

impl<K, V> LpmTrie<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        let flags = flags | BPF_F_NO_PREALLOC;
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LPM_TRIE,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        let flags = flags | BPF_F_NO_PREALLOC;
        Self {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LPM_TRIE,
                max_entries,
                flags,
                PinningType::ByName,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    #[inline]
    pub fn get(&self, key: &Key<K>) -> Option<&V> {
        lookup(self.def.get().cast(), key).map(|p| unsafe { p.as_ref() })
    }

    #[inline]
    pub fn insert(&self, key: &Key<K>, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.def.get().cast(), key, value, flags)
    }

    #[inline]
    pub fn remove(&self, key: &Key<K>) -> Result<(), c_long> {
        remove(self.def.get().cast(), key)
    }
}

const fn build_def<K, V>(ty: u32, max_entries: u32, flags: u32, pin: PinningType) -> bpf_map_def {
    bpf_map_def {
        type_: ty,
        key_size: mem::size_of::<Key<K>>() as u32,
        value_size: mem::size_of::<V>() as u32,
        max_entries,
        map_flags: flags,
        id: 0,
        pinning: pin as u32,
    }
}
