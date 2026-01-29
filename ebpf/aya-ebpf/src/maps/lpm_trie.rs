use core::{borrow::Borrow, marker::PhantomData};

use aya_ebpf_bindings::bindings::BPF_F_NO_PREALLOC;
use aya_ebpf_cty::c_long;

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_LPM_TRIE,
    insert, lookup,
    maps::{InnerMap, MapDef, PinningType},
    remove,
};

#[repr(transparent)]
pub struct LpmTrie<K, V> {
    def: MapDef,
    _kv: PhantomData<(K, V)>,
}

unsafe impl<K: Sync, V: Sync> Sync for LpmTrie<K, V> {}
impl<K, V> super::private::Sealed for LpmTrie<K, V> {}
unsafe impl<K, V> InnerMap for LpmTrie<K, V> {}

#[repr(C, packed)]
pub struct Key<K> {
    /// Represents the number of bits matched against.
    pub prefix_len: u32,
    /// Represents arbitrary data stored in the [`LpmTrie`].
    pub data: K,
}

impl<K> Key<K> {
    pub const fn new(prefix_len: u32, data: K) -> Self {
        Self { prefix_len, data }
    }
}

impl<K, V> LpmTrie<K, V> {
    map_constructors!(Key<K>, V, BPF_MAP_TYPE_LPM_TRIE, extra_flags BPF_F_NO_PREALLOC, phantom _kv);

    #[inline]
    pub fn get(&self, key: impl Borrow<Key<K>>) -> Option<&V> {
        lookup(self.def.as_ptr(), key.borrow()).map(|p| unsafe { p.as_ref() })
    }

    #[inline]
    pub fn insert(
        &self,
        key: impl Borrow<Key<K>>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), c_long> {
        insert(self.def.as_ptr(), key.borrow(), value.borrow(), flags)
    }

    #[inline]
    pub fn remove(&self, key: impl Borrow<Key<K>>) -> Result<(), c_long> {
        remove(self.def.as_ptr(), key.borrow())
    }
}
