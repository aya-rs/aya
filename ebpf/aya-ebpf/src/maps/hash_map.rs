use core::{borrow::Borrow, marker::PhantomData};

use aya_ebpf_bindings::bindings::bpf_map_type::{
    BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH,
};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_HASH,
    insert, lookup,
    maps::{MapDef, PinningType},
    remove,
};

macro_rules! define_hash_map {
    ($name:ident, $map_type:expr) => {
        #[repr(transparent)]
        pub struct $name<K, V> {
            def: MapDef,
            _kv: PhantomData<(K, V)>,
        }

        impl<K, V> $name<K, V> {
            pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
                Self::new(max_entries, flags, PinningType::None)
            }

            pub const fn pinned(max_entries: u32, flags: u32) -> Self {
                Self::new(max_entries, flags, PinningType::ByName)
            }

            const fn new(max_entries: u32, flags: u32, pinning: PinningType) -> Self {
                Self {
                    def: MapDef::new::<K, V>($map_type, max_entries, flags, pinning),
                    _kv: PhantomData,
                }
            }

            /// Retrieve the value associate with `key` from the map.
            ///
            /// # Safety
            ///
            /// Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not guarantee the
            /// atomicity of `insert` or `remove`, and any element removed from the map might get
            /// aliased by another element in the map, causing garbage to be read, or corruption in
            /// case of writes.
            #[inline]
            pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V> {
                unsafe { get(self.def.as_ptr(), key.borrow()) }
            }

            /// Retrieve the value associate with `key` from the map.
            /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the
            /// caller to decide whether it's safe to dereference the pointer or not.
            #[inline]
            pub fn get_ptr(&self, key: impl Borrow<K>) -> Option<*const V> {
                get_ptr(self.def.as_ptr(), key.borrow())
            }

            /// Retrieve the value associate with `key` from the map.
            /// The same caveat as `get` applies, and additionally cares should be taken to avoid
            /// concurrent writes, but it's up to the caller to decide whether it's safe to
            /// dereference the pointer or not.
            #[inline]
            pub fn get_ptr_mut(&self, key: impl Borrow<K>) -> Option<*mut V> {
                get_ptr_mut(self.def.as_ptr(), key.borrow())
            }

            #[inline]
            pub fn insert(
                &self,
                key: impl Borrow<K>,
                value: impl Borrow<V>,
                flags: u64,
            ) -> Result<(), i32> {
                insert(self.def.as_ptr(), key.borrow(), value.borrow(), flags)
            }

            #[inline]
            pub fn remove(&self, key: impl Borrow<K>) -> Result<(), i32> {
                remove(self.def.as_ptr(), key.borrow())
            }
        }
    };
}

define_hash_map!(HashMap, BPF_MAP_TYPE_HASH);
define_hash_map!(LruHashMap, BPF_MAP_TYPE_LRU_HASH);
define_hash_map!(PerCpuHashMap, BPF_MAP_TYPE_PERCPU_HASH);
define_hash_map!(LruPerCpuHashMap, BPF_MAP_TYPE_LRU_PERCPU_HASH);

#[inline]
unsafe fn get<'a, K, V>(def: *mut aya_ebpf_cty::c_void, key: &K) -> Option<&'a V> {
    get_ptr(def, key).map(|p| unsafe { &*p })
}

#[inline]
fn get_ptr_mut<K, V>(def: *mut aya_ebpf_cty::c_void, key: &K) -> Option<*mut V> {
    lookup(def.cast(), key).map(|p| p.as_ptr())
}

#[inline]
fn get_ptr<K, V>(def: *mut aya_ebpf_cty::c_void, key: &K) -> Option<*const V> {
    lookup::<_, V>(def.cast(), key).map(|p| p.as_ptr().cast_const())
}
