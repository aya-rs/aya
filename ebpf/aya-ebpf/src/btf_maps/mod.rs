use core::marker::PhantomData;

pub mod array;
pub mod hash_map;
pub mod sk_storage;

pub use array::Array;
pub use hash_map::{HashMap, LruHashMap, LruPerCpuHashMap, PerCpuHashMap};
pub use sk_storage::SkStorage;

/// A marker used to remove names of annotated types in LLVM debug info and
/// therefore also in BTF.
#[repr(transparent)]
pub(crate) struct AyaBtfMapMarker(PhantomData<()>);

impl AyaBtfMapMarker {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

#[macro_export]
macro_rules! btf_map_def {
    ($name:ident, $t:ident) => {
        #[doc(hidden)]
        #[expect(
            dead_code,
            reason = "These fields exist only for BTF metadata exposure. None of them are actually used."
        )]
        pub struct $name<K, V, const M: usize, const F: usize = 0> {
            r#type: *const [i32; $t as usize],
            key: *const K,
            value: *const V,
            max_entries: *const [i32; M],
            map_flags: *const [i32; F],

            // Anonymize the struct.
            _anon: $crate::btf_maps::AyaBtfMapMarker,
        }

        #[expect(
            clippy::new_without_default,
            reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
        )]
        impl<K, V, const M: usize, const F: usize> $name<K, V, M, F> {
            pub const fn new() -> $name<K, V, M, F> {
                $name {
                    r#type: ::core::ptr::null(),
                    key: ::core::ptr::null(),
                    value: ::core::ptr::null(),
                    max_entries: ::core::ptr::null(),
                    map_flags: ::core::ptr::null(),
                    _anon: $crate::btf_maps::AyaBtfMapMarker::new(),
                }
            }
        }
    };
}
