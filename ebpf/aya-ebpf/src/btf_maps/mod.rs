use core::marker::PhantomData;

pub mod array;

pub use array::Array;

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
        #[allow(dead_code)]
        pub struct $name<K, V, const M: usize, const F: usize = 0> {
            r#type: *const [i32; $t as usize],
            key: *const K,
            value: *const V,
            max_entries: *const [i32; M],
            map_flags: *const [i32; F],

            // Anonymize the struct.
            _anon: $crate::btf_maps::AyaBtfMapMarker,
        }

        // Implementing `Default` makes no sense in this case. Maps are always
        // global variables, so they need to be instantiated with a `const`
        // method. `Default::default` method is not `const`.
        #[allow(clippy::new_without_default)]
        impl<K, V, const M: usize, const F: usize> $name<K, V, M, F> {
            pub const fn new() -> $name<K, V, M, F> {
                $name {
                    r#type: &[0i32; $t as usize],
                    key: ::core::ptr::null(),
                    value: ::core::ptr::null(),
                    max_entries: &[0i32; M],
                    map_flags: &[0i32; F],
                    _anon: $crate::btf_maps::AyaBtfMapMarker::new(),
                }
            }
        }
    };
}
