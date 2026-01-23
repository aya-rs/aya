use core::marker::PhantomData;

pub mod array;
pub mod ring_buf;
pub mod sk_storage;

pub use array::Array;
pub use ring_buf::RingBuf;
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

/// Defines a BTF-compatible map struct with flat `#[repr(C)]` layout.
///
/// This macro generates a map definition struct that produces BTF metadata
/// compatible with both aya and libbpf loaders.
macro_rules! btf_map_def {
    // Variant for maps with <T, const M: usize, const F: usize> generics
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident<T, const M: usize, const F: usize>,
        map_type: $map_type:ident,
        key: $key_ty:ty
        $(, $extra_field:ident : $extra_ty:ty)*
        $(,)?
    ) => {
        $(#[$attr])*
        #[repr(C)]
        #[allow(dead_code)]
        $vis struct $name<T, const M: usize, const F: usize = 0> {
            r#type: *const [i32; $crate::bindings::bpf_map_type::$map_type as usize],
            key: *const $key_ty,
            value: *const T,
            max_entries: *const [i32; M],
            map_flags: *const [i32; F],
            $($extra_field: $extra_ty,)*
            _anon: $crate::btf_maps::AyaBtfMapMarker,
        }

        unsafe impl<T: Sync, const M: usize, const F: usize> Sync for $name<T, M, F> {}

        impl<T, const M: usize, const F: usize> $name<T, M, F> {
            #[expect(
                clippy::new_without_default,
                reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
            )]
            pub const fn new() -> Self {
                Self {
                    r#type: ::core::ptr::null(),
                    key: ::core::ptr::null(),
                    value: ::core::ptr::null(),
                    max_entries: ::core::ptr::null(),
                    map_flags: ::core::ptr::null(),
                    $($extra_field: ::core::ptr::null(),)*
                    _anon: $crate::btf_maps::AyaBtfMapMarker::new(),
                }
            }

            #[inline(always)]
            pub(crate) fn as_ptr(&self) -> *mut ::core::ffi::c_void {
                ::core::ptr::from_ref(self).cast_mut().cast()
            }
        }
    };

    // Variant for maps with <T> only and fixed max_entries/map_flags
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident<T>,
        map_type: $map_type:ident,
        key: $key_ty:ty,
        max_entries: $max_entries:expr,
        map_flags: $map_flags:expr
        $(,)?
    ) => {
        $(#[$attr])*
        #[repr(C)]
        #[allow(dead_code)]
        $vis struct $name<T> {
            r#type: *const [i32; $crate::bindings::bpf_map_type::$map_type as usize],
            key: *const $key_ty,
            value: *const T,
            max_entries: *const [i32; $max_entries],
            map_flags: *const [i32; $map_flags],
            _anon: $crate::btf_maps::AyaBtfMapMarker,
        }

        unsafe impl<T: Sync> Sync for $name<T> {}

        impl<T> $name<T> {
            #[expect(
                clippy::new_without_default,
                reason = "BPF maps are always used as static variables, therefore this method has to be `const`. `Default::default` is not `const`."
            )]
            pub const fn new() -> Self {
                Self {
                    r#type: ::core::ptr::null(),
                    key: ::core::ptr::null(),
                    value: ::core::ptr::null(),
                    max_entries: ::core::ptr::null(),
                    map_flags: ::core::ptr::null(),
                    _anon: $crate::btf_maps::AyaBtfMapMarker::new(),
                }
            }

            #[inline(always)]
            pub(crate) fn as_ptr(&self) -> *mut ::core::ffi::c_void {
                ::core::ptr::from_ref(self).cast_mut().cast()
            }
        }
    };
}

pub(crate) use btf_map_def;
