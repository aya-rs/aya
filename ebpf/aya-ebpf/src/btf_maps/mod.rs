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
///
/// The invoker must provide `key` and `value` fields explicitly, which allows
/// for maps with different type parameter patterns (e.g., `<K, V>`).
macro_rules! btf_map_def {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident<$tp:ident $(, const $cg_name:ident : usize $(= $cg_default:tt)?)*>,
        map_type: $map_type:ident,
        max_entries: $max_entries:expr,
        map_flags: $map_flags:expr,
        key: $key_ty:ty,
        value: $value_ty:ty
        $(, $extra_field:ident : $extra_ty:ty)*
        $(,)?
    ) => {
        $(#[$attr])*
        #[repr(C)]
        $vis struct $name<$tp $(, const $cg_name : usize $(= $cg_default)?)*> {
            r#type: *const [i32; $crate::bindings::bpf_map_type::$map_type as usize],
            key: $key_ty,
            value: $value_ty,

            max_entries: *const [i32; $max_entries],
            map_flags: *const [i32; $map_flags],

            $($extra_field: $extra_ty,)*
            // Anonymize the struct.
            _anon: $crate::btf_maps::AyaBtfMapMarker,
        }

        unsafe impl<$tp: Sync $(, const $cg_name : usize)*> Sync for $name<$tp $(, $cg_name)*> {}

        impl<$tp $(, const $cg_name : usize)*> Default for $name<$tp $(, $cg_name)*> {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<$tp $(, const $cg_name : usize)*> $name<$tp $(, $cg_name)*> {
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
}

pub(crate) use btf_map_def;
