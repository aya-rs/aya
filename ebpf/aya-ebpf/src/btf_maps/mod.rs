pub mod array;
pub mod array_of_maps;
pub mod hash_of_maps;
pub mod ring_buf;
pub mod sk_storage;

pub use array::Array;
pub use array_of_maps::ArrayOfMaps;
pub use hash_of_maps::HashOfMaps;
pub use ring_buf::RingBuf;
pub use sk_storage::SkStorage;

/// Defines a BTF-compatible map struct with flat `#[repr(C)]` layout.
///
/// This macro generates a map definition struct that produces BTF metadata
/// compatible with both aya and libbpf loaders.
///
/// The invoker provides `key_type` and `value_type` types without the `*const`
/// wrapper; the macro adds `*const` internally (this is a BTF implementation
/// detail).
///
/// Generics are limited to type parameters (with optional defaults) followed by
/// a semicolon and const parameters (with optional defaults). Lifetimes and
/// bounds are not supported.
///
/// # Map-of-maps support
///
/// For map-of-maps types (`ArrayOfMaps`, `HashOfMaps`), add an `inner_map` clause:
///
/// ```ignore
/// btf_map_def!(
///     pub struct HashOfMaps<K, V; const M: usize, const F: usize = 0>,
///     map_type: BPF_MAP_TYPE_HASH_OF_MAPS,
///     max_entries: M,
///     map_flags: F,
///     key_type: K,
///     value_type: u32,
///     inner_map: V,
/// );
/// ```
///
/// This generates a `values: [*const V; 0]` field for BTF relocation and
/// changes the constructor to `new(_inner: &'static V)`. No `Default` impl
/// is generated for map-of-maps.
macro_rules! btf_map_def {
    // Map-of-maps (with inner_map) - must come first to match before regular arm
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident<
            $($ty_gen:ident $(= $ty_default:ty)?),+
            $(; $(const $const_gen:ident : $const_ty:ty $(= $const_default:tt)?),+)?
            $(,)?
        >,
        map_type: $map_type:ident,
        max_entries: $max_entries:expr,
        map_flags: $map_flags:expr,
        key_type: $key_ty:ty,
        value_type: $value_ty:ty,
        inner_map: $inner_ty:ty
        $(,)?
    ) => {
        $(#[$attr])*
        // repr(C) is required to ensure fields maintain their declared order in BTF.
        // Without it, Rust may reorder fields and libbpf will fail to parse the map definition.
        #[repr(C)]
        $vis struct $name<
            $($ty_gen $(= $ty_default)?),+
            $(, $(const $const_gen : $const_ty $(= $const_default)?),+)?
        > {
            r#type: *const [i32; $crate::bindings::bpf_map_type::$map_type as usize],
            key: *const $key_ty,
            value: *const $value_ty,

            max_entries: *const [i32; $max_entries],
            map_flags: *const [i32; $map_flags],

            /// Zero-sized array for BTF relocation. This field generates a BTF entry
            /// that libbpf uses to determine the inner map type for map-of-maps.
            values: [*const $inner_ty; 0],
        }

        unsafe impl<
            $($ty_gen),+
            $(, $(const $const_gen : $const_ty),+)?
        > Sync for $name<
            $($ty_gen),+
            $(, $($const_gen),+)?
        > {}

        // No Default impl for map-of-maps: they require an inner map reference.

        impl<
            $($ty_gen),+
            $(, $(const $const_gen : $const_ty),+)?
        > $name<
            $($ty_gen),+
            $(, $($const_gen),+)?
        > {
            /// Creates a new map-of-maps with a reference to an inner map template.
            ///
            /// The `_inner` parameter should be a reference to a static map that serves
            /// as the template for inner maps. This reference generates a BTF relocation
            /// that allows libbpf to understand the inner map type.
            pub const fn new(_inner: &'static $inner_ty) -> Self {
                Self {
                    r#type: ::core::ptr::null(),
                    key: ::core::ptr::null(),
                    value: ::core::ptr::null(),

                    max_entries: ::core::ptr::null(),
                    map_flags: ::core::ptr::null(),

                    values: [],
                }
            }

            #[inline(always)]
            pub(crate) const fn as_ptr(&self) -> *mut ::core::ffi::c_void {
                ::core::ptr::from_ref(self).cast_mut().cast()
            }
        }
    };

    // Regular map (no inner_map)
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident<
            $($ty_gen:ident $(= $ty_default:ty)?),+
            $(; $(const $const_gen:ident : $const_ty:ty $(= $const_default:tt)?),+)?
            $(,)?
        >,
        map_type: $map_type:ident,
        max_entries: $max_entries:expr,
        map_flags: $map_flags:expr,
        key_type: $key_ty:ty,
        value_type: $value_ty:ty
        $(, $extra_field:ident : $extra_ty:ty)*
        $(,)?
    ) => {
        $(#[$attr])*
        // repr(C) is required to ensure fields maintain their declared order in BTF.
        // Without it, Rust may reorder fields and libbpf will fail to parse the map definition.
        #[repr(C)]
        $vis struct $name<
            $($ty_gen $(= $ty_default)?),+
            $(, $(const $const_gen : $const_ty $(= $const_default)?),+)?
        > {
            r#type: *const [i32; $crate::bindings::bpf_map_type::$map_type as usize],
            key: *const $key_ty,
            value: *const $value_ty,

            max_entries: *const [i32; $max_entries],
            map_flags: *const [i32; $map_flags],

            $($extra_field: $extra_ty,)*
        }

        unsafe impl<
            $($ty_gen),+
            $(, $(const $const_gen : $const_ty),+)?
        > Sync for $name<
            $($ty_gen),+
            $(, $($const_gen),+)?
        > {}

        impl<
            $($ty_gen),+
            $(, $(const $const_gen : $const_ty),+)?
        > Default for $name<
            $($ty_gen),+
            $(, $($const_gen),+)?
        > {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<
            $($ty_gen),+
            $(, $(const $const_gen : $const_ty),+)?
        > $name<
            $($ty_gen),+
            $(, $($const_gen),+)?
        > {
            pub const fn new() -> Self {
                Self {
                    r#type: ::core::ptr::null(),
                    key: ::core::ptr::null(),
                    value: ::core::ptr::null(),

                    max_entries: ::core::ptr::null(),
                    map_flags: ::core::ptr::null(),

                    $($extra_field: ::core::ptr::null(),)*
                }
            }

            #[inline(always)]
            pub(crate) const fn as_ptr(&self) -> *mut ::core::ffi::c_void {
                ::core::ptr::from_ref(self).cast_mut().cast()
            }
        }
    };
}

pub(crate) use btf_map_def;
