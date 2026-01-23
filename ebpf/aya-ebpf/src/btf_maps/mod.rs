pub mod array;
pub mod ring_buf;
pub mod sk_storage;

pub use array::Array;
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
macro_rules! btf_map_def {
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
