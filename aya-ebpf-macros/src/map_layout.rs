use proc_macro2::TokenStream;
use quote::{format_ident, quote_spanned};
use syn::{Type, spanned::Spanned as _};

pub(crate) fn map(map_ty: &Type) -> TokenStream {
    let layout_trait = quote_spanned!(map_ty.span() => ::aya_ebpf::maps::__MapLayout);
    ffi_safety_checks(map_ty, layout_trait, "__aya_map", false)
}

pub(crate) fn btf_map(map_ty: &Type) -> TokenStream {
    let layout_trait = quote_spanned!(map_ty.span() => ::aya_ebpf::btf_maps::__MapLayout);
    ffi_safety_checks(map_ty, layout_trait, "__aya_btf_map", true)
}

fn ffi_safety_checks(
    map_ty: &Type,
    layout_trait: TokenStream,
    prefix: &str,
    check_inner_map: bool,
) -> TokenStream {
    let key_check = format_ident!("{prefix}_key_must_be_ffi_safe");
    let value_check = format_ident!("{prefix}_value_must_be_ffi_safe");
    // The kernel rejects map-in-map nesting deeper than one level.
    // https://github.com/torvalds/linux/blob/v6.17/kernel/bpf/map_in_map.c#L20-L22
    let inner_checks = check_inner_map.then(|| {
        let key_check = format_ident!("{prefix}_inner_key_must_be_ffi_safe");
        let value_check = format_ident!("{prefix}_inner_value_must_be_ffi_safe");
        quote_spanned! {map_ty.span() =>
            #[deny(improper_ctypes_definitions)]
            #[allow(dead_code)]
            extern "C" fn #key_check(
                _: ::aya_ebpf::__LayoutCheck<
                    <<#map_ty as #layout_trait>::Inner as #layout_trait>::Key,
                >,
            ) {
            }

            #[deny(improper_ctypes_definitions)]
            #[allow(dead_code)]
            extern "C" fn #value_check(
                _: ::aya_ebpf::__LayoutCheck<
                    <<#map_ty as #layout_trait>::Inner as #layout_trait>::Value,
                >,
            ) {
            }
        }
    });

    // quote_spanned! rather than quote!: rustc suppresses
    // `improper_ctypes_definitions` (like most lints) in code carrying an
    // external macro expansion context, which call-site spans do. Spanning the
    // generated tokens onto the user's map type keeps the lint active and
    // points its diagnostics at the map definition.
    //
    // The parameters are wrapped in `__LayoutCheck` (a `repr(C)` struct)
    // because the lint's predicate for bare parameters is stricter than what a
    // map layout requires: arrays decay to pointers in C calls and `()` is
    // rejected as an argument, yet both are valid map key/value layouts (e.g.
    // `HashMap<[u8; 16], _>` keys, ring buffer `()` keys). As a `repr(C)`
    // field the same types are checked for layout stability only.
    quote_spanned! {map_ty.span() =>
        const _: () = {
            #[deny(improper_ctypes_definitions)]
            #[allow(dead_code)]
            extern "C" fn #key_check(
                _: ::aya_ebpf::__LayoutCheck<<#map_ty as #layout_trait>::Key>,
            ) {
            }

            #[deny(improper_ctypes_definitions)]
            #[allow(dead_code)]
            extern "C" fn #value_check(
                _: ::aya_ebpf::__LayoutCheck<<#map_ty as #layout_trait>::Value>,
            ) {
            }

            #inner_checks
        };
    }
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse_quote;

    use super::*;

    #[test]
    #[rustfmt::skip]
    fn test_map_layout_checks() {
        let expected = quote!(
            const _: () = {
                #[deny(improper_ctypes_definitions)]
                #[allow(dead_code)]
                extern "C" fn __aya_map_key_must_be_ffi_safe(
                    _: ::aya_ebpf::__LayoutCheck<<HashMap<&'static str, u32> as ::aya_ebpf::maps::__MapLayout>::Key>,
                ) {
                }

                #[deny(improper_ctypes_definitions)]
                #[allow(dead_code)]
                extern "C" fn __aya_map_value_must_be_ffi_safe(
                    _: ::aya_ebpf::__LayoutCheck<<HashMap<&'static str, u32> as ::aya_ebpf::maps::__MapLayout>::Value>,
                ) {
                }
            };
        );
        let expanded = map(&parse_quote!(HashMap<&'static str, u32>));
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    #[rustfmt::skip]
    fn test_btf_map_layout_checks() {
        let expected = quote!(
            const _: () = {
                #[deny(improper_ctypes_definitions)]
                #[allow(dead_code)]
                extern "C" fn __aya_btf_map_key_must_be_ffi_safe(
                    _: ::aya_ebpf::__LayoutCheck<<Array<u32, 4> as ::aya_ebpf::btf_maps::__MapLayout>::Key>,
                ) {
                }

                #[deny(improper_ctypes_definitions)]
                #[allow(dead_code)]
                extern "C" fn __aya_btf_map_value_must_be_ffi_safe(
                    _: ::aya_ebpf::__LayoutCheck<<Array<u32, 4> as ::aya_ebpf::btf_maps::__MapLayout>::Value>,
                ) {
                }

                #[deny(improper_ctypes_definitions)]
                #[allow(dead_code)]
                extern "C" fn __aya_btf_map_inner_key_must_be_ffi_safe(
                    _: ::aya_ebpf::__LayoutCheck<
                        <<Array<u32, 4> as ::aya_ebpf::btf_maps::__MapLayout>::Inner as ::aya_ebpf::btf_maps::__MapLayout>::Key,
                    >,
                ) {
                }

                #[deny(improper_ctypes_definitions)]
                #[allow(dead_code)]
                extern "C" fn __aya_btf_map_inner_value_must_be_ffi_safe(
                    _: ::aya_ebpf::__LayoutCheck<
                        <<Array<u32, 4> as ::aya_ebpf::btf_maps::__MapLayout>::Inner as ::aya_ebpf::btf_maps::__MapLayout>::Value,
                    >,
                ) {
                }
            };
        );
        let expanded = btf_map(&parse_quote!(Array<u32, 4>));
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
