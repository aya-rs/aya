use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{ItemStatic, Result};

use crate::args::Args;

pub(crate) struct Map {
    item: ItemStatic,
    name: String,
    inner: Option<String>,
}

impl Map {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item: ItemStatic = syn::parse2(item)?;
        let mut args: Args = syn::parse2(attrs)?;
        let name = args.pop_name().unwrap_or_else(|| item.ident.to_string());
        let inner = args.pop_string("inner");
        args.into_error()?;
        Ok(Self { item, name, inner })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let section_name: Cow<'_, _> = "maps".into();
        let name = &self.name;
        let item = &self.item;

        // Aya-specific mechanism for inner map bindings.
        //
        // Unlike libbpf which uses BTF relocations within the `.maps` section
        // (see https://patchwork.ozlabs.org/comment/2418417/), aya uses a separate
        // `.maps.inner` section containing null-terminated string pairs.
        //
        // This approach was chosen because aya-ebpf doesn't require BTF for map
        // definitions and this provides a simpler mechanism that works with both
        // legacy and BTF-style maps.
        //
        // Format: "outer_name\0inner_name\0" pairs, parsed by aya-obj.
        let inner_binding = self.inner.as_ref().map(|inner| {
            let binding_ident = format_ident!("__inner_map_binding_{}", name);
            let binding_value = format!("{}\0{}\0", name, inner);
            let binding_len = binding_value.len();
            let binding_bytes = binding_value.as_bytes();
            quote! {
                #[unsafe(link_section = ".maps.inner")]
                #[used]
                static #binding_ident: [u8; #binding_len] = [#(#binding_bytes),*];
            }
        });

        quote! {
            #[unsafe(link_section = #section_name)]
            #[unsafe(export_name = #name)]
            #item

            #inner_binding
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    #[test]
    fn test_map_with_name() {
        let map = Map::parse(
            parse_quote!(name = "foo"),
            parse_quote!(
                static BAR: HashMap<&'static str, u32> = HashMap::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let expected = quote!(
            #[unsafe(link_section = "maps")]
            #[unsafe(export_name = "foo")]
            static BAR: HashMap<&'static str, u32> = HashMap::new();
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_map_no_name() {
        let map = Map::parse(
            parse_quote!(),
            parse_quote!(
                static BAR: HashMap<&'static str, u32> = HashMap::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let expected = quote!(
            #[unsafe(link_section = "maps")]
            #[unsafe(export_name = "BAR")]
            static BAR: HashMap<&'static str, u32> = HashMap::new();
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_map_with_inner() {
        let map = Map::parse(
            parse_quote!(inner = "INNER_TEMPLATE"),
            parse_quote!(
                static OUTER: Array<u32> = Array::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let expanded_str = expanded.to_string();
        // Verify the binding section is generated
        assert!(
            expanded_str.contains(".maps.inner"),
            "expected .maps.inner section in: {expanded_str}"
        );
        assert!(
            expanded_str.contains("__inner_map_binding_OUTER"),
            "expected binding identifier in: {expanded_str}"
        );
        // "OUTER\0INNER_TEMPLATE\0" = 21 bytes
        assert!(
            expanded_str.contains("21usize"),
            "expected 21 bytes in: {expanded_str}"
        );
    }

    #[test]
    fn test_map_with_name_and_inner() {
        let map = Map::parse(
            parse_quote!(name = "my_map", inner = "my_template"),
            parse_quote!(
                static OUTER: Array<u32> = Array::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let expanded_str = expanded.to_string();
        // Verify the binding section is generated with the custom name
        assert!(
            expanded_str.contains(".maps.inner"),
            "expected .maps.inner section in: {expanded_str}"
        );
        assert!(
            expanded_str.contains("__inner_map_binding_my_map"),
            "expected binding identifier with custom name in: {expanded_str}"
        );
        assert!(
            expanded_str.contains("export_name = \"my_map\""),
            "expected custom export name in: {expanded_str}"
        );
        // "my_map\0my_template\0" = 19 bytes
        assert!(
            expanded_str.contains("19usize"),
            "expected 19 bytes in: {expanded_str}"
        );
    }

    #[test]
    fn test_map_unknown_arg() {
        let result = Map::parse(
            parse_quote!(unknown = "foo"),
            parse_quote!(
                static BAR: HashMap<&'static str, u32> = HashMap::new();
            ),
        );
        assert!(result.is_err());
    }
}
