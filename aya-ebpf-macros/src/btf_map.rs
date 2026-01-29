use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{ItemStatic, Result};

use crate::args::Args;

pub(crate) struct BtfMap {
    item: ItemStatic,
    name: String,
    inner: Option<String>,
}

impl BtfMap {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item: ItemStatic = syn::parse2(item)?;
        let mut args: Args = syn::parse2(attrs)?;
        let name = args.pop_name().unwrap_or_else(|| item.ident.to_string());
        let inner = args.pop_string("inner");
        args.into_error()?;
        Ok(Self { item, name, inner })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let section_name: Cow<'_, _> = ".maps".into();
        let name = &self.name;
        let item = &self.item;

        // Inner map binding: emits a `.maps.inner` section entry so that aya
        // can resolve the outer→inner relationship explicitly (instead of
        // falling back to a heuristic). This uses the same mechanism as the
        // legacy `#[map(inner = "...")]` attribute.
        let inner_binding = self.inner.as_ref().map(|inner| {
            let binding_ident = format_ident!("__inner_map_binding_{}", name);
            let binding_value = format!("{name}\0{inner}\0");
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
        let map = BtfMap::parse(
            parse_quote!(name = "foo"),
            parse_quote!(
                static BAR: HashMap<&'static str, u32> = HashMap::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let expected = quote!(
            #[unsafe(link_section = ".maps")]
            #[unsafe(export_name = "foo")]
            static BAR: HashMap<&'static str, u32> = HashMap::new();
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_map_no_name() {
        let map = BtfMap::parse(
            parse_quote!(),
            parse_quote!(
                static BAR: HashMap<&'static str, u32> = HashMap::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let expected = quote!(
            #[unsafe(link_section = ".maps")]
            #[unsafe(export_name = "BAR")]
            static BAR: HashMap<&'static str, u32> = HashMap::new();
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_map_with_inner() {
        let map = BtfMap::parse(
            parse_quote!(inner = "INNER_TEMPLATE"),
            parse_quote!(
                static OUTER: ArrayOfMaps<Array<u32, 10>, 4> = ArrayOfMaps::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let binding_bytes: &[u8] = b"OUTER\0INNER_TEMPLATE\0";
        let expected = quote!(
            #[unsafe(link_section = ".maps")]
            #[unsafe(export_name = "OUTER")]
            static OUTER: ArrayOfMaps<Array<u32, 10>, 4> = ArrayOfMaps::new();

            #[unsafe(link_section = ".maps.inner")]
            #[used]
            static __inner_map_binding_OUTER: [u8; 21usize] = [#(#binding_bytes),*];
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_map_with_name_and_inner() {
        let map = BtfMap::parse(
            parse_quote!(name = "my_map", inner = "my_template"),
            parse_quote!(
                static OUTER: HashOfMaps<u32, Array<u32, 10>, 4> = HashOfMaps::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let binding_bytes: &[u8] = b"my_map\0my_template\0";
        let expected = quote!(
            #[unsafe(link_section = ".maps")]
            #[unsafe(export_name = "my_map")]
            static OUTER: HashOfMaps<u32, Array<u32, 10>, 4> = HashOfMaps::new();

            #[unsafe(link_section = ".maps.inner")]
            #[used]
            static __inner_map_binding_my_map: [u8; 19usize] = [#(#binding_bytes),*];
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
