use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemStatic, Result};

use crate::args::name_arg;

pub(crate) struct BtfMap {
    item: ItemStatic,
    name: String,
}

impl BtfMap {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<BtfMap> {
        let item: ItemStatic = syn::parse2(item)?;
        let mut args = syn::parse2(attrs)?;
        let name = name_arg(&mut args).unwrap_or_else(|| item.ident.to_string());
        Ok(BtfMap { item, name })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let section_name: Cow<'_, _> = ".maps".into();
        let name = &self.name;
        let item = &self.item;
        quote! {
            #[unsafe(link_section = #section_name)]
            #[unsafe(export_name = #name)]
            #item
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
}
