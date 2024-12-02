use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemStatic, Result};

use crate::args::name_arg;
pub(crate) struct Map {
    item: ItemStatic,
    name: String,
}

impl Map {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Map> {
        let item: ItemStatic = syn::parse2(item)?;
        let mut args = syn::parse2(attrs)?;
        let name = name_arg(&mut args).unwrap_or_else(|| item.ident.to_string());
        Ok(Self { item, name })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let section_name: Cow<'_, _> = "maps".into();
        let name = &self.name;
        let item = &self.item;
        quote! {
            #[link_section = #section_name]
            #[export_name = #name]
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
        let map = Map::parse(
            parse_quote!(name = "foo"),
            parse_quote!(
                static BAR: HashMap<&'static str, u32> = HashMap::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let expected = quote!(
            #[link_section = "maps"]
            #[export_name = "foo"]
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
            #[link_section = "maps"]
            #[export_name = "BAR"]
            static BAR: HashMap<&'static str, u32> = HashMap::new();
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
