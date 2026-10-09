use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemStatic, Result};

use crate::args::Args;

pub(crate) struct BtfMap {
    item: ItemStatic,
    name: String,
    pin_by_name: bool,
}

impl BtfMap {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item: ItemStatic = syn::parse2(item)?;
        let mut args: Args = syn::parse2(attrs)?;
        let name = args.pop_name().unwrap_or_else(|| item.ident.to_string());
        let pin_by_name = args.pop_bool("pin_by_name");
        args.into_error()?;
        Ok(Self {
            item,
            name,
            pin_by_name,
        })
    }

    pub(crate) fn expand(self) -> TokenStream {
        let Self {
            mut item,
            name,
            pin_by_name,
        } = self;
        if pin_by_name {
            let ItemStatic {
                attrs: _,
                vis: _,
                static_token: _,
                mutability: _,
                ident: _,
                colon_token: _,
                ty,
                eq_token: _,
                expr,
                semi_token: _,
            } = &mut item;
            *ty = syn::parse_quote!(::aya_ebpf::btf_maps::Pinned<#ty>);
            *expr = syn::parse_quote!((#expr).pin_by_name());
        }
        quote! {
            #[unsafe(link_section = ".maps")]
            #[unsafe(export_name = #name)]
            #item
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use syn::parse_quote;

    use super::*;

    #[rstest]
    #[case::unnamed(
        quote!(), "BAR",
        parse_quote!(HashMap<&'static str, u32>), quote!(HashMap::new())
    )]
    #[case::named(
        quote!(name = "foo"), "foo",
        parse_quote!(HashMap<&'static str, u32>), quote!(HashMap::new())
    )]
    #[case::pinned(
        quote!(pin_by_name), "BAR",
        parse_quote!(::aya_ebpf::btf_maps::Pinned<HashMap<&'static str, u32>>),
        quote!((HashMap::new()).pin_by_name())
    )]
    #[case::named_pinned(
        quote!(pin_by_name, name = "foo"), "foo",
        parse_quote!(::aya_ebpf::btf_maps::Pinned<HashMap<&'static str, u32>>),
        quote!((HashMap::new()).pin_by_name())
    )]
    fn test_map(
        #[case] attrs: TokenStream,
        #[case] name: &str,
        #[case] ty: syn::Type,
        #[case] expr: TokenStream,
    ) {
        let map = BtfMap::parse(
            attrs,
            parse_quote!(
                #[allow(dead_code)]
                pub static BAR: HashMap<&'static str, u32> = HashMap::new();
            ),
        )
        .unwrap();
        let expanded = map.expand();
        let expected = quote!(
            #[unsafe(link_section = ".maps")]
            #[unsafe(export_name = #name)]
            #[allow(dead_code)]
            pub static BAR: #ty = #expr;
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
