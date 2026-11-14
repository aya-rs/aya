use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::Args;

pub(crate) struct FModRet {
    item: ItemFn,
    function: Option<String>,
    sleepable: bool,
}

impl FModRet {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item = syn::parse2(item)?;
        let mut args: Args = syn::parse2(attrs)?;
        let function = args.pop_string("function");
        let sleepable = args.pop_bool("sleepable");
        args.into_error()?;
        Ok(Self {
            item,
            function,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self {
            item,
            function,
            sleepable,
        } = self;
        let ItemFn { vis, sig, .. } = item;
        let prefix = if *sleepable { "fmod_ret.s" } else { "fmod_ret" };
        let section: Cow<'_, str> = if let Some(function) = function {
            format!("{prefix}/{function}").into()
        } else {
            prefix.into()
        };
        let name = &sig.ident;
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section)]
            #vis fn #name(ctx: *mut ::core::ffi::c_void) -> i64 {
                return ::core::primitive::i64::from(#name(::aya_ebpf::programs::FModRetContext::new(ctx)));

                #item
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    #[test]
    fn sections_preserve_the_modifier_return_value() {
        for (attrs, section) in [
            (quote! {}, "fmod_ret"),
            (quote! { function = "target" }, "fmod_ret/target"),
            (quote! { sleepable }, "fmod_ret.s"),
            (
                quote! { function = "target", sleepable },
                "fmod_ret.s/target",
            ),
        ] {
            for result in [quote! { i32 }, quote! { i64 }] {
                let item = parse_quote! { fn modifier(ctx: FModRetContext) -> #result { -1 } };
                let expanded = FModRet::parse(attrs.clone(), item).unwrap().expand();
                let expected = quote! {
                    #[unsafe(no_mangle)]
                    #[unsafe(link_section = #section)]
                    fn modifier(ctx: *mut ::core::ffi::c_void) -> i64 {
                        return ::core::primitive::i64::from(modifier(::aya_ebpf::programs::FModRetContext::new(ctx)));

                        fn modifier(ctx: FModRetContext) -> #result { -1 }
                    }
                };
                assert_eq!(expanded.to_string(), expected.to_string());
            }
        }
    }

    #[test]
    fn rejects_unknown_arguments() {
        assert!(FModRet::parse(quote! { unknown }, quote! { fn modifier() {} }).is_err());
    }
}
