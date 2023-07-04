use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{Ident, ItemFn, Result};

pub(crate) struct Xdp {
    item: ItemFn,
    frags: bool,
}

impl Xdp {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Xdp> {
        let mut frags = false;
        let item = syn::parse2(item)?;
        if !attrs.is_empty() {
            let ident: Ident = syn::parse2(attrs)?;
            if ident != "frags" {
                abort!(ident, "unexpected attribute");
            }
            frags = true;
        }
        Ok(Xdp { item, frags })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_name: Cow<'_, _> = if self.frags {
            "xdp.frags".into()
        } else {
            "xdp".into()
        };
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return #fn_name(::aya_bpf::programs::XdpContext::new(ctx));

                #item
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_xdp() {
        let prog = Xdp::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "xdp"]
            fn prog(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return prog(::aya_bpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_xdp_frags() {
        let prog = Xdp::parse(
            parse_quote! { frags },
            parse_quote! {
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "xdp.frags"]
            fn prog(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return prog(::aya_bpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
