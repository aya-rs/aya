use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

pub(crate) struct SkMsg {
    item: ItemFn,
}

impl SkMsg {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        if !attrs.is_empty() {
            abort!(attrs, "unexpected attribute")
        }
        let item = syn::parse2(item)?;
        Ok(SkMsg { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = "sk_msg"]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::sk_msg_md) -> u32 {
                return #fn_name(::aya_bpf::programs::SkMsgContext::new(ctx));

                #item
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    #[test]
    fn test_sk_msg() {
        let prog = SkMsg::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_bpf::programs::SkMsgContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "sk_msg"]
            fn prog(ctx: *mut ::aya_bpf::bindings:: sk_msg_md) -> u32 {
                return prog(::aya_bpf::programs::SkMsgContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::SkMsgContext) -> u32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
