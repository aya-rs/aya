use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

pub(crate) struct SocketFilter {
    item: ItemFn,
}

impl SocketFilter {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        if !attrs.is_empty() {
            abort!(attrs, "unexpected attribute")
        }
        let item = syn::parse2(item)?;
        Ok(SocketFilter { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_name = self.item.sig.ident.clone();
        let fn_vis = &self.item.vis;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = "socket"]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i64 {
                return #fn_name(::aya_bpf::programs::SkBuffContext::new(ctx));

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
    fn test_socket_filter() {
        let prog = SocketFilter::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_bpf::programs::SkBuffContext) -> i64 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "socket"]
            fn prog(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i64 {
                return prog(::aya_bpf::programs::SkBuffContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::SkBuffContext) -> i64 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
