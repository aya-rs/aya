use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{spanned::Spanned as _, ItemFn};

pub(crate) struct SocketFilter {
    item: ItemFn,
}

impl SocketFilter {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        if !attrs.is_empty() {
            return Err(attrs.span().error("unexpected attribute"));
        }
        let item = syn::parse2(item)?;
        Ok(Self { item })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let fn_name = &sig.ident;
        quote! {
            #[no_mangle]
            #[link_section = "socket"]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i64 {
                return #fn_name(::aya_ebpf::programs::SkBuffContext::new(ctx));

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
    fn test_socket_filter() {
        let prog = SocketFilter::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::SkBuffContext) -> i64 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "socket"]
            fn prog(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i64 {
                return prog(::aya_ebpf::programs::SkBuffContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::SkBuffContext) -> i64 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
