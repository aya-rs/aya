use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{spanned::Spanned as _, ItemFn};

pub(crate) struct SchedClassifier {
    item: ItemFn,
}

impl SchedClassifier {
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
            #[link_section = "classifier"]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return #fn_name(::aya_ebpf::programs::TcContext::new(ctx));

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
    fn test_sched_classifier() {
        let prog = SchedClassifier::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::TcContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "classifier"]
            fn prog(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return prog(::aya_ebpf::programs::TcContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::TcContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
