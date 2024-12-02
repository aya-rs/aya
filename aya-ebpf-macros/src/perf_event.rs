use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{spanned::Spanned as _, ItemFn};

pub(crate) struct PerfEvent {
    item: ItemFn,
}

impl PerfEvent {
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
            #[link_section = "perf_event"]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = #fn_name(::aya_ebpf::programs::PerfEventContext::new(ctx));
               return 0;

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
    fn test_perf_event() {
        let prog = PerfEvent::parse(
            parse_quote!(),
            parse_quote!(
                fn foo(ctx: PerfEventContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "perf_event"]
            fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = foo(::aya_ebpf::programs::PerfEventContext::new(ctx));
               return 0;

               fn foo(ctx: PerfEventContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
