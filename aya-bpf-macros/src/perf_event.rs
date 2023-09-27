use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

pub(crate) struct PerfEvent {
    item: ItemFn,
}

impl PerfEvent {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        if !attrs.is_empty() {
            abort!(attrs, "unexpected attribute")
        }
        let item = syn::parse2(item)?;
        Ok(PerfEvent { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = "perf_event"]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = #fn_name(::aya_bpf::programs::PerfEventContext::new(ctx));
               return 0;

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "perf_event"]
            fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = foo(::aya_bpf::programs::PerfEventContext::new(ctx));
               return 0;

               fn foo(ctx: PerfEventContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
