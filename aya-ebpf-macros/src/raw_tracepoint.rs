use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_string_arg};

pub(crate) struct RawTracePoint {
    item: ItemFn,
    tracepoint: Option<String>,
}

impl RawTracePoint {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item = syn::parse2(item)?;
        let mut args = syn::parse2(attrs)?;
        let tracepoint = pop_string_arg(&mut args, "tracepoint");
        err_on_unknown_args(&args)?;
        Ok(Self { item, tracepoint })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item, tracepoint } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let section_name: Cow<'_, _> = if let Some(tracepoint) = tracepoint {
            format!("raw_tp/{}", tracepoint).into()
        } else {
            "raw_tp".into()
        };
        let fn_name = &sig.ident;
        quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = #fn_name(::aya_ebpf::programs::RawTracePointContext::new(ctx));
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
    fn test_raw_tracepoint() {
        let prog = RawTracePoint::parse(
            parse_quote! { tracepoint = "sys_enter" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::RawTracePointContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "raw_tp/sys_enter"]
            fn prog(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = prog(::aya_ebpf::programs::RawTracePointContext::new(ctx));
                return 0;

                fn prog(ctx: &mut ::aya_ebpf::programs::RawTracePointContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
