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
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<RawTracePoint> {
        let item = syn::parse2(item)?;
        let mut tracepoint = None;
        if !attrs.is_empty() {
            let mut args = syn::parse2(attrs)?;
            if let Some(tp) = pop_string_arg(&mut args, "tracepoint") {
                tracepoint = Some(tp)
            };
            err_on_unknown_args(&args)?;
        }
        Ok(RawTracePoint { item, tracepoint })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_name: Cow<'_, _> = if self.tracepoint.is_none() {
            "raw_tp".into()
        } else {
            format!("raw_tp/{}", self.tracepoint.as_ref().unwrap()).into()
        };
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = #fn_name(::aya_bpf::programs::RawTracePointContext::new(ctx));
                return 0;

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
    fn test_raw_tracepoint() {
        let prog = RawTracePoint::parse(
            parse_quote! { tracepoint = "sys_enter" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_bpf::programs::RawTracePointContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "raw_tp/sys_enter"]
            fn prog(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = prog(::aya_bpf::programs::RawTracePointContext::new(ctx));
                return 0;

                fn prog(ctx: &mut ::aya_bpf::programs::RawTracePointContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
