use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_string_arg, Args};

pub(crate) struct BtfTracePoint {
    item: ItemFn,
    function: Option<String>,
}

impl BtfTracePoint {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item = syn::parse2(item)?;
        let mut args: Args = syn::parse2(attrs)?;
        let function = pop_string_arg(&mut args, "function");
        err_on_unknown_args(&args)?;

        Ok(Self { item, function })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item, function } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let section_name: Cow<'_, _> = if let Some(function) = function {
            format!("tp_btf/{}", function).into()
        } else {
            "tp_btf".into()
        };
        let fn_name = &sig.ident;
        quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_ebpf::programs::BtfTracePointContext::new(ctx));
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
    fn test_btf_tracepoint() {
        let prog = BtfTracePoint::parse(
            parse_quote!(),
            parse_quote!(
                fn foo(ctx: BtfTracePointContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote!(
            #[no_mangle]
            #[link_section = "tp_btf"]
            fn foo(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = foo(::aya_ebpf::programs::BtfTracePointContext::new(ctx));
                return 0;

                fn foo(ctx: BtfTracePointContext) -> i32 {
                    0
                }
            }
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_btf_tracepoint_with_function() {
        let prog = BtfTracePoint::parse(
            parse_quote!(function = "some_func"),
            parse_quote!(
                fn foo(ctx: BtfTracePointContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote!(
            #[no_mangle]
            #[link_section = "tp_btf/some_func"]
            fn foo(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = foo(::aya_ebpf::programs::BtfTracePointContext::new(ctx));
                return 0;

                fn foo(ctx: BtfTracePointContext) -> i32 {
                    0
                }
            }
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
