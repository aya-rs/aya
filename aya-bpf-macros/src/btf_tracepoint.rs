use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_arg, pop_required_arg, Args};

pub(crate) struct BtfTracePoint {
    item: ItemFn,
    function: String,
    sleepable: bool,
}

impl BtfTracePoint {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let mut args: Args = syn::parse2(attrs)?;
        let item = syn::parse2(item)?;
        let function = pop_required_arg(&mut args, "function")?;
        let mut sleepable = false;
        if let Some(s) = pop_arg(&mut args, "sleepable") {
            if let Ok(m) = s.parse() {
                sleepable = m
            } else {
                return Err(Error::new_spanned(
                    s,
                    "invalid value. should be 'true' or 'false'",
                ));
            }
        }
        err_on_unknown_args(&args)?;
        Ok(BtfTracePoint {
            item,
            function,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_prefix = if self.sleepable { "tp_btf.s" } else { "tp_btf" };
        let section_name: Cow<'_, _> = format!("{}/{}", section_prefix, self.function).into();
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_bpf::programs::BtfTracePointContext::new(ctx));
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
    fn test_btf_tracepoint() {
        let prog = BtfTracePoint::parse(
            parse_quote!(function = "some_func"),
            parse_quote!(
                fn foo(ctx: BtfTracePointContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote!(
            #[no_mangle]
            #[link_section = "tp_btf/some_func"]
            fn foo(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = foo(::aya_bpf::programs::BtfTracePointContext::new(ctx));
                return 0;

                fn foo(ctx: BtfTracePointContext) -> i32 {
                    0
                }
            }
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
