use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{spanned::Spanned as _, ItemFn};

use crate::args::{err_on_unknown_args, pop_string_arg};

pub(crate) struct TracePoint {
    item: ItemFn,
    name_and_category: Option<(String, String)>,
}

impl TracePoint {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        let item = syn::parse2(item)?;
        let span = attrs.span();
        let mut args = syn::parse2(attrs)?;
        let name = pop_string_arg(&mut args, "name");
        let category = pop_string_arg(&mut args, "category");
        err_on_unknown_args(&args)?;
        match (name, category) {
            (None, None) => Ok(Self {
                item,
                name_and_category: None,
            }),
            (Some(name), Some(category)) => Ok(Self {
                item,
                name_and_category: Some((name, category)),
            }),
            _ => Err(span.error("expected `name` and `category` arguments")),
        }
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self {
            item,
            name_and_category,
        } = self;
        let section_name: Cow<'_, _> = match name_and_category {
            Some((name, category)) => format!("tracepoint/{category}/{name}").into(),
            None => "tracepoint".into(),
        };
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let fn_name = &sig.ident;
        quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = #fn_name(::aya_ebpf::programs::TracePointContext::new(ctx));
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
    fn test_tracepoint() {
        let prog = TracePoint::parse(
            parse_quote! { name = "sys_enter_bind", category = "syscalls" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::TracePointContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "tracepoint/syscalls/sys_enter_bind"]
            fn prog(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = prog(::aya_ebpf::programs::TracePointContext::new(ctx));
               return 0;

               fn prog(ctx: &mut ::aya_ebpf::programs::TracePointContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
