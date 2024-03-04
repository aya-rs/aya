use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_string_arg};

pub(crate) struct TracePoint {
    item: ItemFn,
    category: Option<String>,
    name: Option<String>,
}

impl TracePoint {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<TracePoint> {
        let item = syn::parse2(item)?;
        let mut args = syn::parse2(attrs)?;
        let name = pop_string_arg(&mut args, "name");
        let category = pop_string_arg(&mut args, "category");
        err_on_unknown_args(&args)?;
        Ok(TracePoint {
            item,
            category,
            name,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_name: Cow<'_, _> = match (&self.category, &self.name) {
            (Some(category), Some(name)) => format!("tracepoint/{}/{}", category, name).into(),
            (Some(_), None) => abort!(self.item, "expected `name` and `category` arguments"),
            (None, Some(_)) => abort!(self.item, "expected `name` and `category` arguments"),
            _ => "tracepoint".into(),
        };
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = #fn_name(::aya_ebpf::programs::TracePointContext::new(ctx));
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
        let expanded = prog.expand().unwrap();
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
