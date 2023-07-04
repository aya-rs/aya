use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_required_arg};

pub(crate) struct FExit {
    item: ItemFn,
    function: String,
    sleepable: bool,
}

impl FExit {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<FExit> {
        if attrs.is_empty() {
            abort!(attrs, "missing function name");
        }
        let mut args = syn::parse2(attrs)?;
        let item = syn::parse2(item)?;
        let function = pop_required_arg(&mut args, "function")?;
        err_on_unknown_args(&args)?;
        Ok(FExit {
            item,
            function,
            sleepable: false,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_prefix = if self.sleepable { "fexit.s" } else { "fexit" };
        let section_name: Cow<'_, _> = format!("{}/{}", section_prefix, self.function).into();
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_bpf::programs::FExitContext::new(ctx));
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
    fn test_fexit() {
        let prog = FExit::parse(
            parse_quote! {
                function = "sys_clone"
            },
            parse_quote! {
                fn sys_clone(ctx: &mut FExitContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "fexit/sys_clone"]
            fn sys_clone(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = sys_clone(::aya_bpf::programs::FExitContext::new(ctx));
                return 0;

                fn sys_clone(ctx: &mut FExitContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
