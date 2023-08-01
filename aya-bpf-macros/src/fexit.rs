use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_bool_arg, pop_string_arg};

pub(crate) struct FExit {
    item: ItemFn,
    function: Option<String>,
    sleepable: bool,
}

impl FExit {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<FExit> {
        let item = syn::parse2(item)?;
        let mut function = None;
        let mut sleepable = false;
        if !attrs.is_empty() {
            let mut args = syn::parse2(attrs)?;
            if let Some(f) = pop_string_arg(&mut args, "function") {
                function = Some(f);
            };
            sleepable = pop_bool_arg(&mut args, "sleepable");
            err_on_unknown_args(&args)?;
        }
        Ok(FExit {
            item,
            function,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_prefix = if self.sleepable { "fexit.s" } else { "fexit" };
        let section_name: Cow<'_, _> = if self.function.is_none() {
            section_prefix.into()
        } else {
            format!("{}/{}", section_prefix, self.function.as_ref().unwrap()).into()
        };
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
            parse_quote! {},
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
            #[link_section = "fexit"]
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

    #[test]
    fn test_fexit_with_function() {
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

    #[test]
    fn test_fexit_sleepable() {
        let prog = FExit::parse(
            parse_quote! {
                function = "sys_clone", sleepable
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
            #[link_section = "fexit.s/sys_clone"]
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
