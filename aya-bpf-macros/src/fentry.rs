use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_bool_arg, pop_string_arg};

pub(crate) struct FEntry {
    item: ItemFn,
    function: Option<String>,
    sleepable: bool,
}

impl FEntry {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<FEntry> {
        let item = syn::parse2(item)?;
        let mut args = syn::parse2(attrs)?;
        let function = pop_string_arg(&mut args, "function");
        let sleepable = pop_bool_arg(&mut args, "sleepable");
        err_on_unknown_args(&args)?;
        Ok(FEntry {
            item,
            function,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_prefix = if self.sleepable { "fentry.s" } else { "fentry" };
        let section_name: Cow<'_, _> = if let Some(function) = &self.function {
            format!("{}/{}", section_prefix, function).into()
        } else {
            section_prefix.into()
        };
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_bpf::programs::FEntryContext::new(ctx));
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
    fn test_fentry() {
        let prog = FEntry::parse(
            parse_quote! {},
            parse_quote! {
                fn sys_clone(ctx: &mut aya_bpf::programs::FEntryContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "fentry"]
            fn sys_clone(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = sys_clone(::aya_bpf::programs::FEntryContext::new(ctx));
                return 0;

                fn sys_clone(ctx: &mut aya_bpf::programs::FEntryContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_fentry_with_function() {
        let prog = FEntry::parse(
            parse_quote! {
                function = "sys_clone"
            },
            parse_quote! {
                fn sys_clone(ctx: &mut aya_bpf::programs::FEntryContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "fentry/sys_clone"]
            fn sys_clone(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = sys_clone(::aya_bpf::programs::FEntryContext::new(ctx));
                return 0;

                fn sys_clone(ctx: &mut aya_bpf::programs::FEntryContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_fentry_sleepable() {
        let prog = FEntry::parse(
            parse_quote! {
                sleepable
            },
            parse_quote! {
                fn sys_clone(ctx: &mut aya_bpf::programs::FEntryContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "fentry.s"]
            fn sys_clone(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = sys_clone(::aya_bpf::programs::FEntryContext::new(ctx));
                return 0;

                fn sys_clone(ctx: &mut aya_bpf::programs::FEntryContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
