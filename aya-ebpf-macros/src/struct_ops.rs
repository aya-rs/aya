use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_bool_arg, pop_string_arg};

pub(crate) struct StructOps {
    item: ItemFn,
    name: Option<String>,
    sleepable: bool,
}

impl StructOps {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item = syn::parse2(item)?;
        let mut args = syn::parse2(attrs)?;
        let name = pop_string_arg(&mut args, "name");
        let sleepable = pop_bool_arg(&mut args, "sleepable");
        err_on_unknown_args(&args)?;
        Ok(Self {
            item,
            name,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self {
            item,
            name,
            sleepable,
        } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let section_prefix = if *sleepable {
            "struct_ops.s"
        } else {
            "struct_ops"
        };
        let fn_name = &sig.ident;
        let section_name: Cow<'_, _> = if let Some(name) = name {
            format!("{section_prefix}/{name}").into()
        } else {
            format!("{section_prefix}/{fn_name}").into()
        };
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section_name)]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_ebpf::programs::StructOpsContext::new(ctx));
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
    fn test_struct_ops() {
        let prog = StructOps::parse(
            parse_quote! {},
            parse_quote! {
                fn my_callback(ctx: &mut aya_ebpf::programs::StructOpsContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "struct_ops/my_callback")]
            fn my_callback(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = my_callback(::aya_ebpf::programs::StructOpsContext::new(ctx));
                return 0;

                fn my_callback(ctx: &mut aya_ebpf::programs::StructOpsContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_struct_ops_with_name() {
        let prog = StructOps::parse(
            parse_quote! {
                name = "hid_device_event"
            },
            parse_quote! {
                fn my_handler(ctx: &mut aya_ebpf::programs::StructOpsContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "struct_ops/hid_device_event")]
            fn my_handler(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = my_handler(::aya_ebpf::programs::StructOpsContext::new(ctx));
                return 0;

                fn my_handler(ctx: &mut aya_ebpf::programs::StructOpsContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_struct_ops_sleepable() {
        let prog = StructOps::parse(
            parse_quote! {
                sleepable
            },
            parse_quote! {
                fn my_callback(ctx: &mut aya_ebpf::programs::StructOpsContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "struct_ops.s/my_callback")]
            fn my_callback(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = my_callback(::aya_ebpf::programs::StructOpsContext::new(ctx));
                return 0;

                fn my_callback(ctx: &mut aya_ebpf::programs::StructOpsContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
