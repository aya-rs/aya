use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_bool_arg, pop_string_arg};

pub(crate) struct Lsm {
    item: ItemFn,
    hook: Option<String>,
    sleepable: bool,
}

impl Lsm {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Lsm> {
        let item = syn::parse2(item)?;
        let mut args = syn::parse2(attrs)?;
        let hook = pop_string_arg(&mut args, "hook");
        let sleepable = pop_bool_arg(&mut args, "sleepable");
        err_on_unknown_args(&args)?;
        Ok(Lsm {
            item,
            hook,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_prefix = if self.sleepable { "lsm.s" } else { "lsm" };
        let section_name: Cow<'_, _> = if let Some(hook) = &self.hook {
            format!("{}/{}", section_prefix, hook).into()
        } else {
            section_prefix.into()
        };
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        // LSM probes need to return an integer corresponding to the correct
        // policy decision. Therefore we do not simply default to a return value
        // of 0 as in other program types.
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                return #fn_name(::aya_bpf::programs::LsmContext::new(ctx));

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
    fn test_lsm_sleepable() {
        let prog = Lsm::parse(
            parse_quote! {
                sleepable,
                hook = "bprm_committed_creds"
            },
            parse_quote! {
                fn bprm_committed_creds(ctx: &mut ::aya_bpf::programs::LsmContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "lsm.s/bprm_committed_creds"]
            fn bprm_committed_creds(ctx: *mut ::core::ffi::c_void) -> i32 {
                return bprm_committed_creds(::aya_bpf::programs::LsmContext::new(ctx));

                fn bprm_committed_creds(ctx: &mut ::aya_bpf::programs::LsmContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_lsm() {
        let prog = Lsm::parse(
            parse_quote! {
                hook = "bprm_committed_creds"
            },
            parse_quote! {
                fn bprm_committed_creds(ctx: &mut ::aya_bpf::programs::LsmContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "lsm/bprm_committed_creds"]
            fn bprm_committed_creds(ctx: *mut ::core::ffi::c_void) -> i32 {
                return bprm_committed_creds(::aya_bpf::programs::LsmContext::new(ctx));

                fn bprm_committed_creds(ctx: &mut ::aya_bpf::programs::LsmContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
