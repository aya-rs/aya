use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_string_arg};

pub(crate) struct LsmCgroup {
    item: ItemFn,
    hook: Option<String>,
}

impl LsmCgroup {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item = syn::parse2(item)?;
        let mut args = syn::parse2(attrs)?;
        let hook = pop_string_arg(&mut args, "hook");
        err_on_unknown_args(&args)?;

        Ok(Self { item, hook })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item, hook } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let section_prefix = "lsm_cgroup";
        let section_name: Cow<'_, _> = if let Some(name) = hook {
            format!("{}/{}", section_prefix, name).into()
        } else {
            section_prefix.into()
        };
        let fn_name = &sig.ident;
        // LSM probes need to return an integer corresponding to the correct
        // policy decision. Therefore we do not simply default to a return value
        // of 0 as in other program types.
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section_name)]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                return #fn_name(::aya_ebpf::programs::LsmContext::new(ctx));

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
    fn test_lsm_cgroup() {
        let prog = LsmCgroup::parse(
            parse_quote! {
                hook = "bprm_committed_creds",
            },
            parse_quote! {
                fn bprm_committed_creds(ctx: &mut ::aya_ebpf::programs::LsmContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "lsm_cgroup/bprm_committed_creds")]
            fn bprm_committed_creds(ctx: *mut ::core::ffi::c_void) -> i32 {
                return bprm_committed_creds(::aya_ebpf::programs::LsmContext::new(ctx));

                fn bprm_committed_creds(ctx: &mut ::aya_ebpf::programs::LsmContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
