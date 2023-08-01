use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{Ident, ItemFn, Result};

pub(crate) struct CgroupSockopt {
    item: ItemFn,
    attach_type: String,
}

impl CgroupSockopt {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<CgroupSockopt> {
        if attrs.is_empty() {
            abort!(attrs, "expected attach type");
        }
        let item = syn::parse2(item)?;
        let attach_type: Ident = syn::parse2(attrs)?;
        match attach_type.to_string().as_str() {
            "getsockopt" | "setsockopt" => (),
            _ => abort!(attach_type, "invalid attach type"),
        }
        Ok(CgroupSockopt {
            item,
            attach_type: attach_type.to_string(),
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_name: Cow<'_, _> = format!("cgroup/{}", self.attach_type).into();
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sockopt) -> i32 {
                return #fn_name(::aya_bpf::programs::SockoptContext::new(ctx));

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
    fn cgroup_sockopt_getsockopt() {
        let prog = CgroupSockopt::parse(
            parse_quote!(getsockopt),
            parse_quote!(
                fn foo(ctx: SockoptContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote!(
            #[no_mangle]
            #[link_section = "cgroup/getsockopt"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sockopt) -> i32 {
                return foo(::aya_bpf::programs::SockoptContext::new(ctx));

                fn foo(ctx: SockoptContext) -> i32 {
                    0
                }
            }
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sockopt_setsockopt() {
        let prog = CgroupSockopt::parse(
            parse_quote!(setsockopt),
            parse_quote!(
                fn foo(ctx: SockoptContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote!(
            #[no_mangle]
            #[link_section = "cgroup/setsockopt"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sockopt) -> i32 {
                return foo(::aya_bpf::programs::SockoptContext::new(ctx));

                fn foo(ctx: SockoptContext) -> i32 {
                    0
                }
            }
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
