use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{Ident, ItemFn, spanned::Spanned as _};

pub(crate) struct CgroupSockopt {
    item: ItemFn,
    attach_type: Ident,
}

impl CgroupSockopt {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        if attrs.is_empty() {
            return Err(attrs.span().error("missing attach type"));
        }
        let item = syn::parse2(item)?;
        let attach_type: Ident = syn::parse2(attrs)?;
        if attach_type != "getsockopt" && attach_type != "setsockopt" {
            return Err(attach_type.span().error("invalid attach type"));
        }
        Ok(Self { item, attach_type })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item, attach_type } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let section_name: Cow<'_, _> = format!("cgroup/{attach_type}").into();
        let fn_name = &sig.ident;
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section_name)]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::bpf_sockopt) -> i32 {
                return #fn_name(::aya_ebpf::programs::SockoptContext::new(ctx));

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
        let expanded = prog.expand();
        let expected = quote!(
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/getsockopt")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sockopt) -> i32 {
                return foo(::aya_ebpf::programs::SockoptContext::new(ctx));

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
        let expanded = prog.expand();
        let expected = quote!(
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/setsockopt")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sockopt) -> i32 {
                return foo(::aya_ebpf::programs::SockoptContext::new(ctx));

                fn foo(ctx: SockoptContext) -> i32 {
                    0
                }
            }
        );
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
