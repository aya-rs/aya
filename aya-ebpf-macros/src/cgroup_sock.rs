use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{Ident, ItemFn, spanned::Spanned as _};

pub(crate) struct CgroupSock {
    item: ItemFn,
    attach_type: Ident,
}

impl CgroupSock {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        if attrs.is_empty() {
            return Err(attrs.span().error("missing attach type"));
        }
        let item: ItemFn = syn::parse2(item)?;
        let attach_type: Ident = syn::parse2(attrs)?;
        if attach_type != "post_bind4"
            && attach_type != "post_bind6"
            && attach_type != "sock_create"
            && attach_type != "sock_release"
        {
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
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::bpf_sock) -> i32 {
                return #fn_name(::aya_ebpf::programs::SockContext::new(ctx));

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
    fn cgroup_sock_post_bind4() {
        let prog = CgroupSock::parse(
            parse_quote!(post_bind4),
            parse_quote!(
                fn foo(ctx: SockContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/post_bind4")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock) -> i32 {
                return foo(::aya_ebpf::programs::SockContext::new(ctx));

                fn foo(ctx: SockContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_post_bind6() {
        let prog = CgroupSock::parse(
            parse_quote!(post_bind6),
            parse_quote!(
                fn foo(ctx: SockContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/post_bind6")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock) -> i32 {
                return foo(::aya_ebpf::programs::SockContext::new(ctx));

                fn foo(ctx: SockContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
    #[test]
    fn cgroup_sock_sock_create() {
        let prog = CgroupSock::parse(
            parse_quote!(sock_create),
            parse_quote!(
                fn foo(ctx: SockContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/sock_create")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock) -> i32 {
                return foo(::aya_ebpf::programs::SockContext::new(ctx));

                fn foo(ctx: SockContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
    #[test]
    fn cgroup_sock_sock_release() {
        let prog = CgroupSock::parse(
            parse_quote!(sock_release),
            parse_quote!(
                fn foo(ctx: SockContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/sock_release")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock) -> i32 {
                return foo(::aya_ebpf::programs::SockContext::new(ctx));

                fn foo(ctx: SockContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
