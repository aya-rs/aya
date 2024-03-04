use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{Ident, ItemFn, Result};

pub(crate) struct CgroupSock {
    item: ItemFn,
    attach_type: String,
}

impl CgroupSock {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<CgroupSock> {
        if attrs.is_empty() {
            abort!(attrs, "missing attach type")
        }
        let item: ItemFn = syn::parse2(item)?;
        let attach_type: Ident = syn::parse2(attrs)?;
        match attach_type.to_string().as_str() {
            "post_bind4" | "post_bind6" | "sock_create" | "sock_release" => (),
            _ => abort!(attach_type, "invalid attach type"),
        }
        Ok(CgroupSock {
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
            #fn_vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::bpf_sock) -> i32 {
                return #fn_name(::aya_ebpf::programs::SockContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/post_bind4"]
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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/post_bind6"]
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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/sock_create"]
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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/sock_release"]
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
