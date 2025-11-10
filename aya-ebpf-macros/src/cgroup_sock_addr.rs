use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{Ident, ItemFn, spanned::Spanned as _};

pub(crate) struct CgroupSockAddr {
    item: ItemFn,
    attach_type: Ident,
}

impl CgroupSockAddr {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        if attrs.is_empty() {
            return Err(attrs.span().error("missing attach type"));
        }
        let item = syn::parse2(item)?;
        let attach_type: Ident = syn::parse2(attrs)?;
        if attach_type != "connect4"
            && attach_type != "connect6"
            && attach_type != "bind4"
            && attach_type != "bind6"
            && attach_type != "getpeername4"
            && attach_type != "getpeername6"
            && attach_type != "getsockname4"
            && attach_type != "getsockname6"
            && attach_type != "sendmsg4"
            && attach_type != "sendmsg6"
            && attach_type != "recvmsg4"
            && attach_type != "recvmsg6"
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
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return #fn_name(::aya_ebpf::programs::SockAddrContext::new(ctx));

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
    fn cgroup_sock_addr_connect4() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(connect4),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/connect4")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_connect6() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(connect6),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/connect6")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_bind4() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(bind4),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/bind4")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_bind6() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(bind6),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/bind6")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_getpeername4() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(getpeername4),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/getpeername4")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_getpeername6() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(getpeername6),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/getpeername6")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_getsockname4() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(getsockname4),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/getsockname4")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_getsockname6() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(getsockname6),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/getsockname6")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_sendmsg4() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(sendmsg4),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/sendmsg4")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_sendmsg6() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(sendmsg6),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/sendmsg6")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_recvmsg4() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(recvmsg4),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/recvmsg4")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_sock_addr_recvmsg6() {
        let prog = CgroupSockAddr::parse(
            parse_quote!(recvmsg6),
            parse_quote!(
                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/recvmsg6")]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_ebpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
