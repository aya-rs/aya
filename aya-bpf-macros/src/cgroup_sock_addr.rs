use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{Ident, ItemFn, Result};

pub(crate) struct CgroupSockAddr {
    item: ItemFn,
    attach_type: String,
}

impl CgroupSockAddr {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        if attrs.is_empty() {
            abort!(attrs, "missing attach type")
        }
        let attach_type: Ident = syn::parse2(attrs)?;
        match attach_type.to_string().as_str() {
            "connect4" | "connect6" | "bind4" | "bind6" | "getpeername4" | "getpeername6"
            | "getsockname4" | "getsockname6" | "sendmsg4" | "sendmsg6" | "recvmsg4"
            | "recvmsg6" => (),
            _ => abort!(attach_type, "invalid attach type"),
        }
        let item = syn::parse2(item)?;
        Ok(CgroupSockAddr {
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
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return #fn_name(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/connect4"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/connect6"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/bind4"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/bind6"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/getpeername4"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/getpeername6"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/getsockname4"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/getsockname6"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/sendmsg4"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/sendmsg6"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/recvmsg4"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/recvmsg6"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return foo(::aya_bpf::programs::SockAddrContext::new(ctx));

                fn foo(ctx: CgroupSockAddrContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
