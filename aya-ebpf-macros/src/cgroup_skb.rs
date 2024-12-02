use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{Ident, ItemFn};

pub(crate) struct CgroupSkb {
    item: ItemFn,
    attach_type: Option<Ident>,
}

impl CgroupSkb {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        let item: ItemFn = syn::parse2(item)?;
        let attach_type = if attrs.is_empty() {
            None
        } else {
            let ident: Ident = syn::parse2(attrs)?;
            if ident != "ingress" && ident != "egress" {
                return Err(ident.span().error("invalid attach type"));
            }
            Some(ident)
        };
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
        let section_name: Cow<'_, _> = match attach_type {
            Some(attach_type) => format!("cgroup_skb/{attach_type}").into(),
            None => "cgroup/skb".into(),
        };
        let fn_name = &sig.ident;
        quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return #fn_name(::aya_ebpf::programs::SkBuffContext::new(ctx));

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
    fn cgroup_skb() {
        let prog = CgroupSkb::parse(
            parse_quote!(),
            parse_quote!(
                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/skb"]
            fn foo(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_ebpf::programs::SkBuffContext::new(ctx));

                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_skb_egress() {
        let prog = CgroupSkb::parse(
            parse_quote!(egress),
            parse_quote!(
                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/egress"]
            fn foo(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_ebpf::programs::SkBuffContext::new(ctx));

                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn cgroup_skb_ingress() {
        let prog = CgroupSkb::parse(
            parse_quote!(ingress),
            parse_quote!(
                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/ingress"]
            fn foo(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_ebpf::programs::SkBuffContext::new(ctx));

                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn priv_function() {
        let prog = CgroupSkb::parse(
            parse_quote!(egress),
            parse_quote!(
                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/egress"]
            fn foo(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_ebpf::programs::SkBuffContext::new(ctx));

                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn pub_function() {
        let prog = CgroupSkb::parse(
            parse_quote!(egress),
            parse_quote!(
                pub fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/egress"]
            pub fn foo(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_ebpf::programs::SkBuffContext::new(ctx));

                pub fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn pub_crate_function() {
        let prog = CgroupSkb::parse(
            parse_quote!(egress),
            parse_quote!(
                pub(crate) fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/egress"]
            pub(crate) fn foo(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_ebpf::programs::SkBuffContext::new(ctx));

                pub(crate) fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
