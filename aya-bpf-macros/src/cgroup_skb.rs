use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{Ident, ItemFn, Result};

pub(crate) struct CgroupSkb {
    item: ItemFn,
    attach_type: Option<String>,
}

impl CgroupSkb {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<CgroupSkb> {
        let item: ItemFn = syn::parse2(item)?;
        let mut attach_type = None;
        if !attrs.is_empty() {
            let ident: Ident = syn::parse2(attrs)?;
            match ident.to_string().as_str() {
                "ingress" | "egress" => (),
                _ => abort!(ident, "invalid attach type"),
            }
            attach_type = Some(ident.to_string());
        }
        Ok(CgroupSkb { item, attach_type })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_name: Cow<'_, _> = if self.attach_type.is_some() {
            format!("cgroup_skb/{}", self.attach_type.as_ref().unwrap()).into()
        } else {
            "cgroup_skb".into()
        };
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return #fn_name(::aya_bpf::programs::SkBuffContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb"]
            fn foo(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_bpf::programs::SkBuffContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/egress"]
            fn foo(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_bpf::programs::SkBuffContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/ingress"]
            fn foo(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_bpf::programs::SkBuffContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/egress"]
            fn foo(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_bpf::programs::SkBuffContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/egress"]
            pub fn foo(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_bpf::programs::SkBuffContext::new(ctx));

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
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup_skb/egress"]
            pub(crate) fn foo(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return foo(::aya_bpf::programs::SkBuffContext::new(ctx));

                pub(crate) fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
