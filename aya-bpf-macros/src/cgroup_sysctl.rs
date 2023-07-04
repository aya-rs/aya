use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

pub(crate) struct CgroupSysctl {
    item: ItemFn,
}

impl CgroupSysctl {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        if !attrs.is_empty() {
            abort!(attrs, "unexpected attribute")
        }
        let item = syn::parse2(item)?;
        Ok(CgroupSysctl { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = "cgroup/sysctl"]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sysctl) -> i32 {
                return #fn_name(::aya_bpf::programs::SysctlContext::new(ctx));

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
    fn test_cgroup_sysctl() {
        let prog = CgroupSysctl::parse(
            parse_quote!(),
            parse_quote!(
                fn foo(ctx: SysctlContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/sysctl"]
            fn foo(ctx: *mut ::aya_bpf::bindings::bpf_sysctl) -> i32 {
                return foo(::aya_bpf::programs::SysctlContext::new(ctx));

                fn foo(ctx: SysctlContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
