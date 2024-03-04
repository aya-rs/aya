use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

pub(crate) struct CgroupDevice {
    item: ItemFn,
}

impl CgroupDevice {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        if !attrs.is_empty() {
            abort!(attrs, "unexpected attribute")
        }
        let item = syn::parse2(item)?;
        Ok(CgroupDevice { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = "cgroup/dev"]
            #fn_vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::bpf_cgroup_dev_ctx) -> i32 {
                return #fn_name(::aya_ebpf::programs::DeviceContext::new(ctx));

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
    fn test_cgroup_device() {
        let prog = CgroupDevice::parse(
            parse_quote!(),
            parse_quote!(
                fn foo(ctx: DeviceContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "cgroup/dev"]
            fn foo(ctx: *mut ::aya_ebpf::bindings::bpf_cgroup_dev_ctx) -> i32 {
                return foo(::aya_ebpf::programs::DeviceContext::new(ctx));

                fn foo(ctx: DeviceContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
