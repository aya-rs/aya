use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{ItemFn, spanned::Spanned as _};

pub(crate) struct CgroupDevice {
    item: ItemFn,
}

impl CgroupDevice {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        if !attrs.is_empty() {
            return Err(attrs.span().error("unexpected attribute"));
        }
        let item = syn::parse2(item)?;
        Ok(Self { item })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let fn_name = &sig.ident;
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/dev")]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::bpf_cgroup_dev_ctx) -> i32 {
                return #fn_name(::aya_ebpf::programs::DeviceContext::new(ctx));

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
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "cgroup/dev")]
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
