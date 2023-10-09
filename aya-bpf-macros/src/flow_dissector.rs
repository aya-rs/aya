use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

pub(crate) struct FlowDissector {
    item: ItemFn,
}

impl FlowDissector {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        if !attrs.is_empty() {
            abort!(attrs, "unexpected attribute")
        }
        let item = syn::parse2(item)?;
        Ok(FlowDissector { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_name = self.item.sig.ident.clone();
        let fn_vis = &self.item.vis;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = "flow_dissector"]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> u32 {
                return #fn_name(::aya_bpf::programs::FlowDissectorContext::new(ctx));

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
    fn test_flow_dissector() {
        let prog = FlowDissector::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_bpf::programs::FlowDissectorContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "flow_dissector"]
            fn prog(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> u32 {
                return prog(::aya_bpf::programs::FlowDissectorContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::FlowDissectorContext) -> u32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
