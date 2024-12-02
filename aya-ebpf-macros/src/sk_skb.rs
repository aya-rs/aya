use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{spanned::Spanned as _, ItemFn};

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone)]
pub(crate) enum SkSkbKind {
    StreamVerdict,
    StreamParser,
}

impl std::fmt::Display for SkSkbKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SkSkbKind::*;
        match self {
            StreamVerdict => write!(f, "stream_verdict"),
            StreamParser => write!(f, "stream_parser"),
        }
    }
}

pub(crate) struct SkSkb {
    kind: SkSkbKind,
    item: ItemFn,
}

impl SkSkb {
    pub(crate) fn parse(
        kind: SkSkbKind,
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<Self, Diagnostic> {
        if !attrs.is_empty() {
            return Err(attrs.span().error("unexpected attribute"));
        }
        let item = syn::parse2(item)?;
        Ok(Self { item, kind })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { kind, item } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let section_name: Cow<'_, _> = format!("sk_skb/{kind}").into();
        let fn_name = &sig.ident;
        quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> u32 {
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
    fn test_stream_parser() {
        let prog = SkSkb::parse(
            SkSkbKind::StreamParser,
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::SkBuffContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "sk_skb/stream_parser"]
            fn prog(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> u32 {
                return prog(::aya_ebpf::programs::SkBuffContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::SkBuffContext) -> u32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_stream_verdict() {
        let prog = SkSkb::parse(
            SkSkbKind::StreamVerdict,
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::SkBuffContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "sk_skb/stream_verdict"]
            fn prog(ctx: *mut ::aya_ebpf::bindings::__sk_buff) -> u32 {
                return prog(::aya_ebpf::programs::SkBuffContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::SkBuffContext) -> u32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
