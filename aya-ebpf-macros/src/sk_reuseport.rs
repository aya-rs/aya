use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{Ident, ItemFn, spanned::Spanned as _};

#[derive(Clone, Copy)]
enum SkReuseportSection {
    Select,
    SelectOrMigrate,
}

impl SkReuseportSection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Select => "sk_reuseport",
            Self::SelectOrMigrate => "sk_reuseport/migrate",
        }
    }
}

pub(crate) struct SkReuseport {
    item: ItemFn,
    section: SkReuseportSection,
}

impl SkReuseport {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        let section = if attrs.is_empty() {
            SkReuseportSection::Select
        } else {
            let attr = syn::parse2::<Ident>(attrs.clone())?;
            if attr == "migrate" {
                SkReuseportSection::SelectOrMigrate
            } else {
                return Err(attrs.span().error("unexpected attribute"));
            }
        };
        let item = syn::parse2(item)?;
        Ok(Self { item, section })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item, section } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let fn_name = &sig.ident;
        let section = section.as_str();
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section)]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::sk_reuseport_md) -> u32 {
                return #fn_name(::aya_ebpf::programs::SkReuseportContext::new(ctx));

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
    fn test_sk_reuseport() {
        let prog = SkReuseport::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::SkReuseportContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "sk_reuseport")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::sk_reuseport_md) -> u32 {
                return prog(::aya_ebpf::programs::SkReuseportContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::SkReuseportContext) -> u32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_sk_reuseport_migrate() {
        let prog = SkReuseport::parse(
            parse_quote! { migrate },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::SkReuseportContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "sk_reuseport/migrate")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::sk_reuseport_md) -> u32 {
                return prog(::aya_ebpf::programs::SkReuseportContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::SkReuseportContext) -> u32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
