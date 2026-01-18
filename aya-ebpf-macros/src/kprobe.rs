use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{ItemFn, spanned::Spanned as _};

use crate::args::Args;

#[derive(Debug, Copy, Clone)]
pub(crate) enum KProbeKind {
    KProbe,
    KRetProbe,
}

impl std::fmt::Display for KProbeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KProbe => write!(f, "kprobe"),
            Self::KRetProbe => write!(f, "kretprobe"),
        }
    }
}

pub(crate) struct KProbe {
    kind: KProbeKind,
    function: Option<String>,
    offset: Option<u64>,
    item: ItemFn,
}

impl KProbe {
    pub(crate) fn parse(
        kind: KProbeKind,
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<Self, Diagnostic> {
        let item = syn::parse2(item)?;
        let span = attrs.span();
        let mut args: Args = syn::parse2(attrs)?;
        let function = args.pop_string("function");
        let offset = args
            .pop_string("offset")
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|err| span.error(format!("failed to parse `offset` argument: {err}")))?;
        args.into_error()?;

        Ok(Self {
            kind,
            item,
            function,
            offset,
        })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self {
            kind,
            function,
            offset,
            item,
        } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let section_name: Cow<'_, _> = match function {
            None => self.kind.to_string().into(),
            Some(function) => match offset {
                None => format!("{kind}/{function}").into(),
                Some(offset) => format!("{kind}/{function}+{offset}").into(),
            },
        };
        let probe_type = if section_name.as_ref().starts_with("kprobe") {
            quote! { ProbeContext }
        } else {
            quote! { RetProbeContext }
        };
        let fn_name = &sig.ident;
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section_name)]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = #fn_name(::aya_ebpf::programs::#probe_type::new(ctx));
                return 0;

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
    fn test_kprobe() {
        let kprobe = KProbe::parse(
            KProbeKind::KProbe,
            parse_quote! {},
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            kprobe.expand().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "kprobe")]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_ebpf::programs::ProbeContext::new(ctx));
                    return 0;

                    fn foo(ctx: ProbeContext) -> u32 {
                        0
                    }
                }
            }
            .to_string()
        );
    }

    #[test]
    fn test_kprobe_with_function() {
        let kprobe = KProbe::parse(
            KProbeKind::KProbe,
            parse_quote! {
                function = "fib_lookup"
            },
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            kprobe.expand().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "kprobe/fib_lookup")]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_ebpf::programs::ProbeContext::new(ctx));
                    return 0;

                    fn foo(ctx: ProbeContext) -> u32 {
                        0
                    }
                }
            }
            .to_string()
        );
    }

    #[test]
    fn test_kprobe_with_function_and_offset() {
        let kprobe = KProbe::parse(
            KProbeKind::KProbe,
            parse_quote! {
                function = "fib_lookup",
                offset = "10"
            },
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            kprobe.expand().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "kprobe/fib_lookup+10")]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_ebpf::programs::ProbeContext::new(ctx));
                    return 0;

                    fn foo(ctx: ProbeContext) -> u32 {
                        0
                    }
                }
            }
            .to_string()
        );
    }

    #[test]
    fn test_kretprobe() {
        let kprobe = KProbe::parse(
            KProbeKind::KRetProbe,
            parse_quote! {},
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            kprobe.expand().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "kretprobe")]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_ebpf::programs::RetProbeContext::new(ctx));
                    return 0;

                    fn foo(ctx: ProbeContext) -> u32 {
                        0
                    }
                }
            }
            .to_string()
        );
    }
}
