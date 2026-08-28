use std::borrow::Cow;

use proc_macro2::TokenStream;
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
    is_multi: bool,
    item: ItemFn,
}

impl KProbe {
    pub(crate) fn parse(
        kind: KProbeKind,
        attrs: TokenStream,
        item: TokenStream,
    ) -> syn::Result<Self> {
        let item = syn::parse2(item)?;
        let span = attrs.span();
        let mut args: Args = syn::parse2(attrs)?;
        let function = args.pop_string("function");
        let offset = args
            .pop_string("offset")
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|err| {
                syn::Error::new(span, format!("failed to parse `offset` argument: {err}"))
            })?;
        let is_multi = args.pop_bool("multi");
        args.into_error()?;

        // `kprobe.multi` sections accept a function-name pattern, but no offset:
        // https://github.com/torvalds/linux/blob/46d9f15a5/Documentation/bpf/libbpf/program_types.rst#L245-L247
        if is_multi && offset.is_some() {
            return Err(syn::Error::new(
                span,
                "`multi` cannot be combined with `offset`",
            ));
        }

        Ok(Self {
            kind,
            function,
            offset,
            is_multi,
            item,
        })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self {
            kind,
            function,
            offset,
            is_multi,
            item,
        } = self;
        let ItemFn {
            attrs: _,
            vis,
            modifiers: _,
            sig,
            block: _,
        } = item;
        let mut prefix = kind.to_string();
        if *is_multi {
            prefix.push_str(".multi");
        }
        let section_name: Cow<'_, _> = match function {
            None => prefix.into(),
            Some(function) => match offset {
                None => format!("{prefix}/{function}").into(),
                Some(offset) => format!("{prefix}/{function}+{offset}").into(),
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
    use rstest::rstest;
    use syn::parse_quote;

    use super::*;

    #[rstest]
    #[case::kprobe(KProbeKind::KProbe, "", "kprobe")]
    #[case::kprobe_with_function(
        KProbeKind::KProbe,
        r#"function = "fib_lookup""#,
        "kprobe/fib_lookup"
    )]
    #[case::kprobe_with_function_and_offset(
        KProbeKind::KProbe,
        r#"function = "fib_lookup", offset = "10""#,
        "kprobe/fib_lookup+10"
    )]
    #[case::kretprobe(KProbeKind::KRetProbe, "", "kretprobe")]
    #[case::kprobe_multi(KProbeKind::KProbe, "multi", "kprobe.multi")]
    #[case::kprobe_multi_with_function(
        KProbeKind::KProbe,
        r#"multi, function = "fib_lookup""#,
        "kprobe.multi/fib_lookup"
    )]
    #[case::kretprobe_multi(KProbeKind::KRetProbe, "multi", "kretprobe.multi")]
    #[case::kretprobe_multi_with_pattern(
        KProbeKind::KRetProbe,
        r#"multi, function = "fib_*""#,
        "kretprobe.multi/fib_*"
    )]
    fn emits_expected_section(
        #[case] kind: KProbeKind,
        #[case] attrs: &str,
        #[case] section_name: &str,
    ) {
        let kprobe = KProbe::parse(
            kind,
            attrs.parse().unwrap(),
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();

        let probe_type = match kind {
            KProbeKind::KProbe => quote! { ProbeContext },
            KProbeKind::KRetProbe => quote! { RetProbeContext },
        };

        assert_eq!(
            kprobe.expand().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = #section_name)]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_ebpf::programs::#probe_type::new(ctx));
                    return 0;

                    fn foo(ctx: ProbeContext) -> u32 {
                        0
                    }
                }
            }
            .to_string()
        );
    }

    #[rstest]
    #[case::offset(r#"multi, offset = "10""#)]
    #[case::function_and_offset(r#"multi, function = "fib_lookup", offset = "10""#)]
    fn kprobe_multi_rejects_offset(#[case] attrs: &str) {
        let Err(err) = KProbe::parse(
            KProbeKind::KProbe,
            attrs.parse().unwrap(),
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        ) else {
            panic!("expected multi-kprobe offset to be rejected");
        };

        assert_eq!(err.to_string(), "`multi` cannot be combined with `offset`");
    }
}
