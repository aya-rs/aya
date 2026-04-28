use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{ItemFn, spanned::Spanned as _};

use crate::args::Args;

#[derive(Debug, Copy, Clone)]
pub(crate) enum UProbeKind {
    UProbe,
    URetProbe,
}

impl std::fmt::Display for UProbeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UProbe => write!(f, "uprobe"),
            Self::URetProbe => write!(f, "uretprobe"),
        }
    }
}

pub(crate) struct UProbe {
    kind: UProbeKind,
    path: Option<String>,
    function: Option<String>,
    offset: Option<u64>,
    item: ItemFn,
    sleepable: bool,
    multi: bool,
}

impl UProbe {
    pub(crate) fn parse(
        kind: UProbeKind,
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<Self, Diagnostic> {
        let item = syn::parse2(item)?;
        let span = attrs.span();
        let mut args: Args = syn::parse2(attrs)?;
        let path = args.pop_string("path");
        let function = args.pop_string("function");
        let offset = args
            .pop_string("offset")
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|err| span.error(format!("failed to parse `offset` argument: {err}")))?;
        let sleepable = args.pop_bool("sleepable");
        let multi = args.pop_bool("multi");
        args.into_error()?;
        Ok(Self {
            kind,
            path,
            function,
            offset,
            item,
            sleepable,
            multi,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream, Diagnostic> {
        let Self {
            kind,
            path,
            function,
            offset,
            item,
            sleepable,
            multi,
        } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let mut prefix = kind.to_string();
        // `.multi` must come before `.s` to match libbpf's SEC convention,
        // e.g. `uprobe.multi.s` rather than `uprobe.s.multi`.
        // https://docs.kernel.org/bpf/libbpf/program_types.html
        if *multi {
            prefix.push_str(".multi");
        }
        if *sleepable {
            prefix.push_str(".s");
        }
        let section_name: Cow<'_, _> = match path {
            None => prefix.into(),
            Some(path) => {
                let path = path.strip_prefix("/").unwrap_or(path);
                // TODO: check this in parse instead.
                let function = function
                    .as_deref()
                    .ok_or_else(|| item.sig.span().error("expected `function` attribute"))?;
                match offset {
                    None => format!("{prefix}/{path}:{function}").into(),
                    Some(offset) => format!("{prefix}/{path}:{function}+{offset}").into(),
                }
            }
        };

        let probe_type = if section_name.as_ref().starts_with("uprobe") {
            quote! { ProbeContext }
        } else {
            quote! { RetProbeContext }
        };
        let fn_name = &sig.ident;
        Ok(quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section_name)]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = #fn_name(::aya_ebpf::programs::#probe_type::new(ctx));
                return 0;

                #item
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;
    use test_case::test_case;

    use super::*;

    #[test_case(UProbeKind::UProbe, "", "uprobe"; "uprobe")]
    #[test_case(UProbeKind::UProbe, "sleepable", "uprobe.s"; "uprobe_sleepable")]
    #[test_case(
        UProbeKind::UProbe,
        r#"path = "/self/proc/exe", function = "trigger_uprobe""#,
        "uprobe/self/proc/exe:trigger_uprobe";
        "uprobe_with_path"
    )]
    #[test_case(
        UProbeKind::UProbe,
        r#"path = "/self/proc/exe", function = "foo", offset = "123""#,
        "uprobe/self/proc/exe:foo+123";
        "uprobe_with_path_and_offset"
    )]
    #[test_case(UProbeKind::URetProbe, "", "uretprobe"; "uretprobe")]
    #[test_case(UProbeKind::UProbe, "multi", "uprobe.multi"; "uprobe_multi")]
    #[test_case(
        UProbeKind::UProbe,
        "multi, sleepable",
        "uprobe.multi.s";
        "uprobe_multi_sleepable"
    )]
    #[test_case(
        UProbeKind::UProbe,
        r#"multi, path = "/self/proc/exe", function = "trigger_uprobe""#,
        "uprobe.multi/self/proc/exe:trigger_uprobe";
        "uprobe_multi_with_path"
    )]
    #[test_case(UProbeKind::URetProbe, "multi", "uretprobe.multi"; "uretprobe_multi")]
    #[test_case(
        UProbeKind::URetProbe,
        "multi, sleepable",
        "uretprobe.multi.s";
        "uretprobe_multi_sleepable"
    )]
    fn uprobe(kind: UProbeKind, attrs: &str, section_name: &str) {
        let uprobe = UProbe::parse(
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
            UProbeKind::UProbe => quote! { ProbeContext },
            UProbeKind::URetProbe => quote! { RetProbeContext },
        };

        assert_eq!(
            uprobe.expand().unwrap().to_string(),
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
}
