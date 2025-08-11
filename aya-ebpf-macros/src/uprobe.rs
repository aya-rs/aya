use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{ItemFn, spanned::Spanned as _};

use crate::args::{err_on_unknown_args, pop_bool_arg, pop_string_arg};

#[derive(Debug, Copy, Clone)]
pub(crate) enum UProbeKind {
    UProbe,
    URetProbe,
}

impl std::fmt::Display for UProbeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use UProbeKind::*;
        match self {
            UProbe => write!(f, "uprobe"),
            URetProbe => write!(f, "uretprobe"),
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
}

impl UProbe {
    pub(crate) fn parse(
        kind: UProbeKind,
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<Self, Diagnostic> {
        let item = syn::parse2(item)?;
        let span = attrs.span();
        let mut args = syn::parse2(attrs)?;
        let path = pop_string_arg(&mut args, "path");
        let function = pop_string_arg(&mut args, "function");
        let offset = pop_string_arg(&mut args, "offset")
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|err| span.error(format!("failed to parse `offset` argument: {err}")))?;
        let sleepable = pop_bool_arg(&mut args, "sleepable");
        err_on_unknown_args(&args)?;
        Ok(Self {
            kind,
            item,
            path,
            function,
            offset,
            sleepable,
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
        } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let mut prefix = kind.to_string();
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
                    .ok_or(item.sig.span().error("expected `function` attribute"))?;
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

    use super::*;

    #[test]
    fn uprobe() {
        let uprobe = UProbe::parse(
            UProbeKind::UProbe,
            parse_quote! {},
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            uprobe.expand().unwrap().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "uprobe")]
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
    fn uprobe_sleepable() {
        let uprobe = UProbe::parse(
            UProbeKind::UProbe,
            parse_quote! {sleepable},
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            uprobe.expand().unwrap().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "uprobe.s")]
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
    fn uprobe_with_path() {
        let uprobe = UProbe::parse(
            UProbeKind::UProbe,
            parse_quote! {
                path = "/self/proc/exe",
                function = "trigger_uprobe"
            },
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            uprobe.expand().unwrap().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "uprobe/self/proc/exe:trigger_uprobe")]
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
    fn test_uprobe_with_path_and_offset() {
        let uprobe = UProbe::parse(
            UProbeKind::UProbe,
            parse_quote! {
                path = "/self/proc/exe", function = "foo", offset = "123"
            },
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            uprobe.expand().unwrap().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "uprobe/self/proc/exe:foo+123")]
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
    fn test_uretprobe() {
        let uprobe = UProbe::parse(
            UProbeKind::URetProbe,
            parse_quote! {},
            parse_quote! {
                fn foo(ctx: ProbeContext) -> u32 {
                    0
                }
            },
        )
        .unwrap();
        assert_eq!(
            uprobe.expand().unwrap().to_string(),
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = "uretprobe")]
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
