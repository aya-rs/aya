use std::borrow::Cow;

use proc_macro2::TokenStream;

use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_string_arg};

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone)]
pub(crate) enum KProbeKind {
    KProbe,
    KRetProbe,
}

impl std::fmt::Display for KProbeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use KProbeKind::*;
        match self {
            KProbe => write!(f, "kprobe"),
            KRetProbe => write!(f, "kretprobe"),
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
    pub(crate) fn parse(kind: KProbeKind, attrs: TokenStream, item: TokenStream) -> Result<KProbe> {
        let mut args = syn::parse2(attrs)?;
        let function = pop_string_arg(&mut args, "function");
        let offset = pop_string_arg(&mut args, "offset").map(|v| v.parse::<u64>().unwrap());
        err_on_unknown_args(&args)?;

        let item = syn::parse2(item)?;
        Ok(KProbe {
            kind,
            item,
            function,
            offset,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let section_name: Cow<'_, _> = if self.function.is_some() && self.offset.is_some() {
            format!(
                "{}/{}+{}",
                self.kind,
                self.function.as_ref().unwrap(),
                self.offset.unwrap()
            )
            .into()
        } else if self.function.is_some() {
            format!("{}/{}", self.kind, self.function.as_ref().unwrap()).into()
        } else {
            format!("{}", self.kind).into()
        };
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = #fn_name(::aya_bpf::programs::ProbeContext::new(ctx));
                return 0;

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
            kprobe.expand().unwrap().to_string(),
            quote! {
                #[no_mangle]
                #[link_section = "kprobe"]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_bpf::programs::ProbeContext::new(ctx));
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
            kprobe.expand().unwrap().to_string(),
            quote! {
                #[no_mangle]
                #[link_section = "kprobe/fib_lookup"]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_bpf::programs::ProbeContext::new(ctx));
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
            kprobe.expand().unwrap().to_string(),
            quote! {
                #[no_mangle]
                #[link_section = "kprobe/fib_lookup+10"]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_bpf::programs::ProbeContext::new(ctx));
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
            kprobe.expand().unwrap().to_string(),
            quote! {
                #[no_mangle]
                #[link_section = "kretprobe"]
                fn foo(ctx: *mut ::core::ffi::c_void) -> u32 {
                    let _ = foo(::aya_bpf::programs::ProbeContext::new(ctx));
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
