use std::borrow::Cow;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_bool_arg, pop_string_arg};

#[allow(clippy::enum_variant_names)]
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
    pub(crate) fn parse(kind: UProbeKind, attrs: TokenStream, item: TokenStream) -> Result<UProbe> {
        let mut path = None;
        let mut function = None;
        let mut offset = None;
        let mut sleepable = false;
        if !attrs.is_empty() {
            let mut args = syn::parse2(attrs)?;
            path = pop_string_arg(&mut args, "path");
            function = pop_string_arg(&mut args, "function");
            offset = pop_string_arg(&mut args, "offset").map(|v| v.parse::<u64>().unwrap());
            sleepable = pop_bool_arg(&mut args, "sleepable");
            err_on_unknown_args(&args)?;
        }

        let item = syn::parse2(item)?;
        Ok(UProbe {
            kind,
            item,
            path,
            function,
            offset,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let prefix = if self.sleepable {
            format!("{}.s", self.kind)
        } else {
            format!("{}", self.kind)
        };
        let section_name: Cow<'_, _> = if self.path.is_some() && self.offset.is_some() {
            if self.function.is_none() {
                abort!(self.item.sig.ident, "expected `function` attribute");
            }
            let mut path = self.path.as_ref().unwrap().clone();
            if path.starts_with('/') {
                path.remove(0);
            }
            format!(
                "{}/{}:{}+{}",
                prefix,
                path,
                self.function.as_ref().unwrap(),
                self.offset.unwrap()
            )
            .into()
        } else if self.path.is_some() {
            if self.function.is_none() {
                abort!(self.item.sig.ident, "expected `function` attribute");
            }
            let mut path = self.path.as_ref().unwrap().clone();
            if path.starts_with('/') {
                path.remove(0);
            }
            format!("{}/{}:{}", prefix, path, self.function.as_ref().unwrap()).into()
        } else {
            prefix.to_string().into()
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
                #[no_mangle]
                #[link_section = "uprobe"]
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
                #[no_mangle]
                #[link_section = "uprobe.s"]
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
                #[no_mangle]
                #[link_section = "uprobe/self/proc/exe:trigger_uprobe"]
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
                #[no_mangle]
                #[link_section = "uprobe/self/proc/exe:foo+123"]
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
                #[no_mangle]
                #[link_section = "uretprobe"]
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
