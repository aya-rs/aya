use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, SpanDiagnosticExt as _};
use quote::quote;
use syn::{ItemFn, spanned::Spanned as _};

use crate::args::Args;

pub(crate) struct Xdp {
    item: ItemFn,
    frags: bool,
    map: Option<XdpMap>,
}

#[derive(Clone, Copy)]
pub(crate) enum XdpMap {
    CpuMap,
    DevMap,
}

impl Xdp {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self, Diagnostic> {
        let item = syn::parse2(item)?;
        let span = attrs.span();
        let mut args: Args = syn::parse2(attrs)?;

        let frags = args.pop_bool("frags");
        let map = match args.pop_string("map").as_deref() {
            Some("cpumap") => Some(XdpMap::CpuMap),
            Some("devmap") => Some(XdpMap::DevMap),
            Some(name) => {
                return Err(span.error(format!(
                    "Invalid value. Expected 'cpumap' or 'devmap', found '{name}'"
                )));
            }
            None => None,
        };

        args.into_error()?;
        Ok(Self { item, frags, map })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { item, frags, map } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let mut section_name = vec![if *frags { "xdp.frags" } else { "xdp" }];
        match map {
            Some(XdpMap::CpuMap) => section_name.push("cpumap"),
            Some(XdpMap::DevMap) => section_name.push("devmap"),
            None => (),
        }
        let section_name = section_name.join("/");
        let fn_name = &sig.ident;
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section_name)]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::bindings::xdp_md) -> u32 {
                return #fn_name(::aya_ebpf::programs::XdpContext::new(ctx));

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
    fn test_xdp() {
        let prog = Xdp::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "xdp")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::xdp_md) -> u32 {
                return prog(::aya_ebpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_xdp_frags() {
        let prog = Xdp::parse(
            parse_quote! { frags },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "xdp.frags")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::xdp_md) -> u32 {
                return prog(::aya_ebpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_xdp_cpumap() {
        let prog = Xdp::parse(
            parse_quote! { map = "cpumap" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "xdp/cpumap")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::xdp_md) -> u32 {
                return prog(::aya_ebpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_xdp_devmap() {
        let prog = Xdp::parse(
            parse_quote! { map = "devmap" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "xdp/devmap")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::xdp_md) -> u32 {
                return prog(::aya_ebpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    #[should_panic(expected = "Invalid value. Expected 'cpumap' or 'devmap', found 'badmap'")]
    fn test_xdp_bad_map() {
        Xdp::parse(
            parse_quote! { map = "badmap" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
    }

    #[test]
    fn test_xdp_frags_cpumap() {
        let prog = Xdp::parse(
            parse_quote! { frags, map = "cpumap" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "xdp.frags/cpumap")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::xdp_md) -> u32 {
                return prog(::aya_ebpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_xdp_frags_devmap() {
        let prog = Xdp::parse(
            parse_quote! { frags, map = "devmap" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "xdp.frags/devmap")]
            fn prog(ctx: *mut ::aya_ebpf::bindings::xdp_md) -> u32 {
                return prog(::aya_ebpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_ebpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
