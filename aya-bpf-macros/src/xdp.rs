use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, ItemFn, Result};

use crate::args::{err_on_unknown_args, pop_bool_arg, pop_string_arg, Args};

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
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Xdp> {
        let item = syn::parse2(item)?;
        let mut args: Args = syn::parse2(attrs)?;

        let frags = pop_bool_arg(&mut args, "frags");
        let map = match pop_string_arg(&mut args, "map").as_deref() {
            Some("cpumap") => Some(XdpMap::CpuMap),
            Some("devmap") => Some(XdpMap::DevMap),
            Some(_) => {
                return Err(Error::new_spanned(
                    "map",
                    "invalid value. should be 'cpumap' or 'devmap'",
                ))
            }
            None => None,
        };

        err_on_unknown_args(&args)?;
        Ok(Xdp { item, frags, map })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let mut section_name = vec![if self.frags { "xdp.frags" } else { "xdp" }];
        match self.map {
            Some(XdpMap::CpuMap) => section_name.push("cpumap"),
            Some(XdpMap::DevMap) => section_name.push("devmap"),
            None => (),
        };
        let section_name = section_name.join("/");

        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return #fn_name(::aya_bpf::programs::XdpContext::new(ctx));

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
    fn test_xdp() {
        let prog = Xdp::parse(
            parse_quote! {},
            parse_quote! {
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "xdp"]
            fn prog(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return prog(::aya_bpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
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
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "xdp.frags"]
            fn prog(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return prog(::aya_bpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
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
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "xdp/cpumap"]
            fn prog(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return prog(::aya_bpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
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
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "xdp/devmap"]
            fn prog(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return prog(::aya_bpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    #[should_panic(expected = "invalid value. should be 'cpumap' or 'devmap'")]
    fn test_xdp_bad_map() {
        Xdp::parse(
            parse_quote! { map = "badmap" },
            parse_quote! {
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
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
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "xdp.frags/cpumap"]
            fn prog(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return prog(::aya_bpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
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
                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand().unwrap();
        let expected = quote! {
            #[no_mangle]
            #[link_section = "xdp.frags/devmap"]
            fn prog(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return prog(::aya_bpf::programs::XdpContext::new(ctx));

                fn prog(ctx: &mut ::aya_bpf::programs::XdpContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
