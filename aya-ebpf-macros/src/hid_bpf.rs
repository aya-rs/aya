use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::err_on_unknown_args;

/// The type of HID-BPF callback.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HidBpfKind {
    /// Called for each HID input report.
    DeviceEvent,
    /// Called to fix report descriptor at probe time.
    RdescFixup,
    /// Called for hardware requests (feature reports, etc).
    HwRequest,
    /// Called for output reports.
    HwOutputReport,
}

impl HidBpfKind {
    fn section_name(&self) -> &'static str {
        match self {
            Self::DeviceEvent => "struct_ops/hid_device_event",
            Self::RdescFixup => "struct_ops/hid_rdesc_fixup",
            Self::HwRequest => "struct_ops/hid_hw_request",
            Self::HwOutputReport => "struct_ops/hid_hw_output_report",
        }
    }
}

pub(crate) struct HidBpf {
    kind: HidBpfKind,
    item: ItemFn,
}

impl HidBpf {
    pub(crate) fn parse(kind: HidBpfKind, attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item = syn::parse2(item)?;
        let args = syn::parse2(attrs)?;
        err_on_unknown_args(&args)?;
        Ok(Self { kind, item })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self { kind, item } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let fn_name = &sig.ident;
        let section_name: Cow<'_, _> = kind.section_name().into();

        // IMPORTANT: The entry point MUST use *mut hid_bpf_ctx (not c_void)
        // to generate correct BTF for kfuncs like hid_bpf_get_data.
        // The kernel verifier checks that kfunc args match BTF struct types.
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section_name)]
            #vis fn #fn_name(ctx: *mut ::aya_ebpf::programs::hid_bpf::hid_bpf_ctx) -> i32 {
                return #fn_name(unsafe { ::aya_ebpf::programs::HidBpfContext::new(ctx) });

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
    fn test_hid_device_event() {
        let prog = HidBpf::parse(
            HidBpfKind::DeviceEvent,
            parse_quote! {},
            parse_quote! {
                fn device_event(ctx: HidBpfContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "struct_ops/hid_device_event")]
            fn device_event(ctx: *mut ::aya_ebpf::programs::hid_bpf::hid_bpf_ctx) -> i32 {
                return device_event(unsafe { ::aya_ebpf::programs::HidBpfContext::new(ctx) });

                fn device_event(ctx: HidBpfContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }

    #[test]
    fn test_hid_rdesc_fixup() {
        let prog = HidBpf::parse(
            HidBpfKind::RdescFixup,
            parse_quote! {},
            parse_quote! {
                fn rdesc_fixup(ctx: HidBpfContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "struct_ops/hid_rdesc_fixup")]
            fn rdesc_fixup(ctx: *mut ::aya_ebpf::programs::hid_bpf::hid_bpf_ctx) -> i32 {
                return rdesc_fixup(unsafe { ::aya_ebpf::programs::HidBpfContext::new(ctx) });

                fn rdesc_fixup(ctx: HidBpfContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
