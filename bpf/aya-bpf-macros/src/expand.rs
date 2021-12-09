use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    punctuated::{Pair, Punctuated},
    token::Eq,
    Error, Ident, ItemFn, ItemStatic, LitStr, Result, Token,
};

pub struct NameValue {
    name: Ident,
    _eq: Eq,
    value: LitStr,
}

pub struct Args {
    args: Vec<NameValue>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> Result<Args> {
        let args = Punctuated::<NameValue, Token![,]>::parse_terminated_with(input, |input| {
            Ok(NameValue {
                name: input.parse()?,
                _eq: input.parse()?,
                value: input.parse()?,
            })
        })?
        .into_pairs()
        .map(|pair| match pair {
            Pair::Punctuated(name_val, _) => name_val,
            Pair::End(name_val) => name_val,
        })
        .collect();

        Ok(Args { args })
    }
}

pub struct Map {
    item: ItemStatic,
    name: String,
}

impl Map {
    pub fn from_syn(mut args: Args, item: ItemStatic) -> Result<Map> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.ident.to_string());
        Ok(Map { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("maps/{}", self.name);
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #item
        })
    }
}

pub struct Probe {
    kind: ProbeKind,
    item: ItemFn,
    name: String,
}

impl Probe {
    pub fn from_syn(kind: ProbeKind, mut args: Args, item: ItemFn) -> Result<Probe> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(Probe { kind, item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("{}/{}", self.kind, self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = #fn_name(::aya_bpf::programs::ProbeContext::new(ctx));
                return 0;

                #item
            }
        })
    }
}

pub struct SockOps {
    item: ItemFn,
    name: Option<String>,
}

impl SockOps {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<SockOps> {
        let name = name_arg(&mut args)?;

        Ok(SockOps { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("sockops/{}", name)
        } else {
            "sockops".to_owned()
        };
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sock_ops) -> u32 {
                return #fn_name(::aya_bpf::programs::SockOpsContext::new(ctx));

                #item
            }
        })
    }
}

pub struct SkMsg {
    item: ItemFn,
    name: String,
}

impl SkMsg {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<SkMsg> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(SkMsg { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("sk_msg/{}", self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::aya_bpf::bindings::sk_msg_md) -> u32 {
                return #fn_name(::aya_bpf::programs::SkMsgContext::new(ctx));

                #item
            }
        })
    }
}

pub struct Xdp {
    item: ItemFn,
    name: Option<String>,
}

impl Xdp {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<Xdp> {
        let name = name_arg(&mut args)?;

        Ok(Xdp { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("xdp/{}", name)
        } else {
            "xdp".to_owned()
        };
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::aya_bpf::bindings::xdp_md) -> u32 {
                return #fn_name(::aya_bpf::programs::XdpContext::new(ctx));

                #item
            }
        })
    }
}

pub struct SchedClassifier {
    item: ItemFn,
    name: Option<String>,
}

impl SchedClassifier {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<SchedClassifier> {
        let name = name_arg(&mut args)?;

        Ok(SchedClassifier { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("classifier/{}", name)
        } else {
            "classifier".to_owned()
        };
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return #fn_name(::aya_bpf::programs::SkBuffContext::new(ctx));

                #item
            }
        })
    }
}

pub struct CgroupSkb {
    item: ItemFn,
    expected_attach_type: Option<String>,
    name: Option<String>,
}

impl CgroupSkb {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<CgroupSkb> {
        let name = pop_arg(&mut args, "name");
        let expected_attach_type = pop_arg(&mut args, "attach");

        Ok(CgroupSkb {
            item,
            expected_attach_type,
            name,
        })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(attach) = &self.expected_attach_type {
            if let Some(name) = &self.name {
                format!("cgroup_skb/{}/{}", attach, name)
            } else {
                format!("cgroup_skb/{}", attach)
            }
        } else if let Some(name) = &self.name {
            format!("cgroup/skb/{}", name)
        } else {
            ("cgroup/skb").to_owned()
        };
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return #fn_name(::aya_bpf::programs::SkBuffContext::new(ctx));

                #item
            }
        })
    }
}

fn pop_arg(args: &mut Args, name: &str) -> Option<String> {
    match args.args.iter().position(|arg| arg.name == name) {
        Some(index) => Some(args.args.remove(index).value.value()),
        None => None,
    }
}

fn err_on_unknown_args(args: &Args) -> Result<()> {
    if let Some(arg) = args.args.get(0) {
        return Err(Error::new_spanned(&arg.name, "invalid argument"));
    }

    Ok(())
}

fn name_arg(args: &mut Args) -> Result<Option<String>> {
    let name = pop_arg(args, "name");
    err_on_unknown_args(args)?;

    Ok(name)
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone)]
pub enum ProbeKind {
    KProbe,
    KRetProbe,
    UProbe,
    URetProbe,
}

impl std::fmt::Display for ProbeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProbeKind::*;
        match self {
            KProbe => write!(f, "kprobe"),
            KRetProbe => write!(f, "kretprobe"),
            UProbe => write!(f, "uprobe"),
            URetProbe => write!(f, "uretprobe"),
        }
    }
}

pub struct TracePoint {
    item: ItemFn,
    name: String,
}

impl TracePoint {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<TracePoint> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(TracePoint { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("tp/{}", self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = #fn_name(::aya_bpf::programs::TracePointContext::new(ctx));
               return 0;

               #item
            }
        })
    }
}

pub struct PerfEvent {
    item: ItemFn,
    name: String,
}

impl PerfEvent {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<PerfEvent> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(PerfEvent { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("perf_event/{}", self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
               let _ = #fn_name(::aya_bpf::programs::PerfEventContext::new(ctx));
               return 0;

               #item
            }
        })
    }
}

pub struct RawTracePoint {
    item: ItemFn,
    name: String,
}

impl RawTracePoint {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<RawTracePoint> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(RawTracePoint { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("raw_tp/{}", self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = #fn_name(::aya_bpf::programs::RawTracePointContext::new(ctx));
                return 0;

                #item
            }
        })
    }
}

pub struct Lsm {
    item: ItemFn,
    name: String,
}

impl Lsm {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<Lsm> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(Lsm { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("lsm/{}", self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        // LSM probes need to return an integer corresponding to the correct
        // policy decision. Therefore we do not simply default to a return value
        // of 0 as in other program types.
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                return #fn_name(::aya_bpf::programs::LsmContext::new(ctx));

                #item
            }
        })
    }
}

pub struct BtfTracePoint {
    item: ItemFn,
    name: String,
}

impl BtfTracePoint {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<BtfTracePoint> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(BtfTracePoint { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("tp_btf/{}", self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_bpf::programs::BtfTracePointContext::new(ctx));
                return 0;

                #item
            }
        })
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone)]
pub enum SkSkbKind {
    StreamVerdict,
    StreamParser,
}

impl std::fmt::Display for SkSkbKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SkSkbKind::*;
        match self {
            StreamVerdict => write!(f, "stream_verdict"),
            StreamParser => write!(f, "stream_parser"),
        }
    }
}

pub struct SkSkb {
    kind: SkSkbKind,
    item: ItemFn,
    name: Option<String>,
}

impl SkSkb {
    pub fn from_syn(kind: SkSkbKind, mut args: Args, item: ItemFn) -> Result<SkSkb> {
        let name = pop_arg(&mut args, "name");
        Ok(SkSkb { item, kind, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let kind = &self.kind;
        let section_name = if let Some(name) = &self.name {
            format!("sk_skb/{}/{}", kind, name)
        } else {
            format!("sk_skb/{}", kind)
        };
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> u32 {
                return #fn_name(::aya_bpf::programs::SkBuffContext::new(ctx));

                #item
            }
        })
    }
}

pub struct SocketFilter {
    item: ItemFn,
    name: Option<String>,
}

impl SocketFilter {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<SocketFilter> {
        let name = name_arg(&mut args)?;

        Ok(SocketFilter { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("socket/{}", name)
        } else {
            "socket".to_owned()
        };
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i64 {
                return #fn_name(::aya_bpf::programs::SkBuffContext::new(ctx));

                #item
            }
        })
    }
}

pub struct FEntry {
    item: ItemFn,
    name: String,
}

impl FEntry {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<FEntry> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(FEntry { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("fentry/{}", self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_bpf::programs::FEntryContext::new(ctx));
                return 0;

                #item
            }
        })
    }
}

pub struct FExit {
    item: ItemFn,
    name: String,
}

impl FExit {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<FExit> {
        let name = name_arg(&mut args)?.unwrap_or_else(|| item.sig.ident.to_string());

        Ok(FExit { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = format!("fexit/{}", self.name);
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_bpf::programs::FExitContext::new(ctx));
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
    fn cgroup_skb_with_attach_and_name() {
        let prog = CgroupSkb::from_syn(
            parse_quote!(name = "foo", attach = "ingress"),
            parse_quote!(
                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let stream = prog.expand().unwrap();
        assert!(stream
            .to_string()
            .contains("[link_section = \"cgroup_skb/ingress/foo\"]"));
    }

    #[test]
    fn cgroup_skb_with_name() {
        let prog = CgroupSkb::from_syn(
            parse_quote!(name = "foo"),
            parse_quote!(
                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let stream = prog.expand().unwrap();
        assert!(stream
            .to_string()
            .contains("[link_section = \"cgroup/skb/foo\"]"));
    }

    #[test]
    fn cgroup_skb_no_name() {
        let prog = CgroupSkb::from_syn(
            parse_quote!(),
            parse_quote!(
                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let stream = prog.expand().unwrap();
        assert!(stream
            .to_string()
            .contains("[link_section = \"cgroup/skb\"]"));
    }

    #[test]
    fn cgroup_skb_with_attach_no_name() {
        let prog = CgroupSkb::from_syn(
            parse_quote!(attach = "egress"),
            parse_quote!(
                fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let stream = prog.expand().unwrap();
        assert!(stream
            .to_string()
            .contains("[link_section = \"cgroup_skb/egress\"]"));
    }
}
