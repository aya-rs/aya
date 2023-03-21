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

pub struct SockAddrArgs {
    pub(crate) attach_type: Ident,
    pub(crate) args: Args,
}

impl Parse for SockAddrArgs {
    fn parse(input: ParseStream) -> Result<SockAddrArgs> {
        let attach_type: Ident = input.parse()?;
        match attach_type.to_string().as_str() {
            "connect4" | "connect6" | "bind4" | "bind6" | "getpeername4" | "getpeername6"
            | "getsockname4" | "getsockname6" | "sendmsg4" | "sendmsg6" | "recvmsg4"
            | "recvmsg6" => (),
            _ => return Err(input.error("invalid attach type")),
        }
        let args = if input.parse::<Token![,]>().is_ok() {
            Args::parse(input)?
        } else {
            Args { args: vec![] }
        };
        Ok(SockAddrArgs { attach_type, args })
    }
}

pub struct SockoptArgs {
    pub(crate) attach_type: Ident,
    pub(crate) args: Args,
}

impl Parse for SockoptArgs {
    fn parse(input: ParseStream) -> Result<SockoptArgs> {
        let attach_type: Ident = input.parse()?;
        match attach_type.to_string().as_str() {
            "getsockopt" | "setsockopt" => (),
            _ => return Err(input.error("invalid attach type")),
        }
        let args = if input.parse::<Token![,]>().is_ok() {
            Args::parse(input)?
        } else {
            Args { args: vec![] }
        };
        Ok(SockoptArgs { attach_type, args })
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
        let section_name = "maps".to_string();
        let name = &self.name;
        let item = &self.item;
        Ok(quote! {
            #[link_section = #section_name]
            #[export_name = #name]
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
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
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
            format!("sockops/{name}")
        } else {
            "sockops".to_owned()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sock_ops) -> u32 {
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
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::sk_msg_md) -> u32 {
                return #fn_name(::aya_bpf::programs::SkMsgContext::new(ctx));

                #item
            }
        })
    }
}

pub struct Xdp {
    item: ItemFn,
    name: Option<String>,
    frags: bool,
}

impl Xdp {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<Xdp> {
        let name = pop_arg(&mut args, "name");
        let mut frags = false;
        if let Some(s) = pop_arg(&mut args, "frags") {
            if let Ok(m) = s.parse() {
                frags = m
            } else {
                return Err(Error::new_spanned(
                    s,
                    "invalid value. should be 'true' or 'false'",
                ));
            }
        }
        err_on_unknown_args(&args)?;
        Ok(Xdp { item, name, frags })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_prefix = if self.frags { "xdp.frags" } else { "xdp" };
        let section_name = if let Some(name) = &self.name {
            format!("{section_prefix}/{name}")
        } else {
            section_prefix.to_string()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
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
            format!("classifier/{name}")
        } else {
            "classifier".to_owned()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return #fn_name(::aya_bpf::programs::TcContext::new(ctx));

                #item
            }
        })
    }
}

pub struct CgroupSysctl {
    item: ItemFn,
    name: Option<String>,
}

impl CgroupSysctl {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<CgroupSysctl> {
        let name = name_arg(&mut args)?;

        Ok(CgroupSysctl { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("cgroup/sysctl/{name}")
        } else {
            ("cgroup/sysctl").to_owned()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sysctl) -> i32 {
                return #fn_name(::aya_bpf::programs::SysctlContext::new(ctx));

                #item
            }
        })
    }
}

pub struct CgroupSockopt {
    item: ItemFn,
    attach_type: String,
    name: Option<String>,
}

impl CgroupSockopt {
    pub fn from_syn(mut args: Args, item: ItemFn, attach_type: String) -> Result<CgroupSockopt> {
        let name = pop_arg(&mut args, "name");
        err_on_unknown_args(&args)?;

        Ok(CgroupSockopt {
            item,
            attach_type,
            name,
        })
    }
    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("cgroup/{}/{}", self.attach_type, name)
        } else {
            format!("cgroup/{}", self.attach_type)
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sockopt) -> i32 {
                return #fn_name(::aya_bpf::programs::SockoptContext::new(ctx));

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
        err_on_unknown_args(&args)?;

        Ok(CgroupSkb {
            item,
            expected_attach_type,
            name,
        })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(attach) = &self.expected_attach_type {
            if let Some(name) = &self.name {
                format!("cgroup_skb/{attach}/{name}")
            } else {
                format!("cgroup_skb/{attach}")
            }
        } else if let Some(name) = &self.name {
            format!("cgroup/skb/{name}")
        } else {
            ("cgroup/skb").to_owned()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return #fn_name(::aya_bpf::programs::SkBuffContext::new(ctx));

                #item
            }
        })
    }
}

pub struct CgroupSockAddr {
    item: ItemFn,
    attach_type: String,
    name: Option<String>,
}

impl CgroupSockAddr {
    pub fn from_syn(mut args: Args, item: ItemFn, attach_type: String) -> Result<CgroupSockAddr> {
        let name = pop_arg(&mut args, "name");
        err_on_unknown_args(&args)?;

        Ok(CgroupSockAddr {
            item,
            attach_type,
            name,
        })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("cgroup/{}/{}", self.attach_type, name)
        } else {
            format!("cgroup/{}", self.attach_type)
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sock_addr) -> i32 {
                return #fn_name(::aya_bpf::programs::SockAddrContext::new(ctx));

                #item
            }
        })
    }
}

pub struct CgroupSock {
    item: ItemFn,
    attach_type: Option<String>,
    name: Option<String>,
}

impl CgroupSock {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<CgroupSock> {
        let name = pop_arg(&mut args, "name");
        let attach_type = pop_arg(&mut args, "attach");
        err_on_unknown_args(&args)?;

        Ok(CgroupSock {
            item,
            attach_type,
            name,
        })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            if let Some(attach_type) = &self.attach_type {
                format!("cgroup/{attach_type}/{name}")
            } else {
                format!("cgroup/sock/{name}")
            }
        } else if let Some(attach_type) = &self.attach_type {
            format!("cgroup/{attach_type}")
        } else {
            "cgroup/sock".to_string()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sock) -> i32 {
                return #fn_name(::aya_bpf::programs::SockContext::new(ctx));

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
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
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
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
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
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> u32 {
                let _ = #fn_name(::aya_bpf::programs::RawTracePointContext::new(ctx));
                return 0;

                #item
            }
        })
    }
}

pub struct Lsm {
    item: ItemFn,
    name: Option<String>,
    sleepable: bool,
}

impl Lsm {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<Lsm> {
        let name = pop_arg(&mut args, "name");
        let mut sleepable = false;
        if let Some(s) = pop_arg(&mut args, "sleepable") {
            if let Ok(m) = s.parse() {
                sleepable = m
            } else {
                return Err(Error::new_spanned(
                    s,
                    "invalid value. should be 'true' or 'false'",
                ));
            }
        }
        err_on_unknown_args(&args)?;
        Ok(Lsm {
            item,
            name,
            sleepable,
        })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_prefix = if self.sleepable { "lsm.s" } else { "lsm" };
        let section_name = if let Some(name) = &self.name {
            format!("{section_prefix}/{name}")
        } else {
            section_prefix.to_string()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        // LSM probes need to return an integer corresponding to the correct
        // policy decision. Therefore we do not simply default to a return value
        // of 0 as in other program types.
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
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
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
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
        err_on_unknown_args(&args)?;

        Ok(SkSkb { item, kind, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let kind = &self.kind;
        let section_name = if let Some(name) = &self.name {
            format!("sk_skb/{kind}/{name}")
        } else {
            format!("sk_skb/{kind}")
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> u32 {
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
        err_on_unknown_args(&args)?;

        Ok(SocketFilter { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("socket/{name}")
        } else {
            "socket".to_owned()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i64 {
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
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
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
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                let _ = #fn_name(::aya_bpf::programs::FExitContext::new(ctx));
                return 0;

                #item
            }
        })
    }
}

pub struct SkLookup {
    item: ItemFn,
    name: Option<String>,
}

impl SkLookup {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<SkLookup> {
        let name = name_arg(&mut args)?;

        Ok(SkLookup { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("sk_lookup/{name}")
        } else {
            "sk_lookup".to_owned()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_sk_lookup) -> u32 {
                return #fn_name(::aya_bpf::programs::SkLookupContext::new(ctx));

                #item
            }
        })
    }
}

pub struct CgroupDevice {
    item: ItemFn,
    name: Option<String>,
}

impl CgroupDevice {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<Self> {
        let name = name_arg(&mut args)?;

        Ok(CgroupDevice { item, name })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let section_name = if let Some(name) = &self.name {
            format!("cgroup/dev/{name}")
        } else {
            ("cgroup/dev").to_owned()
        };
        let fn_vis = &self.item.vis;
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            #fn_vis fn #fn_name(ctx: *mut ::aya_bpf::bindings::bpf_cgroup_dev_ctx) -> i32 {
                return #fn_name(::aya_bpf::programs::DeviceContext::new(ctx));

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

    #[test]
    fn cgroup_device_no_name() {
        let prog = CgroupDevice::from_syn(
            parse_quote!(),
            parse_quote!(
                fn foo(ctx: DeviceContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let stream = prog.expand().unwrap();
        assert!(stream
            .to_string()
            .contains("[link_section = \"cgroup/dev\"]"));
    }

    #[test]
    fn priv_function() {
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
        assert!(stream.to_string().contains("] fn foo ("));
    }

    #[test]
    fn pub_function() {
        let prog = CgroupSkb::from_syn(
            parse_quote!(attach = "egress"),
            parse_quote!(
                pub fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let stream = prog.expand().unwrap();
        assert!(stream.to_string().contains("] pub fn foo ("));
    }

    #[test]
    fn pub_crate_function() {
        let prog = CgroupSkb::from_syn(
            parse_quote!(attach = "egress"),
            parse_quote!(
                pub(crate) fn foo(ctx: SkBuffContext) -> i32 {
                    0
                }
            ),
        )
        .unwrap();
        let stream = prog.expand().unwrap();
        assert!(stream.to_string().contains("] pub (crate) fn foo ("));
    }
}
