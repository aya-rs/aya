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
                return #fn_name(::aya_bpf::programs::SkSkbContext::new(ctx));

                #item
            }
        })
    }
}

pub struct CgroupSkb {
    item: ItemFn,
    expected_attach_type: String,
    name: Option<String>,
}

impl CgroupSkb {
    pub fn from_syn(mut args: Args, item: ItemFn) -> Result<CgroupSkb> {
        let name = pop_arg(&mut args, "name");
        let expected_attach_type = pop_arg(&mut args, "attach").unwrap_or_else(|| "skb".to_owned());

        Ok(CgroupSkb {
            item,
            expected_attach_type,
            name,
        })
    }

    pub fn expand(&self) -> Result<TokenStream> {
        let attach = &self.expected_attach_type;
        let section_name = if let Some(name) = &self.name {
            format!("cgroup_skb/{}/{}", attach, name)
        } else {
            format!("cgroup_skb/{}", attach)
        };
        let fn_name = &self.item.sig.ident;
        let item = &self.item;
        Ok(quote! {
            #[no_mangle]
            #[link_section = #section_name]
            fn #fn_name(ctx: *mut ::aya_bpf::bindings::__sk_buff) -> i32 {
                return #fn_name(::aya_bpf::programs::SkSkbContext::new(ctx));

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
