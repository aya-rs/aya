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
    pub fn from_syn(args: Args, item: ItemStatic) -> Result<Map> {
        let name = name_arg(&args)?.unwrap_or_else(|| item.ident.to_string());
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
    pub fn from_syn(kind: ProbeKind, args: Args, item: ItemFn) -> Result<Probe> {
        let name = name_arg(&args)?.unwrap_or_else(|| item.sig.ident.to_string());

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

fn name_arg(args: &Args) -> Result<Option<String>> {
    for arg in &args.args {
        if arg.name == "name" {
            return Ok(Some(arg.value.value()));
        } else {
            return Err(Error::new_spanned(&arg.name, "invalid argument"));
        }
    }

    Ok(None)
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
