mod expand;

use expand::{Args, Map, Probe, ProbeKind};
use proc_macro::TokenStream;
use syn::{parse_macro_input, ItemFn, ItemStatic};

#[proc_macro_attribute]
pub fn map(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemStatic);

    Map::from_syn(args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn kprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe(ProbeKind::KProbe, attrs, item)
}

#[proc_macro_attribute]
pub fn kretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe(ProbeKind::KRetProbe, attrs, item)
}

#[proc_macro_attribute]
pub fn uprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe(ProbeKind::UProbe, attrs, item)
}

#[proc_macro_attribute]
pub fn uretprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    probe(ProbeKind::URetProbe, attrs, item)
}

fn probe(kind: ProbeKind, attrs: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attrs as Args);
    let item = parse_macro_input!(item as ItemFn);

    Probe::from_syn(kind, args, item)
        .and_then(|u| u.expand())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
