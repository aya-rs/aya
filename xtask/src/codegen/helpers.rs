use proc_macro2::TokenStream;
use quote::{quote, TokenStreamExt};
use syn::{
    punctuated::Punctuated, AngleBracketedGenericArguments, BareFnArg, ForeignItem,
    ForeignItemStatic, GenericArgument, Ident, Item, Path, PathArguments, ReturnType, Token, Type,
    TypeBareFn, TypePath,
};

pub fn extract_helpers(items: &[Item]) -> (Vec<usize>, Vec<Helper<'_>>) {
    let mut helpers = Vec::new();
    let mut indexes = Vec::new();
    for (item_index, item) in items.iter().enumerate() {
        if let Item::ForeignMod(module) = item {
            for i in &module.items {
                if let ForeignItem::Static(s_item) = i {
                    let ident_s = s_item.ident.to_string();
                    if ident_s.starts_with("bpf_") {
                        helpers.push(
                            helper_from_item(s_item, helpers.len() + 1)
                                .expect("unexpected bindgen helper signature"),
                        );
                        indexes.push(item_index);
                    }
                }
            }
        }
    }

    (indexes, helpers)
}

pub fn helper_from_item(item: &ForeignItemStatic, call_index: usize) -> Option<Helper<'_>> {
    if let Type::Path(TypePath {
        path: Path { segments, .. },
        ..
    }) = &*item.ty
    {
        let generics = &segments.last().unwrap().arguments;
        if let PathArguments::AngleBracketed(AngleBracketedGenericArguments { args, .. }) = generics
        {
            if let Some(GenericArgument::Type(ty)) = args.first() {
                if let Type::BareFn(TypeBareFn { inputs, output, .. }) = ty {
                    return Some(Helper {
                        ident: &item.ident,
                        ty,
                        inputs,
                        output,
                        call_index,
                    });
                }
            }
        };
    }

    None
}

pub fn expand_helpers(helpers: &[Helper<'_>]) -> TokenStream {
    let mut tokens = TokenStream::new();
    tokens.append_all(
        helpers
            .iter()
            .filter(|h| *h.ident != "bpf_trace_printk")
            .map(expand_helper),
    );

    tokens
}

pub fn expand_helper(helper: &Helper<'_>) -> TokenStream {
    let Helper {
        ident,
        ty,
        inputs,
        output,
        call_index,
    } = helper;

    let args = inputs
        .iter()
        .map(|arg| &arg.name.as_ref().unwrap().0)
        .collect::<Vec<_>>();

    let helper = quote! {
        pub unsafe fn #ident(#inputs) #output {
            let fun: #ty = ::core::mem::transmute(#call_index);
            fun(#(#args),*)
        }
    };

    helper
}

pub struct Helper<'a> {
    ident: &'a Ident,
    ty: &'a Type,
    inputs: &'a Punctuated<BareFnArg, Token![,]>,
    output: &'a ReturnType,
    call_index: usize,
}
