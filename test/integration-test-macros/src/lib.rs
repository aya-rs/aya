use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn integration_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = &item.sig.ident;
    let name_str = &item.sig.ident.to_string();
    let expanded = quote! {
        #item

        inventory::submit!(crate::IntegrationTest {
            name: concat!(module_path!(), "::", #name_str),
            test_fn: #name,
        });
    };
    TokenStream::from(expanded)
}
