use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Ident, ItemFn};

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

#[proc_macro_attribute]
pub fn tokio_integration_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = &item.sig.ident;
    let name_str = &item.sig.ident.to_string();
    let sync_name_str = format!("sync_{name_str}");
    let sync_name = Ident::new(&sync_name_str, Span::call_site());
    let expanded = quote! {
        #item

        fn #sync_name() {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(#name());
        }

        inventory::submit!(crate::IntegrationTest {
            name: concat!(module_path!(), "::", #sync_name_str),
            test_fn: #sync_name,
        });
    };
    TokenStream::from(expanded)
}
