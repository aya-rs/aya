use aya_log_common::DisplayHint;
use aya_log_parser::{Fragment, parse};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{
    Error, Expr, LitStr, Result, Token,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

pub(crate) struct LogArgs {
    pub(crate) ctx: Expr,
    pub(crate) target: Option<Expr>,
    pub(crate) level: Option<Expr>,
    pub(crate) format_string: LitStr,
    pub(crate) formatting_args: Option<Punctuated<Expr, Token![,]>>,
}

mod kw {
    syn::custom_keyword!(target);
}

impl Parse for LogArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let ctx: Expr = input.parse()?;
        input.parse::<Token![,]>()?;

        // Parse `target: &str`, which is an optional argument.
        let target: Option<Expr> = if input.peek(kw::target) {
            input.parse::<kw::target>()?;
            input.parse::<Token![:]>()?;
            let t: Expr = input.parse()?;
            input.parse::<Token![,]>()?;
            Some(t)
        } else {
            None
        };

        // Check whether the next token is `format_string: &str` (which i
        // always provided) or `level` (which is an optional expression).
        // If `level` is provided, it comes before `format_string`.
        let (level, format_string): (Option<Expr>, LitStr) = if input.peek(LitStr) {
            // Only `format_string` is provided.
            (None, input.parse()?)
        } else {
            // Both `level` and `format_string` are provided.
            let level: Expr = input.parse()?;
            input.parse::<Token![,]>()?;
            let format_string: LitStr = input.parse()?;
            (Some(level), format_string)
        };

        // Parse variadic arguments.
        let formatting_args: Option<Punctuated<Expr, Token![,]>> = if input.is_empty() {
            None
        } else {
            input.parse::<Token![,]>()?;
            Some(Punctuated::parse_terminated(input)?)
        };

        Ok(Self {
            ctx,
            target,
            level,
            format_string,
            formatting_args,
        })
    }
}

pub(crate) fn log(args: LogArgs, level: Option<TokenStream>) -> Result<TokenStream> {
    let ctx = args.ctx;
    let target = match args.target {
        Some(t) => quote! { #t },
        None => quote! { module_path!() },
    };
    let lvl: TokenStream = if let Some(l) = level {
        l
    } else if let Some(l) = args.level {
        quote! { #l }
    } else {
        return Err(Error::new(
            args.format_string.span(),
            "missing `level` argument: try passing an `aya_log_ebpf::Level` value",
        ));
    };
    let format_string = args.format_string;

    let format_string_val = format_string.value();
    let fragments = parse(&format_string_val).map_err(|e| {
        Error::new(
            format_string.span(),
            format!("could not parse the format string: {e}"),
        )
    })?;

    let mut arg_i = 0;

    let mut values = Vec::new();
    for fragment in fragments {
        match fragment {
            Fragment::Literal(s) => values.push(quote!(#s)),
            Fragment::Parameter(p) => {
                let arg = match args.formatting_args {
                    Some(ref args) => args[arg_i].clone(),
                    None => return Err(Error::new(format_string.span(), "no arguments provided")),
                };
                let (hint, formatter) = match p.hint {
                    DisplayHint::Default => {
                        (quote!(DisplayHint::Default), quote!(DefaultFormatter))
                    }
                    DisplayHint::LowerHex => {
                        (quote!(DisplayHint::LowerHex), quote!(LowerHexFormatter))
                    }
                    DisplayHint::UpperHex => {
                        (quote!(DisplayHint::UpperHex), quote!(UpperHexFormatter))
                    }
                    DisplayHint::Ip => (quote!(DisplayHint::Ip), quote!(IpFormatter)),
                    DisplayHint::LowerMac => {
                        (quote!(DisplayHint::LowerMac), quote!(LowerMacFormatter))
                    }
                    DisplayHint::UpperMac => {
                        (quote!(DisplayHint::UpperMac), quote!(UpperMacFormatter))
                    }
                };
                let hint = quote!(::aya_log_ebpf::macro_support::#hint);
                let arg = quote!(
                    {
                        let tmp = #arg;
                        let _: &dyn ::aya_log_ebpf::macro_support::#formatter = &tmp;
                        tmp
                    }
                );
                values.push(hint);
                values.push(arg);

                arg_i += 1;
            }
        }
    }

    let num_args = values.len();
    let values_iter = values.iter();
    let size = Ident::new("size", Span::mixed_site());
    let len = Ident::new("len", Span::mixed_site());
    let slice = Ident::new("slice", Span::mixed_site());
    let record = Ident::new("record", Span::mixed_site());
    Ok(quote! {
        match ::aya_log_ebpf::AYA_LOG_BUF.get_ptr_mut(0).and_then(|ptr| unsafe { ptr.as_mut() }) {
            None => {},
            Some(::aya_log_ebpf::LogBuf { buf }) => {
                let _: Option<()> = (|| {
                    let #size = ::aya_log_ebpf::write_record_header(
                        buf,
                        #target,
                        #lvl,
                        module_path!(),
                        file!(),
                        line!(),
                        #num_args,
                    )?;
                    let mut #size = #size.get();
                    #(
                        let #slice = buf.get_mut(#size..)?;
                        let #len = ::aya_log_ebpf::WriteToBuf::write(#values_iter, #slice)?;
                        #size += #len.get();
                    )*
                    let #record = buf.get(..#size)?;
                    ::aya_log_ebpf::AYA_LOGS.output(#ctx, #record, 0);
                    Some(())
                })();
            }
        }
    })
}

pub(crate) fn error(args: LogArgs) -> Result<TokenStream> {
    log(
        args,
        Some(quote! { ::aya_log_ebpf::macro_support::Level::Error }),
    )
}

pub(crate) fn warn(args: LogArgs) -> Result<TokenStream> {
    log(
        args,
        Some(quote! { ::aya_log_ebpf::macro_support::Level::Warn }),
    )
}

pub(crate) fn info(args: LogArgs) -> Result<TokenStream> {
    log(
        args,
        Some(quote! { ::aya_log_ebpf::macro_support::Level::Info }),
    )
}

pub(crate) fn debug(args: LogArgs) -> Result<TokenStream> {
    log(
        args,
        Some(quote! { ::aya_log_ebpf::macro_support::Level::Debug }),
    )
}

pub(crate) fn trace(args: LogArgs) -> Result<TokenStream> {
    log(
        args,
        Some(quote! { ::aya_log_ebpf::macro_support::Level::Trace }),
    )
}
