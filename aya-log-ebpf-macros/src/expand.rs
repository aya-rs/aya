use aya_log_common::DisplayHint;
use aya_log_parser::{Fragment, Parameter, parse};
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
    fn parse(input: ParseStream<'_>) -> Result<Self> {
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

pub(crate) fn log(args: LogArgs, level_expr: Option<TokenStream>) -> Result<TokenStream> {
    let LogArgs {
        ctx,
        target,
        level,
        format_string,
        formatting_args,
    } = args;
    let target = match target {
        Some(t) => quote! { #t },
        None => quote! { module_path!() },
    };
    let level_expr = match level_expr {
        Some(level_expr) => level_expr,
        None => {
            let level_expr = level.ok_or(Error::new(
                format_string.span(),
                "missing `level` argument: try passing an `aya_log_ebpf::Level` value",
            ))?;
            quote! { #level_expr }
        }
    };

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
            Fragment::Parameter(Parameter { hint }) => {
                let arg = match &formatting_args {
                    Some(args) => &args[arg_i],
                    None => return Err(Error::new(format_string.span(), "no arguments provided")),
                };
                let (hint, formatter) = match hint {
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
                    DisplayHint::Pointer => {
                        (quote!(DisplayHint::Pointer), quote!(PointerFormatter))
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

    let idents: Vec<_> = (0..values.len())
        .map(|arg_i| quote::format_ident!("__arg{arg_i}"))
        .collect();

    let num_args = values.len();
    let num_args = u32::try_from(num_args).map_err(|core::num::TryFromIntError { .. }| {
        Error::new(
            Span::call_site(),
            format!("too many arguments: {num_args} overflows u32"),
        )
    })?;
    let level = Ident::new("level", Span::mixed_site());
    let header = Ident::new("__header", Span::call_site());
    let tmp = Ident::new("__tmp", Span::call_site());
    let kind = Ident::new("__kind", Span::call_site());
    let value = Ident::new("__value", Span::call_site());
    let size = Ident::new("__size", Span::call_site());
    let capacity = Ident::new("__capacity", Span::call_site());
    let pos = Ident::new("__pos", Span::call_site());
    let op = Ident::new("__op", Span::call_site());
    let buf = Ident::new("__buf", Span::call_site());
    Ok(quote! {
        {
            let #level = #level_expr;
            if ::aya_log_ebpf::macro_support::level_enabled(#level) {
                // Silence unused variable warning; we may need ctx in the future.
                let _ = #ctx;
                let _: Option<()> = (|| {
                    use ::aya_log_ebpf::macro_support::{Header, Field, Argument, AYA_LOGS};

                    let #header = Header::new(
                                        #target,
                                        #level,
                                        module_path!(),
                                        file!(),
                                        line!(),
                                        #num_args,
                                    )?;

                    #(
                        let #tmp = #values;
                        let (#kind, #value) = #tmp.as_argument();
                        let #idents = Field::new(#kind, #value)?;
                    )*

                    let mut #size = size_of::<::aya_log_ebpf::macro_support::LogValueLength>(); // For the size field itself.
                    let mut #op = |slice: &[u8]| {
                        #size += slice.len();
                        Some(())
                    };
                    #header.with_bytes(&mut #op)?;
                    #(
                        #idents.with_bytes(&mut #op)?;
                    )*

                    let #size = match ::aya_log_ebpf::macro_support::LogValueLength::try_from(#size) {
                        Ok(#size) => #size,
                        Err(core::num::TryFromIntError { .. }) => return None,
                    };
                    let #size = core::hint::black_box(#size);
                    let mut #capacity = 64;
                    while #capacity < #size {
                        #capacity <<= 1;
                        if #capacity > 8192 {
                            // The size is too large to log.
                            return None;
                        }
                    }
                    let mut #buf = core::hint::black_box(AYA_LOGS.reserve_bytes(#capacity.into(), 0)?);

                    match (|| {
                        let mut #pos = 0;
                        let mut #op = |slice: &[u8]| {
                            let #buf = #buf.get_mut(#pos..)?;
                            let #buf = #buf.get_mut(..slice.len())?;
                            #buf.copy_from_slice(slice);
                            #pos += slice.len();
                            Some(())
                        };
                        #op(#size.to_ne_bytes().as_ref())?;
                        #header.with_bytes(&mut #op)?;
                        #(
                            #idents.with_bytes(&mut #op)?;
                        )*
                        Some(())
                    })() {
                        Some(()) => #buf.submit(0),
                        None => #buf.discard(0),
                    }

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
