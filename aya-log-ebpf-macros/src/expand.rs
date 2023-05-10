use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_str,
    punctuated::Punctuated,
    Error, Expr, LitStr, Result, Token,
};

use aya_log_common::DisplayHint;
use aya_log_parser::{parse, Fragment};

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

fn string_to_expr(s: String) -> Result<Expr> {
    parse_str(&format!("\"{s}\""))
}

fn hint_to_expr(hint: DisplayHint) -> Result<Expr> {
    match hint {
        DisplayHint::Default => parse_str("::aya_log_ebpf::macro_support::DisplayHint::Default"),
        DisplayHint::LowerHex => parse_str("::aya_log_ebpf::macro_support::DisplayHint::LowerHex"),
        DisplayHint::UpperHex => parse_str("::aya_log_ebpf::macro_support::DisplayHint::UpperHex"),
        DisplayHint::Ipv4 => parse_str("::aya_log_ebpf::macro_support::DisplayHint::Ipv4"),
        DisplayHint::Ipv6 => parse_str("::aya_log_ebpf::macro_support::DisplayHint::Ipv6"),
        DisplayHint::LowerMac => parse_str("::aya_log_ebpf::macro_support::DisplayHint::LowerMac"),
        DisplayHint::UpperMac => parse_str("::aya_log_ebpf::macro_support::DisplayHint::UpperMac"),
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
            Fragment::Literal(s) => {
                values.push(string_to_expr(s)?);
            }
            Fragment::Parameter(p) => {
                let arg = match args.formatting_args {
                    Some(ref args) => args[arg_i].clone(),
                    None => return Err(Error::new(format_string.span(), "no arguments provided")),
                };
                values.push(hint_to_expr(p.hint)?);
                values.push(arg);
                arg_i += 1;
            }
        }
    }

    let num_args = values.len();
    let values_iter = values.iter();

    Ok(quote! {
        {
            if let Some(buf_ptr) = unsafe { ::aya_log_ebpf::AYA_LOG_BUF.get_ptr_mut(0) } {
                let buf = unsafe { &mut *buf_ptr };
                if let Ok(header_len) = ::aya_log_ebpf::write_record_header(
                    &mut buf.buf,
                    #target,
                    #lvl,
                    module_path!(),
                    file!(),
                    line!(),
                    #num_args,
                ) {
                    let record_len = header_len;

                    if let Ok(record_len) = {
                        Ok::<_, ()>(record_len) #( .and_then(|record_len| {
                            if record_len >= buf.buf.len() {
                                return Err(());
                            }
                            aya_log_ebpf::WriteToBuf::write({ #values_iter }, &mut buf.buf[record_len..]).map(|len| record_len + len)
                        }) )*
                    } {
                        unsafe { ::aya_log_ebpf::AYA_LOGS.output(
                            #ctx,
                            &buf.buf[..record_len], 0
                        )}
                    }
                }
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
