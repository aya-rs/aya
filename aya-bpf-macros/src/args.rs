use syn::{
    parse::{Parse, ParseStream},
    punctuated::{Pair, Punctuated},
    token::Eq,
    Error, Ident, LitStr, Result, Token,
};

pub(crate) struct NameValue {
    name: Ident,
    value: LitStr,
}

pub(crate) enum Arg {
    String(NameValue),
    Bool(Ident),
}

pub(crate) struct Args {
    pub(crate) args: Vec<Arg>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> Result<Args> {
        let args = Punctuated::<Arg, Token![,]>::parse_terminated_with(input, |input| {
            let ident = input.parse::<Ident>()?;
            let lookahead = input.lookahead1();
            if lookahead.peek(Token![=]) {
                let _ = input.parse::<Eq>()?;
                Ok(Arg::String(NameValue {
                    name: ident,
                    value: input.parse()?,
                }))
            } else {
                Ok(Arg::Bool(ident))
            }
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

pub(crate) fn pop_string_arg(args: &mut Args, name: &str) -> Option<String> {
    let value = match args.args.iter().position(|arg| match arg {
        Arg::String(name_val) => name_val.name == name,
        Arg::Bool(_) => false,
    }) {
        Some(index) => Some(args.args.remove(index)),
        None => None,
    };
    match value {
        Some(Arg::String(value)) => Some(value.value.value()),
        Some(Arg::Bool(_)) | None => None,
    }
}

pub(crate) fn pop_bool_arg(args: &mut Args, name: &str) -> bool {
    let value = match args.args.iter().position(|arg| match arg {
        Arg::String(_) => false,
        Arg::Bool(ident) => ident == name,
    }) {
        Some(index) => Some(args.args.remove(index)),
        None => None,
    };
    value.is_some()
}

pub(crate) fn err_on_unknown_args(args: &Args) -> Result<()> {
    if let Some(arg) = args.args.get(0) {
        let tokens = match arg {
            Arg::String(name_val) => name_val.name.clone(),
            Arg::Bool(ident) => ident.clone(),
        };
        return Err(Error::new_spanned(tokens, "invalid argument"));
    }
    Ok(())
}

pub(crate) fn name_arg(args: &mut Args) -> Option<String> {
    pop_string_arg(args, "name")
}
