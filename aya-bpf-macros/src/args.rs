use syn::{
    parse::{Parse, ParseStream},
    punctuated::{Pair, Punctuated},
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
            if input.is_empty() || lookahead.peek(Token![,]) {
                Ok(Arg::Bool(ident))
            } else if lookahead.peek(Token![=]) {
                let _: Token![=] = input.parse()?;
                Ok(Arg::String(NameValue {
                    name: ident,
                    value: input.parse()?,
                }))
            } else {
                Err(lookahead.error())
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
    args.args
        .iter()
        .position(|arg| matches!(arg, Arg::String(name_val) if name_val.name == name))
        .map(|index| match args.args.remove(index) {
            Arg::String(v) => v.value.value(),
            _ => panic!("impossible variant"),
        })
}

pub(crate) fn pop_bool_arg(args: &mut Args, name: &str) -> bool {
    args.args
        .iter()
        .position(|arg| matches!(arg, Arg::Bool(ident) if ident == name))
        .map(|index| match args.args.remove(index) {
            Arg::Bool(ident) => ident,
            _ => panic!("impossible variant"),
        })
        .is_some()
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
