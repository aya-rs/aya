use syn::{
    parse::{Parse, ParseStream},
    punctuated::{Pair, Punctuated},
    token::Eq,
    Error, Ident, LitStr, Result, Token,
};

pub(crate) struct NameValue {
    name: Ident,
    _eq: Eq,
    value: LitStr,
}

pub(crate) struct Args {
    pub(crate) args: Vec<NameValue>,
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

pub(crate) fn pop_arg(args: &mut Args, name: &str) -> Option<String> {
    match args.args.iter().position(|arg| arg.name == name) {
        Some(index) => Some(args.args.remove(index).value.value()),
        None => None,
    }
}

pub(crate) fn pop_required_arg(args: &mut Args, name: &str) -> Result<String> {
    let value = match args.args.iter().position(|arg| arg.name == name) {
        Some(index) => Some(args.args.remove(index).value.value()),
        None => None,
    };
    match value {
        Some(value) => Ok(value),
        None => Err(Error::new_spanned(
            args.args.first().unwrap().name.clone(),
            format!("missing required argument `{}`", name),
        )),
    }
}

pub(crate) fn err_on_unknown_args(args: &Args) -> Result<()> {
    if let Some(arg) = args.args.get(0) {
        return Err(Error::new_spanned(&arg.name, "invalid argument"));
    }
    Ok(())
}

pub(crate) fn name_arg(args: &mut Args) -> Result<Option<String>> {
    let name = pop_arg(args, "name");
    Ok(name)
}
