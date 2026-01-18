use syn::{
    Error, Ident, LitStr, Result, Token,
    parse::{Parse, ParseStream},
    punctuated::{Pair, Punctuated},
};

pub(crate) struct NameValue {
    name: Ident,
    value: LitStr,
}

pub(crate) struct Args {
    pub(crate) strings: Vec<NameValue>,
    pub(crate) bools: Vec<Ident>,
}

impl Parse for Args {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        enum NameValueOrBool {
            String(NameValue),
            Bool(Ident),
        }

        let args =
            Punctuated::<NameValueOrBool, Token![,]>::parse_terminated_with(input, |input| {
                let ident = input.parse::<Ident>()?;
                let lookahead = input.lookahead1();
                if input.is_empty() || lookahead.peek(Token![,]) {
                    Ok(NameValueOrBool::Bool(ident))
                } else if lookahead.peek(Token![=]) {
                    let _: Token![=] = input.parse()?;
                    Ok(NameValueOrBool::String(NameValue {
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
            });

        let mut strings = Vec::new();
        let mut bools = Vec::new();
        for arg in args {
            match arg {
                NameValueOrBool::String(name_val) => strings.push(name_val),
                NameValueOrBool::Bool(ident) => bools.push(ident),
            }
        }

        Ok(Self { strings, bools })
    }
}

impl Args {
    pub(crate) fn pop_string(&mut self, name: &str) -> Option<String> {
        let Self { strings, bools: _ } = self;
        strings
            .iter()
            .position(|name_val| name_val.name == name)
            .map(|index| strings.swap_remove(index).value.value())
    }

    pub(crate) fn pop_bool(&mut self, name: &str) -> bool {
        let Self { strings: _, bools } = self;
        bools
            .iter()
            .position(|ident| ident == name)
            .map(|index| bools.swap_remove(index))
            .is_some()
    }

    pub(crate) fn into_error(self) -> Result<()> {
        let Self { strings, bools } = self;
        match strings
            .into_iter()
            .map(|NameValue { name, value: _ }| Error::new_spanned(name, "invalid argument"))
            .chain(
                bools
                    .into_iter()
                    .map(|ident| Error::new_spanned(ident, "invalid argument")),
            )
            .reduce(|mut acc, err| {
                acc.combine(err);
                acc
            }) {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    pub(crate) fn pop_name(&mut self) -> Option<String> {
        self.pop_string("name")
    }
}
