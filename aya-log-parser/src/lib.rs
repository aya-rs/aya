// We implement our own formatter here and we pass literal strings on purpose.
#![allow(clippy::literal_string_with_formatting_args)]

use std::str;

use aya_log_common::DisplayHint;

/// A parsed formatting parameter (contents of `{` `}` block).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    /// The display hint, e.g. ':ipv4', ':x'.
    pub hint: DisplayHint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fragment {
    /// A literal string (eg. `"literal "` in `"literal {}"`).
    Literal(String),

    /// A format parameter.
    Parameter(Parameter),
}

fn push_literal(frag: &mut Vec<Fragment>, unescaped_literal: &str) -> Result<(), String> {
    // Replace `{{` with `{` and `}}` with `}`. Single braces are errors.

    // Scan for single braces first. The rest is trivial.
    let mut last_open = false;
    let mut last_close = false;
    for c in unescaped_literal.chars() {
        match c {
            '{' => last_open = !last_open,
            '}' => last_close = !last_close,
            _ => {
                if last_open {
                    return Err("unmatched `{` in format string".into());
                }
                if last_close {
                    return Err("unmatched `}` in format string".into());
                }
            }
        }
    }

    // Handle trailing unescaped `{` or `}`.
    if last_open {
        return Err("unmatched `{` in format string".into());
    }
    if last_close {
        return Err("unmatched `}` in format string".into());
    }

    let literal = unescaped_literal.replace("{{", "{").replace("}}", "}");
    frag.push(Fragment::Literal(literal));
    Ok(())
}

/// Parse `Param` from the given `&str` which can specify an optional format
/// like `:x` or `:ipv4` (without curly braces, which are parsed by the `parse`
/// function).
fn parse_param(input: &str) -> Result<Parameter, String> {
    let hint = match input.strip_prefix(":") {
        Some(input) => match input {
            "" => return Err("malformed format string (missing display hint after ':')".into()),
            "p" | "x" => DisplayHint::LowerHex,
            "X" => DisplayHint::UpperHex,
            "i" => DisplayHint::Ip,
            "mac" => DisplayHint::LowerMac,
            "MAC" => DisplayHint::UpperMac,
            input => return Err(format!("unknown display hint: {input:?}")),
        },
        None => {
            if !input.is_empty() {
                return Err(format!("unexpected content {input:?} in format string"));
            }
            DisplayHint::Default
        }
    };
    Ok(Parameter { hint })
}

/// Parses the given format string into string literals and parameters specified
/// by curly braces (with optional format hints like `:x` or `:ipv4`).
pub fn parse(format_string: &str) -> Result<Vec<Fragment>, String> {
    let mut fragments = Vec::new();

    // Index after the `}` of the last format specifier.
    let mut end_pos = 0;

    let mut chars = format_string.char_indices();
    while let Some((brace_pos, ch)) = chars.next() {
        if ch != '{' {
            // Part of a literal fragment.
            continue;
        }

        // Peek at the next char.
        if chars.as_str().starts_with('{') {
            // Escaped `{{`, also part of a literal fragment.
            chars.next();
            continue;
        }

        if brace_pos > end_pos {
            // There's a literal fragment with at least 1 character before this
            // parameter fragment.
            let unescaped_literal = &format_string[end_pos..brace_pos];
            push_literal(&mut fragments, unescaped_literal)?;
        }

        // Else, this is a format specifier. It ends at the next `}`.
        let len = chars
            .as_str()
            .find('}')
            .ok_or("missing `}` in format string")?;
        end_pos = brace_pos + 1 + len + 1;

        // Parse the contents inside the braces.
        let param_str = &format_string[brace_pos + 1..][..len];
        let param = parse_param(param_str)?;
        fragments.push(Fragment::Parameter(param));
    }

    // Trailing literal.
    if end_pos != format_string.len() {
        push_literal(&mut fragments, &format_string[end_pos..])?;
    }

    Ok(fragments)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            parse("foo {} bar {:x} test {:X} ayy {:i} lmao {{}} {{something}} {:p}"),
            Ok(vec![
                Fragment::Literal("foo ".into()),
                Fragment::Parameter(Parameter {
                    hint: DisplayHint::Default
                }),
                Fragment::Literal(" bar ".into()),
                Fragment::Parameter(Parameter {
                    hint: DisplayHint::LowerHex
                }),
                Fragment::Literal(" test ".into()),
                Fragment::Parameter(Parameter {
                    hint: DisplayHint::UpperHex
                }),
                Fragment::Literal(" ayy ".into()),
                Fragment::Parameter(Parameter {
                    hint: DisplayHint::Ip
                }),
                Fragment::Literal(" lmao {} {something} ".into()),
                Fragment::Parameter(Parameter {
                    hint: DisplayHint::LowerHex
                }),
            ])
        );
        assert!(parse("foo {:}").is_err());
        assert!(parse("foo { bar").is_err());
        assert!(parse("foo } bar").is_err());
        assert!(parse("foo { bar }").is_err());
    }
}
