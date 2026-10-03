//! HTML living standard 3.2.6.5 The `style` attribute:
//!
//! > All HTML elements may have the `style` content attribute set.
//! > This is a style attribute as defined by [CSS Style Attributes](CSSATTR).
//!
//! CSSATTR 3. Syntax and Parsing
//!
//! The value of the style attribute must match the syntax of the contents of a CSS
//! declaration block (excluding the delimiting braces), whose formal grammar is given
//! below in the terms and conventions of the CSS core grammar:
//!
//! ```yacc
//! style-attribute
//!   : S* declaration-list
//!   ;
//!
//! declaration-list
//!     : declaration [ ';' S* declaration-list ]?
//!     | at-rule declaration-list
//!     | /* empty */
//!     ;
//! ```
//!
//! > Note that because there is no open brace delimiting the declaration list in
//! > the CSS style attribute syntax, a close brace (`}`) in the style attribute's
//! > value does not terminate the style data: it is merely an invalid token.
//!
//! > [...] Although the grammar allows it, no at-rule valid in style attributes is
//! > define[d] at the moment. The forward-compatible parsing rules are such that
//! > a declaration following an at-rule is *not* ignored
//!
//! [CSSATTR]: https://w3c.github.io/csswg-drafts/css-style-attr/
use std::collections::HashSet;

use cssparser::{
    BasicParseErrorKind, DeclarationParser, ParseError, ParseErrorKind, Parser, ParserState, ToCss,
    Token,
};

use url::Url;

use crate::UrlRelative;

/// Filters `style` to only keep the declarations whose property name are listed in
/// `names`. Also normalises the style attribute by stripping broken declarations
/// and constructs per [CSSATTR] rules.
pub fn filter_style_attribute<'a>(
    style: &str,
    names: &HashSet<&str>,
    url_relative: &UrlRelative<'a>,
    url_schemes: &HashSet<&'a str>,
) -> String {
    // add room for the trailing semicolon because we lazy
    let mut out = String::with_capacity(style.len() + 1);

    let mut p = Parser::new(style);

    loop {
        let position_before_parse = p.position();
        match parse_one_declaration(&mut p, names, url_relative, url_schemes) {
            Ok((name, value)) => {
                if !name.is_empty() {
                    out.push_str(&name);
                    out.push(':');
                    out.push_str(&value);
                    out.push(';');
                }
            }
            Err(e) => match e.kind {
                ParseErrorKind::Basic(BasicParseErrorKind::EndOfInput) => break,
                ParseErrorKind::Basic(BasicParseErrorKind::UnexpectedToken) => {
                    let position_after_parse = p.position();
                    // scan to the next semicolon, if we didn't already hit one
                    if !p
                        .slice(position_before_parse..position_after_parse)
                        .trim_end()
                        .ends_with(';')
                    {
                        advance(&mut p);
                    }
                }
                _ => unreachable!(
                    "parse_one_declaration should only attempt to parse an ident, a colon, \
                    or a Declaration, so its only errors should be EOF or an unexpected token"
                ),
            },
        }
    }
    if !out.is_empty() {
        // remove trailing semicolon (?)
        out.pop();
    }
    out
}

/// The builtin parse_one_declaration errors on a declaration list, that is not what we want.
///
/// Also we don't need the errorneous slice on failure, since we just skip.
///
/// Finally, add property filtering directly so we don't need to pay for the
/// `DeclarationParser::parse_value` if the property is not whitelisted. If
/// a property is filtered out, it gets parsed as `("", "")`.
pub fn parse_one_declaration<'i, 'a>(
    input: &mut Parser<'i>,
    valid_properties: &HashSet<&str>,
    url_relative: &UrlRelative<'a>,
    url_schemes: &HashSet<&'a str>,
) -> Result<(cssparser::CowRcStr<'i>, String), ParseError<()>> {
    let name = input.expect_ident()?.clone();
    if !valid_properties.contains(&*name) {
        advance(input);
        return Ok(("".into(), String::new()));
    }
    input.expect_colon()?;
    Declarations(url_relative, url_schemes).parse_value(name, input, &input.state())
}

struct Declarations<'x, 'a: 'x>(&'x UrlRelative<'a>, &'x HashSet<&'a str>);
impl<'a, 'i> DeclarationParser<'i> for Declarations<'_, 'a> {
    type Declaration = (cssparser::CowRcStr<'i>, String);
    type Error = ();

    fn parse_value(
        &mut self,
        name: cssparser::CowRcStr<'i>,
        input: &mut Parser<'i>,
        _declaration_start: &ParserState,
    ) -> Result<Self::Declaration, cssparser::ParseError<Self::Error>> {
        let Declarations(url_relative, url_schemes) = self;
        let mut value = String::new();
        loop {
            let t = match input.next() {
                Err(e) if e.kind == cssparser::BasicParseErrorKind::EndOfInput => &Token::Semicolon,
                t => t?,
            };
            use Token::*;
            match t {
                Semicolon => {
                    if value.chars().all(char::is_whitespace) {
                        return Ok(("".into(), String::new()));
                    }
                    break;
                }

                BadString(_) | BadUrl(_) => {
                    let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                    return Err(ParseError::from_basic_kind(err));
                }

                UnquotedUrl(url_value) => {
                    if !value.is_empty() && value.chars().last() != Some(' ') {
                        value.push(' ');
                    }
                    let url = match Url::parse(url_value) {
                        Ok(url) if url_schemes.contains(url.scheme()) => Some(url.as_str().into()),
                        Err(url::ParseError::RelativeUrlWithoutBase)
                            if !matches!(url_relative, UrlRelative::Deny) =>
                        {
                            url_relative.evaluate(&url_value)
                        }
                        _ => None,
                    };
                    if let Some(url) = url {
                        // add quotes to URLs,
                        // because the relative URL rewriter might have done something
                        value.push_str(r#"url(""#);
                        value.push_str(&url[..]);
                        value.push_str(r#"")"#);
                        continue;
                    } else {
                        let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                        return Err(ParseError::from_basic_kind(err));
                    }
                }

                Function(name) if *name == "url" => {
                    if !value.is_empty() && value.chars().last() != Some(' ') {
                        value.push(' ');
                    }
                    let url_value = input.parse_nested_block(|p| {
                        // this is how quoted urls are parsed
                        // unquoted urls are handled above
                        let url_value = match p.next() {
                            Ok(QuotedString(url_value)) => url_value.to_string(),
                            _ => {
                                let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                                return Err(ParseError::from_basic_kind(err));
                            }
                        };
                        // url must contain a string, and nothing else
                        if let Err(e) = p.next() {
                            if e.kind == BasicParseErrorKind::EndOfInput {
                                return Ok(url_value);
                            }
                        }
                        let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                        return Err(ParseError::from_basic_kind(err));
                    })?;
                    let url = match Url::parse(&url_value) {
                        Ok(url) if url_schemes.contains(url.scheme()) => Some(url.as_str().into()),
                        Err(url::ParseError::RelativeUrlWithoutBase)
                            if !matches!(url_relative, UrlRelative::Deny) =>
                        {
                            url_relative.evaluate(&url_value)
                        }
                        _ => None,
                    };
                    if let Some(url) = url {
                        value.push_str(r#"url(""#);
                        value.push_str(&url[..]);
                        value.push_str(r#"")"#);
                        continue;
                    } else {
                        let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                        return Err(ParseError::from_basic_kind(err));
                    }
                }

                Function(_) => {
                    if !value.is_empty() && value.chars().last() != Some(' ') {
                        value.push(' ');
                    }
                    let Ok(_) = t.to_css(&mut value) else {
                        let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                        return Err(ParseError::from_basic_kind(err));
                    };
                    input.parse_nested_block(|p| {
                        let mut first = true;
                        loop {
                            match p.next() {
                                Ok(t) => {
                                    if t.is_parse_error() {
                                        let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                                        return Err(ParseError::from_basic_kind(err));
                                    }
                                    if !first && t != &Comma {
                                        value.push(' ');
                                    }
                                    let Ok(_) = t.to_css(&mut value) else {
                                        let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                                        return Err(ParseError::from_basic_kind(err));
                                    };
                                    first = false;
                                }
                                Err(e) if e.kind == BasicParseErrorKind::EndOfInput => break Ok(()),
                                Err(e) => return Err(e.into()),
                            }
                        }
                    })?;
                    value.push(')');
                    continue;
                }

                _ => (),
            }
            if !value.is_empty() && value.chars().last() != Some(' ') {
                value.push(' ');
            }
            let Ok(_) = t.to_css(&mut value) else {
                let err = cssparser::BasicParseErrorKind::UnexpectedToken;
                return Err(ParseError::from_basic_kind(err));
            };
        }
        if value.chars().all(char::is_whitespace) {
            Err(ParseError::from_basic_kind(
                cssparser::BasicParseErrorKind::EndOfInput,
            ))
        } else {
            Ok((name, value))
        }
    }
}

// find end of declaration (EOF or semicolon) in order to recover
fn advance<'i>(p: &mut Parser<'i>) {
    loop {
        match p.next() {
            Ok(Token::Semicolon) => return,
            // cssparser automatically handles paired delimiters, if we encounter a curly
            // bracket the next token is whatever follows the corresponding closing
            // bracket, which may be a new declaration
            Ok(Token::CurlyBracketBlock) => return,
            Err(e) if e.kind == cssparser::BasicParseErrorKind::EndOfInput => return,
            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::filter_style_attribute;
    use crate::UrlRelative;
    use std::{collections::HashSet, sync::LazyLock};

    #[test]
    fn single_declaration() {
        assert_eq!(
            filter_style_attribute(
                "font-style: italic",
                &HashSet::from(["font-style"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "font-style:italic",
        );
    }

    #[test]
    fn terminated_declaration() {
        assert_eq!(
            filter_style_attribute(
                "font-style: italic;",
                &HashSet::from(["font-style"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "font-style:italic",
        );
    }

    #[test]
    fn complex() {
        assert_eq!(
            filter_style_attribute(
                "background: no-repeat center/80% url(\"../img/image.png\");",
                &HashSet::from(["background"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "background:no-repeat center / 80% url(\"../img/image.png\")",
        )
    }

    /// forward-compatible parsing rules should just skip the unknown / contextually invalid at-rule
    #[test]
    fn at_rule() {
        assert_eq!(
            filter_style_attribute(
                "@unsupported { splines: reticulating } color: green",
                &HashSet::from(["color", "splines"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "color:green",
        );
    }

    #[test]
    fn invalid_at_rules() {
        assert_eq!(
            filter_style_attribute(
                "@charset 'utf-8'; color: green",
                &HashSet::from(["color"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "color:green",
        );
        assert_eq!(
            filter_style_attribute(
                "@foo url(https://example.org); color: green",
                &HashSet::from(["color"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "color:green",
        );
        assert_eq!(
            filter_style_attribute(
                "@media screen { color: red }; color: green",
                &HashSet::from(["color"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "color:green",
        );

        assert_eq!(
            filter_style_attribute(
                "@scope (main) { div { color: red } }; color: green",
                &HashSet::from(["color"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "color:green",
        );
    }

    #[test]
    fn empty_value() {
        assert_eq!(
            filter_style_attribute(
                "content: ''",
                &HashSet::from(["content"]),
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "content:\"\"",
        )
    }

    static ALLOWED: LazyLock<HashSet<&str>> = LazyLock::new(|| HashSet::from(["color", "foo"]));
    #[test]
    fn multiple() {
        assert_eq!(
            filter_style_attribute(
                "foo: 1; color: green",
                &ALLOWED,
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "foo:1;color:green"
        );
    }

    /// https://www.w3.org/TR/CSS21/syndata.html#:~:text=malformed%20declarations
    #[test]
    fn malformed_declarations() {
        let h = &HashSet::from(["color"]);
        for decl in [
            "color:green",
            "color:green; color",
            "color:green; color:",
            "color:green; color{;color:maroon}",
        ] {
            assert_eq!(
                filter_style_attribute(decl, h, &UrlRelative::PassThrough, &HashSet::default()),
                "color:green",
                "{}",
                decl,
            );
        }
        // should we also keep track of properties and remove duplicates?
        for decl in [
            "color:red;   color; color:green",
            "color:red;   color:; color:green",
            "color:red;   color{;color:maroon}; color:green",
        ] {
            assert_eq!(
                filter_style_attribute(decl, h, &UrlRelative::PassThrough, &HashSet::default()),
                "color:red;color:green",
                "{}",
                decl,
            );
        }
    }

    #[ignore = "can't recover from such a BadString (servo/rust-cssparser#393)"]
    #[test]
    fn badstring_escaped_newline() {
        assert_eq!(
            filter_style_attribute(
                "foo: '\n'; color: green",
                &ALLOWED,
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "color:green"
        );
    }

    #[ignore = "can't recover from such a BadString (servo/rust-cssparser#393)"]
    #[test]
    fn badstring_literal_newline() {
        assert_eq!(
            filter_style_attribute(
                "foo: '
        '; color: green",
                &ALLOWED,
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "color:green"
        );
    }

    #[test]
    fn bad_url() {
        assert_eq!(
            filter_style_attribute(
                "foo: url(x'y); color: green",
                &ALLOWED,
                &UrlRelative::PassThrough,
                &HashSet::default()
            ),
            "color:green"
        );
    }
}
