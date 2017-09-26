#![doc(html_root_url = "https://docs.rs/ammonia/1.0.0-rc1")]

// Copyright (C) Michael Howell and others
// this library is released under the same terms as Rust itself.

//! Ammonia is a whitelist-based HTML sanitization library. It is designed to
//! prevent cross-site scripting, layout breaking, and clickjacking caused
//! by untrusted user-provided HTML being mixed into a larger web page.
//!
//! Ammonia uses [html5ever] to parse and serialize document fragments the same way browsers do,
//! so it is extremely resilient to syntactic obfuscation.
//!
//! Ammonia parses its input exactly according to the HTML5 specification;
//! it will not linkify bare URLs, insert line or paragraph breaks, or convert `(C)` into &copy;.
//! If you want that, use a markup processor before running the sanitizer, like [pulldown-cmark].
//!
//! # Examples
//!
//! ```
//! let result = ammonia::clean(
//!     "<b><img src='' onerror='alert(\\'hax\\')'>I'm not trying to XSS you</b>"
//! );
//! assert_eq!(result, "<b><img>I'm not trying to XSS you</b>");
//! ```
//!
//! [html5ever]: https://github.com/servo/html5ever "The HTML parser in Servo"
//! [pulldown-cmark]: https://github.com/google/pulldown-cmark "CommonMark parser"

#[macro_use]
extern crate html5ever;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate maplit;
#[macro_use]
extern crate tendril;
extern crate url;

use html5ever::{driver as html, QualName};
use html5ever::rcdom::{Handle, NodeData, RcDom};
use html5ever::serialize::{serialize, SerializeOpts};
use html5ever::tree_builder::{NodeOrText, TreeSink};
use html5ever::interface::Attribute;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::mem::replace;
use std::rc::Rc;
use tendril::stream::TendrilSink;
use tendril::StrTendril;
use url::Url;

lazy_static! {
    static ref AMMONIA: Builder<'static> = Builder::default();
}

/// Clean HTML with a conservative set of defaults.
///
///  * Formatting: `b`, `blockquote`, `br`, `code`, `dd`, `del`, `dl`, `dt`,
///                `em`, `h1`, `h2`, `h3`, `hr`, `i`, `kbd`, `li`, `ol`, `p`,
///                `pre`, `s`, `strike`, `strong`, `sub`, `sup`, `ul`
///  * Tables: `table`, `tbody`, `td`, `th`, `thead`, `tr`
///  * Links: `a`, `img`
///  * Attributes: `<* title="">`, `<a href="">`,
///                `<img width="" height="" src="" alt="">`
///  * URL schemes in links and images: `http`, `https`, `mailto`
///  * Relative URLs are not allowed, to prevent cross-site request forgery.
///  * `<a>` links have `rel="noopener noreferrer"` implicitly added,
///    since the [opener] allows a particular kind of XSS attack
///    and the [referrer] might leak private information if it's stored in the URL.
///
/// [opener]: https://mathiasbynens.github.io/rel-noopener/
/// [referrer]: https://en.wikipedia.org/wiki/HTTP_referer
///
/// # Examples
///
///     assert_eq!(ammonia::clean("<script>XSS</script>"), "XSS")
pub fn clean(src: &str) -> String {
    AMMONIA.clean(src).to_string()
}

/// An HTML sanitizer.
///
/// Given a fragment of HTML, Ammonia will parse it according to the HTML5
/// parsing algorithm and sanitize any disallowed tags or attributes. This
/// algorithm also takes care of things like unclosed and (some) misnested
/// tags.
///
/// # Examples
///
///     use ammonia::{Builder, UrlRelative};
///
///     let a = Builder::default()
///         .link_rel(None)
///         .url_relative(UrlRelative::PassThrough)
///         .clean("<a href=/>test")
///         .to_string();
///     assert_eq!(
///         a,
///         "<a href=\"/\">test</a>");
///
/// # Panics
///
/// Running [`clean`] or [`clean_from_reader`] may cause a panic if the builder is
/// configured with any of these (contradictory) settings:
///
///  * the `rel` attribute is added to [`generic_attributes`] or the
///    [`tag_attributes`] for the `<a>` tag, and [`link_rel`] is not set to `None`.
///
///    For example, this is going to panic, since [`link_rel`] is set  to
///    `Some("noopener noreferrer")` by default,
///    and it makes no sense to simultaneously say that the user is allowed to
///    set their own `rel` attribute while saying that every link shall be set to
///    a particular value:
///
///    ```should_panic
///    #[macro_use]
///    extern crate maplit;
///    # extern crate ammonia;
///
///    use ammonia::Builder;
///
///    # fn main() {
///    Builder::default()
///        .generic_attributes(hashset!["rel"])
///        .clean("");
///    # }
///    ```
///
///    This, however, is perfectly valid:
///
///    ```
///    #[macro_use]
///    extern crate maplit;
///    # extern crate ammonia;
///
///    use ammonia::Builder;
///
///    # fn main() {
///    Builder::default()
///        .generic_attributes(hashset!["rel"])
///        .link_rel(None)
///        .clean("");
///    # }
///    ```
///
///  * the `class` attribute is in [`allowed_classes`] and is in the
///    corresponding [`tag_attributes`] or in [`generic_attributes`]
///
///    This is done both to line up with the treatment of `rel`,
///    and to prevent people from accidentally allowing arbitrary
///    classes on a particular element.
///
///    This will panic:
///
///    ```should_panic
///    #[macro_use]
///    extern crate maplit;
///    # extern crate ammonia;
///
///    use ammonia::Builder;
///
///    # fn main() {
///    Builder::default()
///        .generic_attributes(hashset!["class"])
///        .allowed_classes(hashmap!["span" => hashset!["hidden"]])
///        .clean("");
///    # }
///    ```
///
///    This, however, is perfectly valid:
///
///    ```
///    #[macro_use]
///    extern crate maplit;
///    # extern crate ammonia;
///
///    use ammonia::Builder;
///
///    # fn main() {
///    Builder::default()
///        .allowed_classes(hashmap!["span" => hashset!["hidden"]])
///        .clean("");
///    # }
///    ```
///
/// [`clean`]: #method.clean
/// [`clean_from_reader`]: #method.clean_from_reader
/// [`generic_attributes`]: #method.generic_attributes
/// [`tag_attributes`]: #method.tag_attributes
/// [`generic_attributes`]: #method.generic_attributes
/// [`link_rel`]: #method.link_rel
/// [`allowed_classes`]: #method.allowed_classes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Builder<'a> {
    tags: HashSet<&'a str>,
    tag_attributes: HashMap<&'a str, HashSet<&'a str>>,
    generic_attributes: HashSet<&'a str>,
    url_schemes: HashSet<&'a str>,
    url_relative: UrlRelative<'a>,
    link_rel: Option<&'a str>,
    allowed_classes: HashMap<&'a str, HashSet<&'a str>>,
    strip_comments: bool,
}

impl<'a> Default for Builder<'a> {
    fn default() -> Self {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let tags = hashset![
            "a", "abbr", "acronym", "area", "article", "aside", "b", "bdi",
            "bdo", "blockquote", "br", "caption", "center", "cite", "code",
            "col", "colgroup", "data", "dd", "del", "details", "dfn", "div",
            "dl", "dt", "em", "figcaption", "figure", "footer", "h1", "h2",
            "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "hr", "i", "img",
            "ins", "kbd", "kbd", "li", "map", "mark", "nav", "ol", "p", "pre",
            "q", "rp", "rt", "rtc", "ruby", "s", "samp", "small", "span",
            "strike", "strong", "sub", "summary", "sup", "table", "tbody",
            "td", "th", "thead", "time", "tr", "tt", "u", "ul", "var", "wbr"
        ];
        let generic_attributes = hashset![
            "lang", "title"
        ];
        let tag_attributes = hashmap![
            "a" => hashset![
                "href", "hreflang"
            ],
            "bdo" => hashset![
                "dir"
            ],
            "blockquote" => hashset![
                "cite"
            ],
            "col" => hashset![
                "align", "char", "charoff", "span"
            ],
            "colgroup" => hashset![
                "align", "char", "charoff", "span"
            ],
            "del" => hashset![
                "cite", "datetime"
            ],
            "hr" => hashset![
                "align", "size", "width"
            ],
            "img" => hashset![
                "align", "alt", "height", "src", "width"
            ],
            "ins" => hashset![
                "cite", "datetime"
            ],
            "ol" => hashset![
                "start"
            ],
            "q" => hashset![
                "cite"
            ],
            "table" => hashset![
                "align", "char", "charoff", "summary"
            ],
            "tbody" => hashset![
                "align", "char", "charoff"
            ],
            "td" => hashset![
                "align", "char", "charoff", "colspan", "headers", "rowspan",
            ],
            "tfoot" => hashset![
                "align", "char", "charoff"
            ],
            "th" => hashset![
                "align", "char", "charoff", "colspan", "headers", "rowspan",
            ],
            "thead" => hashset![
                "align", "char", "charoff"
            ],
            "tr" => hashset![
                "align", "char", "charoff"
            ],
        ];
        let url_schemes = hashset![
            "bitcoin", "ftp", "ftps", "geo", "http", "https", "im", "irc",
            "ircs", "magnet", "mailto", "mms", "mx", "news", "nntp",
            "openpgp4fpr", "sip", "sms", "smsto", "ssh", "tel", "url",
            "webcal", "wtai", "xmpp"
        ];
        let allowed_classes = hashmap![];

        Builder {
            tags: tags,
            tag_attributes: tag_attributes,
            generic_attributes: generic_attributes,
            url_schemes: url_schemes,
            url_relative: UrlRelative::Deny,
            link_rel: Some("noopener noreferrer"),
            allowed_classes: allowed_classes,
            strip_comments: true,
        }
    }
}

impl<'a> Builder<'a> {
    /// Sets the tags that are allowed.
    ///
    /// Note that this only whitelists the tag; by default elements will still be stripped
    /// if they have unlisted attributes.
    ///
    /// # Examples
    ///
    ///     #[macro_use]
    ///     extern crate maplit;
    ///     # extern crate ammonia;
    ///
    ///     use ammonia::Builder;
    ///
    ///     # fn main() {
    ///     let tags = hashset!["my-tag"];
    ///     let a = Builder::new()
    ///         .tags(tags)
    ///         .clean("<my-tag>")
    ///         .to_string();
    ///     assert_eq!(a, "<my-tag></my-tag>");
    ///     # }
    ///
    /// # Defaults
    ///
    /// ```notest
    /// a, abbr, acronym, area, article, aside, b, bdi,
    /// bdo, blockquote, br, caption, center, cite, code,
    /// col, colgroup, data, dd, del, details, dfn, div,
    /// dl, dt, em, figcaption, figure, footer, h1, h2,
    /// h3, h4, h5, h6, header, hgroup, hr, hr, i, img,
    /// ins, kbd, kbd, li, map, mark, nav, ol, p, pre,
    /// q, rp, rt, rtc, ruby, s, samp, small, span,
    /// strike, strong, sub, summary, sup, table, tbody,
    /// td, th, thead, time, tr, tt, u, ul, var, wbr
    /// ```
    pub fn tags(&mut self, value: HashSet<&'a str>) -> &mut Self {
        self.tags = value;
        self
    }

    /// Sets the HTML attributes that are allowed on specific tags.
    ///
    /// The value is structured as a map from tag names to a set of attribute names.
    ///
    /// If a tag is not itself whitelisted, adding entries to this map will do nothing.
    ///
    /// # Examples
    ///
    ///     #[macro_use]
    ///     extern crate maplit;
    ///     # extern crate ammonia;
    ///
    ///     use ammonia::Builder;
    ///
    ///     # fn main() {
    ///     let tags = hashset!["my-tag"];
    ///     let tag_attributes = hashmap![
    ///         "my-tag" => hashset!["val"]
    ///     ];
    ///     let a = Builder::new().tags(tags).tag_attributes(tag_attributes)
    ///         .clean("<my-tag val=1>")
    ///         .to_string();
    ///     assert_eq!(a, "<my-tag val=\"1\"></my-tag>");
    ///     # }
    ///
    /// # Defaults
    ///
    /// ```notest
    /// a =>
    ///     href, hreflang
    /// bdo =>
    ///     dir
    /// blockquote =>
    ///     cite
    /// col =>
    ///     align, char, charoff, span
    /// colgroup =>
    ///     align, char, charoff, span
    /// del =>
    ///     cite, datetime
    /// hr =>
    ///     align, size, width
    /// img =>
    ///     align, alt, height, src, width
    /// ins =>
    ///     cite, datetime
    /// ol =>
    ///     start
    /// q =>
    ///     cite
    /// table =>
    ///     align, char, charoff, summary
    /// tbody =>
    ///     align, char, charoff
    /// td =>
    ///     align, char, charoff, colspan, headers, rowspan,
    /// tfoot =>
    ///     align, char, charoff
    /// th =>
    ///     align, char, charoff, colspan, headers, rowspan,
    /// thead =>
    ///     align, char, charoff
    /// tr =>
    ///     align, char, charoff
    /// ```
    pub fn tag_attributes(&mut self, value: HashMap<&'a str, HashSet<&'a str>>) -> &mut Self {
        self.tag_attributes = value;
        self
    }

    /// Sets the attributes that are allowed on any tag.
    ///
    /// # Examples
    ///
    ///     #[macro_use]
    ///     extern crate maplit;
    ///     # extern crate ammonia;
    ///
    ///     use ammonia::Builder;
    ///
    ///     # fn main() {
    ///     let attributes = hashset!["data-val"];
    ///     let a = Builder::new()
    ///         .generic_attributes(attributes)
    ///         .clean("<b data-val=1>")
    ///         .to_string();
    ///     assert_eq!(a, "<b data-val=\"1\"></b>");
    ///     # }
    ///
    /// # Defaults
    ///
    /// ```notest
    /// lang, title
    /// ```
    pub fn generic_attributes(&mut self, value: HashSet<&'a str>) -> &mut Self {
        self.generic_attributes = value;
        self
    }

    /// Sets the URL schemes permitted on `href` and `src` attributes.
    ///
    /// # Examples
    ///
    ///     #[macro_use]
    ///     extern crate maplit;
    ///     # extern crate ammonia;
    ///
    ///     use ammonia::Builder;
    ///
    ///     # fn main() {
    ///     let url_schemes = hashset![
    ///         "http", "https", "mailto", "magnet"
    ///     ];
    ///     let a = Builder::new().url_schemes(url_schemes)
    ///         .clean("<a href=\"magnet:?xt=urn:ed2k:31D6CFE0D16AE931B73C59D7E0C089C0&xl=0&dn=zero_len.fil&xt=urn:bitprint:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ.LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ&xt=urn:md5:D41D8CD98F00B204E9800998ECF8427E\">zero-length file</a>")
    ///         .to_string();
    ///
    ///     // See `link_rel` for information on the rel="noopener noreferrer" attribute
    ///     // in the cleaned HTML.
    ///     assert_eq!(a,
    ///       "<a href=\"magnet:?xt=urn:ed2k:31D6CFE0D16AE931B73C59D7E0C089C0&amp;xl=0&amp;dn=zero_len.fil&amp;xt=urn:bitprint:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ.LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ&amp;xt=urn:md5:D41D8CD98F00B204E9800998ECF8427E\" rel=\"noopener noreferrer\">zero-length file</a>");
    ///     # }
    ///
    /// # Defaults
    ///
    /// ```notest
    /// bitcoin, ftp, ftps, geo, http, https, im, irc,
    /// ircs, magnet, mailto, mms, mx, news, nntp,
    /// openpgp4fpr, sip, sms, smsto, ssh, tel, url,
    /// webcal, wtai, xmpp
    /// ```
    pub fn url_schemes(&mut self, value: HashSet<&'a str>) -> &mut Self {
        self.url_schemes = value;
        self
    }

    /// Configures the behavior for relative URLs: pass-through, resolve-with-base, or deny.
    ///
    /// # Examples
    ///
    ///     use ammonia::{Builder, UrlRelative};
    ///
    ///     let a = Builder::new().url_relative(UrlRelative::PassThrough)
    ///         .clean("<a href=/>Home</a>")
    ///         .to_string();
    ///
    ///     // See `link_rel` for information on the rel="noopener noreferrer" attribute
    ///     // in the cleaned HTML.
    ///     assert_eq!(
    ///       a,
    ///       "<a href=\"/\" rel=\"noopener noreferrer\">Home</a>");
    ///
    /// # Defaults
    ///
    /// ```notest
    /// UrlRelative::Deny
    /// ```
    pub fn url_relative(&mut self, value: UrlRelative<'a>) -> &mut Self {
        self.url_relative = value;
        self
    }

    /// Configures a `rel` attribute that will be added on links.
    ///
    /// If `rel` is in the generic or tag attributes, this must be set to `None`.
    /// Common `rel` values to include:
    ///
    /// * `noopener`: This prevents [a particular type of XSS attack],
    ///   and should usually be turned on for untrusted HTML.
    /// * `noreferrer`: This prevents the browser from [sending the source URL]
    ///   to the website that is linked to.
    /// * `nofollow`: This prevents search engines from [using this link for
    ///   ranking], which disincentivizes spammers.
    ///
    /// To turn on rel-insertion, call this function with a space-separated list.
    /// Ammonia does not parse rel-attributes;
    /// it just puts the given string into the attribute directly.
    ///
    /// [a particular type of XSS attack]: https://mathiasbynens.github.io/rel-noopener/
    /// [sending the source URL]: https://en.wikipedia.org/wiki/HTTP_referer
    /// [using this link for ranking]: https://en.wikipedia.org/wiki/Nofollow
    ///
    /// # Examples
    ///
    ///     use ammonia::Builder;
    ///
    ///     let a = Builder::new().link_rel(None)
    ///         .clean("<a href=https://rust-lang.org/>Rust</a>")
    ///         .to_string();
    ///     assert_eq!(
    ///       a,
    ///       "<a href=\"https://rust-lang.org/\">Rust</a>");
    ///
    /// # Defaults
    ///
    /// ```notest
    /// Some("noopener noreferrer")
    /// ```
    pub fn link_rel(&mut self, value: Option<&'a str>) -> &mut Self {
        self.link_rel = value;
        self
    }

    /// Sets the CSS classes that are allowed on specific tags.
    ///
    /// The values is structured as a map from tag names to a set of class names.
    ///
    /// If the `class` attribute is itself whitelisted for a tag, then adding entries to
    /// this map will cause a panic.
    ///
    /// # Examples
    ///
    ///     #[macro_use]
    ///     extern crate maplit;
    ///     # extern crate ammonia;
    ///
    ///     use ammonia::Builder;
    ///
    ///     # fn main() {
    ///     let allowed_classes = hashmap![
    ///         "code" => hashset!["rs", "ex", "c", "cxx", "js"]
    ///     ];
    ///     let a = Builder::new()
    ///         .allowed_classes(allowed_classes)
    ///         .clean("<code class=rs>fn main() {}</code>")
    ///         .to_string();
    ///     assert_eq!(
    ///       a,
    ///       "<code class=\"rs\">fn main() {}</code>");
    ///     # }
    ///
    /// # Defaults
    ///
    /// The set of allowed classes is empty by default.
    pub fn allowed_classes(&mut self, value: HashMap<&'a str, HashSet<&'a str>>) -> &mut Self {
        self.allowed_classes = value;
        self
    }

    /// Configures the handling of HTML comments.
    ///
    /// If this option is false, comments will be preserved.
    ///
    /// # Examples
    ///
    ///     use ammonia::Builder;
    ///
    ///     let a = Builder::new().strip_comments(false)
    ///         .clean("<!-- yes -->")
    ///         .to_string();
    ///     assert_eq!(
    ///       a,
    ///       "<!-- yes -->");
    ///
    /// # Defaults
    ///
    /// `true`
    pub fn strip_comments(&mut self, value: bool) -> &mut Self {
        self.strip_comments = value;
        self
    }

    /// Constructs a [`Builder`] instance configured with the [default options].
    ///
    /// # Examples
    ///
    ///     use ammonia::{Builder, UrlRelative};
    ///
    ///     let input = "<!-- comments will be stripped -->This is an <a href=.>Ammonia</a> example using <a href=struct.Builder.html#method.new onclick=xss>the <code onmouseover=xss>new()</code> function</a>.";
    ///     let output = "This is an <a href=\"https://docs.rs/ammonia/1.0/ammonia/\" rel=\"noopener noreferrer\">Ammonia</a> example using <a href=\"https://docs.rs/ammonia/1.0/ammonia/struct.Builder.html#method.new\" rel=\"noopener noreferrer\">the <code>new()</code> function</a>.";
    ///
    ///     let result = Builder::new() // <--
    ///         .url_relative(UrlRelative::RewriteWithBase("https://docs.rs/ammonia/1.0/ammonia/"))
    ///         .clean(input)
    ///         .to_string();
    ///     assert_eq!(result, output);
    ///
    /// [default options]: fn.clean.html
    /// [`Builder`]: struct.Builder.html
    pub fn new() -> Self {
        Self::default()
    }

    /// Sanitizes an HTML fragment in a string according to the configured options.
    ///
    /// # Examples
    ///
    ///     use ammonia::{Builder, UrlRelative};
    ///
    ///     let input = "<!-- comments will be stripped -->This is an <a href=.>Ammonia</a> example using <a href=struct.Builder.html#method.new onclick=xss>the <code onmouseover=xss>new()</code> function</a>.";
    ///     let output = "This is an <a href=\"https://docs.rs/ammonia/1.0/ammonia/\" rel=\"noopener noreferrer\">Ammonia</a> example using <a href=\"https://docs.rs/ammonia/1.0/ammonia/struct.Builder.html#method.new\" rel=\"noopener noreferrer\">the <code>new()</code> function</a>.";
    ///
    ///     let result = Builder::new()
    ///         .url_relative(UrlRelative::RewriteWithBase("https://docs.rs/ammonia/1.0/ammonia/"))
    ///         .clean(input)
    ///         .to_string(); // <--
    ///     assert_eq!(result, output);
    pub fn clean(&self, src: &'a str) -> Document {
        let parser = Self::make_parser();
        let dom = parser.one(src);
        self.clean_dom(dom)
    }

    /// Sanitizes an HTML fragment from a reader according to the configured options.
    ///
    /// The input should be UTF-8 encoding, otherwise the decoding is lossy, just
    /// like when using [`String::from_utf8_lossy`].
    ///
    /// # Examples
    ///
    ///     use ammonia::Builder;
    ///     # use std::error::Error;
    ///
    ///     # fn do_main() -> Result<(), Box<Error>> {
    ///     let a = Builder::new()
    ///         .clean_from_reader(&mut (b"<!-- no -->" as &[u8]))? // notice the `b`
    ///         .to_string();
    ///     assert_eq!(a, "");
    ///     # Ok(()) }
    ///     # fn main() { do_main().unwrap() }
    ///
    /// [`String::from_utf8_lossy`]: https://doc.rust-lang.org/std/string/struct.String.html#method.from_utf8_lossy
    pub fn clean_from_reader<R>(&self, src: &mut R) -> io::Result<Document>
    where
        R: io::Read,
    {
        let parser = Self::make_parser().from_utf8();
        let dom = parser.read_from(src)?;
        Ok(self.clean_dom(dom))
    }

    /// Clean a post-parsing DOM.
    ///
    /// This is not a public API because RcDom isn't really stable.
    /// We want to be able to take breaking changes to html5ever itself
    /// without having to break Ammonia's API.
    fn clean_dom(&self, mut dom: RcDom) -> Document {
        let mut stack = Vec::new();
        let link_rel = self.link_rel
            .map(|link_rel| format_tendril!("{}", link_rel));
        if link_rel.is_some() {
            assert!(self.generic_attributes.get("rel").is_none());
            assert!(
                self.tag_attributes
                    .get("a")
                    .and_then(|a| a.get("rel"))
                    .is_none()
            );
        }
        assert!(self.allowed_classes.is_empty() || !self.generic_attributes.contains("class"));
        for (tag_name, _classes) in &self.allowed_classes {
            assert!(
                self.tag_attributes
                    .get(tag_name)
                    .and_then(|a| a.get("class"))
                    .is_none()
            );
        }
        let url_base = if let UrlRelative::RewriteWithBase(base) = self.url_relative {
            Some(
                Url::parse(base).expect("RewriteWithBase(base) should have a valid URL for base"),
            )
        } else {
            None
        };
        let body = {
            let children = dom.document.children.borrow();
            children[0].clone()
        };
        stack.extend(
            replace(&mut *body.children.borrow_mut(), Vec::new())
                .into_iter()
                .rev(),
        );
        while let Some(mut node) = stack.pop() {
            let parent = node.parent
                .replace(None).expect("a node in the DOM will have a parent, except the root, which is not processed")
                .upgrade().expect("a node's parent will be pointed to by its parent (or the root pointer), and will not be dropped");
            let pass = self.clean_child(&mut node);
            if pass {
                self.adjust_node_attributes(&mut node, &link_rel, &url_base);
                dom.append(&parent.clone(), NodeOrText::AppendNode(node.clone()));
            } else {
                for sub in node.children.borrow_mut().iter_mut() {
                    sub.parent.replace(Some(Rc::downgrade(&parent)));
                }
            }
            stack.extend(
                replace(&mut *node.children.borrow_mut(), Vec::new())
                    .into_iter()
                    .rev(),
            );
        }
        Document(body)
    }

    /// Remove unwanted attributes, and check if the node should be kept or not.
    ///
    /// The root node doesn't need cleaning because we create the root node ourselves,
    /// and it doesn't get serialized, and ... it just exists to give the parser
    /// a context (in this case, a div-like block context).
    fn clean_child(&self, child: &mut Handle) -> bool {
        match child.data {
            NodeData::Text { .. } => true,
            NodeData::Comment { .. } => !self.strip_comments,
            NodeData::Doctype { .. } |
            NodeData::Document |
            NodeData::ProcessingInstruction { .. } => false,
            NodeData::Element {
                ref name,
                ref attrs,
                ..
            } => if self.tags.contains(&*name.local) {
                let attr_filter = |attr: &html5ever::Attribute| {
                    let whitelisted = self.generic_attributes.contains(&*attr.name.local) ||
                        self.tag_attributes
                            .get(&*name.local)
                            .map(|ta| ta.contains(&*attr.name.local)) ==
                            Some(true);
                    if !whitelisted {
                        // If the class attribute is not whitelisted,
                        // but there is a whitelisted set of allowed_classes,
                        // do not strip out the class attribute.
                        // Banned classes will be filtered later.
                        &*attr.name.local == "class" &&
                          self.allowed_classes.contains_key(&*name.local)
                    } else if is_url_attr(&*name.local, &*attr.name.local) {
                        let url = Url::parse(&*attr.value);
                        if let Ok(url) = url {
                            self.url_schemes.contains(url.scheme())
                        } else if url == Err(url::ParseError::RelativeUrlWithoutBase) {
                            self.url_relative != UrlRelative::Deny
                        } else {
                            false
                        }
                    } else {
                        true
                    }
                };
                attrs.borrow_mut().retain(attr_filter);
                true
            } else {
                false
            },
        }
    }

    /// Add and transform special-cased attributes and elements.
    ///
    /// This function handles:
    ///
    /// * relative URL rewriting
    /// * adding `<a rel>` attributes
    /// * filtering out banned classes
    fn adjust_node_attributes(
        &self,
        child: &mut Handle,
        link_rel: &Option<StrTendril>,
        url_base: &Option<Url>,
    ) {
        if let NodeData::Element {
            ref name,
            ref attrs,
            ..
        } = child.data
        {
            if let Some(ref link_rel) = *link_rel {
                if &*name.local == "a" {
                    attrs.borrow_mut().push(Attribute {
                        name: QualName::new(None, ns!(), local_name!("rel")),
                        value: link_rel.clone(),
                    })
                }
            }
            if let Some(ref base) = *url_base {
                for attr in &mut *attrs.borrow_mut() {
                    if is_url_attr(&*name.local, &*attr.name.local) {
                        let url = base.join(&*attr.value)
                            .expect("invalid URLs should be stripped earlier");
                        attr.value = format_tendril!("{}", url);
                    }
                }
            }
            if let Some(allowed_values) = self.allowed_classes.get(&*name.local) {
                for attr in &mut *attrs.borrow_mut() {
                    if &attr.name.local == "class" {
                        let mut classes = vec![];
                        for class in attr.value.split(' ') {
                            if allowed_values.contains(class) {
                                classes.push(class.to_owned());
                            }
                        }
                        attr.value = format_tendril!("{}", classes.join(" "));
                    }
                }
            }
        }
    }

    /// Initializes an HTML fragment parser.
    ///
    /// Ammonia conforms to the HTML5 fragment parsing rules,
    /// by parsing the given fragment as if it were included in a <div> tag.
    fn make_parser() -> html::Parser<RcDom> {
        html::parse_fragment(
            RcDom::default(),
            html::ParseOpts::default(),
            QualName::new(None, ns!(html), local_name!("div")),
            vec![],
        )
    }
}

/// Given an element name and attribute name, determine if the given attribute contains a URL.
fn is_url_attr(element: &str, attr: &str) -> bool {
    attr == "href" || attr == "src" || (element == "object" && attr == "data")
}

/// Policy for [relative URLs], that is, URLs that do not specify the scheme in full.
///
/// This policy kicks in, if set, for any attribute named `src` or `href`,
/// as well as the `data` attribute of an `object` tag.
///
/// [relative URLs]: struct.Builder.html#method.url_relative
///
/// # Examples
///
/// ## `Deny`
///
/// * `<a href="test">` is a file-relative URL, and will be removed
/// * `<a href="/test">` is a domain-relative URL, and will be removed
/// * `<a href="//example.com/test">` is a scheme-relative URL, and will be removed
/// * `<a href="http://example.com/test">` is an absolute URL, and will be kept
///
/// ## `PassThrough`
///
/// No changes will be made to any URLs, except if a disallowed scheme is used.
///
/// ## `RewriteWithBase`
///
/// If the base is set to "http://notriddle.com/some-directory/some-file"
///
/// * `<a href="test">` will be rewritten to `<a href="http://notriddle.com/some-directory/test">`
/// * `<a href="/test">` will be rewritten to `<a href="http://notriddle.com/test">`
/// * `<a href="//example.com/test">` will be rewritten to `<a href="http://example.com/test">`
/// * `<a href="http://example.com/test">` is an absolute URL, so it will be kept as-is
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UrlRelative<'a> {
    /// Relative URLs will be completely stripped from the document.
    Deny,
    /// Relative URLs will be passed through unchanged.
    PassThrough,
    /// Relative URLs will be changed into absolute URLs, based on this base URL.
    RewriteWithBase(&'a str),
    // Do not allow the user to exhaustively match on UrlRelative,
    // because we may add new items to it later.
    #[doc(hidden)]
    __NonExhaustive,
}

/// A sanitized HTML document.
///
/// The `Document` type is an opaque struct representing an HTML fragment that was sanitized by
/// `ammonia`. It can be converted to a [`String`] or written to a [`Write`] instance. This allows
/// users to avoid buffering the serialized representation to a [`String`] when desired.
///
/// This type is opaque to insulate the caller from breaking changes in the `html5ever` interface.
///
/// Note that this type wraps an `html5ever` DOM tree. `ammonia` does not support streaming, so
/// the complete fragment needs to be stored in memory during processing. Currently, `Document`
/// is backed by an [`html5ever::rcdom::Node`] object.
///
/// [`String`]: ../std/string/struct.String.html
/// [`Write`]: ../std/io/trait.Write.html
/// [`html5ever::rcdom::Node`]: ../markup5ever/rcdom/struct.Node.html
///
/// # Examples
///
///     use ammonia::Builder;
///
///     let input = "<!-- comments will be stripped -->This is an Ammonia example.";
///     let output = "This is an Ammonia example.";
///
///     let document = Builder::new()
///         .clean(input);
///     assert_eq!(document.to_string(), output);
#[derive(Clone)]
pub struct Document(Handle);

impl Document {
    /// Serializes a `Document` instance to a `String`.
    ///
    /// This method returns a [`String`] with the sanitized HTML. This is the simplest way to use
    /// `ammonia`.
    ///
    /// [`String`]: ../std/string/struct.String.html
    ///
    /// # Examples
    ///
    ///     use ammonia::Builder;
    ///
    ///     let input = "Some <style>HTML here";
    ///     let output = "Some HTML here";
    ///
    ///     let document = Builder::new()
    ///         .clean(input);
    ///     assert_eq!(document.to_string(), output);
    pub fn to_string(&self) -> String {
        let opts = Self::serialize_opts();
        let mut ret_val = Vec::new();
        serialize(&mut ret_val, &self.0, opts)
            .expect("Writing to a string shouldn't fail (expect on OOM)");
        String::from_utf8(ret_val)
            .expect("html5ever only supports UTF8")
    }

    /// Serializes a `Document` instance to a writer.
    ///
    /// This method writes the sanitized HTML to a [`Write`] instance, avoiding a buffering step.
    ///
    /// Note that the in-memory representation of `Document` is larger than the serialized
    /// `String`.
    ///
    /// [`Write`]: ../std/io/trait.Write.html
    ///
    /// # Examples
    ///
    ///     use ammonia::Builder;
    ///
    ///     let input = "Some <style>HTML here";
    ///     let expected = b"Some HTML here";
    ///
    ///     let document = Builder::new()
    ///         .clean(input);
    ///
    ///     let mut sanitized = Vec::new();
    ///     document.write_to(&mut sanitized)
    ///         .expect("Writing to a string should not fail (except on OOM)");
    ///     assert_eq!(sanitized, expected);
    pub fn write_to<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        let opts = Self::serialize_opts();
        serialize(writer, &self.0, opts)
    }

    /// Exposes the `Document` instance as an [`html5ever::rcdom::Handle`][h].
    ///
    /// This method returns the inner object backing the `Document` instance. This allows
    /// making further changes to the DOM without introducing redundant serialization and
    /// parsing.
    ///
    /// Note that this method should be considered unstable and sits outside of the semver
    /// stability guarantees. It may change, break, or go away at any time, either because
    /// of `html5ever` changes or `ammonia` implementation changes.
    ///
    /// For this method to be accessible, a `cfg` flag is required. The easiest way is to
    /// use the `RUSTFLAGS` environment variable:
    ///
    /// [h]: ../markup5ever/rcdom/type.Handle.html
    ///
    /// ```text
    /// RUSTFLAGS='--cfg ammonia_unstable' cargo build
    /// ```
    ///
    /// on Unix-like platforms, or
    ///
    /// ```text
    /// set RUSTFLAGS=--cfg ammonia_unstable
    /// cargo build
    /// ```
    ///
    /// on Windows.
    ///
    /// This requirement also applies to crates that transitively depend on crates that use
    /// this flag.
    ///
    /// # Examples
    ///
    ///     # extern crate ammonia;
    ///     extern crate html5ever;
    ///
    ///     use ammonia::Builder;
    ///     use html5ever::serialize::{serialize, SerializeOpts};
    ///
    ///     # use std::error::Error;
    ///     # fn do_main() -> Result<(), Box<Error>> {
    ///     let input = "<a>one link</a> and <a>one more</a>";
    ///     let expected = "<a>one more</a> and <a>one link</a>";
    ///
    ///     let document = Builder::new()
    ///         .link_rel(None)
    ///         .clean(input);
    ///
    ///     let mut node = document.to_dom_node();
    ///     node.children.borrow_mut().reverse();
    ///
    ///     let mut buf = Vec::new();
    ///     serialize(&mut buf, &node, SerializeOpts::default())?;
    ///     let output = String::from_utf8(buf)?;
    ///
    ///     assert_eq!(output, expected);
    ///     # Ok(())
    ///     # }
    ///     # fn main() { do_main().unwrap() }
    #[cfg(ammonia_unstable)]
    pub fn to_dom_node(&self) -> Handle {
        self.0.clone()
    }

    fn serialize_opts() -> SerializeOpts {
        SerializeOpts::default()
    }
}

impl fmt::Debug for Document {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Document({})", self.to_string())
    }
}

impl From<Document> for String {
    fn from(document: Document) -> Self {
        document.to_string()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn included_angles() {
        let fragment = "1 < 2";
        let result = clean(fragment);
        assert_eq!(result, "1 &lt; 2");
    }
    #[test]
    fn remove_script() {
        let fragment = "an <script>evil()</script> example";
        let result = clean(fragment);
        assert_eq!(result, "an evil() example");
    }
    #[test]
    fn ignore_link() {
        let fragment = "a <a href=\"http://www.google.com\">good</a> example";
        let expected = "a <a href=\"http://www.google.com\" rel=\"noopener noreferrer\">\
                        good</a> example";
        let result = clean(fragment);
        assert_eq!(result, expected);
    }
    #[test]
    fn remove_unsafe_link() {
        let fragment = "an <a onclick=\"evil()\" href=\"http://www.google.com\">evil</a> example";
        let result = clean(fragment);
        assert_eq!(
            result,
            "an <a href=\"http://www.google.com\" rel=\"noopener noreferrer\">evil</a> example"
        );
    }
    #[test]
    fn remove_js_link() {
        let fragment = "an <a href=\"javascript:evil()\">evil</a> example";
        let result = clean(fragment);
        assert_eq!(result, "an <a rel=\"noopener noreferrer\">evil</a> example");
    }
    #[test]
    fn tag_rebalance() {
        let fragment = "<b>AWESOME!";
        let result = clean(fragment);
        assert_eq!(result, "<b>AWESOME!</b>");
    }
    #[test]
    fn allow_url_relative() {
        let fragment = "<a href=test>Test</a>";
        let result = Builder::new()
            .url_relative(UrlRelative::PassThrough)
            .clean(fragment)
            .to_string();
        assert_eq!(
            result,
            "<a href=\"test\" rel=\"noopener noreferrer\">Test</a>"
        );
    }
    #[test]
    fn rewrite_url_relative() {
        let fragment = "<a href=test>Test</a>";
        let result = Builder::new()
            .url_relative(UrlRelative::RewriteWithBase("http://example.com/"))
            .clean(fragment)
            .to_string();
        assert_eq!(
            result,
            "<a href=\"http://example.com/test\" rel=\"noopener noreferrer\">Test</a>"
        );
    }
    #[test]
    fn rewrite_url_relative_no_rel() {
        let fragment = "<a href=test>Test</a>";
        let result = Builder::new()
            .url_relative(UrlRelative::RewriteWithBase("http://example.com/"))
            .link_rel(None)
            .clean(fragment)
            .to_string();
        assert_eq!(result, "<a href=\"http://example.com/test\">Test</a>");
    }
    #[test]
    fn deny_url_relative() {
        let fragment = "<a href=test>Test</a>";
        let result = Builder::new()
            .url_relative(UrlRelative::Deny)
            .clean(fragment)
            .to_string();
        assert_eq!(result, "<a rel=\"noopener noreferrer\">Test</a>");
    }
    #[test]
    fn replace_rel() {
        let fragment = "<a href=test rel=\"garbage\">Test</a>";
        let result = Builder::new()
            .url_relative(UrlRelative::PassThrough)
            .clean(fragment)
            .to_string();
        assert_eq!(
            result,
            "<a href=\"test\" rel=\"noopener noreferrer\">Test</a>"
        );
    }
    #[test]
    fn consider_rel_still_banned() {
        let fragment = "<a href=test rel=\"garbage\">Test</a>";
        let result = Builder::new()
            .url_relative(UrlRelative::PassThrough)
            .link_rel(None)
            .clean(fragment)
            .to_string();
        assert_eq!(result, "<a href=\"test\">Test</a>");
    }
    #[test]
    fn object_data() {
        let fragment = "<span data=\"javascript:evil()\">Test</span>\
                        <object data=\"javascript:evil()\"></object>M";
        let expected = r#"<span data="javascript:evil()">Test</span><object></object>M"#;
        let result = Builder::new()
            .tags(hashset!["span", "object"])
            .generic_attributes(hashset!["data"])
            .clean(fragment)
            .to_string();
        assert_eq!(result, expected);
    }
    #[test]
    fn remove_attributes() {
        let fragment = "<table border=\"1\"><tr></tr></table>";
        let result = Builder::new().clean(fragment);
        assert_eq!(
            result.to_string(),
            "<table><tbody><tr></tr></tbody></table>"
        );
    }
    #[test]
    fn quotes_in_attrs() {
        let fragment = "<b title='\"'>contents</b>";
        let result = clean(fragment);
        assert_eq!(result, "<b title=\"&quot;\">contents</b>");
    }
    #[test]
    #[should_panic]
    fn panic_if_rel_is_allowed_and_replaced_generic() {
        Builder::new()
            .link_rel(Some("noopener noreferrer"))
            .generic_attributes(hashset!["rel"])
            .clean("something");
    }
    #[test]
    #[should_panic]
    fn panic_if_rel_is_allowed_and_replaced_a() {
        Builder::new()
            .link_rel(Some("noopener noreferrer"))
            .tag_attributes(hashmap![
                "a" => hashset!["rel"],
            ])
            .clean("something");
    }
    #[test]
    fn no_panic_if_rel_is_allowed_and_replaced_span() {
        Builder::new()
            .link_rel(Some("noopener noreferrer"))
            .tag_attributes(hashmap![
                "span" => hashset!["rel"],
            ])
            .clean("<span rel=\"what\">s</span>");
    }
    #[test]
    fn no_panic_if_rel_is_allowed_and_not_replaced_generic() {
        Builder::new()
            .link_rel(None)
            .generic_attributes(hashset!["rel"])
            .clean("<a rel=\"what\">s</a>");
    }
    #[test]
    fn no_panic_if_rel_is_allowed_and_not_replaced_a() {
        Builder::new()
            .link_rel(None)
            .tag_attributes(hashmap![
                "a" => hashset!["rel"],
            ])
            .clean("<a rel=\"what\">s</a>");
    }
    #[test]
    fn dont_close_void_elements() {
        let fragment = "<br>";
        let result = clean(fragment);
        assert_eq!(result.to_string(), "<br>");
    }
    #[should_panic]
    #[test]
    fn panic_on_allowed_classes_tag_attributes() {
        let fragment = "<p class=\"foo bar\"><a class=\"baz bleh\">Hey</a></p>";
        Builder::new()
            .link_rel(None)
            .tag_attributes(hashmap![
                "p" => hashset!["class"],
                "a" => hashset!["class"],
            ])
            .allowed_classes(hashmap![
                "p" => hashset!["foo", "bar"],
                "a" => hashset!["baz"],
            ])
            .clean(fragment);
    }
    #[should_panic]
    #[test]
    fn panic_on_allowed_classes_generic_attributes() {
        let fragment = "<p class=\"foo bar\"><a class=\"baz bleh\">Hey</a></p>";
        Builder::new()
            .link_rel(None)
            .generic_attributes(hashset!["class", "href", "some-foo"])
            .allowed_classes(hashmap![
                "p" => hashset!["foo", "bar"],
                "a" => hashset!["baz"],
            ])
            .clean(fragment);
    }
    #[test]
    fn remove_non_allowed_classes() {
        let fragment = "<p class=\"foo bar\"><a class=\"baz bleh\">Hey</a></p>";
        let result = Builder::new()
            .link_rel(None)
            .allowed_classes(hashmap![
                "p" => hashset!["foo", "bar"],
                "a" => hashset!["baz"],
            ])
            .clean(fragment);
        assert_eq!(
            result.to_string(),
            "<p class=\"foo bar\"><a class=\"baz\">Hey</a></p>"
        );
    }
    #[test]
    fn remove_non_allowed_classes_with_tag_class() {
        let fragment = "<p class=\"foo bar\"><a class=\"baz bleh\">Hey</a></p>";
        let result = Builder::new()
            .link_rel(None)
            .tag_attributes(hashmap![
                "div" => hashset!["class"],
            ])
            .allowed_classes(hashmap![
                "p" => hashset!["foo", "bar"],
                "a" => hashset!["baz"],
            ])
            .clean(fragment);
        assert_eq!(
            result.to_string(),
            "<p class=\"foo bar\"><a class=\"baz\">Hey</a></p>"
        );
    }
    #[test]
    fn remove_entity_link() {
        let fragment = "<a href=\"&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61\
                        &#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29\">Click me!</a>";
        let result = clean(fragment);
        assert_eq!(
            result.to_string(),
            "<a rel=\"noopener noreferrer\">Click me!</a>"
        );
    }
    #[test]
    fn clean_children_of_bad_element() {
        let fragment = "<bad><evil>a</evil>b</bad>";
        let result = Builder::new().clean(fragment);
        assert_eq!(result.to_string(), "ab");
    }
    #[test]
    fn reader_input() {
        let fragment = b"an <script>evil()</script> example";
        let result = Builder::new().clean_from_reader(&mut &fragment[..]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "an evil() example");
    }
    #[test]
    fn reader_non_utf8() {
        let fragment = b"non-utf8 \xF0\x90\x80string";
        let result = Builder::new().clean_from_reader(&mut &fragment[..]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "non-utf8 \u{fffd}string");
    }
    #[test]
    fn debug_impl() {
        let fragment = r#"a <a>link</a>"#;
        let result = Builder::new().link_rel(None).clean(fragment);
        assert_eq!(format!("{:?}", result), "Document(a <a>link</a>)");
    }
    #[cfg(ammonia_unstable)]
    #[test]
    fn to_dom_node() {
        let fragment = r#"a <a>link</a>"#;
        let result = Builder::new().link_rel(None).clean(fragment);
        let _node = result.to_dom_node();
    }
    #[test]
    fn string_from_document() {
        let fragment = r#"a <a>link"#;
        let result = String::from(Builder::new().link_rel(None).clean(fragment));
        assert_eq!(format!("{}", result), "a <a>link</a>");
    }
    fn require_sync<T: Sync>(_: T) {}
    fn require_send<T: Send>(_: T) {}
    #[test]
    fn require_sync_and_send() {
        require_sync(Builder::new());
        require_send(Builder::new());
    }
}
