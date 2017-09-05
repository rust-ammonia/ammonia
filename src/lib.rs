// Copyright (C) Michael Howell and others
// this library is released under the same terms as Rust itself.

//! Ammonia is a whitelist-based HTML sanitization library. It is designed to
//! take untrusted user input with some HTML.
//!
//! Because Ammonia uses [html5ever] to parse document fragments the same way
//! browsers do, it is extremely resilient to unknown attacks, much more so
//! than regular-expression-based sanitizers.
//!
//! This library's API is modeled after [jsocol's Bleach] library for Python,
//! but is not affiliated with it in any way. Unlike Bleach, it does not do
//! linkification, it only sanitizes URLs in existing links.
//!
//! # Example
//!
//! ```
//! let result = ammonia::clean("<b><img src='' onerror='alert(\\'hax\\')'>I'm not trying to XSS you</b>");
//! assert_eq!(result, "<b>I'm not trying to XSS you</b>");
//! ```
//!
//! [html5ever]: https://github.com/servo/html5ever "The HTML parser in Servo"
//! [jsocol's Bleach]: https://github.com/jsocol/bleach

#[macro_use]
extern crate html5ever;
#[macro_use]
extern crate maplit;
#[macro_use]
extern crate tendril;
extern crate url;
#[macro_use]
extern crate lazy_static;

use html5ever::{driver as html, QualName};
use html5ever::rcdom::{RcDom, NodeData, Handle};
use html5ever::serialize::{serialize, SerializeOpts, TraversalScope};
use html5ever::tree_builder::{NodeOrText, TreeSink};
use html5ever::interface::Attribute;
use std::collections::{HashMap, HashSet};
use std::mem::replace;
use std::rc::Rc;
use tendril::stream::TendrilSink;
use tendril::StrTendril;
use url::Url;

lazy_static! {
    static ref AMMONIA: Ammonia<'static> = Ammonia::default();
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
///  * Elements with invalid attributes are completely removed,
///    to avoid confusion about what is and is not allowed.
pub fn clean(src: &str) -> String {
    AMMONIA.clean(src)
}

/// Settings for HTML cleaning.
pub struct Ammonia<'a> {
    /// Tags that are allowed. Note that this only whitelists the tag; it will
    /// still be stripped if it has unlisted attributes.
    pub tags: HashSet<&'a str>,
    /// Attributes that are allowed on certain tags. If the tag is not itself
    /// whitelisted, adding entries to this map do nothing. It is structured
    /// as a map from tag name to set of attribute name.
    pub tag_attributes: HashMap<&'a str, HashSet<&'a str>>,
    /// Attributes that are allowed on any tag.
    pub generic_attributes: HashSet<&'a str>,
    /// Permitted URL schemes on href and src attributes.
    pub url_schemes: HashSet<&'a str>,
    /// Behavior on relative URLs: pass-through, resolve-with-base, or deny.
    pub url_relative: UrlRelative<'a>,
    /// Stick these rel="" attributes on every link.
    /// If rel is in the generic or tag attributes, this must be `None`.
    pub link_rel: Option<&'a str>,
    /// Classes that are allowed on certain tags. If the class attribute is not
    /// itself whitelisted for a tag, then adding entries to this map does
    /// nothing. It is structured as a map from tag name to a set of class names.
    pub allowed_classes: HashMap<&'a str, HashSet<&'a str>>,
    /// True: strip HTML comments. False: leave HTML comments in.
    pub strip_comments: bool,
    /// True: remove disallowed attributes, but not the elements containing them.
    /// False: remove elements with disallowed attributes.
    pub keep_cleaned_elements: bool,
}

impl<'a> Default for Ammonia<'a> {
    fn default() -> Self {
        let tags = hashset![
            "a", "b", "blockquote", "br", "code", "dd", "del", "dl", "dt",
            "em", "i", "h1", "h2", "h3", "hr", "img", "kbd", "li", "ol", "p",
            "pre", "s", "strike", "strong", "sub", "sup", "table", "tbody",
            "td", "th", "thead", "tr", "ul", "hr"
        ];
        let generic_attributes = hashset![
            "title"
        ];
        let tag_attributes = hashmap![
            "a" => hashset![
                "href"
            ],
            "img" => hashset![
                "width", "height", "src", "alt"
            ]
        ];
        let url_schemes = hashset![
            "http", "https", "mailto"
        ];
        let allowed_classes = hashmap![];

        Ammonia{
            tags: tags,
            tag_attributes: tag_attributes,
            generic_attributes: generic_attributes,
            url_schemes: url_schemes,
            url_relative: UrlRelative::Deny,
            link_rel: Some("noopener noreferrer"),
            allowed_classes: allowed_classes,
            strip_comments: true,
            keep_cleaned_elements: false,
        }
    }
}

impl<'a> Ammonia<'a> {
    /// Given a fragment of HTML, Ammonia will parse it according to the HTML5
    /// parsing algorithm and sanitize any disallowed tags or attributes. This
    /// algorithm also takes care of things like unclosed and (some) misnested
    /// tags.
    pub fn clean(&self, src: &'a str) -> String {
        let mut parser = html::parse_fragment(RcDom::default(), html::ParseOpts::default(), QualName::new(None, ns!(html), local_name!("div")), vec![]);
        parser.process(format_tendril!("{}", src));
        let mut dom = parser.finish();
        let mut stack = Vec::new();
        let link_rel = self.link_rel.map(|link_rel| format_tendril!("{}", link_rel));
        if link_rel.is_some() {
            assert!(self.generic_attributes.get("rel").is_none());
            assert!(self.tag_attributes.get("a").and_then(|a| a.get("rel")).is_none());
        }
        let url_base = if let UrlRelative::RewriteWithBase(base) = self.url_relative {
            Some(Url::parse(base).expect("RewriteWithBase(base) should have a valid URL for base"))
        } else {
            None
        };
        let body = {
            let children = dom.document.children.borrow();
            children[0].clone()
        };
        stack.extend(replace(&mut *body.children.borrow_mut(), Vec::new()).into_iter().rev());
        while !stack.is_empty() {
            let mut node = stack.pop().unwrap();
            let parent = node.parent.replace(None).unwrap().upgrade().unwrap();
            let pass = self.clean_child(&mut node);
            if pass {
                self.fix_child(&mut node, &link_rel, &url_base);
                dom.append(&parent.clone(), NodeOrText::AppendNode(node.clone()));
            } else {
                for sub in node.children.borrow_mut().iter_mut() {
                    sub.parent.replace(Some(Rc::downgrade(&parent)));
                }
            }
            stack.extend(replace(&mut *node.children.borrow_mut(), Vec::new()).into_iter().rev());
        }
        let mut ret_val = Vec::new();
        let opts = SerializeOpts{
            traversal_scope: TraversalScope::ChildrenOnly,
            .. SerializeOpts::default()
        };
        serialize(&mut ret_val, &body, opts).unwrap();
        String::from_utf8(ret_val).unwrap()
    }

    fn clean_child(&self, child: &mut Handle) -> bool {
        match child.data {
            NodeData::Text{..} => true,
            NodeData::Comment{..} => !self.strip_comments,
            NodeData::Doctype{..} |
            NodeData::Document | NodeData::ProcessingInstruction{..} => false,
            NodeData::Element{ref name, ref attrs, ..} => {
                if self.tags.contains(&*name.local) {
                    let attr_filter = |attr: &html5ever::Attribute| {
                        let whitelisted = self.generic_attributes.contains(&*attr.name.local) ||
                            self.tag_attributes.get(&*name.local).map(|ta| ta.contains(&*attr.name.local)) == Some(true);
                        if !whitelisted {
                            false
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
                    if self.keep_cleaned_elements {
                        attrs.borrow_mut().retain(attr_filter);
                        true
                    } else {
                        attrs.borrow().iter().all(attr_filter)
                    }
                } else {
                    false
                }
            }
        }
    }

    fn fix_child(&self, child: &mut Handle, link_rel: &Option<StrTendril>, url_base: &Option<Url>) {
        if let &NodeData::Element{ref name, ref attrs, ..} = &child.data {
            if let &Some(ref link_rel) = link_rel {
                if &*name.local == "a" {
                    attrs.borrow_mut().push(Attribute{
                        name: QualName::new(None, ns!(), local_name!("rel")),
                        value: link_rel.clone(),
                    })
                }
            }
            if let &Some(ref base) = url_base {
                for attr in &mut *attrs.borrow_mut() {
                    if is_url_attr(&*name.local, &*attr.name.local) {
                        let url = base.join(&*attr.value).expect("invalid URLs should be stripped earlier");
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
}

/// Given an element name and attribute name, determine if the given attribute contains a URL.
fn is_url_attr(element: &str, attr: &str) -> bool {
    attr == "href" || attr == "src" || (element == "object" && attr == "data")
}

/// Policy for relative URLs, that is, URLs that do not specify the scheme in full.
///
/// This policy kicks in, if set, for any attribute named `src` or `href`,
/// as well as the `data` attribute of an `object` tag.
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UrlRelative<'a> {
    /// Relative URLs will be completely stripped from the document.
    Deny,
    /// Relative URLs will be passed through unchanged.
    PassThrough,
    /// Relative URLs will be changed into absolute URLs, based on this base URL.
    RewriteWithBase(&'a str),
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
        let expected = "a <a href=\"http://www.google.com\" rel=\"noopener noreferrer\">good</a> example";
        let result = clean(fragment);
        assert_eq!(result, expected);
    }
    #[test]
    fn remove_unsafe_link() {
        let fragment = "an <a onclick=\"evil()\" href=\"http://www.google.com\">evil</a> example";
        let result = clean(fragment);
        assert_eq!(result, "an evil example");
    }
    #[test]
    fn remove_js_link() {
        let fragment = "an <a href=\"javascript:evil()\">evil</a> example";
        let result = clean(fragment);
        assert_eq!(result, "an evil example");
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
        let cleaner = Ammonia{
            url_relative: UrlRelative::PassThrough,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "<a href=\"test\" rel=\"noopener noreferrer\">Test</a>");
    }
    #[test]
    fn rewrite_url_relative() {
        let fragment = "<a href=test>Test</a>";
        let cleaner = Ammonia{
            url_relative: UrlRelative::RewriteWithBase("http://example.com/"),
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "<a href=\"http://example.com/test\" rel=\"noopener noreferrer\">Test</a>");
    }
    #[test]
    fn rewrite_url_relative_no_rel() {
        let fragment = "<a href=test>Test</a>";
        let cleaner = Ammonia{
            url_relative: UrlRelative::RewriteWithBase("http://example.com/"),
            link_rel: None,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "<a href=\"http://example.com/test\">Test</a>");
    }
    #[test]
    fn deny_url_relative() {
        let fragment = "<a href=test>Test</a>";
        let cleaner = Ammonia{
            url_relative: UrlRelative::Deny,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "Test");
    }
    #[test]
    fn replace_rel() {
        let fragment = "<a href=test rel=\"garbage\">Test</a>";
        let cleaner = Ammonia{
            url_relative: UrlRelative::PassThrough,
            keep_cleaned_elements: true,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "<a href=\"test\" rel=\"noopener noreferrer\">Test</a>");
    }
    #[test]
    fn consider_rel_still_banned() {
        let fragment = "<a href=test rel=\"garbage\">Test</a>";
        let cleaner = Ammonia{
            url_relative: UrlRelative::PassThrough,
            keep_cleaned_elements: false,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "Test");
    }
    #[test]
    fn object_data() {
        let fragment = "<span data=\"javascript:evil()\">Test</span><object data=\"javascript:evil()\"></object>M";
        let expected = "<span data=\"javascript:evil()\">Test</span>M";
        let cleaner = Ammonia{
            tags: hashset![
                "span", "object"
            ],
            generic_attributes: hashset![
                "data"
            ],
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, expected);
    }
    #[test]
    fn remove_attributes() {
        let fragment = "<table border=\"1\"><tr></tr></table>";
        let cleaner = Ammonia {
            keep_cleaned_elements: true,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "<table><tbody><tr></tr></tbody></table>");
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
        let cleaner = Ammonia {
            link_rel: Some("noopener noreferrer"),
            generic_attributes: hashset!["rel"],
            .. Ammonia::default()
        };
        cleaner.clean("something");
    }
    #[test]
    #[should_panic]
    fn panic_if_rel_is_allowed_and_replaced_a() {
        let cleaner = Ammonia {
            link_rel: Some("noopener noreferrer"),
            tag_attributes: hashmap![
                "a" => hashset!["rel"],
            ],
            .. Ammonia::default()
        };
        cleaner.clean("something");
    }
    #[test]
    fn no_panic_if_rel_is_allowed_and_replaced_span() {
        let cleaner = Ammonia {
            link_rel: Some("noopener noreferrer"),
            tag_attributes: hashmap![
                "span" => hashset!["rel"],
            ],
            .. Ammonia::default()
        };
        cleaner.clean("<span rel=\"what\">s</span>");
    }
    #[test]
    fn no_panic_if_rel_is_allowed_and_not_replaced_generic() {
        let cleaner = Ammonia {
            link_rel: None,
            generic_attributes: hashset![
                "rel"
            ],
            .. Ammonia::default()
        };
        cleaner.clean("<a rel=\"what\">s</a>");
    }
    #[test]
    fn no_panic_if_rel_is_allowed_and_not_replaced_a() {
        let cleaner = Ammonia {
            link_rel: None,
            tag_attributes: hashmap![
                "a" => hashset!["rel"],
            ],
            .. Ammonia::default()
        };
        cleaner.clean("<a rel=\"what\">s</a>");
    }
    // The rest of these are stolen from
    // https://code.google.com/p/html-sanitizer-testbed/source/browse/trunk/testcases/t10.html
    #[test]
    fn test_10() {
        let fragment = "<SCRIPT/alert(10);/";
        let result = clean(fragment);
        assert_eq!(result, "");
    }
    #[test]
    fn test_11() {
        let fragment = "<IMG SRC=\"javas%63ript:alert(11);\">";
        let result = clean(fragment);
        assert_eq!(result, "");
    }
    #[test]
    fn test_100() {
        let fragment = "<!-- Here is a comment: -- This is a nested comment -->\n<a href=\"http://harmless.com/This is still inside the comment: --evadefilter><img onerror=alert(100) src=''/><a href=\"test\">link</a>";
        let result = clean(fragment);
        assert_eq!(result, "\nlink");
    }
    #[test]
    fn dont_close_void_elements() {
        let fragment = "<br>";
        let result = clean(fragment);
        assert_eq!(result, "<br>");
    }
    #[test]
    fn remove_non_allowed_classes() {
        let fragment = "<p class=\"foo bar\"><a class=\"baz bleh\">Hey</a></p>";
        let cleaner = Ammonia {
            link_rel: None,
            tag_attributes: hashmap![
                "p" => hashset!["class"],
                "a" => hashset!["class"],
            ],
            allowed_classes: hashmap![
                "p" => hashset!["foo", "bar"],
                "a" => hashset!["baz"],
            ],
            .. Ammonia::default()
        };

        let result = cleaner.clean(fragment);
        assert_eq!(result, "<p class=\"foo bar\"><a class=\"baz\">Hey</a></p>");
    }
    #[test]
    fn remove_entity_link() {
        let fragment = r#"<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29">Click me!</a>"#;
        let result = clean(fragment);
        assert_eq!(result, "Click me!");
    }
    #[test]
    fn clean_children_of_bad_element() {
        let fragment = "<bad><evil>a</evil>b</bad>";
        let cleaner = Ammonia {
            keep_cleaned_elements: false,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "ab");
        let cleaner = Ammonia {
            keep_cleaned_elements: true,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "ab");
    }
    fn require_sync<T: Sync>(_: T) {}
    fn require_send<T: Send>(_: T) {}
    #[test]
    fn require_sync_and_send() {
        require_sync(Ammonia::default());
        require_send(Ammonia::default());
    }
}
