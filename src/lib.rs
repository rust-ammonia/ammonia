// Copyright (C) 2015 Michael Howell
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
use html5ever::{driver as html, QualName};
use html5ever::rcdom::{RcDom, NodeData, Handle};
use html5ever::serialize::{serialize, SerializeOpts, TraversalScope};
use html5ever::tree_builder::{NodeOrText, TreeSink};
use std::collections::{HashMap, HashSet};
use tendril::stream::TendrilSink;
use url::Url;

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
    Ammonia::default().clean(src)
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
    /// Permit relative URLs on href and src attributes.
    pub url_relative: bool,
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
        Ammonia{
            tags: tags,
            tag_attributes: tag_attributes,
            generic_attributes: generic_attributes,
            url_schemes: url_schemes,
            url_relative: false,
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
        let mut parser = html::parse_fragment(RcDom::default(), html::ParseOpts::default(), QualName::new(None, ns!(), local_name!("div")), vec![]);
        parser.process(format_tendril!("{}", src));
        let mut dom = parser.finish();
        let mut stack = Vec::new();
        let body = {
            let children = dom.document.children.borrow();
            children[0].clone()
        };
        stack.push(body.clone());
        while !stack.is_empty() {
            let node = stack.pop().unwrap();
            let mut has_children = {
                match node.data {
                    NodeData::Comment{..} | NodeData::Text{..} | NodeData::Doctype{..} | NodeData::ProcessingInstruction{..} => false,
                    NodeData::Document | NodeData::Element{..} => true,
                }
            };
            while has_children {
                let mut children = std::mem::replace(&mut *node.children.borrow_mut(), Vec::new());

                for child in &mut children {
                    self.clean_child(&mut dom, child, node.clone());
                }
                {
                    has_children = node.children.borrow().len() != children.len();
                }
            }

            stack.extend(node.children.borrow().iter().cloned());
        }
        let mut ret_val = Vec::new();
        let opts = SerializeOpts{
            traversal_scope: TraversalScope::ChildrenOnly,
            .. SerializeOpts::default()
        };
        serialize(&mut ret_val, &body, opts).unwrap();
        String::from_utf8(ret_val).unwrap()
    }

    fn clean_child(&self, dom: &mut RcDom, child: &mut Handle, parent: Handle) {
        let pass = {
            match child.data {
                NodeData::Text{..} => true,
                NodeData::Comment{..} => !self.strip_comments,
                NodeData::Doctype{..} |
                NodeData::Document | NodeData::ProcessingInstruction{..} => false,
                NodeData::Element{ref name, ref attrs, ..} => {
                    let safe_tag = {
                        if self.tags.contains(&*name.local) {
                            let attr_filter = |attr: &html5ever::Attribute| {
                                let whitelisted = self.generic_attributes.contains(&*attr.name.local) ||
                                    self.tag_attributes.get(&*name.local).map(|ta| ta.contains(&*attr.name.local)) == Some(true);
                                if !whitelisted {
                                    false
                                } else if &*attr.name.local == "href" || &*attr.name.local == "src" || (&*name.local == "object" && &*attr.name.local == "data") {
                                    let url = Url::parse(&*attr.value);
                                    if let Ok(url) = url {
                                        self.url_schemes.contains(url.scheme())
                                    } else if url == Err(url::ParseError::RelativeUrlWithoutBase) {
                                        self.url_relative
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
                    };

                    if !safe_tag {
                        for sub in child.children.borrow_mut().iter_mut() {
                            sub.parent.replace(None);
                            dom.append(&parent.clone(), NodeOrText::AppendNode(sub.clone()));
                        }
                    }
                    safe_tag
                },
            }
        };
        if pass {
            child.parent.replace(None);
            dom.append(&parent.clone(), NodeOrText::AppendNode(child.clone()));
        }
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
        let result = clean(fragment);
        assert_eq!(result, fragment);
    }
    #[test]
    fn remove_unsafe_link() {
        let fragment = "a <a onclick=\"evil()\" href=\"http://www.google.com\">evil</a> example";
        let result = clean(fragment);
        assert_eq!(result, "a evil example");
    }
    #[test]
    fn remove_js_link() {
        let fragment = "a <a href=\"javascript:evil()\">evil</a> example";
        let result = clean(fragment);
        assert_eq!(result, "a evil example");
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
            url_relative: true,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "<a href=\"test\">Test</a>");
    }
    #[test]
    fn deny_url_relative() {
        let fragment = "<a href=test>Test</a>";
        let cleaner = Ammonia{
            url_relative: false,
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
        assert_eq!(result, "<table><tr></tr></table>");
    }
    #[test]
    fn quotes_in_attrs() {
        let fragment = "<b title='\"'>contents</b>";
        let result = clean(fragment);
        assert_eq!(result, "<b title=\"&quot;\">contents</b>");
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
}
