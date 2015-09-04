// This file is a part of Ammonia.
// 
// Copyright (C) 2015 Michael Howell
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
//! [html5ever]: https://github.com/servo/html5ever "The HTML parser in Servo"
//! [jsocol's Bleach]: https://github.com/jsocol/bleach

#[macro_use]
extern crate grabbag_macros;
extern crate html5ever;
extern crate string_cache;
#[macro_use]
extern crate tendril;
extern crate url;
use html5ever::driver as html;
use html5ever::rcdom::{RcDom, NodeEnum, Handle};
use html5ever::serialize::{serialize, SerializeOpts, TraversalScope};
use html5ever::tree_builder::interface::{NodeOrText, TreeSink};
use std::collections::{HashMap, HashSet};
use std::mem::swap;
use string_cache::{Atom, QualName, Namespace};
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
    /// True: do not include stripped tags. False: escape stripped tags.
    pub strip: bool,
    /// True: strip HTML comments. False: leave HTML comments in.
    pub strip_comments: bool,
}

impl<'a> Default for Ammonia<'a> {
    fn default() -> Self {
        let tags = collect![
            "a", "b", "blockquote", "br", "code", "dd", "del", "dl", "dt",
            "em", "i", "h1", "h2", "h3", "hr", "img", "kbd", "li", "ol", "p",
            "pre", "s", "strike", "strong", "sub", "sup", "table", "tbody",
            "td", "th", "thead", "tr", "ul", "hr"
        ];
        let generic_attributes = collect![
            "title"
        ];
        let tag_attributes = collect![
            "a" => collect![
                "href"
            ],
            "img" => collect![
                "width", "height", "src", "alt"
            ]
        ];
        let url_schemes = collect![
            "http", "https", "mailto"
        ];
        Ammonia{
            tags: tags,
            tag_attributes: tag_attributes,
            generic_attributes: generic_attributes,
            url_schemes: url_schemes,
            strip: true,
            strip_comments: true,
        }
    }
}

impl<'a> Ammonia<'a> {
    /// Given a fragment of HTML, Ammonia will parse it according to the HTML5
    /// parsing algorithm and sanitize any disallowed tags or attributes. This
    /// algorithm also takes care of things like unclosed and (some) misnested
    /// tags.
    pub fn clean(&self, src: &'a str) -> String {
        let mut dom: RcDom = html::parse_fragment(std::iter::once(format_tendril!("{}", src)), QualName::new(Namespace(Atom::from_slice("")), Atom::from_slice("div")), Vec::new(), html::ParseOpts::default());
        let mut stack = Vec::new();
        let body = {
            let document = dom.document.borrow_mut();
            document.children[0].clone()
        };
        stack.push(body.clone());
        while stack.len() != 0 {
            let node_handle = stack.pop().unwrap();
            let mut has_children = {
                let node = node_handle.borrow_mut();
                match &node.node {
                    &NodeEnum::Comment(_) | &NodeEnum::Text(_) | &NodeEnum::Doctype(_, _, _) => false,
                    &NodeEnum::Document | &NodeEnum::Element(_, _, _) => true,
                }
            };
            while has_children {
                let mut children = Vec::new();
                {
                    let mut node = node_handle.borrow_mut();
                    swap(&mut node.children, &mut children);
                }
                for child in &mut children {
                    self.clean_child(&mut dom, child, node_handle.clone());
                }
                {
                    let node = node_handle.borrow_mut();
                    has_children = node.children.len() != children.len();
                }
            }
            let node = node_handle.borrow_mut();
            stack.extend(node.children.clone());
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
            let mut child = child.borrow_mut();
            let mut child = &mut *child;
            match &mut child.node {
                &mut NodeEnum::Text(_) => true,
                &mut NodeEnum::Comment(_) => !self.strip_comments,
                &mut NodeEnum::Doctype(_, _, _) |
                &mut NodeEnum::Document => false,
                &mut NodeEnum::Element(ref name, _, ref attrs) => {
                    let safe_tag = {
                        if self.tags.contains(&*name.local) {
                            attrs.iter().skip_while(|attr| {
                                let whitelisted = self.generic_attributes.contains(&*attr.name.local) ||
                                    self.tag_attributes.get(&*name.local).map(|ta| ta.contains(&*attr.name.local)) == Some(true);
                                if !whitelisted {
                                    false
                                } else if &*attr.name.local == "href" || &*attr.name.local == "src" {
                                    let url = Url::parse(&*attr.value);
                                    if let Ok(url) = url {
                                        self.url_schemes.contains(&*url.scheme)
                                    } else {
                                        false
                                    }
                                } else {
                                    true
                                }
                            }).next().is_none()
                        } else {
                            false
                        }
                    };
                    if !safe_tag {
                        if !self.strip {
                            dom.append(parent.clone(), NodeOrText::AppendText(format_tendril!("<{}", &*name.local)));
                            for attr in attrs {
                                dom.append(parent.clone(), NodeOrText::AppendText(format_tendril!(" {}=\"{}\"", &*attr.name.local, attr.value)))
                            }
                            dom.append(parent.clone(), NodeOrText::AppendText(format_tendril!(">")));
                        }
                        for sub in &mut child.children {
                            {
                                let mut sub = sub.borrow_mut();
                                sub.parent = None;
                            }
                            dom.append(parent.clone(), NodeOrText::AppendNode(sub.clone()));
                        }
                        if !self.strip {
                            dom.append(parent.clone(), NodeOrText::AppendText(format_tendril!("</{}>", &*name.local)))
                        }
                    }
                    safe_tag
                },
            }
        };
        if pass {
            {
                let mut child = child.borrow_mut();
                child.parent = None;
            }
            dom.append(parent, NodeOrText::AppendNode(child.clone()));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
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
    fn strip_js_link() {
        let fragment = "a <a href=\"javascript:evil()\">evil</a> example";
        let cleaner = Ammonia{
            strip: false,
            .. Ammonia::default()
        };
        let result = cleaner.clean(fragment);
        assert_eq!(result, "a &lt;a href=\"javascript:evil()\"&gt;evil&lt;/a&gt; example");
    }
    #[test]
    fn tag_rebalance() {
        let fragment = "<b>AWESOME!";
        let result = clean(fragment);
        assert_eq!(result, "<b>AWESOME!</b>");
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
