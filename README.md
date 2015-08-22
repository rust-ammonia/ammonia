HTML Sanitization
=================

[Full documentation here.](https://www.notriddle.com/rustdoc/ammonia/)

[![Build Status](https://travis-ci.org/notriddle/rust-ammonia.svg)](https://travis-ci.org/notriddle/rust-ammonia)

Ammonia is a whitelist-based HTML sanitization library. It is designed to
take untrusted user input with some HTML.

Because Ammonia uses [html5ever] to parse document fragments the same way
browsers do, it is extremely resilient to unknown attacks, much more so
than regular-expression-based sanitizers.
 
This library's API is modeled after [jsocol's Bleach] library for Python,
but is not affiliated with it in any way. Unlike Bleach, it does not do
linkification, it only sanitizes URLs in existing links.

[html5ever]: https://github.com/servo/html5ever "The HTML parser in Servo"
[jsocol's Bleach]: https://github.com/jsocol/bleach


Example
-------

Using [pulldown-cmark] together with Ammonia for a friendly user-facing comment
site.

```rust
let text = "[a link](http://www.notriddle.com/)";
let mut md_parse = Parser::new_opt(text, OPTION_ENABLE_TABLES);
let mut unsafe_html = String::new();
push_html(&mut unsafe_html, md_parse);
let safe_html = clean(&*unsafe_html);
assert_eq!(safe_html, "<a href=\"http://www.notriddle.com/\">a link</a>");
```

[pulldown-cmark]: https://github.com/google/pulldown-cmark

