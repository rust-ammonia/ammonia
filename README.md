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
extern crate pulldown_cmark;
extern crate ammonia;
use pulldown_cmark::{push_html, Parser};
use ammonia::clean;
let text = "[a link](http://www.notriddle.com/)";
let mut md_parse = Parser::new_ext(text, OPTION_ENABLE_TABLES);
let mut unsafe_html = String::new();
push_html(&mut unsafe_html, md_parse);
let safe_html = clean(&*unsafe_html);
assert_eq!(safe_html, "<a href=\"http://www.notriddle.com/\">a link</a>");
```

[pulldown-cmark]: https://github.com/google/pulldown-cmark


Performance
-----------

Ammonia builds a DOM, traverses it (replacing unwanted nodes along the way),
and serializes it again. It could be faster for what it does, and if you don't
want to allow any HTML it is possible to be even faster than that.

However, it takes about fifty times longer to sanitize an HTML string using
Bleach than it does using Ammonia.

    $ cd benchmarks
    $ cargo run --release --features unstable
        Running `target/release/ammonia_bench`
    56829 nanoseconds to clean up the intro to the Ammonia docs.
    $ python3 bleach_bench.py
    2910792.875289917 nanoseconds to clean up the intro to the Ammonia docs.

