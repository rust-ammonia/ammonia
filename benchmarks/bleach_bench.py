import bleach
import time
n = 10000
# Ensure the settings are the same.
tags = [
    "a", "b", "blockquote", "br", "code", "dd", "del", "dl", "dt",
    "em", "i", "h1", "h2", "h3", "hr", "img", "kbd", "li", "ol", "p",
    "pre", "s", "strike", "strong", "sub", "sup", "table", "tbody",
    "td", "th", "thead", "tr", "ul", "hr"
]
attributes = {
    "*": [ "title" ],
    "a": [ "href" ],
    "img": [ "width", "height", "src", "alt" ],
}
start = time.time()
for i in range(0, n):
    bleach.clean("""
        <p>Ammonia is a whitelist-based HTML sanitization library. It is designed to
        take untrusted user input with some HTML.</p>
        <p>Because Ammonia uses <a href="https://github.com/servo/html5ever" title="The HTML parser in Servo">html5ever</a> to parse document fragments the same way
        browsers do, it is extremely resilient to unknown attacks, much more so
        than regular-expression-based sanitizers.</p>
        <p>This library&#39;s API is modeled after <a href="https://github.com/jsocol/bleach">jsocol&#39;s Bleach</a> library for Python,
        but is not affiliated with it in any way. Unlike Bleach, it does not do
        linkification, it only sanitizes URLs in existing links.</p>
    """, tags=tags, attributes=attributes, strip=True)
print(((time.time() - start) * (10**9)) / n, "nanoseconds to clean up the intro to the Ammonia docs.")
