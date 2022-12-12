use time::Instant;

fn main() {
    let n = 10_000;
    let start = Instant::now();
    for _ in 0 .. n {
        ammonia::clean(r##"
        <p>Ammonia is a whitelist-based HTML sanitization library. It is designed to
        take untrusted user input with some HTML.</p>
        <p>Because Ammonia uses <a href="https://github.com/servo/html5ever" title="The HTML parser in Servo">html5ever</a> to parse document fragments the same way
        browsers do, it is extremely resilient to unknown attacks, much more so
        than regular-expression-based sanitizers.</p>
        <p>This library&#39;s API is modeled after <a href="https://github.com/jsocol/bleach">jsocol&#39;s Bleach</a> library for Python,
        but is not affiliated with it in any way. Unlike Bleach, it does not do
        linkification, it only sanitizes URLs in existing links.</p>
        "##);
    }
    println!("{} nanoseconds to clean up the intro to the Ammonia docs.", (Instant::now() - start).whole_nanoseconds() / n);
}
